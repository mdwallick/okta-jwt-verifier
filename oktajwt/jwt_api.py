import base64
import json
import logging
import os
import struct
import time

from calendar import timegm
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .http import Http
from .file_cache_plugin import FileCachePlugin
from .s3_cache_plugin import S3CachePlugin

from .exceptions import (
    OktaError,
    DecodeError,
    InvalidSignatureError,
    InvalidIssuerError,
    MissingRequiredClaimError,
    InvalidAudienceError,
    ExpiredTokenError,
    InvalidIssuedAtError,
    InvalidKeyError,
    KeyNotFoundError,
    CacheObjectNotFoundError
)


class JwtVerifier:

    PADDING = padding.PKCS1v15()
    HASH_ALGORITHM = hashes.SHA256()
    PEM_ENCODING = Encoding.PEM
    PUBLIC_KEY_FORMAT = PublicFormat.SubjectPublicKeyInfo
    logger = logging.getLogger(__name__)

    def __init__(self, *args, **kwargs):
        # used to store the issuer from the incoming JWT
        self.reported_issuer = None

        if "verbosity" in kwargs and kwargs["verbosity"] == 2:
            logging.basicConfig(level="DEBUG")
        elif "verbosity" in kwargs and kwargs["verbosity"] == 1:
            logging.basicConfig(level="INFO")
        else:
            logging.basicConfig(level="ERROR")

        if "issuer" in kwargs and kwargs["issuer"]:
            self.issuer = kwargs["issuer"]
            self.logger.info("Issuer: {0}".format(self.issuer))
        else:
            raise ValueError("An issuer is required")

        if "client_id" in kwargs and kwargs["client_id"]:
            self.client_id = kwargs["client_id"]
            self.logger.info("Client ID: {0}".format(self.client_id))
        else:
            raise ValueError("A client ID is required")

        if "client_secret" in kwargs and kwargs["client_secret"]:
            self.client_secret = kwargs["client_secret"]
            self.logger.info("Client secret: ********")
        else:
            self.client_secret = None
            self.logger.info("Client secret: None. Assuming PKCE.")

        if "cache" not in kwargs or kwargs["cache"] == "file":
            home_dir = str(Path.home())
            cache_dir = "{0}/.oktajwt".format(home_dir)
            self.jwks_cache = FileCachePlugin(cache_dir)
            self.logger.info(
                "Caching: filesystem with cache directory {0}".format(cache_dir))
        else:
            if kwargs["cache"] == "S3":
                if "bucket" in kwargs and kwargs["bucket"]:
                    bucket = kwargs["bucket"]
                    self.jwks_cache = S3CachePlugin(bucket)
                    self.logger.info(
                        "Caching: S3 with bucket {0}".format(bucket))
                else:
                    raise ValueError("Bucket is required if cache is S3")
            else:
                raise ValueError(
                    "Unknow caching method {0}".format(kwargs["cache"]))

    def verify(self, access_token, expected_audience):
        """
        Verify the access token and return the claims as JSON.

        """
        return self.__decode(access_token, expected_audience)

    def __decode(self, jwt, expected_audience):
        self.logger.info("starting __decode()")
        # crack open the token and get the header, payload, signature
        # and signed message (header + payload)
        header, payload, signature, signed_message = self.__get_jwt_parts(jwt)

        # get the issuer and audience from the JWT
        self.reported_issuer = payload["iss"]
        self.reported_audience = payload["aud"]

        self.logger.info("Reported issuer:   {0}".format(self.reported_issuer))
        self.logger.info("Reported audience: {0}".format(self.reported_audience))

        # validate the signature. at this point we know that we
        # at least have well-formed JSON for the header and payload
        if self.__verify_signature(signature, signed_message, header["kid"]):
            # parse the token and validate the claims
            self.logger.info("Trying to parse the payload into JSON")
            try:
                # verify and return the payload
                return self.__verify_payload(payload, expected_audience)
            except ValueError as e:
                raise DecodeError("Invalid payload JSON: %s" % e)
        else:
            raise InvalidSignatureError("Signature is not valid")

    def __get_jwt_parts(self, jwt):
        # decode the JWT and return the header as JSON,
        # the payload as a b64 decoded byte array
        # the signature as a b64 decoded byte array
        if isinstance(jwt, str):
            jwt = jwt.encode("utf-8")

        # the JWT looks like this:
        # <b64 header>.<b64 payload>.<b64 signature>
        # signed_message is the header+payload in its raw JWT form
        #  e.g. <b64 header>.<b64 payload> (including the period)
        # signature_chunk is the raw signature from the JWT
        #  e.g. <b64 signature>
        signed_message, signature_chunk = jwt.rsplit(b".", 1)
        header_chunk, payload_chunk = signed_message.split(b".", 1)

        # make sure the header is valid json
        header = self.__decode_base64(header_chunk)
        try:
            header = json.loads(header.decode("utf-8"))
            self.logger.info("Header is well-formed JSON")
        except ValueError as e:
            raise DecodeError("Invalid header JSON: %s" % e)

        # make sure the payload is also valid json
        payload = self.__decode_base64(payload_chunk)
        try:
            payload = json.loads(payload.decode("utf-8"))
            self.logger.info("Payload is well-formed JSON")
        except ValueError as e:
            raise DecodeError("Invalid payload JSON: %s" % e)
        
        signature = self.__decode_base64(signature_chunk)
        return (header, payload, signature, signed_message)

    def __verify_payload(self, payload, expected_audience):
        # check for and validate the required claims
        if "iss" not in payload:
            raise MissingRequiredClaimError("iss")

        if "aud" not in payload:
            raise MissingRequiredClaimError("aud")

        if "exp" not in payload:
            raise MissingRequiredClaimError("exp")

        if "iat" not in payload:
            raise MissingRequiredClaimError("iat")

        self.__verify_aud(payload["aud"], expected_audience)
        self.__verify_iss(payload["iss"], self.issuer)
        now = timegm(datetime.utcnow().utctimetuple())
        self.__verify_exp(payload["exp"], now)
        self.__verify_iat(payload["iat"], now)
        self.logger.info("JWT is valid")
        return payload

    def __verify_iss(self, issuer, expected):
        self.logger.info("starting __verify_iss()")
        self.logger.info("issuer:   {0}".format(issuer))
        self.logger.info("expected: {0}".format(expected))
        if issuer != expected:
            raise InvalidIssuerError(
                "Issuer mismatch. Got '{0}' expected '{1}'".format(issuer, expected))

    def __verify_aud(self, audience, expected):
        self.logger.info("starting __verify_aud()")
        self.logger.info("audience: {0}".format(audience))
        self.logger.info("expected: {0}".format(expected))
        if audience != expected:
            raise InvalidAudienceError(
                "Audience mismatch. Got '{0}' expected '{1}'".format(audience, expected))

    def __verify_exp(self, expiration, now):
        self.logger.info("starting __verify_exp()")
        try:
            exp = int(expiration)
        except ValueError:
            raise DecodeError(
                "Expiration Time claim (exp) must be an integer.")

        if exp < now:
            raise ExpiredTokenError("This JWT is expired.")

    def __verify_iat(self, issued, now):
        self.logger.info("starting __verify_iat()")
        try:
            iat = int(issued)
        except ValueError:
            raise DecodeError("Issued At Time claim (iat) must be an integer.")

        if iat > now:
            raise InvalidIssuedAtError("This JWT is not yet valid (iat).")

    def __verify_signature(self, signature, message, kid):
        self.logger.info("starting __verify_signature()")
        public_key = self.__get_public_key(kid)
        try:
            public_key.verify(signature, message,
                              self.PADDING, self.HASH_ALGORITHM)
            self.logger.info("JWT signature is valid")
            return True
        except InvalidSignature:
            raise InvalidSignatureError("JWT signature is not valid.")

    def __get_public_key(self, kid):
        self.logger.info("starting __get_public_key()")
        # get the exponent and modulus from the jwk so we can get the public key
        exponent, modulus = self.__get_jwk_parts(kid)
        numbers = RSAPublicNumbers(exponent, modulus)
        public_key = numbers.public_key(default_backend())
        public_key_serialized = public_key.public_bytes(
            self.PEM_ENCODING, self.PUBLIC_KEY_FORMAT)
        self.logger.info("public key: {0}".format(public_key_serialized))
        return public_key

    def __get_jwk_parts(self, kid):
        self.logger.info("starting __get_jwk_parts({0})".format(kid))
        jwk = self.__get_jwk_by_id(kid)
        # return the exponent and modulus of the public key
        exponent = self.__base64_to_int(jwk["e"])
        modulus = self.__base64_to_int(jwk["n"])
        return (exponent, modulus)

    def __get_jwk_by_id(self, kid):
        self.logger.info("starting __get_jwk_by_id({0})".format(kid))
        keys = self.__get_jwks_from_cache()
        for jwk in keys:
            if jwk["kid"] == kid:
                self.logger.info(
                    "Got jwk: {0}".format(self.__dump_json(jwk)))
                return jwk

        # if we get here, we got a key set, but no key matched the ID
        raise KeyNotFoundError("No jwk found for key ID: {0}".format(kid))

    def __get_jwks_from_cache(self):
        self.logger.info("starting __get_jwks_from_cache()")
        # use the auth server ID as the filename
        auth_server = self.__get_auth_server_id()
        key_name = "{0}-jwks-cache.json".format(auth_server)
        self.logger.info("Fetching JWKS from cache: {0}".format(key_name))

        try:
            response = self.jwks_cache.read_from_cache(key_name)
            self.logger.info("Got response from cache: {0}".format(response))
            return response["keys"]
        except CacheObjectNotFoundError as e:
            # cache read failed, refresh the jwks from the issuer,
            # write it back to cache and return the data
            self.logger.info(e)
            response = self.__get_jwks_from_issuer()
            # refresh the cache
            self.logger.info("Writing jwks to cache: {0}".format(key_name))
            self.jwks_cache.write_to_cache(key_name, response)
            # return the key set since we just got it anyway
            return response["keys"]
        except Exception as e:
            # catch all
            self.logger.error("An unhandled error occurred: {0}".format(e))
            raise InvalidKeyError(
                "No jwks found for issuer: {0}".format(self.issuer))

    def __get_jwks_from_issuer(self):
        # Gets the jwks from the reported issuer.
        jwks_uri = "{0}/v1/keys".format(self.reported_issuer)
        self.logger.info("Getting key set from {0}".format(jwks_uri))
        response = Http.execute_get(jwks_uri)
        self.logger.info(self.__dump_json(response))
        return response

    def __get_auth_server_id(self):
        self.logger.info("starting __get_auth_server_id()")
        issuer = self.issuer
        parts = issuer.split("/")
        server_id = parts.pop()
        self.logger.info("Auth server ID: {0}".format(server_id))
        return server_id

    def __decode_base64(self, data):
        missing_padding = len(data) % 4
        if missing_padding > 0:
            data += b"=" * (4 - missing_padding)
        return base64.urlsafe_b64decode(data)

    def __base64_to_int(self, val):
        # takes a base64 encoded byte array
        # and decodes it into its integer representation
        data = self.__decode_base64(val.encode("utf-8"))
        buf = struct.unpack("%sB" % len(data), data)
        return int(''.join(["%02x" % byte for byte in buf]), 16)

    def __dump_json(self, content):
        return json.dumps(content, indent=4, sort_keys=True)
