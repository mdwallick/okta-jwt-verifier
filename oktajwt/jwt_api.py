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
from .memcached_plugin import MemCachedPlugin
from .s3_cache_plugin import S3CachePlugin

from .exceptions import (
    OktaError, DecodeError, InvalidSignatureError, InvalidIssuerError,
    MissingRequiredClaimError, InvalidAudienceError, ExpiredTokenError,
    InvalidIssuedAtError, InvalidKeyError, KeyNotFoundError, CacheObjectNotFoundError
)

class JwtVerifier:

    PADDING = padding.PKCS1v15()
    HASH_ALGORITHM = hashes.SHA256()
    PEM_ENCODING = Encoding.PEM
    PUBLIC_KEY_FORMAT = PublicFormat.SubjectPublicKeyInfo
    logger = logging.getLogger(__name__)

    def __init__(self, *args, **kwargs):
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
            self.logger.info("Caching: filesystem with cache directory {0}".format(cache_dir))
        else:
            if kwargs["cache"] == "S3":
                if "bucket" in kwargs and kwargs["bucket"]:
                    bucket = kwargs["bucket"]
                    self.jwks_cache = S3CachePlugin(bucket)
                    self.logger.info("Caching: S3 with bucket {0}".format(bucket))
                else:
                    raise ValueError("Bucket is required if cache is S3")
            else:
                raise ValueError("Unknow caching method {0}".format(kwargs["cache"]))

    
    def decode(self, access_token, expected_audience):
        """
        Verify the access token and return the claims as JSON.

        """
        return self.__decode_as_claims(access_token, expected_audience)

    
    def is_token_valid(self, access_token, expected_audience):
        """
        Verify the access token and return True/False.

        """
        return self.__introspect(access_token, expected_audience)

    # local introspection
    def __introspect(self, access_token, expected_audience):
        try:
            claims = self.__decode_as_claims(access_token, expected_audience)
            self.logger.info("Claims: {0}".format(claims))
            return True

        except ExpiredTokenError:
            self.logger.error(
                "JWT signature is valid, but the token has expired!")
            return False

        except InvalidSignatureError:
            self.logger.error("JWT signature validation failed!")
            return False

        except KeyNotFoundError as key_error:
            self.logger.error(key_error)
            return False

        except InvalidKeyError as key_error:
            self.logger.error(key_error)
            return False

        except Exception as e:
            self.logger.error(e)
            return False

    # remote introspection at the issuer
    def __introspect_remote(self, access_token):
        self.logger.info("starting introspect()")
        encoded_auth = self.__get_encoded_auth(
            self.client_id, self.client_secret)
        self.logger.info("Basic authorization: {0}".format(encoded_auth))
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic {0}".format(encoded_auth)
        }
        uri = "{issuer}/v1/introspect?token={token}&token_type_hint=access_token".format(
            issuer=self.issuer,
            token=access_token
        )
        response = Http.execute_post(uri, headers=headers)
        self.logger.info("introspect(): {0}".format(
            self.__dump_json(response)))
        return response

    def __decode_as_claims(self, jwt, expected_audience):
        self.logger.info("starting __decodeAsClaims()")
        # decode the token, validate the signature
        # and check for required claims
        payload = self.__decode(jwt)
        # check for the existence of required claims
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

    def __decode(self, jwt):
        self.logger.info("starting __decode()")
        # to decode:
        # 1. crack open the token and get the header, payload, signature
        #    and signed message (header + payload)
        header, payload, signature, signed_message = self.__get_jwt_parts(jwt)

        # 2. verify the signature on the JWT
        if self.__verify_signature(signature, signed_message, header["kid"]):
            # 3. if the signature is valid, try to parse the payload into JSON
            self.logger.info("Trying to parse the payload into JSON")
            try:
                payload = json.loads(payload.decode("utf-8"))
                self.logger.info("JSON is well-formed")
                self.logger.info(self.__dump_json(payload))
            except ValueError as e:
                raise DecodeError("Invalid payload JSON: %s" % e)

            # 4. return the JSON representation of the payload
            return payload
        else:
            raise InvalidSignatureError("Signature is not valid")

    def __verify_iss(self, issuer, expected):
        self.logger.info("starting __verify_iss()")
        if issuer != expected:
            raise InvalidIssuerError(
                "This token isn't from who you think it's from (Issuer mismatch).")

    def __verify_aud(self, audience, expected):
        self.logger.info("starting __verify_aud()")
        if audience != expected:
            raise InvalidAudienceError(
                "This token is not for your eyes (Audience mismatch).")

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
            return False

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
        exponent = self.__base64_to_int(jwk["e"].encode("utf-8"))
        modulus = self.__base64_to_int(jwk["n"].encode("utf-8"))
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
        self.logger.info("Fetching {0} from cache...".format(key_name))

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
        # except Exception as e:
        #     # catch all
        #     self.logger.error("An unhandled error occurred: {0}".format(e))
        #     raise InvalidKeyError("No jwks found for issuer: {0}".format(self.issuer))

    def __get_auth_server_id(self):
        self.logger.info("starting __get_auth_server_id()")
        issuer = self.issuer
        parts = issuer.split("/")
        server_id = parts.pop()
        self.logger.info("Auth server ID: {0}".format(server_id))
        return server_id

    def __get_jwks_from_issuer(self):
        # Gets the jwks JSON from the issuer.
        jwks_uri = "{0}/v1/keys".format(self.issuer)
        self.logger.info("Getting key set from {0}".format(jwks_uri))
        response = Http.execute_get(jwks_uri) # JSON
        self.logger.info(self.__dump_json(response))
        return response

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
        except ValueError as e:
            raise DecodeError("Invalid header JSON: %s" % e)

        payload = self.__decode_base64(payload_chunk)
        signature = self.__decode_base64(signature_chunk)
        return (header, payload, signature, signed_message)

    def __get_encoded_auth(self, client_id, client_secret=None):
        if client_secret != None:
            auth_raw = "{client_id}:{client_secret}".format(
                client_id=client_id,
                client_secret=client_secret
            )
        else:
            auth_raw = client_id

        encoded_auth = base64.b64encode(
            bytes(auth_raw, 'UTF-8')).decode("UTF-8")
        return encoded_auth

    def __decode_base64(self, data):
        missing_padding = len(data) % 4
        if missing_padding > 0:
            data += b"=" * (4 - missing_padding)
        return base64.urlsafe_b64decode(data)

    # takes a base64 encoded byte array
    # and decodes it into its integer representation
    def __base64_to_int(self, val):
        data = self.__decode_base64(val)
        buf = struct.unpack("%sB" % len(data), data)
        return int(''.join(["%02x" % byte for byte in buf]), 16)

    def __dump_json(self, content):
        return json.dumps(content, indent=4, sort_keys=True)
