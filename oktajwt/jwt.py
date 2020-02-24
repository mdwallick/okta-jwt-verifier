import base64
import json
import logging
import os
import struct
import time

from calendar import timegm
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .util.exceptions import *
from .util.http import Http
from .settings import *

class JwtVerifier(object):

    PADDING = padding.PKCS1v15()
    HASH_ALGORITHM = hashes.SHA256()
    ONE_DAY = 86400
    CACHE_DIR = "cache"
    PEM_ENCODING = Encoding.PEM
    PUBLIC_KEY_FORMAT = PublicFormat.SubjectPublicKeyInfo

    def __init__(self):
        # constructor
        loglevel = logging.WARNING

        if "LOG_LEVEL" in os.environ:
            loglevel = os.getenv("LOG_LEVEL")

        logging.basicConfig(level=loglevel)

        if "ISSUER" in os.environ:
            self.issuer = os.getenv("ISSUER")
        else:
            raise OktaError("Issuer not specified. Did you check your .env file?")

        if "AUDIENCE" in os.environ:
            self.audience = os.getenv("AUDIENCE")
        else:
            self.audience = "api://default"

        if "CLIENT_ID" in os.environ:
            self.client_id = os.getenv("CLIENT_ID")
        else:
            raise OktaError("Client ID not specified. Did you check your .env file?")

        if "CLIENT_SECRET" in os.environ:
            self.client_secret = os.getenv("CLIENT_SECRET")
        else:
            raise OktaError("Client Secret not specified. Did you check your .env file?")

        logging.debug("Issuer:        {0}".format(self.issuer))
        logging.debug("Audience:      {0}".format(self.audience))
        logging.debug("Client ID:     {0}".format(self.client_id))
        logging.debug("Client Secret: {0}".format(self.client_secret))

        if not os.path.isdir(self.CACHE_DIR):
           # create the cache directory if it doesn't exist
           logging.debug("Creating directory: {0}".format(self.CACHE_DIR))
           os.mkdir(self.CACHE_DIR)


    def decode(self, jwt):
        logging.debug("starting decode()")
        # to decode:
        # 1. crack open the token and get the header, payload, signature
        #    and signed message (header + payload)
        header, payload, signature, signed_message = self.__get_jwt_parts(jwt)

        # 2. verify the signature on the JWT
        if self.__verify_signature(signature, signed_message, header["kid"]):
            # 3. if the signature is valid, try to parse the payload into JSON
            logging.debug("Trying to parse the payload into JSON")
            try:
                payload = json.loads(payload.decode("utf-8"))
                logging.debug("Successfully parsed payload to JSON")
                logging.debug(self.__dump_json(payload))
            except ValueError as e:
                raise DecodeError("Invalid payload JSON: %s" % e)

            # 4. verify the required claims
            self.__verify_claims(payload)

            # 5. return the JSON representation of the payload
            return payload
        else:
            raise InvalidSignatureError("Signature is not valid")


    def introspect(self, jwt):
        logging.debug("starting introspect()")
        introspection_uri = self.__get_introspection_endpoint()
        uri = (
            "{0}?token={1}&"
            "client_id={2}&"
            "client_secret={3}"
        ).format(introspection_uri, jwt, self.client_id, self.client_secret)

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        logging.debug("Calling introspection endpoint")
        response = Http.execute_post(uri, headers=headers)
        logging.debug("Introspection: {0}".format(self.__dump_json(response)))
        return response["active"] == True


    def __verify_claims(self, payload):
        logging.debug("starting __verify_claims()")
        now = timegm(datetime.utcnow().utctimetuple())
        self.__verify_exp(payload, now)
        self.__verify_iat(payload, now)
        self.__verify_iss(payload)
        self.__verify_aud(payload)

    def __verify_iss(self, payload):
        logging.debug("starting __verify_iss()")
        if "iss" not in payload:
            raise MissingRequiredClaimError("iss")

        if payload["iss"] != self.issuer:
            raise InvalidIssuerError("This token isn't from who you think it's from (Issuer mismatch).")

    def __verify_aud(self, payload):
        logging.debug("starting __verify_aud()")
        if "aud" not in payload:
            raise MissingRequiredClaimError("aud")

        if payload["aud"] != self.audience:
            raise InvalidAudienceError("This token is not for your eyes (Audience mismatch).")

    def __verify_exp(self, payload, now):
        logging.debug("starting __verify_exp()")
        try:
            exp = int(payload["exp"])
        except ValueError:
            raise DecodeError("Expiration Time claim (exp) must be an integer.")

        if exp < now:
            raise ExpiredTokenError("Token has expired. Please re-authenticate.")

    def __verify_iat(self, payload, now):
        logging.debug("starting __verify_iat()")
        try:
            iat = int(payload["iat"])
        except ValueError:
            raise DecodeError("Issued At Time claim (iat) must be an integer.")

        if iat > now:
            raise InvalidIssuedAtError("This token is not yet valid (iat).")

    def __verify_signature(self, signature, message, kid):
        logging.debug("starting __verify_signature()")
        public_key = self.__get_public_key(kid)
        try:
            public_key.verify(signature, message, self.PADDING, self.HASH_ALGORITHM)
            logging.info("JWT signature is valid")
            return True
        except InvalidSignature:
            return False

    def __get_public_key(self, kid):
        logging.debug("starting __get_public_key()")
        # get the exponent and modulus from the jwk so we can get the public key
        exponent, modulus = self.__get_jwk(kid)
        numbers = RSAPublicNumbers(exponent, modulus)
        public_key = numbers.public_key(default_backend())
        public_key_serialized = public_key.public_bytes(self.PEM_ENCODING, self.PUBLIC_KEY_FORMAT)
        logging.debug("public key: {0}".format(public_key_serialized))
        return public_key

    def __get_jwk(self, kid):
        logging.debug("starting __get_jwk()")
        jwk = self.__get_jwk_by_id(kid)
        # return the exponent and modulus of the public key
        exponent = self.__base64_to_int(jwk["e"].encode("utf-8"))
        modulus = self.__base64_to_int(jwk["n"].encode("utf-8"))
        logging.debug("exponent: {0}".format(exponent))
        logging.debug("modulus:  {0}".format(modulus))
        return (exponent, modulus)

    def __get_jwk_by_id(self, kid):
        logging.debug("starting __get_jwk_by_id()")
        metadata = self.__get_oauth_metadata()
        jwks_uri = metadata["jwks_uri"]
        jwks_cache = self.CACHE_DIR + '/jwks.json'

        if os.path.isfile(jwks_cache):
            # we have a cache file, how old is it?
            file_age = self.__get_file_age(jwks_cache)
            if file_age > self.ONE_DAY:
                # it's a day old, go get a new copy and cache it
                jwks = Http.execute_get(jwks_uri)
                logging.debug("Writing cache file {0}".format(jwks_cache))
                self.__write_json_file(jwks_cache, jwks)
            else:
                # just read in the metadata from the cached file
                logging.debug("jwks cache is fresh, reading from disk")
                jwks = self.__read_json_file(jwks_cache)
        else:
            # no cache file exists, go get the jwks and cache it
            jwks = Http.execute_get(jwks_uri)
            logging.debug("Writing cache file {0}".format(jwks_cache))
            self.__write_json_file(jwks_cache, jwks)

        keys = jwks["keys"]
        for jwk in keys:
            if jwk["kid"] == kid:
                logging.debug("Got jwk with kid {0}".format(kid))
                logging.debug("Got jwk: {0}".format(self.__dump_json(jwk)))
                return jwk

        # no key found, return an empty json object
        # maybe raise an exception instead?
        logging.error("No jwk found for key ID: {0}".format(kid))
        return {}

    def __get_introspection_endpoint(self):
        metadata = self.__get_oauth_metadata()
        if "introspection_endpoint" not in metadata:
            raise OktaError("Introspection endpoint not found in auth server metadata!")

        return metadata["introspection_endpoint"]

    def __get_oauth_metadata(self):
        logging.debug("Getting OAuth metadata from issuer")
        metadata_uri = "{0}/.well-known/oauth-authorization-server".format(self.issuer)

        # is there a cache file present?
        metadata_cache = self.CACHE_DIR + '/issuer.json'
        if os.path.isfile(metadata_cache):
            # we have a cache file, how old is it?
            file_age = self.__get_file_age(metadata_cache)
            if file_age > self.ONE_DAY:
                # it's a day old, go get a new copy and cache it
                metadata = Http.execute_get(metadata_uri)
                #logging.debug("Writing cache file {0}".format(metadata_cache))
                self.__write_json_file(metadata_cache, metadata)
            else:
                # just read in the metadata from the cached file
                logging.debug("Metadata cache is fresh, reading from disk")
                metadata = self.__read_json_file(metadata_cache)
        else:
            # no cache file exists, go get the metadata and cache it
            metadata = Http.execute_get(metadata_uri)
            #logging.debug("Writing cache file {0}".format(metadata_cache))
            self.__write_json_file(metadata_cache, metadata)

        #logging.debug("OAuth metadata: {0}".format(self.__dump_json(metadata)))
        return metadata

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

    def __decode_base64(self, data):
        missing_padding = len(data) % 4
        if missing_padding > 0:
            data += b"="* (4 - missing_padding)
        return base64.urlsafe_b64decode(data)

    # takes a base64 encoded byte array
    # and decodes it into its integer representation
    def __base64_to_int(self, val):
        data = self.__decode_base64(val)
        buf = struct.unpack("%sB" % len(data), data)
        return int(''.join(["%02x" % byte for byte in buf]), 16)

    def __read_json_file(self, filename):
        logging.debug("opening {0} for reading".format(filename))
        data = None
        with open(filename, "r") as json_file:
            data = json.load(json_file)
            logging.debug("loaded JSON from file {0}".format(filename))
            #logging.debug("JSON: {0}".format(self.__dump_json(data)))

        return data

    def __write_json_file(self, filename, data):
        logging.debug("writing JSON to {0}".format(filename))
        with open(filename, "w") as outfile:
            json.dump(data, outfile)

    def __get_file_age(self, filepath):
        age = time.time() - os.path.getmtime(filepath)
        logging.debug("File is {0} seconds old".format(age))
        return age

    def __dump_json(self, content):
        return json.dumps(content, indent=4, sort_keys=True)