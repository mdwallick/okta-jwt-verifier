import base64
import json
import logging
import os
import struct

from calendar import timegm
from datetime import datetime

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# from joblib import Memory
# location = "./cachedir"
# memory = Memory(location, verbose=0)

from .http import Http
from .exceptions import (
    DecodeError, ExpiredTokenError, ImmatureSignatureError,
    InvalidAudienceError, InvalidIssuedAtError,
    InvalidIssuerError, InvalidSignatureError, MissingRequiredClaimError
)
from .settings import *

# TODO - figure out how to periodically expire the cache
# these are "costly" methods in that they require getting data off the wire
#def _get_oauth_metadata_cached(metadata_uri):
#    metadata = Http.execute_get(metadata_uri)
#    return metadata

#def _get_jwk_cached(metadata, kid):
#    jwks_uri = metadata["jwks_uri"]
#    jwks = Http.execute_get(jwks_uri)
#    keys = jwks["keys"]
#    for jwk in keys:
#        if jwk["kid"] == kid:
#            return jwk

class JwtVerifier(object):

    PADDING = padding.PKCS1v15()
    HASH_ALGORITHM = hashes.SHA256()

    def __init__(self, loglevel=logging.WARNING):
        # constructor
        logging.basicConfig(level=loglevel)

        if "OKTA_ORG" in os.environ:
            self.okta_org = os.getenv("OKTA_ORG")
        else:
            raise OktaError("Okta org not specified. Did you check your .env file?")

        if "AUTH_SERVER_ID" in os.environ:
            self.auth_server_id = os.getenv("AUTH_SERVER_ID")
        else:
            self.auth_server_id = "default"

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

        self.issuer = "{0}/oauth2/{1}".format(self.okta_org, self.auth_server_id)
        logging.debug("Issuer:        {0}".format(self.issuer))
        logging.debug("Audience:      {0}".format(self.audience))
        logging.debug("Client ID:     {0}".format(self.client_id))
        logging.debug("Client Secret: {0}".format(self.client_secret))


    def decode(self, jwt):
        logging.info("starting decode()")
        # to decode:
        # 1. crack open the token and get the header, payload, signature
        #    and signed message (header + payload)
        header, payload, signature, signed_message = self._get_jwt_parts(jwt)

        # 2. get the kid from the jwt header, get the jwk from the issuer
        #  and compute the public key
        kid = header["kid"]
        public_key = self._get_public_key(kid)

        # 3. verify the signature on the JWT
        if self._verify_signature(signature, signed_message, public_key):
            # 4. if the signature is valid, try to parse the payload into JSON
            logging.info("Trying to parse the payload into JSON")
            try:
                payload = json.loads(payload.decode("utf-8"))
                logging.info("Successfully parsed payload to JSON")
                logging.debug(self._dump_json(payload))
            except ValueError as e:
                raise DecodeError("Invalid payload JSON: %s" % e)

            # 5. verify the required claims
            self._verify_claims(payload)

            # 6. return the JSON representation of the payload
            return payload
        else:
            raise InvalidSignatureError("Signature is not valid")


    def introspect(self, jwt):
        logging.info("starting introspect()")
        uri = "{0}/v1/introspect?token={1}&client_id={2}&client_secret={3}".format(
            self.issuer, jwt, self.client_id, self.client_secret
        )
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        logging.info("Calling introspection endpoint")
        response = Http.execute_post(uri, headers=headers)
        logging.debug("introspection response: {0}".format(self._dump_json(response)))
        return response["active"] == True


    def _verify_claims(self, payload):
        logging.debug("starting _verify_claims()")
        if payload.get("exp") is None:
            raise MissingRequiredClaimError("exp")

        if payload.get("iat") is None:
            raise MissingRequiredClaimError("iat")

        if payload.get("iss") is None:
            raise MissingRequiredClaimError("iss")

        if payload.get("aud") is None:
            raise MissingRequiredClaimError("aud")

        now = timegm(datetime.utcnow().utctimetuple())
        self._verify_iss(payload)
        self._verify_aud(payload)
        self._verify_exp(payload, now)
        self._verify_iat(payload, now)

    def _verify_iss(self, payload):
        logging.debug("starting _verify_iss()")
        if "iss" not in payload:
            raise MissingRequiredClaimError("iss")

        if payload["iss"] != self.issuer:
            raise InvalidIssuerError("This token isn't from who you think it's from (Issuer mismatch).")

    def _verify_aud(self, payload):
        logging.debug("starting _verify_aud()")
        if "aud" not in payload:
            raise MissingRequiredClaimError("aud")

        if payload["aud"] != self.audience:
            raise InvalidAudienceError("This token is not for your eyes (Audience mismatch).")

    def _verify_exp(self, payload, now):
        logging.debug("starting _verify_exp()")
        try:
            exp = int(payload["exp"])
        except ValueError:
            raise DecodeError("Expiration Time claim (exp) must be an integer.")

        if exp < now:
            raise ExpiredTokenError("Token has expired. Please re-authenticate.")

    def _verify_iat(self, payload, now):
        logging.debug("starting _verify_iat()")
        try:
            iat = int(payload["iat"])
        except ValueError:
            raise DecodeError("Issued At Time claim (iat) must be an integer.")

        if iat > now:
            raise ImmatureSignatureError("This token is not yet valid (iat).")

    def _verify_signature(self, signature, message, key):
        logging.info("starting _verify_signature()")
        try:
            key.verify(signature, message, self.PADDING, self.HASH_ALGORITHM)
            logging.info("JWT signature is valid")
            return True
        except InvalidSignature:
            return False

    def _get_public_key(self, kid):
        # get the exponent and modulus from the jwk so we can get the public key
        e, n = self._get_jwk(kid)
        numbers = RSAPublicNumbers(e, n)
        public_key = numbers.public_key(default_backend())
        public_key_serialized = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        logging.debug("public key: {0}".format(public_key_serialized))
        return public_key

    def _get_jwk(self, kid):
        #get_jwk = memory.cache(_get_jwk_cached)
        #jwk = get_jwk(metadata, kid)
        jwk = self._get_jwk_by_id(kid)
        # return the exponent and modulus of the public key
        e = self._base64_to_int(jwk["e"].encode("utf-8"))
        n = self._base64_to_int(jwk["n"].encode("utf-8"))
        return (e, n)

    # TODO - see if there's a better way to cache this than using joblib
    def _get_jwk_by_id(self, kid):
        metadata = self._get_oauth_metadata()
        jwks_uri = metadata["jwks_uri"]
        jwks = Http.execute_get(jwks_uri)
        keys = jwks["keys"]
        for jwk in keys:
            if jwk["kid"] == kid:
                logging.info("Got jwk with kid {0}".format(kid))
                logging.debug("Got jwk: {0}".format(self._dump_json(jwk)))
                return jwk

        # no key found, return an empty json object
        # maybe raise an exception instead?
        logging.error("No jwk found for key ID: {0}".format(kid))
        return {}

    # TODO - see if there's a better way to cache this than using joblib
    def _get_oauth_metadata(self):
        metadata_uri = "{0}/.well-known/oauth-authorization-server".format(self.issuer)
        logging.info("Getting OAuth metadata from issuer")
        metadata = Http.execute_get(metadata_uri)
        logging.debug("OAuth metadata: {0}".format(self._dump_json(metadata)))
        return metadata
        #oauth_metadata = memory.cache(_get_oauth_metadata_cached)
        #return oauth_metadata(metadata_uri)

    def _get_jwt_parts(self, jwt):
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
        header = self._decode_base64(header_chunk)
        try:
            header = json.loads(header.decode("utf-8"))
        except ValueError as e:
            raise DecodeError("Invalid header JSON: %s" % e)

        payload = self._decode_base64(payload_chunk)
        signature = self._decode_base64(signature_chunk)
        return (header, payload, signature, signed_message)

    def _decode_base64(self, data):
        missing_padding = len(data) % 4
        if missing_padding > 0:
            data += b"="* (4 - missing_padding)
        return base64.urlsafe_b64decode(data)

    # takes a base64 encoded byte array
    # and decodes it into its integer representation
    def _base64_to_int(self, val):
        data = self._decode_base64(val)
        buf = struct.unpack("%sB" % len(data), data)
        return int(''.join(["%02x" % byte for byte in buf]), 16)

    def _dump_json(self, content):
        return json.dumps(content, indent=4, sort_keys=True)
