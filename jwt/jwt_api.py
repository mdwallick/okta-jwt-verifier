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

from .http import Http
from .exceptions import (
    OktaError, DecodeError, InvalidSignatureError, InvalidIssuerError, 
    MissingRequiredClaimError, InvalidAudienceError, ExpiredTokenError, 
    InvalidIssuedAtError, InvalidKeyError, KeyNotFoundError
)

class JwtVerifier:

    PADDING = padding.PKCS1v15()
    HASH_ALGORITHM = hashes.SHA256()
    PEM_ENCODING = Encoding.PEM
    PUBLIC_KEY_FORMAT = PublicFormat.SubjectPublicKeyInfo
    logger = logging.getLogger(__name__)

    def __init__(self, issuer, client_id, client_secret=None, verbosity=0):
        if verbosity == 2:
            logging.basicConfig(level="DEBUG")
        elif verbosity == 1:
            logging.basicConfig(level="INFO")
        else:
            logging.basicConfig(level="WARNING")

        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        
        self.logger.debug("Issuer:        {0}".format(self.issuer))
        self.logger.debug("Client ID:     {0}".format(self.client_id))
        if (self.client_secret == None):
            self.logger.debug("Client secret: None. Assuming PKCE.")


    def decode(self, access_token: str, expected_audience: str, 
                remote_validation=False) -> json:
        """ Verify the access token and return the claims as JSON """
        return self.__decode_as_claims(access_token, expected_audience)


    def is_token_valid(self, access_token: str, expected_audience: str, 
                        remote_validation=False) -> bool:
        """ Verify the access token and return True/False """
        if remote_validation:
            response = self.__introspect_remote(access_token)
            active = False

            if "active" in response:
                active = response["active"] == True
            
            return active
        else:
            return self.__introspect(access_token, expected_audience)


    """
    private/helper functions
    """

    # local introspection
    def __introspect(self, access_token, expected_audience):
        try:
            claims = self.__decode_as_claims(access_token, expected_audience)
            self.logger.debug("Claims: {0}".format(claims))
            return True
        
        except ExpiredTokenError:
            self.logger.error("JWT signature is valid, but the token has expired!")
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
        self.logger.debug("starting introspect()")
        encoded_auth = self.__get_encoded_auth(self.client_id, self.client_secret)
        self.logger.debug("Basic authorization: {0}".format(encoded_auth))
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
        self.logger.debug("introspect(): {0}".format(self.__dump_json(response)))
        return response

    def __decode_as_claims(self, jwt, expected_audience):
        self.logger.debug("starting __decodeAsClaims()")
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
        self.logger.debug("JWT is valid")
        return payload

    def __decode(self, jwt):
        self.logger.debug("starting __decode()")
        # to decode:
        # 1. crack open the token and get the header, payload, signature
        #    and signed message (header + payload)
        header, payload, signature, signed_message = self.__get_jwt_parts(jwt)

        # 2. verify the signature on the JWT
        if self.__verify_signature(signature, signed_message, header["kid"]):
            # 3. if the signature is valid, try to parse the payload into JSON
            self.logger.debug("Trying to parse the payload into JSON")
            try:
                payload = json.loads(payload.decode("utf-8"))
                self.logger.debug("JSON is well-formed")
                self.logger.debug(self.__dump_json(payload))
            except ValueError as e:
                raise DecodeError("Invalid payload JSON: %s" % e)

            # 4. return the JSON representation of the payload
            return payload
        else:
            raise InvalidSignatureError("Signature is not valid")

    def __verify_iss(self, issuer, expected):
        self.logger.debug("starting __verify_iss()")
        if issuer != expected:
            raise InvalidIssuerError("This token isn't from who you think it's from (Issuer mismatch).")

    def __verify_aud(self, audience, expected):
        self.logger.debug("starting __verify_aud()")
        if audience != expected:
            raise InvalidAudienceError("This token is not for your eyes (Audience mismatch).")

    def __verify_exp(self, expiration, now):
        self.logger.debug("starting __verify_exp()")
        try:
            exp = int(expiration)
        except ValueError:
            raise DecodeError("Expiration Time claim (exp) must be an integer.")

        if exp < now:
            raise ExpiredTokenError("This JWT is expired.")

    def __verify_iat(self, issued, now):
        self.logger.debug("starting __verify_iat()")
        try:
            iat = int(issued)
        except ValueError:
            raise DecodeError("Issued At Time claim (iat) must be an integer.")

        if iat > now:
            raise InvalidIssuedAtError("This JWT is not yet valid (iat).")

    def __verify_signature(self, signature, message, kid):
        self.logger.debug("starting __verify_signature()")
        public_key = self.__get_public_key(kid)
        try:
            public_key.verify(signature, message, self.PADDING, self.HASH_ALGORITHM)
            self.logger.info("JWT signature is valid")
            return True
        except InvalidSignature:
            return False

    def __get_public_key(self, kid):
        self.logger.debug("starting __get_public_key()")
        # get the exponent and modulus from the jwk so we can get the public key
        exponent, modulus = self.__get_jwk(kid)
        numbers = RSAPublicNumbers(exponent, modulus)
        public_key = numbers.public_key(default_backend())
        public_key_serialized = public_key.public_bytes(self.PEM_ENCODING, self.PUBLIC_KEY_FORMAT)
        self.logger.debug("public key: {0}".format(public_key_serialized))
        return public_key

    def __get_jwk(self, kid):
        self.logger.debug("starting __get_jwk()")
        jwk = self.__get_jwk_by_id(kid)
        # return the exponent and modulus of the public key
        exponent = self.__base64_to_int(jwk["e"].encode("utf-8"))
        modulus = self.__base64_to_int(jwk["n"].encode("utf-8"))
        return (exponent, modulus)

    def __get_jwk_by_id(self, kid):
        self.logger.debug("starting __get_jwk_by_id()")
        jwks_uri = "{issuer}/v1/keys".format(issuer=self.issuer)
        response = Http.execute_get(jwks_uri)
        self.logger.debug("Got response: {0}".format(response))
        try:
            keys = response["keys"]
            for jwk in keys:
                if jwk["kid"] == kid:
                    self.logger.debug("Got jwk: {0}".format(self.__dump_json(jwk)))
                    return jwk
            
            # if we get here, we got a key set, but no key matched the ID
            raise KeyNotFoundError("No jwk found for key ID: {0}".format(kid))
        except Exception:
            # something about the response is bad (e.g. no key set, 404 because
            # of an invalid issuer URI, etc.), raise an error
            raise InvalidKeyError("No jwk found for key ID: {0}".format(kid))

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

        encoded_auth = base64.b64encode(bytes(auth_raw, 'UTF-8')).decode("UTF-8")
        return encoded_auth
        
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

    def __dump_json(self, content):
        return json.dumps(content, indent=4, sort_keys=True)