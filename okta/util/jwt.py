import base64
import json
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

from joblib import Memory
location = './cachedir'
memory = Memory(location, verbose=0)

from .http import Http
from .exceptions import (
    DecodeError, ExpiredTokenError, ImmatureSignatureError,
    InvalidAudienceError, InvalidIssuedAtError,
    InvalidIssuerError, MissingRequiredClaimError
)

# TODO - figure out how to periodically expire the cache
# these are "costly" methods in that they require getting data off the wire
def _get_oauth_metadata_cached(metadata_uri):
    metadata = Http.execute_get(metadata_uri)
    return metadata

def _get_jwk_cached(metadata, kid):
    jwks_uri = metadata['jwks_uri']
    jwks = Http.execute_get(jwks_uri)
    keys = jwks['keys']
    for jwk in keys:
        if jwk['kid'] == kid:
            return jwk


class JwtVerifier(object):

    def __init__(self):
        # constructor
        if "OKTA_ORG_URL" in os.environ:
            self.okta_org_url = os.environ['OKTA_ORG_URL']
        else:
            self.okta_org_url = "https://wallick.oktapreview.com"

        if "AUTH_SERVER_ID" in os.environ:
            self.auth_server_id = os.environ['AUTH_SERVER_ID']
        else:
            self.auth_server_id = "ausjtb69rzkswVPCQ0h7"

        if "AUDIENCE" in os.environ:
            self.audience = os.environ['AUDIENCE']
        else:
            self.audience = "api://default"

        self.issuer = "{0}/oauth2/{1}".format(self.okta_org_url, self.auth_server_id)

    def decode(self, jwt):
        # to decode a JWT:
        # 1. crack open the token and get the header, payload, signature
        #    and signed message
        header, payload, signature, signed_message = self._get_jwt_parts(jwt)

        # 2. get the kid from the jwt header
        #    go get the JWK from the issuer
        #    compute the public key
        kid = header['kid']
        public_key = self._get_public_key(kid)

        # 3. verify the signature on the JWT
        if self._validate_signature(signature, signed_message, public_key):
            # 4. if the signature is valid, try to parse the payload into JSON
            try:
                payload = json.loads(payload.decode('utf-8'))
            except ValueError as e:
                raise DecodeError('Invalid payload JSON: %s' % e)

            # 5. verify the required claims: issuer, audience, exp, iat
            self._validate_required_claims(payload)

            # 6. return the JSON representation of the payload
            return payload
        else:
            raise InvalidSignatureError('Signature is not valid')

    def _validate_required_claims(self, payload):
        if payload.get('exp') is None:
            raise MissingRequiredClaimError('exp')

        if payload.get('iat') is None:
            raise MissingRequiredClaimError('iat')

        if payload.get('iss') is None:
            raise MissingRequiredClaimError('iss')

        if payload.get('aud') is None:
            raise MissingRequiredClaimError('aud')

        self._validate_iss(payload)
        self._validate_aud(payload)
        now = timegm(datetime.utcnow().utctimetuple())
        self._validate_exp(payload, now)
        self._validate_iat(payload, now)

    def _validate_iss(self, payload):
        if 'iss' not in payload:
            raise MissingRequiredClaimError('iss')

        if payload['iss'] != self.issuer:
            raise InvalidIssuerError('Issuer mismatch')

    def _validate_aud(self, payload):
        if 'aud' not in payload:
            raise MissingRequiredClaimError('aud')

        if payload['aud'] != self.audience:
            raise InvalidAudienceError('This token is not for your eyes')

    def _validate_exp(self, payload, now):
        try:
            exp = int(payload['exp'])
        except ValueError:
            raise DecodeError('Expiration Time claim (exp) must be an integer.')

        if exp < now:
            raise ExpiredTokenError('Token has expired')

    def _validate_iat(self, payload, now):
        try:
            iat = int(payload['iat'])
        except ValueError:
            raise DecodeError('Issued At Time claim (iat) must be an integer.')

        if iat > now:
            raise ImmatureSignatureError('The token is not yet valid (iat)')

    def _validate_signature(self, signature, message, key):
        try:
            key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    def _get_public_key(self, kid):
        jwk = self._get_jwk(kid)
        # e is the exponent of the public key
        e = self._base64_to_int(jwk['e'].encode('utf-8'))
        # n is the modulus of the public key
        n = self._base64_to_int(jwk['n'].encode('utf-8'))
        numbers = RSAPublicNumbers(e, n)
        public_key = numbers.public_key(default_backend())
        #public_key_serialized = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        #print("public key {0}".format(public_key_serialized))
        return public_key

    # TODO - cache the auth server metadata somehow
    def _get_oauth_metadata(self):
        metadata_uri = "{0}/.well-known/oauth-authorization-server".format(self.issuer)
        oauth_metadata = memory.cache(_get_oauth_metadata_cached)
        return oauth_metadata(metadata_uri)

    def _get_jwk(self, kid):
        metadata = self._get_oauth_metadata()
        get_jwk = memory.cache(_get_jwk_cached)
        return get_jwk(metadata, kid)

    """
    def _get_jwk(self, kid):
        # TODO - actually look up the issuer and go get the key
        # and cache the key in some manner so we're not grabbing it
        # from the issuer over and over

        # 1.  see if the jwk exists in the cache (and it's not expired), return it
        #     a. if it is expired or missing, go get a new one and cache it
        #
        metadata = self._get_oauth_metadata()
        #print("metadata {0}".format(json.dumps(metadata, indent=4, sort_keys=True)))

        jwks_uri = metadata['jwks_uri']
        jwks = Http.execute_get(jwks_uri)
        #print("metadata {0}".format(json.dumps(jwks, indent=4, sort_keys=True)))
        keys = jwks['keys']
        for jwk in keys:
            if jwk['kid'] == kid:
                #print("got key with kid {0}".format(kid))
                #print("key: {0}".format(json.dumps(key, indent=4, sort_keys=True)))
                return jwk

        # just keep a static copy of the jwk JSON for now
        #return json.loads('{"kty":"RSA","alg":"RS256","kid":"ECrMHJmwR8IvEU69E3m6at902C6sGAFxU3Hby34JR_c","use":"sig","e":"AQAB","n":"lza8qFCyHXPdA3Ypm-iVDeg-ivEw6GLfBSzhwQjvaW35GifcKtNAKewrK6MLXt75c5IyIwzVni09LoyUGJHFuoY3Pkb-UM1CmMsSE1MVwokJ9Qn_CK0zqiwu1JVxPIgpjQSxWug3QIjVqBEwxjhfJQNyrJPT85KDEXDdR207tLNZMChnKP6YnglYJnCGzDJJ9dcS5F4L4zkuMeepvpOOXahbk6FhcVRPGXuwf1MCcMQjLeFDPejzQDaUlmv5e7XXe-OAhvZe5xO_CJsgUqplkVF-LO2RKlf4QGZS5LOT9AOLAu_C7oD6OeryLl5PquAbNju7cjXv_T1by-aQRw7aTw"}')
    """

    def _get_jwt_parts(self, jwt):
        # decode the JWT and return the header as JSON,
        # the payload as a b64 decoded byte array
        # the signature as a b64 decoded byte array
        if isinstance(jwt, str):
            jwt = jwt.encode('utf-8')

        # the JWT looks like this:
        # <b64 header>.<b64 payload>.<b64 signature>
        # signed_message is the header+payload in its raw JWT form
        #  e.g. <b64 header>.<b64 payload> (including the period)
        # signature_chunk is the raw signature from the JWT
        #  e.g. <b64 signature>
        signed_message, signature_chunk = jwt.rsplit(b'.', 1)
        header_chunk, payload_chunk = signed_message.split(b'.', 1)

        header = self._decode_base64(header_chunk)

        # make sure the header is valid json
        try:
            header = json.loads(header.decode('utf-8'))
        except ValueError as e:
            raise DecodeError('Invalid header JSON: %s' % e)

        payload = self._decode_base64(payload_chunk)
        signature = self._decode_base64(signature_chunk)
        return (header, payload, signature, signed_message)

    def _decode_base64(self, data):
        missing_padding = len(data) % 4
        if missing_padding > 0:
            data += b'='* (4 - missing_padding)
        return base64.urlsafe_b64decode(data)

    # takes a base64 encoded byte array
    # and decodes it into its integer representation
    def _base64_to_int(self, val):
        data = self._decode_base64(val)
        buf = struct.unpack('%sB' % len(data), data)
        return int(''.join(["%02x" % byte for byte in buf]), 16)
