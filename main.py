import json
import logging
import sys

from okta.util.exceptions import *
from okta.util.jwt import JwtVerifier

jwt = sys.argv[1]

try:
    oktaJwt = JwtVerifier(logging.INFO)
    #okta = JwtVerifier()
    decoded_jwt = oktaJwt.decode(jwt)
    print("decoded_jwt: {0}".format(json.dumps(decoded_jwt, indent=4, sort_keys=True)))

    if oktaJwt.introspect(jwt):
        print("Issuer reports the token is still valid.")
    else:
        print("Issuer reports the token is no longer valid.")

except ExpiredTokenError:
    print("JWT signature is valid, but the token has expired. Please re-authenticate.")

except InvalidSignatureError:
    print("JWT has been tampered with. Signature is not valid.")
