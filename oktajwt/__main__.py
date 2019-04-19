import json
import sys

from .util.exceptions import *
from .jwt import JwtVerifier

"""
Usage: python3 -m oktajwt <base64 encoded JWT>
"""
def main():
    jwt = sys.argv[1]

    try:
        oktaJwt = JwtVerifier()
        claims = oktaJwt.decode(jwt)
        print("claims: {0}".format(json.dumps(claims, indent=4, sort_keys=True)))

        if oktaJwt.introspect(jwt):
            print("Issuer reports the token is still valid.")
        else:
            print("Issuer reports the token is no longer valid.")

    except ExpiredTokenError:
        print("JWT signature is valid, but the token has expired!")

    except InvalidSignatureError:
        print("JWT signature validation failed!")

if __name__ == "__main__":
    main()
