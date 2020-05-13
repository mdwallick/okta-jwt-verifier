import getopt
import json
import sys

from .jwt import JwtVerifier
from .util.exceptions import (
    OktaError, DecodeError, InvalidSignatureError, InvalidIssuerError, 
    MissingRequiredClaimError, InvalidAudienceError, ExpiredTokenError, 
    InvalidIssuedAtError, InvalidKeyError, KeyNotFoundError
)

def main(argv):
    if len(argv) == 0:
        print("python -m oktajwt -i <issuer> -a <audience> -c <client_id> -j <base64 encoded JWT>")
        print("python -m oktajwt --issuer=<issuer> --audience=<audience> --client_id=<client_id> --jwt=<base64 encoded JWT>")
        sys.exit(2)

    jwt = None
    issuer = None
    audience = None
    client_id = None

    try:
        opts, args = getopt.getopt(argv, "hi:a:c:j:", ["help", "issuer=", "audience=", "client_id=", "jwt="])
    except getopt.GetoptError:
        print("python -m oktajwt -i <issuer> -a <audience> -c <client_id> -j <base64 encoded JWT>")
        print("python -m oktajwt --issuer=<issuer> --audience=<audience> --client_id=<client_id> --jwt=<base64 encoded JWT>")
        sys.exit(2)
    
    for opt, arg in opts:
      if opt in ("-h", "--help"):
        print("python -m oktajwt -i <issuer> -a <audience> -c <client_id> -j <base64 encoded JWT>")
        print("python -m oktajwt --issuer=<issuer> --audience=<audience> --client_id=<client_id> --jwt=<base64 encoded JWT>")
        sys.exit()
      elif opt in ("-i", "--issuer"):
         issuer = arg
      elif opt in ("-a", "--audience"):
         audience = arg
      elif opt in ("-c", "--client_id"):
         client_id = arg
      elif opt in ("-j", "--jwt"):
         jwt = arg
 
    if issuer and client_id and audience and jwt:
        try:
            oktaJwt = JwtVerifier(issuer, client_id)
            claims = oktaJwt.verifyAccessToken(jwt, audience)
            print("Local JWT validation succeeded.")
            print("Verified claims: {0}".format(json.dumps(claims, indent=4, sort_keys=True)))

            # print("Calling issuer's introspect endpoint for remote validation...")
            # if oktaJwt.introspect(jwt):
            #     print("Issuer reports the token is still valid.")
            # else:
            #     print("Issuer reports the token is no longer valid.")

        except ExpiredTokenError:
            print("JWT signature is valid, but the token has expired!")

        except InvalidSignatureError:
            print("JWT signature validation failed!")
        
        except KeyNotFoundError as key_error:
            print(key_error)

        except InvalidKeyError as key_error:
            print(key_error)
    else:
        print("python -m oktajwt -i <issuer> -a <audience> -c <client_id> -j <base64 encoded JWT>")
        print("python -m oktajwt --issuer=<issuer> --audience=<audience> --client_id=<client_id> --jwt=<base64 encoded JWT>")
        sys.exit(2)

if __name__ == "__main__":
    main(sys.argv[1:])