# oktajwt

This is a simple JWT package built to work specifically with Okta's API Access Management product (API AM). It was inspried in part by [jpadilla's PyJWT package](https://github.com/jpadilla/pyjwt). This is not meant to be a full implementation of [RFC 7519](https://tools.ietf.org/html/rfc7519), but rather a subset of JWT operations specific to working with Okta.

## Requirements
* Python >= 3.7
* cryptography >= 2.9
* requests >= 2.23

## Dependencies
You can install all the dependencies via the requirements.txt
`pip install -r requirements.txt`

## Okta Configuration Instructions
**1) Okta Org**
You need to have an Okta org with API Access management available.
You can get a free developer account at https://developer.okta.com

**2) Create an OIDC Application**
Create a new OIDC web app in Okta. This is the client that you will create access policies for.

**3) Create an Authorization Server**

## Usage
This module has a command line interface:
```
python -m oktajwt -i <issuer> -a <audience> -c <client_id> -j <base64 encoded JWT>

python -m oktajwt --issuer=<issuer> --audience=<audience> --client_id=<client_id> --jwt=<base64 encoded JWT>
```

However, it's much more likely that this package will be used inside something like an API server, so the
usage would look somethin like this:

```python
import json
import sys

from .util.exceptions import *
from .jwt import JwtVerifier

try:
    oktaJwt = JwtVerifier(issuer, client_id)
    # verifyAccessToken performs local JWT validation
    claims = oktaJwt.verifyAccessToken(jwt, audience)
    print("Local JWT validation succeeded.")
    print("Verified claims: {0}".format(json.dumps(claims, indent=4, sort_keys=True)))

    # you could also call introspect() to query the issuer directly
    print("Calling issuer's introspect endpoint for remote validation...")
    if oktaJwt.introspect(jwt):
        print("Issuer reports the token is still valid.")
    else:
        print("Issuer reports the token is no longer valid.")

except ExpiredTokenError:
    print("JWT signature is valid, but the token has expired!")

except InvalidSignatureError:
    print("JWT signature validation failed!")

except KeyNotFoundError as key_error:
    print(key_error)

except InvalidKeyError as key_error:
    print(key_error)
```
