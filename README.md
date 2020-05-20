# oktajwt

This is a simple JWT package built to work specifically with Okta's API Access Management product (API AM). It was inspried in part by [jpadilla's PyJWT package](https://github.com/jpadilla/pyjwt). This is not meant to be a full implementation of [RFC 7519](https://tools.ietf.org/html/rfc7519), but rather a subset of JWT operations specific to working with Okta.

## Requirements
* Python >= 3.7

## Installing
Install with **pip**:
```
$ pip install oktajwt
```

## Usage
This package is very simple, there is a single function: `decode()`.

```python
from oktajwt import *

issuer = "your OAuth issuer"
client_id = "OIDC client ID"
client_secret = "OIDC client secret or None if using PKCE"
expected_audience = "expected audience"
access_token = "your base64 encoded JWT, pulled out of the HTTP Authorization header bearer token"

jwtVerifier = JwtVerifier(issuer="OAUTH issuer URI",
    client_id="OAuth client ID",
    client_secret="OAuth client secret or None if using PKCE",
    cache="caching method to use, file or S3",
    bucket="S3 bucket to cache to. Required if cache=S3"
)

# validate the token and get claims as a JSON dict
claims = jwtVerifier.decode(access_token, expected_audience)
print("iss {0}".format(claims["iss"]))
print("aud {0}".format(claims["aud"]))
print("sub {0}".format(claims["sub"]))
print("exp {0}".format(claims["exp"]))
```

This module also has a basic command line interface just as an example:
```
usage:
    Decodes and verifies JWTs from an Okta authorization server.

    oktajwt [options] <JWT>


positional arguments:
  JWT                   The base64 encoded JWT to decode and verify

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --verbosity {0,1,2}   increase output verbosity
  -i ISSUER, --issuer ISSUER
                        The expected issuer of the token
  -a AUDIENCE, --audience AUDIENCE
                        The expected audience of the token
  -c CLIENT_ID, --client_id CLIENT_ID
                        The OIDC client ID
  -s CLIENT_SECRET, --client_secret CLIENT_SECRET
                        The OIDC client secret (not required if using PKCE)
  --cache CACHE         The JWKS caching method to use: file or S3
  -b BUCKET, --bucket BUCKET
                        The S3 bucket to cache to. REQUIRED if --cache=S3
  --claims              Show verified claims in addition to validating the JWT
```

However, it's much more likely that this package will be used inside something like Flask API server, so the
usage would look something more like this.

```python
import json
import request
from oktajwt import *

def get_access_token():
    access_token = None
    authorization_header = request.headers.get("authorization")
    print("Authorization header {0}".format(authorization_header))

    if authorization_header != None:
        header = "Bearer"
        bearer, access_token = authorization_header.split(" ")
        if bearer != header:
            abort(401)

    return access_token

@app.route("/api/v1/token_test", methods=["GET"])
def token_test():
    """ a simple route to show token validation """
    logger.debug("token_test()")
    access_token = get_access_token()
    issuer = os.getenv("ISSUER")
    client_id = os.getenv("CLIENT_ID")
    client_secret = os.getenv("CLIENT_SECRET")
    audience = os.getenv("AUDIENCE")
    cache_method = os.getenv("CACHE_METHOD")
    
    # if using S3 caching
    s3_bucket = os.getenv("S3_BUCKET")

    try:
        jwtVerifier = JwtVerifier(
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            cache=cache_method,
            bucket=s3_bucket
        )       
        claims = jwtVerifier.verify(access_token, audience)
        return jsonify(claims)
    except (ExpiredTokenError, InvalidSignatureError, KeyNotFoundError, 
            InvalidKeyError, Exception) as e:
        # something is wrong with the token
        # expired, bad signature, etc.
        logger.debug("Exception in token_test(): {0}".format(e))
        abort(401)
```

If you're interested, I have a [super basic Flask API server](https://github.com/mdwallick/okta-admin-api) that fronts a subset of the Okta APIs (users, groups, factors) that uses this package as an example.

## Okta Configuration
**NOTE:** this package will **NOT** work with the "stock" organization authorization server as access tokens minted by that server are opaque and no public key is published.

**Okta Org**
You need to have an Okta org with API Access management available. You can get a free developer account at https://developer.okta.com. Developer tenants will have API Access Management available.

**"How can I tell if I have API Access Management enabled or not?"**

It's actually quite easy. Copy this link and replace the subdomain with yours (a free developer tenant subdomain will look like dev-123456).

https://<YOUR_SUBDOMAIN>.okta.com/oauth2/default/.well-known/oauth-authorization-server

Paste the link with your subdomain in your browser and if you see this:

```json
{
    "errorCode": "E0000015",
    "errorSummary": "You do not have permission to access the feature you are requesting",
    "errorLink": "E0000015",
    "errorId": "oaeNmCVqapuSJWf017UlTMjbg",
    "errorCauses": []
}
```
You don't have API Access Management enabled in your org. Go get a [free developer account](https://developer.okta.com). Developer tenants will have API Access Management available.

**Create an OIDC Application**
Create a new OIDC application in Okta. This is where you'll get the client ID and client secret values. If you create an app that uses PKCE, a client secret value is not necessary and will not be generated.
x