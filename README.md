# okta-jwt

This is a simple JWT package built to work specifically with Okta's API Access Management product (API AM). It was inspried in part by [jpadilla's PyJWT package](https://github.com/jpadilla/pyjwt). This is not meant to be a full implementation of [RFC 7519](https://tools.ietf.org/html/rfc7519), but rather a subset of JWT operations specific to working with Okta.

## Requirements
* Python >= 3.7
* cryptography >= 2.6
* joblib >= 0.13.2
* python-dotenv >= 0.10.1
* requests >= 2.21

## Dependencies
You can install all the dependencies via the requirements.txt
`pip3 install -r requirements.txt`

## Okta Configuration Instructions
**1) Okta Org**
You need to have an Okta org with API Access management available.
You can get a free developer account at https://developer.okta.com

**2) Create an OIDC Application**
Create a new OIDC web app in Okta. This is the client that you will create access policies for.

**3) Create an Authorization Server**

## Environment variables
This package uses dotenv, so create a `.env` file with these values:

```
OKTA_ORG=https://<yoursubdomain>.okta.com
AUTH_SERVER_ID=<Okta auth server ID>
AUDIENCE=<OIDC audience from your app>
CLIENT_ID=<OIDC client ID>
CLIENT_SECRET=<OIDC client secret>
```

## Usage
See [main.py](https://github.com/mdwallick/okta-jwt/blob/master/main.py) for a basic usage example.

You may also pass a log level into `JwtVerifier()` to get additional information printed to the console. The default log level is `logging.WARNING`.
