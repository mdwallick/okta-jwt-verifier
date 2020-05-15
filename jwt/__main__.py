import argparse
import json
import sys

from .jwt_api import JwtVerifier
from . import __version__ as application

from .exceptions import (
    OktaError, DecodeError, InvalidSignatureError, InvalidIssuerError, 
    MissingRequiredClaimError, InvalidAudienceError, ExpiredTokenError, 
    InvalidIssuedAtError, InvalidKeyError, KeyNotFoundError
)

def get_argparser():
    usage = """
    Decodes and verifies JWTs from an Okta authorization server.

    %(prog)s [options] <JWT>
    """

    arg_parser = argparse.ArgumentParser(prog="oktajwt", usage=usage)

    arg_parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s " + application.__version__
    )

    arg_parser.add_argument(
        "--verbosity",
        type=int,
        choices=[0, 1, 2],
        help="increase output verbosity"
    )
    
    arg_parser.add_argument(
        "-i",
        "--issuer",
        action="store",
        required=True,
        help="The expected issuer of the token"
    )

    arg_parser.add_argument(
        "-a",
        "--audience",
        action="store",
        required=True,
        help="The expected audience of the token"
    )

    arg_parser.add_argument(
        "-c",
        "--client_id",
        action="store",
        required=True,
        help="The OIDC client ID"
    )

    arg_parser.add_argument(
        "-s",
        "--client_secret",
        action="store",
        required=False,
        help="The OIDC client secret (not required if using PKCE)"
    )

    arg_parser.add_argument(
        "--claims",
        action="store_true",
        required=False,
        help="Show verified claims in addition to validating the JWT"
    )

    arg_parser.add_argument(
        "jwt",
        metavar="JWT",
        default=None,
        help="The base64 encoded JWT to decode and verify"
    )

    return arg_parser

def main():
    arg_parser = get_argparser()

    try:
        args = arg_parser.parse_args(sys.argv[1:])
        jwtVerifier = JwtVerifier(args.issuer, args.client_id, args.client_secret, args.verbosity)
        is_valid = jwtVerifier.is_token_valid(args.jwt, args.audience)
        if is_valid:
            print("JWT is valid. Claims can be trusted.")
            if args.claims:
                claims = jwtVerifier.decode(args.jwt, args.audience)
                print("Verified claims: {0}".format(json.dumps(claims, indent=4, sort_keys=True)))
        else:
            print("JWT is not valid.")        

    except Exception as e:
        print("There was an unforseen error: ", e)
        arg_parser.print_help()