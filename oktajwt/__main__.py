import argparse
import json
import sys
import traceback

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
        "--cache",
        action="store",
        required=False,
        default="file",
        help="The JWKS caching method to use: file or S3"
    )

    arg_parser.add_argument(
        "-b",
        "--bucket",
        action="store",
        required=False,
        help="The S3 bucket to cache to. REQUIRED if --cache=S3"
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

        if args.cache == "S3":
            jwtVerifier = JwtVerifier(issuer=args.issuer,
                    client_id=args.client_id,
                    client_secret=args.client_secret,
                    cache=args.cache,
                    bucket=args.bucket,
                    verbosity=args.verbosity)
        else:
            # default to filesystem caching
            jwtVerifier = JwtVerifier(issuer=args.issuer,
                client_id=args.client_id,
                client_secret=args.client_secret,
                cache=args.cache,
                verbosity=args.verbosity)

        try:
            claims = jwtVerifier.verify(args.jwt, args.audience)
            print("JWT is valid. Claims can be trusted.")
            if args.claims:
                print("Verified claims: {0}".format(json.dumps(claims, indent=4, sort_keys=True)))
        except Exception as e:
            print("JWT is not valid: {0}".format(e))

    except Exception as e:
        print("Invalid command: ", e)
        if args.verbosity > 0:
            stack_trace = traceback.format_exc()
            print(stack_trace)
        
        arg_parser.print_help()
