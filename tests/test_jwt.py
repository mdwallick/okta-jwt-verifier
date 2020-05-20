import json
import pytest
import time

from calendar import timegm
from datetime import datetime, timedelta
from decimal import Decimal

from oktajwt.jwt_api import JwtVerifier
from oktajwt.exceptions import (
    OktaError,
    DecodeError,
    InvalidSignatureError,
    InvalidIssuerError, 
    MissingRequiredClaimError,
    InvalidAudienceError,
    ExpiredTokenError, 
    InvalidIssuedAtError,
    InvalidKeyError,
    KeyNotFoundError
)

from .utils import utc_timestamp, has_crypto

#@pytest.fixture
# def jwt():
#     return JwtVerifier()


#@pytest.fixture
def payload():
    # dummy JWT for testing
    return {
        "iss": "les.claypool",
        "aud": "api://default",
        "exp": utc_timestamp() + 15,
        "uat": utc_timestamp() - 15
    }

class TestJwt():
    def func(self, x):
        return x + 1

    def test_answer(self):
        assert self.func(3) == 5
