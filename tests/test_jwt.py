import json
import time
import unittest

from unittest import skipIf
from unittest.mock import Mock, patch

from calendar import timegm
from datetime import datetime, timedelta
from decimal import Decimal

from oktajwt.jwt_api import JwtVerifier
from oktajwt.exceptions import (
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


class TestVerifier(unittest.TestCase):
    def setUp(self):
        self.wrong_issuer = "https://auth.thoraxstudios.com/oauth2/default"
        # note the misspelled domain name below
        self.nonexistent_issuer = "https://auth.thoraxstudiuos.com/oauth2/default"
        self.wrong_audience = "api://default"

        self.issuer = "https://auth.thoraxstudios.com/oauth2/ausrki6tz3fmnVObF0h7"
        self.audience = "com.thoraxstudios.oktaadminapi"
        self.client_id = "0oarcjf7g39FMj1ZJ0h7"
        # This expired token was a valid Okta-minted JWT at one time
        # using the issuer/audience/client ID above.
        # I kept it to have as real a test as possible.
        # The keys.json file in this directory has the public key corresponding
        # to this JWT so we're not fetching keys during testing
        self.expired_token = "eyJraWQiOiIwQi13NHBteHNMTXlmLUVJMng3bHFGTHZUcUNWNFNMTmNjRjZLZmY2UnlJIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULi10bHRwVGlXQ2hHbDFiWnd4RTRHS05LajRuZXp6OFpXVEtTNTV0ZEhmb2ciLCJpc3MiOiJodHRwczovL2F1dGgudGhvcmF4c3R1ZGlvcy5jb20vb2F1dGgyL2F1c3JraTZ0ejNmbW5WT2JGMGg3IiwiYXVkIjoiY29tLnRob3JheHN0dWRpb3Mub2t0YWFkbWluYXBpIiwiaWF0IjoxNTg5OTk5MDYyLCJleHAiOjE1OTAwMDI2NjIsImNpZCI6IjBvYXJjamY3ZzM5Rk1qMVpKMGg3IiwidWlkIjoiMDB1bXNtbjJ6ZUhobHUzc1kwaDciLCJzY3AiOlsiZW1haWwiLCJwcm9maWxlIiwib3BlbmlkIl0sInN1YiI6InRlc3R1c2VyNUBtYWlsaW5hdG9yLmNvbSJ9.PZrpRNVJqy-9Yaa6YGupJ3Lz1EPmdAEJg6uWF6ksWUROOZJYbqUfq1z5X1zHxm8Q5fYmA-iyhafiF179Zp5BT5U9sHS6-6SA9nMEm34QBZdGJVITtUR0D51u6JMpzG6YxLDlnIW0-56vvF-SbfBdPXEkPdhGpRfEdymzMGi3Z_qRoJdSIqW5m9ylUnp7Iy3zArq4bmcjbWp2ys-XBwGHsR2smQPL65SynCcvVL5TDdE6V1iS1EUTQIgbHYt1rNnyB2cO6OL14TL4_AHBVQDYRLNgnyS6K2uWGVSBY4os5D5xKWiwofz7aif_e6PbZc-e29GCUSyzd9WW5DlwRd3ilQ"

        # same JWT as expired token, but the last character was changed from Q to A
        # to make sure it fails signature validation
        self.invalid_signed_token = "eyJraWQiOiIwQi13NHBteHNMTXlmLUVJMng3bHFGTHZUcUNWNFNMTmNjRjZLZmY2UnlJIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULi10bHRwVGlXQ2hHbDFiWnd4RTRHS05LajRuZXp6OFpXVEtTNTV0ZEhmb2ciLCJpc3MiOiJodHRwczovL2F1dGgudGhvcmF4c3R1ZGlvcy5jb20vb2F1dGgyL2F1c3JraTZ0ejNmbW5WT2JGMGg3IiwiYXVkIjoiY29tLnRob3JheHN0dWRpb3Mub2t0YWFkbWluYXBpIiwiaWF0IjoxNTg5OTk5MDYyLCJleHAiOjE1OTAwMDI2NjIsImNpZCI6IjBvYXJjamY3ZzM5Rk1qMVpKMGg3IiwidWlkIjoiMDB1bXNtbjJ6ZUhobHUzc1kwaDciLCJzY3AiOlsiZW1haWwiLCJwcm9maWxlIiwib3BlbmlkIl0sInN1YiI6InRlc3R1c2VyNUBtYWlsaW5hdG9yLmNvbSJ9.PZrpRNVJqy-9Yaa6YGupJ3Lz1EPmdAEJg6uWF6ksWUROOZJYbqUfq1z5X1zHxm8Q5fYmA-iyhafiF179Zp5BT5U9sHS6-6SA9nMEm34QBZdGJVITtUR0D51u6JMpzG6YxLDlnIW0-56vvF-SbfBdPXEkPdhGpRfEdymzMGi3Z_qRoJdSIqW5m9ylUnp7Iy3zArq4bmcjbWp2ys-XBwGHsR2smQPL65SynCcvVL5TDdE6V1iS1EUTQIgbHYt1rNnyB2cO6OL14TL4_AHBVQDYRLNgnyS6K2uWGVSBY4os5D5xKWiwofz7aif_e6PbZc-e29GCUSyzd9WW5DlwRd3ilA"

    def tearDown(self):
        pass

    def test_invalid_signature_raises_InvalidSignatureError(self):
        with self.assertRaises(InvalidSignatureError):
            oj = JwtVerifier(issuer=self.issuer, client_id=self.client_id)
            _claims = oj.verify(
                self.invalid_signed_token, self.audience)

    def test_valid_signature_yet_expired_raises_ExpiredTokenError(self):
        with self.assertRaises(ExpiredTokenError):
            oj = JwtVerifier(issuer=self.issuer, client_id=self.client_id)
            _claims = oj.verify(
                self.expired_token, self.audience)

    def test_issuer_mismatch_raises_InvalidIssuerError(self):
        with self.assertRaises((InvalidIssuerError, KeyNotFoundError)):
            oj = JwtVerifier(issuer=self.wrong_issuer, client_id=self.client_id)
            _claims = oj.verify(self.expired_token, self.audience)

    def test_audience_mismatch_raises_InvalidAudienceError(self):
        with self.assertRaises(InvalidAudienceError):
            oj = JwtVerifier(issuer=self.issuer, client_id=self.client_id)
            _claims = oj.verify(self.expired_token, self.wrong_audience)

    def test_nonexistent_issuer_raises_InvalidIssuerError(self):
        with self.assertRaises((InvalidIssuerError, KeyNotFoundError)):
            oj = JwtVerifier(issuer=self.nonexistent_issuer, client_id=self.client_id)
            _claims = oj.verify(self.expired_token, self.audience)
