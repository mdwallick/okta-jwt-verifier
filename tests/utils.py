import os
import struct
from calendar import timegm
from datetime import datetime

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
        load_pem_public_key,
        load_ssh_public_key,
    )
    has_crypto = True
except ImportError:
    has_crypto = False


def utc_timestamp():
    return timegm(datetime.utcnow().utctimetuple())
