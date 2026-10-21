import base64
import json

import pytest

from aes_service import decrypt_payload, encrypt_payload


KEY = b"K" * 32
PAYLOAD = b"snapshot-2026-10-20.tar"


def test_payload_round_trip_through_serialized_envelope():
    envelope = encrypt_payload(PAYLOAD, KEY)
    assert decrypt_payload(envelope, KEY) == PAYLOAD


def test_fresh_nonce_changes_serialized_envelope():
    first = json.loads(encrypt_payload(PAYLOAD, KEY))
    second = json.loads(encrypt_payload(PAYLOAD, KEY))
    assert first["nonce"] != second["nonce"]


def test_modified_ciphertext_is_rejected():
    envelope = json.loads(encrypt_payload(PAYLOAD, KEY))
    modified = bytearray(base64.b64decode(envelope["ciphertext"]))
    modified[0] ^= 1
    envelope["ciphertext"] = base64.b64encode(modified).decode("ascii")

    with pytest.raises(ValueError, match="tampered payload rejected"):
        decrypt_payload(json.dumps(envelope), KEY)


def test_wrong_key_is_rejected():
    envelope = encrypt_payload(PAYLOAD, KEY)
    with pytest.raises(ValueError, match="tampered payload rejected"):
        decrypt_payload(envelope, b"W" * 32)
