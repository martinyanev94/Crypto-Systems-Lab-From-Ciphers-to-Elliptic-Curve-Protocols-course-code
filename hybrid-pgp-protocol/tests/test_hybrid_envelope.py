import base64
import copy

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa

from hybrid_envelope import CiphertextTampered, RecipientMismatch, build_envelope, open_envelope


def keys():
    alice = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bob = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return alice, bob


def test_round_trip():
    alice, bob = keys()
    envelope = build_envelope("Meet at 10", alice, bob.public_key())
    assert open_envelope(envelope, bob, alice.public_key()) == "Meet at 10"


def test_wrong_recipient():
    alice, bob = keys()
    _, carol = keys()
    envelope = build_envelope("Meet at 10", alice, bob.public_key())
    with pytest.raises(RecipientMismatch):
        open_envelope(envelope, carol, alice.public_key())


def test_ciphertext_tamper():
    alice, bob = keys()
    envelope = build_envelope("Meet at 10", alice, bob.public_key())
    changed = copy.deepcopy(envelope)
    raw = bytearray(base64.b64decode(changed["ciphertext"]))
    raw[0] ^= 1
    changed["ciphertext"] = base64.b64encode(raw).decode("ascii")
    with pytest.raises(CiphertextTampered):
        open_envelope(changed, bob, alice.public_key(), trusted_envelope=envelope)


def test_invalid_signature():
    alice, bob = keys()
    envelope = build_envelope("Meet at 10", alice, bob.public_key())
    changed = copy.deepcopy(envelope)
    raw = bytearray(base64.b64decode(changed["signature"]))
    raw[0] ^= 1
    changed["signature"] = base64.b64encode(raw).decode("ascii")
    with pytest.raises(InvalidSignature):
        open_envelope(changed, bob, alice.public_key(), trusted_envelope=envelope)
