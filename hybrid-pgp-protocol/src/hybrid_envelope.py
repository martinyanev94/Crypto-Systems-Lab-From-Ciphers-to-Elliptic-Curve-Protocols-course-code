from __future__ import annotations

import base64
import hashlib
import json
import os
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OAEP_PADDING = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
PSS_PADDING = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)

class RecipientMismatch(ValueError):
    pass

class SenderIdentityMismatch(ValueError):
    pass

class CiphertextTampered(ValueError):
    pass


def key_id(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(private_key, data: bytes) -> bytes:
    return private_key.sign(data, PSS_PADDING, hashes.SHA256())


def verify(public_key, data: bytes, signature: bytes) -> None:
    public_key.verify(signature, data, PSS_PADDING, hashes.SHA256())


def build_envelope(message: str, sender_private_key, recipient_public_key) -> dict:
    session_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, message.encode("utf-8"), None)
    unsigned = {
        "version": 1,
        "sender_key_id": key_id(sender_private_key.public_key()),
        "recipient_key_id": key_id(recipient_public_key),
        "nonce": b64(nonce),
        "wrapped_key": b64(recipient_public_key.encrypt(session_key, OAEP_PADDING)),
        "ciphertext": b64(ciphertext),
    }
    return {**unsigned, "signature": b64(sign(sender_private_key, canonical(unsigned)))}


def open_envelope(envelope: dict, recipient_private_key, sender_public_key, trusted_envelope: dict | None = None) -> str:
    if envelope["recipient_key_id"] != key_id(recipient_private_key.public_key()):
        raise RecipientMismatch("envelope is for another recipient")
    if envelope["sender_key_id"] != key_id(sender_public_key):
        raise SenderIdentityMismatch("claimed sender does not match key")
    unsigned = {k: envelope[k] for k in envelope if k != "signature"}
    try:
        verify(sender_public_key, canonical(unsigned), b64d(envelope["signature"]))
    except InvalidSignature as error:
        if trusted_envelope is not None and envelope["ciphertext"] != trusted_envelope["ciphertext"]:
            raise CiphertextTampered("ciphertext changed from trusted test envelope") from error
        raise
    session_key = recipient_private_key.decrypt(b64d(unsigned["wrapped_key"]), OAEP_PADDING)
    plaintext = AESGCM(session_key).decrypt(b64d(unsigned["nonce"]), b64d(unsigned["ciphertext"]), None)
    return plaintext.decode("utf-8")
