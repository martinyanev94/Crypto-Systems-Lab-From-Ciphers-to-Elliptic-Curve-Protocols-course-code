import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_payload(payload: bytes, key: bytes) -> str:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes for AES-256")
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, payload, None)
    envelope = {
        "algorithm": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(envelope, sort_keys=True)


def decrypt_payload(envelope_json: str, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes for AES-256")
    envelope = json.loads(envelope_json)
    if envelope.get("algorithm") != "AES-256-GCM":
        raise ValueError("unsupported envelope algorithm")
    nonce = base64.b64decode(envelope["nonce"], validate=True)
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as error:
        raise ValueError("tampered payload rejected") from error
