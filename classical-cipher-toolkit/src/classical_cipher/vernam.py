from .binary import xor_bytes


def encrypt(text: str, key: str) -> bytes:
    return xor_bytes(text.encode("ascii"), key.encode("ascii"))


def decrypt(ciphertext: bytes, key: str) -> str:
    return xor_bytes(ciphertext, key.encode("ascii")).decode("ascii")
