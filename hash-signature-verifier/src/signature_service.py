from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
from typing import Union

Message = Union[str, bytes]


@dataclass(frozen=True)
class PublicKey:
    e: int
    n: int


@dataclass(frozen=True)
class PrivateKey:
    d: int
    n: int


def digest_value(message: Message, n: int) -> int:
    """Return the toy-domain representative of a SHA-256 digest."""
    if n <= 1:
        raise ValueError("the modulus must be greater than one")
    raw = message.encode("utf-8") if isinstance(message, str) else message
    return int.from_bytes(sha256(raw).digest(), "big") % n


def sign(message: Message, private_key: PrivateKey) -> int:
    """Sign the message digest with the toy private exponent."""
    digest = digest_value(message, private_key.n)
    return pow(digest, private_key.d, private_key.n)


def verify(message: Message, signature: int, public_key: PublicKey) -> bool:
    """Verify a signature against the digest of the received message."""
    if not 0 <= signature < public_key.n:
        return False
    expected = digest_value(message, public_key.n)
    recovered = pow(signature, public_key.e, public_key.n)
    return recovered == expected


PUBLIC = PublicKey(e=17, n=3233)
PRIVATE = PrivateKey(d=2753, n=3233)


def main() -> None:
    parser = argparse.ArgumentParser(description="Toy hash-and-sign verifier")
    parser.add_argument("message", help="message to sign or verify")
    parser.add_argument("--signature", type=int, help="signature to verify")
    args = parser.parse_args()

    if args.signature is None:
        signature = sign(args.message, PRIVATE)
        print(signature)
        return

    print("valid" if verify(args.message, args.signature, PUBLIC) else "invalid")


if __name__ == "__main__":
    main()
