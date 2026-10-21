from __future__ import annotations

import argparse
import hashlib
from typing import Union

BytesLike = Union[str, bytes]


def to_bytes(value: BytesLike) -> bytes:
    """Convert supported input into the canonical bytes to hash."""
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def digest_hex(value: BytesLike) -> str:
    """Return the SHA-256 digest as 64 hexadecimal characters."""
    return hashlib.sha256(to_bytes(value)).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Calculate SHA-256 digests")
    parser.add_argument("message", nargs="+", help="messages to hash")
    args = parser.parse_args()
    for message in args.message:
        print(digest_hex(message))


if __name__ == "__main__":
    main()
