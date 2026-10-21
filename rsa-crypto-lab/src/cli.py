from __future__ import annotations

import argparse

from rsa_crypto import decrypt, encrypt, generate_keypair


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bounded textbook RSA demo")
    parser.add_argument("operation", choices=("encrypt", "decrypt"))
    parser.add_argument("value", type=int)
    args = parser.parse_args(argv)

    public_key, private_key = generate_keypair(101, 67, 2407)
    if args.operation == "encrypt":
        result = encrypt(args.value, public_key)
    else:
        result = decrypt(args.value, private_key)
    print(f"{args.operation}={result}")
    return 0


if __name__ == "__main__":
    main()
