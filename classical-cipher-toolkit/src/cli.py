from __future__ import annotations

import argparse

from .caesar import brute_force, decrypt, encrypt


def main() -> None:
    parser = argparse.ArgumentParser(description="Toy Caesar cipher toolkit")
    parser.add_argument("text")
    parser.add_argument("key", type=int, nargs="?", default=0)
    parser.add_argument("--decrypt", action="store_true")
    parser.add_argument("--brute-force", action="store_true")
    args = parser.parse_args()

    if args.brute_force:
        for key, candidate in brute_force(args.text):
            print(f"{key}: {candidate}")
    elif args.decrypt:
        print(decrypt(args.text, args.key))
    else:
        print(encrypt(args.text, args.key))


if __name__ == "__main__":
    main()
