# RSA Crypto Lab

This project demonstrates textbook RSA over bounded integers.

It is intentionally educational and insecure. The toy factors are small, the
message is not padded, and encryption is deterministic. Do not use this code
to protect real messages or keys.

## Run the CLI

```bash
cd rsa-crypto-lab
PYTHONPATH=src python -m cli encrypt 88
```

Expected result:

```text
encrypt=6621
```

The implementation accepts only integers in `[0, n)`. Production RSA requires
large generated parameters and a vetted randomized encoding scheme from a
cryptographic library.
