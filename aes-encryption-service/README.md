# AES encryption service

This project demonstrates an AES-256-GCM envelope for bytes moving between services.
The JSON envelope contains the algorithm marker, Base64-encoded nonce, and Base64-encoded ciphertext plus authentication tag. The key is intentionally kept outside the envelope; this project does not implement key exchange.

Run the tests from this directory:

```bash
python -m pip install -e .
python -m pytest
```

This is an educational integration example, not a replacement for a reviewed production protocol.
