# ElGamal encryption demo

This project is a small teaching implementation of ElGamal over a multiplicative group modulo a prime. It demonstrates correct decryption, injectable ephemeral values for deterministic tests, and the relationship exposed when the same ephemeral value is reused.

The parameters are intentionally small and are not suitable for protecting real data. The runtime path uses Python's `secrets` module when no test value is supplied. Tests inject values only to make the failure experiment reproducible.

## Run

From this directory:

```bash
python -m pytest
```

The message domain is `1 <= M < p`, because this demonstration uses multiplicative masking and therefore excludes zero from the group.
