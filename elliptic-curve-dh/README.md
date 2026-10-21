# Elliptic-Curve Diffie–Hellman

Educational toy implementation of elliptic-curve point arithmetic and ECDH.
The parameters are intentionally tiny and are not suitable for protecting data.

## Run

From this directory:

```bash
python -m pip install pytest
pytest
```

The example curve is `y² = x³ + 2x + 2 (mod 17)` with generator `(5, 1)` and order `19`. For private scalars `3` and `9`, both participants derive the shared point `(13, 7)`.
