# ECDSA Attack Review

This teaching project records practical review findings and detects the repeated-`r` signal associated with ECDSA nonce reuse. It is not a production ECDSA implementation.

Run the tests from this directory:

```bash
python -m pytest
```

The checklist covers curve-point validation, nonce generation, canonical signed bytes, signer identity binding, and future algorithm migration. A repeated `r` finding is critical: stop signing and rotate the affected key while investigating the nonce source.
