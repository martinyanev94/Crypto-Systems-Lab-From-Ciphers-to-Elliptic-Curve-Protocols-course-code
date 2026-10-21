# Hash Signature Verifier

Educational toy RSA-style signing service. The parameters are intentionally tiny and are not suitable for protecting real data.

## Run

From this directory:

```text
PYTHONPATH=src python -m signature_service "pay invoice 42"
PYTHONPATH=src python -m signature_service "pay invoice 42" --signature SIGNATURE
```

The first command prints a toy signature. Pass that integer to the second command to verify it. Changing the message or signature prints `invalid`.

## Test

Install pytest, then run:

```text
PYTHONPATH=src pytest
```
