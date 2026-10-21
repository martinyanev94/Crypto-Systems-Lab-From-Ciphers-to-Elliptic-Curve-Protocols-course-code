# Diffie-Hellman exchange demo

This teaching project demonstrates honest modular Diffie-Hellman, a simulated public-value substitution, and a placeholder identity-verification boundary.

The parameters are intentionally tiny and are not secure for real communication.

## Run the tests

```bash
cd dh-key-exchange-demo
python -m pytest
```

The trusted identity mapping is illustrative. A production protocol needs a defined, independently trusted mechanism for obtaining and validating identity credentials.
