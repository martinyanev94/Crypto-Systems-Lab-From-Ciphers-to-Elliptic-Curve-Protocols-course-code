# Course projects

This cryptography Python tutorial builds a runnable security lab from classical ciphers to elliptic-curve protocols. Learn how encryption, hashing, signatures, key exchange, zero-knowledge proofs, and encrypted search work through small, testable implementations. You’ll learn to: • Implement Caesar, ROT13, Vernam, Feistel, AES, RSA, ElGamal, and el

This repository contains the runnable project code built throughout the course.
Each lesson evolves these files; the repository stores the final working state
instead of disconnected per-lesson snippets.

## Projects and run commands

### `aes-encryption-service`

```bash
cd aes-encryption-service
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
python -m pytest
```

### `classical-cipher-toolkit`

```bash
cd classical-cipher-toolkit
python main.py
```

### `crypto-search-engine`

```bash
cd crypto-search-engine
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
python -m pytest
```

### `des-family-lab`

```bash
cd des-family-lab
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
python -m pytest
```

### `dh-key-exchange-demo`

```bash
cd dh-key-exchange-demo
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
python -m pytest
```

### `ecc-attack-review`

```bash
cd ecc-attack-review
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
python -m pytest
```

### `elgamal-encryption-demo`

```bash
cd elgamal-encryption-demo
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
python -m pytest
```

### `elliptic-curve-dh`

```bash
cd elliptic-curve-dh
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
python -m pytest
```

### `hash-signature-verifier`

```bash
cd hash-signature-verifier
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
python -m pytest
```

### `hybrid-pgp-protocol`

```bash
cd hybrid-pgp-protocol
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
python -m pytest
```

### `rsa-crypto-lab`

```bash
cd rsa-crypto-lab
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
python -m pytest
```

### `secp256k1-signature-lab`

```bash
cd secp256k1-signature-lab
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
python -m pytest
```

### `zero-knowledge-cave-demo`

```bash
cd zero-knowledge-cave-demo
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
python -m pytest
```

## Suggested workflow

1. Clone the repository.
2. Enter the project directory shown above.
3. Install dependencies with the listed command.
4. Run the app or script, then run its tests where provided.
5. Complete the final project in `FINAL_PROJECT.md`.
