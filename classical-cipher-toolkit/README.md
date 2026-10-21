# Classical Cipher Toolkit

A small educational Caesar cipher implementation.

## Run

From the `classical-cipher-toolkit` directory:

```bash
python -m src.cli "MEET AT NOON" 3
python -m src.cli "PHHW DW QRRQ" --brute-force
```

The first command prints `PHHW DW QRRQ`. The second prints candidates for keys 0 through 25; key 3 recovers `MEET AT NOON`.

Run the tests with:

```bash
python -m pytest
```

This is a teaching implementation, not production cryptography. Caesar has only 26 possible shifts and is trivial to exhaustively search.
