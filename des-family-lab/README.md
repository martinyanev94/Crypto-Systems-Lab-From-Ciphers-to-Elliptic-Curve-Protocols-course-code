# DES, Triple DES, and DESX Analysis Lab

Educational toy implementations only. They are intentionally small and are not suitable for protecting data.

## Run the report

```bash
python -m src.des_family
```

## Run tests

```bash
python -m pytest
```

The report uses an 8-bit block and a 4-bit key so exhaustive search is visible. Triple DES uses E-D-E composition. DESX uses input and output XOR whitening around the toy DES stage. Search counts distinguish candidate combinations from primitive evaluations.
