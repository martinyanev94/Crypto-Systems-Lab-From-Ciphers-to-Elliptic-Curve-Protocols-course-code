# Zero-Knowledge Cave Demo

This toy simulator models repeated binary challenge rounds. The honest mode can answer either challenge. The cheating mode commits to route `0` and succeeds only when the verifier selects that route.

The simulator demonstrates repetition and empirical probability. It is not production cryptography and does not implement a real secret-dependent proof.

## Run

From this directory:

```bash
python -m pip install -e .
cave-demo --rounds 4 --trials 1000 --seed 7
```

The expected cheating probability is `2 ** (-rounds)`. The observed value is an estimate from the selected number of trials.

## Test

```bash
python -m pytest
```
