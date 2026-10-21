from __future__ import annotations

from dataclasses import dataclass
from random import Random


@dataclass(frozen=True)
class RoundResult:
    challenge: int
    commitment: int | None
    accepted: bool


def run_round(*, mode: str, challenge: int, commitment: int = 0) -> RoundResult:
    if mode not in {"honest", "cheating"}:
        raise ValueError("mode must be honest or cheating")
    if challenge not in {0, 1}:
        raise ValueError("challenge must be 0 or 1")
    if commitment not in {0, 1}:
        raise ValueError("commitment must be 0 or 1")

    accepted = mode == "honest" or challenge == commitment
    return RoundResult(
        challenge=challenge,
        commitment=None if mode == "honest" else commitment,
        accepted=accepted,
    )


def run_rounds(*, mode: str, rounds: int, rng: Random) -> list[RoundResult]:
    if rounds < 1:
        raise ValueError("rounds must be positive")
    if mode not in {"honest", "cheating"}:
        raise ValueError("mode must be honest or cheating")

    commitment = 0
    return [
        run_round(
            mode=mode,
            challenge=rng.randrange(2),
            commitment=commitment,
        )
        for _ in range(rounds)
    ]


def cheating_probability(rounds: int) -> float:
    if rounds < 1:
        raise ValueError("rounds must be positive")
    return 2 ** (-rounds)


def estimate_cheating_success(*, rounds: int, trials: int, seed: int) -> float:
    if trials < 1:
        raise ValueError("trials must be positive")

    rng = Random(seed)
    successes = 0
    for _ in range(trials):
        results = run_rounds(mode="cheating", rounds=rounds, rng=rng)
        if all(result.accepted for result in results):
            successes += 1
    return successes / trials
