from random import Random

import pytest

from zero_knowledge_cave.cave import (
    cheating_probability,
    estimate_cheating_success,
    run_round,
    run_rounds,
)


def test_honest_prover_passes_both_challenges() -> None:
    assert run_round(mode="honest", challenge=0).accepted
    assert run_round(mode="honest", challenge=1).accepted


def test_cheater_only_passes_committed_route() -> None:
    assert run_round(mode="cheating", challenge=0, commitment=0).accepted
    assert not run_round(mode="cheating", challenge=1, commitment=0).accepted


def test_repeated_rounds_have_requested_length() -> None:
    results = run_rounds(mode="cheating", rounds=5, rng=Random(3))
    assert len(results) == 5
    assert all(result.commitment == 0 for result in results)


def test_probability_halves_each_round() -> None:
    assert cheating_probability(1) == 0.5
    assert cheating_probability(2) == 0.25
    assert cheating_probability(4) == 0.0625


def test_estimate_is_reproducible() -> None:
    first = estimate_cheating_success(rounds=3, trials=100, seed=11)
    second = estimate_cheating_success(rounds=3, trials=100, seed=11)
    assert first == second


@pytest.mark.parametrize("rounds", [0, -1])
def test_round_count_must_be_positive(rounds: int) -> None:
    with pytest.raises(ValueError):
        cheating_probability(rounds)
