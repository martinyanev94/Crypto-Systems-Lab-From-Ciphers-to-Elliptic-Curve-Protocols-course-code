from __future__ import annotations

import argparse

from .cave import cheating_probability, estimate_cheating_success


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run repeated cave rounds")
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--trials", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=7)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    observed = estimate_cheating_success(
        rounds=args.rounds,
        trials=args.trials,
        seed=args.seed,
    )
    expected = cheating_probability(args.rounds)
    print(f"rounds: {args.rounds}")
    print(f"trials: {args.trials}")
    print(f"expected cheating success: {expected:.6f}")
    print(f"observed cheating success: {observed:.6f}")


if __name__ == "__main__":
    main()
