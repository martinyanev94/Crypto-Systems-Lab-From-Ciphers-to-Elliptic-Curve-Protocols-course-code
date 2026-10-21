from __future__ import annotations


def public_value(g: int, private_exponent: int, p: int) -> int:
    return pow(g, private_exponent, p)


def shared_secret(received_public: int, private_exponent: int, p: int) -> int:
    return pow(received_public, private_exponent, p)


def verify_public_value(
    identity: str, received: int, trusted_values: dict[str, int]
) -> bool:
    expected = trusted_values.get(identity)
    return expected is not None and received == expected


def exchange(
    public_values: dict[str, int],
    private_exponents: dict[str, int],
    p: int,
    trusted_values: dict[str, int] | None = None,
) -> dict[str, object]:
    if trusted_values is not None:
        for identity, received in public_values.items():
            if not verify_public_value(identity, received, trusted_values):
                return {"status": "rejected", "reason": f"{identity} value mismatch"}

    alice_key = shared_secret(public_values["Bob"], private_exponents["Alice"], p)
    bob_key = shared_secret(public_values["Alice"], private_exponents["Bob"], p)
    return {
        "status": "accepted",
        "alice_key": alice_key,
        "bob_key": bob_key,
        "equal": alice_key == bob_key,
    }
