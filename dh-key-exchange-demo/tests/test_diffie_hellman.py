from src.diffie_hellman import exchange, public_value, verify_public_value


def test_honest_exchange_derives_equal_secret():
    assert public_value(7, 3, 11) == 2
    assert public_value(7, 6, 11) == 4
    result = exchange(
        {"Alice": 2, "Bob": 4},
        {"Alice": 3, "Bob": 6},
        11,
    )
    assert result == {
        "status": "accepted",
        "alice_key": 9,
        "bob_key": 9,
        "equal": True,
    }


def test_unauthenticated_substitution_breaks_endpoint_equality():
    result = exchange(
        {"Alice": 9, "Bob": 8},
        {"Alice": 3, "Bob": 6},
        11,
    )
    assert result["alice_key"] == 6
    assert result["bob_key"] == 9
    assert result["equal"] is False


def test_authenticated_substitution_is_rejected():
    trusted = {"Alice": 2, "Bob": 4}
    assert verify_public_value("Bob", 4, trusted)
    assert not verify_public_value("Bob", 8, trusted)
    result = exchange(
        {"Alice": 9, "Bob": 8},
        {"Alice": 3, "Bob": 6},
        11,
        trusted,
    )
    assert result == {"status": "rejected", "reason": "Alice value mismatch"}
