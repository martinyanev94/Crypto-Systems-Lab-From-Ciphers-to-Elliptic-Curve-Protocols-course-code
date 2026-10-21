from src.caesar import brute_force, decrypt, encrypt


def test_encrypt_example() -> None:
    assert encrypt("MEET AT NOON", 3) == "PHHW DW QRRQ"


def test_decrypt_reverses_encrypt() -> None:
    message = "Meet at noon!"
    assert decrypt(encrypt(message, 3), 3) == message


def test_wraps_and_preserves_non_letters() -> None:
    assert encrypt("Zz-9", 3) == "Cc-9"


def test_brute_force_checks_all_keys() -> None:
    candidates = brute_force("PHHW DW QRRQ")
    assert len(candidates) == 26
    assert candidates[3] == (3, "MEET AT NOON")
