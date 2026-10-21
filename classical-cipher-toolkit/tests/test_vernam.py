import pytest

from classical_cipher.vernam import decrypt, encrypt


def test_vernam_round_trip():
    ciphertext = encrypt("MEET AT 9", "KEY-12345")
    assert decrypt(ciphertext, "KEY-12345") == "MEET AT 9"


def test_vernam_rejects_wrong_key_length():
    with pytest.raises(ValueError):
        encrypt("MEET AT 9", "SHORT")
