from src.des_family import (
    decrypt_block,
    desx_decrypt,
    desx_encrypt,
    encrypt_block,
    find_keys,
    triple_des_decrypt,
    triple_des_encrypt,
)


def test_toy_des_round_trip() -> None:
    assert encrypt_block(0x3C, 0x0A) == 0x07
    assert decrypt_block(0x07, 0x0A) == 0x3C


def test_triple_des_composition() -> None:
    ciphertext = triple_des_encrypt(0x3C, 0x0A, 0x03, 0x05)
    assert ciphertext == 0x69
    assert triple_des_decrypt(ciphertext, 0x0A, 0x03, 0x05) == 0x3C


def test_desx_composition() -> None:
    ciphertext = desx_encrypt(0x3C, 0x0A, 0x12, 0x34)
    assert ciphertext == 0x6B
    assert desx_decrypt(ciphertext, 0x0A, 0x12, 0x34) == 0x3C


def test_small_key_search() -> None:
    matches, attempts = find_keys(0x3C, 0x07)
    assert matches == [0x0A]
    assert attempts == 11
