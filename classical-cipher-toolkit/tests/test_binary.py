import pytest

from src.binary import (
    add_mod,
    bit_and,
    bit_or,
    bit_xor,
    bits_to_text,
    text_to_bits,
)


def test_text_bits_round_trip() -> None:
    bits = text_to_bits("Hi")
    assert bits == "0100100001101001"
    assert bits_to_text(bits) == "Hi"


def test_non_ascii_text_is_rejected() -> None:
    with pytest.raises(UnicodeEncodeError):
        text_to_bits("café")


def test_incomplete_bits_are_rejected() -> None:
    with pytest.raises(ValueError):
        bits_to_text("0101")


def test_boolean_helpers() -> None:
    assert bit_and(72, 105) == 64
    assert bit_or(72, 105) == 105
    assert bit_xor(72, 105) == 41


def test_byte_range_is_enforced() -> None:
    with pytest.raises(ValueError):
        bit_xor(256, 0)


def test_modular_addition() -> None:
    assert add_mod(72, 105, 256) == 177


def test_xor_identity() -> None:
    assert bit_xor(bit_xor(72, 32), 32) == 72


def test_modulus_must_be_positive() -> None:
    with pytest.raises(ValueError):
        add_mod(1, 2, 0)
