from __future__ import annotations


def text_to_bits(text: str) -> str:
    """Encode ASCII text as one continuous string of eight-bit bytes."""
    return "".join(f"{byte:08b}" for byte in text.encode("ascii"))


def bits_to_text(bits: str) -> str:
    """Decode a complete sequence of ASCII bytes from binary text."""
    if len(bits) % 8 != 0 or any(bit not in "01" for bit in bits):
        raise ValueError("bits must contain complete binary bytes")
    values = (
        int(bits[index:index + 8], 2)
        for index in range(0, len(bits), 8)
    )
    return bytes(values).decode("ascii")


def _check_byte(value: int) -> None:
    if not 0 <= value <= 255:
        raise ValueError("value must fit in one byte")


def bit_and(left: int, right: int) -> int:
    _check_byte(left)
    _check_byte(right)
    return left & right


def bit_or(left: int, right: int) -> int:
    _check_byte(left)
    _check_byte(right)
    return left | right


def bit_xor(left: int, right: int) -> int:
    _check_byte(left)
    _check_byte(right)
    return left ^ right


def mod(value: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    return value % modulus


def add_mod(left: int, right: int, modulus: int) -> int:
    return mod(left + right, modulus)
