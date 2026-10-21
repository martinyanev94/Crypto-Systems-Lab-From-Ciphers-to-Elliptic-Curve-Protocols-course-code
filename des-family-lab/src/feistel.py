from __future__ import annotations

from typing import Iterable

BLOCK_MASK = 0xFFFF
BYTE_MASK = 0xFF
S_BOX = [6, 4, 12, 5, 0, 7, 2, 14, 1, 15, 3, 13, 8, 10, 9, 11]
EXPANSION = [7, 7, 6, 6, 5, 5, 4, 4, 3, 3, 2, 2, 1, 1, 0, 0]
PBOX = [1, 5, 2, 0, 3, 7, 4, 6]


def select_bits(value: int, positions: Iterable[int]) -> int:
    result = 0
    for position in positions:
        result = (result << 1) | ((value >> position) & 1)
    return result


def rotate_left(value: int, amount: int, width: int = 8) -> int:
    if not 0 <= value < (1 << width):
        raise ValueError(f"value must fit in {width} bits")
    amount %= width
    mask = (1 << width) - 1
    return ((value << amount) | (value >> (width - amount))) & mask


def subkeys(master_key: int, rounds: int = 4) -> list[int]:
    if not 0 <= master_key <= BYTE_MASK:
        raise ValueError("master_key must be an 8-bit value")
    if rounds < 1:
        raise ValueError("rounds must be positive")
    return [rotate_left(master_key, round_no) for round_no in range(1, rounds + 1)]


def repeat_byte(value: int) -> int:
    if not 0 <= value <= BYTE_MASK:
        raise ValueError("value must be an 8-bit value")
    return (value << 8) | value


def round_function(right: int, subkey: int) -> int:
    if not 0 <= right <= BYTE_MASK or not 0 <= subkey <= BYTE_MASK:
        raise ValueError("right half and subkey must be 8-bit values")
    expanded = select_bits(right, EXPANSION)
    mixed = expanded ^ repeat_byte(subkey)
    substituted = 0
    for index in range(4):
        nibble = (mixed >> (4 * index)) & 0xF
        substituted |= S_BOX[nibble] << (4 * index)
    return select_bits(substituted, PBOX)


def feistel_round(left: int, right: int, subkey: int) -> tuple[int, int]:
    if not 0 <= left <= BYTE_MASK or not 0 <= right <= BYTE_MASK:
        raise ValueError("left and right halves must be 8-bit values")
    return right, left ^ round_function(right, subkey)


def encrypt_block(
    block: int, master_key: int, rounds: int = 4
) -> tuple[int, list[tuple[int, int, int]]]:
    if not 0 <= block <= BLOCK_MASK:
        raise ValueError("block must be a 16-bit value")
    left, right = block >> 8, block & BYTE_MASK
    trace = [(0, left, right)]
    for round_no, key in enumerate(subkeys(master_key, rounds), 1):
        left, right = feistel_round(left, right, key)
        trace.append((round_no, left, right))
    return (right << 8) | left, trace


def format_trace(trace: list[tuple[int, int, int]]) -> str:
    lines = ["round  left  right"]
    lines += [f"{number:>5}  0x{left:02X}  0x{right:02X}" for number, left, right in trace]
    return "\n".join(lines)


if __name__ == "__main__":
    ciphertext, trace = encrypt_block(0x1234, 0xA6)
    print(format_trace(trace))
    print(f"preoutput: 0x{ciphertext:04X}")
