from __future__ import annotations


def gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in AES's GF(2^8) field."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return result


def gf_pow(value: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = gf_mul(result, value)
        value = gf_mul(value, value)
        exponent >>= 1
    return result


def _rotl8(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (8 - amount))) & 0xFF


def _sbox_value(value: int) -> int:
    inverse = 0 if value == 0 else gf_pow(value, 254)
    return (inverse ^ _rotl8(inverse, 1) ^ _rotl8(inverse, 2)
            ^ _rotl8(inverse, 3) ^ _rotl8(inverse, 4) ^ 0x63)


SBOX = tuple(_sbox_value(value) for value in range(256))


def bytes_to_state(block: bytes) -> list[list[int]]:
    if len(block) != 16:
        raise ValueError("AES blocks must contain 16 bytes")
    return [[block[4 * column + row] for column in range(4)]
            for row in range(4)]


def state_to_bytes(state: list[list[int]]) -> bytes:
    if len(state) != 4 or any(len(row) != 4 for row in state):
        raise ValueError("AES states must be four by four")
    return bytes(state[row][column]
                 for column in range(4)
                 for row in range(4))


def sub_bytes(state: list[list[int]]) -> list[list[int]]:
    return [[SBOX[value] for value in row] for row in state]


def shift_rows(state: list[list[int]]) -> list[list[int]]:
    return [row[offset:] + row[:offset]
            for offset, row in enumerate(state)]


def mix_columns(state: list[list[int]]) -> list[list[int]]:
    result = [[0] * 4 for _ in range(4)]
    for column in range(4):
        a0, a1, a2, a3 = (state[row][column] for row in range(4))
        result[0][column] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3
        result[1][column] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3
        result[2][column] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3)
        result[3][column] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2)
    return result


def add_round_key(state: list[list[int]], round_key: bytes) -> list[list[int]]:
    key_state = bytes_to_state(round_key)
    return [[state[row][column] ^ key_state[row][column]
             for column in range(4)]
            for row in range(4)]


def four_transform_pipeline(block: bytes, round_key: bytes) -> bytes:
    state = bytes_to_state(block)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state)
    return state_to_bytes(add_round_key(state, round_key))
