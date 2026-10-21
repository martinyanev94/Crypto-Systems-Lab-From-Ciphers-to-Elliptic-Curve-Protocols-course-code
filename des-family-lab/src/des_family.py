"""Toy DES-family constructions for teaching only."""

BLOCK_MASK = 0xFF
HALF_MASK = 0x0F
KEY_MASK = 0x0F


def rotate_left_nibble(value: int) -> int:
    value &= HALF_MASK
    return ((value << 1) | (value >> 3)) & HALF_MASK


def round_function(right: int, subkey: int) -> int:
    return rotate_left_nibble(right) ^ (subkey & HALF_MASK)


def _validate_block(block: int) -> None:
    if not 0 <= block <= BLOCK_MASK:
        raise ValueError("block must fit in 8 bits")


def _validate_key(key: int) -> None:
    if not 0 <= key <= KEY_MASK:
        raise ValueError("key must fit in 4 bits")


def encrypt_block(block: int, key: int) -> int:
    _validate_block(block)
    _validate_key(key)
    left, right = (block >> 4) & HALF_MASK, block & HALF_MASK
    for offset in range(2):
        subkey = (key + offset) & KEY_MASK
        left, right = right, left ^ round_function(right, subkey)
    return (left << 4) | right


def decrypt_block(block: int, key: int) -> int:
    _validate_block(block)
    _validate_key(key)
    left, right = (block >> 4) & HALF_MASK, block & HALF_MASK
    for offset in reversed(range(2)):
        subkey = (key + offset) & KEY_MASK
        left, right = right ^ round_function(left, subkey), left
    return (left << 4) | right


def triple_des_encrypt(block: int, k1: int, k2: int, k3: int) -> int:
    return encrypt_block(decrypt_block(encrypt_block(block, k1), k2), k3)


def triple_des_decrypt(block: int, k1: int, k2: int, k3: int) -> int:
    return decrypt_block(encrypt_block(decrypt_block(block, k3), k2), k1)


def desx_encrypt(block: int, key: int, input_whitening: int, output_whitening: int) -> int:
    return encrypt_block(block ^ input_whitening, key) ^ output_whitening


def desx_decrypt(block: int, key: int, input_whitening: int, output_whitening: int) -> int:
    return decrypt_block(block ^ output_whitening, key) ^ input_whitening


def find_keys(plaintext: int, ciphertext: int) -> tuple[list[int], int]:
    matches: list[int] = []
    attempts = 0
    for key in range(KEY_MASK + 1):
        attempts += 1
        if encrypt_block(plaintext, key) == ciphertext:
            matches.append(key)
    return matches, attempts


def report() -> dict[str, object]:
    plaintext = 0x3C
    triple = triple_des_encrypt(plaintext, 0x0A, 0x03, 0x05)
    desx = desx_encrypt(plaintext, 0x0A, 0x12, 0x34)
    matches, attempts = find_keys(plaintext, 0x07)
    return {
        "plaintext": plaintext,
        "triple_des_ciphertext": triple,
        "triple_des_round_trip": triple_des_decrypt(triple, 0x0A, 0x03, 0x05),
        "desx_ciphertext": desx,
        "desx_round_trip": desx_decrypt(desx, 0x0A, 0x12, 0x34),
        "single_des_matches": matches,
        "single_des_attempts": attempts,
    }


if __name__ == "__main__":
    for name, value in report().items():
        print(f"{name}: {value:#04x}" if isinstance(value, int) else f"{name}: {value}")
