from __future__ import annotations

from math import gcd
from typing import Tuple

PublicKey = Tuple[int, int]
PrivateKey = Tuple[int, int]


def _check_message(value: int, n: int) -> None:
    if not isinstance(value, int):
        raise TypeError("RSA values must be integers")
    if not 0 <= value < n:
        raise ValueError(f"message must satisfy 0 <= message < {n}")


def is_prime(value: int) -> bool:
    if value < 2:
        return False
    if value % 2 == 0:
        return value == 2
    divisor = 3
    while divisor * divisor <= value:
        if value % divisor == 0:
            return False
        divisor += 2
    return True


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    common, x1, y1 = extended_gcd(b, a % b)
    return common, y1, x1 - (a // b) * y1


def mod_inverse(value: int, modulus: int) -> int:
    common, coefficient, _ = extended_gcd(value, modulus)
    if common != 1:
        raise ValueError("value has no modular inverse")
    return coefficient % modulus


def generate_keypair(p: int, q: int, e: int) -> tuple[PublicKey, PrivateKey]:
    if not is_prime(p) or not is_prime(q) or p == q:
        raise ValueError("p and q must be distinct primes")
    n = p * q
    phi = (p - 1) * (q - 1)
    if not 1 < e < phi or gcd(e, phi) != 1:
        raise ValueError("e must be between 1 and phi(n) and coprime to phi(n)")
    d = mod_inverse(e, phi)
    return (n, e), (n, d)


def encrypt(message: int, public_key: PublicKey) -> int:
    n, e = public_key
    _check_message(message, n)
    return pow(message, e, n)


def decrypt(ciphertext: int, private_key: PrivateKey) -> int:
    n, d = private_key
    _check_message(ciphertext, n)
    return pow(ciphertext, d, n)
