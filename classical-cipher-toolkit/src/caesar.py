from __future__ import annotations


def transform(text: str, shift: int) -> str:
    result: list[str] = []
    for char in text:
        if char.isupper():
            base = ord("A")
        elif char.islower():
            base = ord("a")
        else:
            result.append(char)
            continue
        position = (ord(char) - base + shift) % 26
        result.append(chr(base + position))
    return "".join(result)


def encrypt(text: str, key: int) -> str:
    return transform(text, key)


def decrypt(text: str, key: int) -> str:
    return transform(text, -key)


def brute_force(ciphertext: str) -> list[tuple[int, str]]:
    return [(key, decrypt(ciphertext, key)) for key in range(26)]
