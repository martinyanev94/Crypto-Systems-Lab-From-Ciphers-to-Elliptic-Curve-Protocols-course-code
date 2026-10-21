from .caesar import encrypt as caesar_encrypt
from .rot13 import rot13
from .vernam import decrypt as vernam_decrypt
from .vernam import encrypt as vernam_encrypt

MESSAGE = "MEET AT 9"
KEY = "KEY-12345"


def compare() -> str:
    caesar_ciphertext = caesar_encrypt(MESSAGE, 3)
    rot13_ciphertext = rot13(MESSAGE)
    vernam_ciphertext = vernam_encrypt(MESSAGE, KEY)
    lines = [
        f"Caesar: {caesar_ciphertext} -> {caesar_encrypt(caesar_ciphertext, -3)}",
        "Caesar attack: try every shift in the small key space",
        f"ROT13: {rot13_ciphertext} -> {rot13(rot13_ciphertext)}",
        "ROT13 attack: the fixed shift is already known",
        f"Vernam hex: {vernam_ciphertext.hex()} -> {vernam_decrypt(vernam_ciphertext, KEY)}",
        "Vernam attack: security depends on random, same-length, one-use keys",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    print(compare())
