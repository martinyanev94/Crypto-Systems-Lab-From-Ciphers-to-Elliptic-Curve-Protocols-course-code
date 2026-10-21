from classical_cipher.rot13 import rot13


def test_rot13_running_example():
    assert rot13("MEET AT 9") == "ZRRG NG 9"
    assert rot13(rot13("MEET AT 9")) == "MEET AT 9"
