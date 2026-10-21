from src.hash_service import digest_hex, to_bytes


def test_text_uses_utf8_bytes() -> None:
    assert to_bytes("café") == "café".encode("utf-8")


def test_digests_have_fixed_hex_length_for_different_inputs() -> None:
    short = digest_hex(b"OK")
    long = digest_hex(b"The deployment passed with notes")

    assert len(short) == 64
    assert len(long) == 64
    assert short != long


def test_one_byte_change_changes_digest() -> None:
    original = digest_hex(b"deployment passed")
    changed = digest_hex(b"deployment passet")

    assert original != changed


def test_same_bytes_are_stable() -> None:
    assert digest_hex(b"deployment passed") == digest_hex("deployment passed")
