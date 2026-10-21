import pytest

from feistel import encrypt_block, round_function, subkeys


def test_key_schedule_rotates_master_key_by_round():
    assert subkeys(0xA6) == [0x4D, 0x9A, 0x35, 0x6A]


def test_running_example_has_expected_trace_and_preoutput():
    ciphertext, trace = encrypt_block(0x1234, 0xA6)
    assert trace == [
        (0, 0x12, 0x34),
        (1, 0x34, 0xA7),
        (2, 0xA7, 0xB6),
        (3, 0xB6, 0x12),
        (4, 0x12, 0x30),
    ]
    assert ciphertext == 0x3012


def test_round_function_returns_an_eight_bit_value():
    assert round_function(0x34, 0x4D) == 0xB5


@pytest.mark.parametrize("value", [-1, 0x100])
def test_round_function_rejects_wrong_width(value):
    with pytest.raises(ValueError):
        round_function(value, 0x4D)
