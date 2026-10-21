from src.aes_primitives import (
    SBOX,
    add_round_key,
    bytes_to_state,
    four_transform_pipeline,
    gf_mul,
    mix_columns,
    shift_rows,
    state_to_bytes,
    sub_bytes,
)


def test_state_round_trip_preserves_column_major_bytes() -> None:
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert state_to_bytes(bytes_to_state(block)) == block


def test_known_primitives() -> None:
    assert SBOX[0x53] == 0xED
    assert gf_mul(0x57, 0x13) == 0xFE


def test_intermediate_states() -> None:
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    round_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    state = bytes_to_state(block)
    state = sub_bytes(state)
    assert state_to_bytes(state).hex() == "63cab7040953d051cd60e0e7ba70e18c"
    state = shift_rows(state)
    assert state_to_bytes(state).hex() == "63cab70453d05109e0e7cd608cba70e1"
    state = mix_columns(state)
    assert state_to_bytes(state).hex() == "5f72641557f5bc92f7be3b291db9f91a"
    assert state_to_bytes(add_round_key(state, round_key)).hex() == "5f73661653f0ba95ffb7312211b4f715"


def test_four_transform_pipeline() -> None:
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    round_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    assert four_transform_pipeline(block, round_key) == bytes.fromhex("5f73661653f0ba95ffb7312211b4f715")
