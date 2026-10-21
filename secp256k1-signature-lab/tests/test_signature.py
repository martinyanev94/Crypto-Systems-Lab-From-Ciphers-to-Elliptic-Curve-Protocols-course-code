from src.secp256k1_signature import (
    GENERATOR,
    compress_public_key,
    derive_public_key,
    make_artifact,
    serialize_artifact,
    sign,
    verify_artifact,
)


def test_scalar_one_derives_generator():
    assert derive_public_key(1) == GENERATOR
    assert len(compress_public_key(GENERATOR)) == 33


def test_artifact_round_trip_and_tamper_rejection():
    message = b"pay 10"
    artifact = make_artifact(message, 1)
    assert verify_artifact(message, artifact)
    assert not verify_artifact(b"pay 11", artifact)


def test_deterministic_signature_and_canonical_bytes():
    message = b"pay 10"
    first = make_artifact(message, 1)
    second = make_artifact(message, 1)
    assert first == second
    r, s = sign(message, 1)
    public_key = compress_public_key(derive_public_key(1))
    assert serialize_artifact(message, public_key, r, s) == first
