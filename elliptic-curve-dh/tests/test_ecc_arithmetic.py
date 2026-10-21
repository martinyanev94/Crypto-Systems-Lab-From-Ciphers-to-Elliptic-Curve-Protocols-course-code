import pytest

from ecc_arithmetic import Curve, Point, ecdh_exchange, scalar_multiply


@pytest.fixture
def curve():
    return Curve(17, 2, 2, Point(5, 1), 19)


def test_known_doubles_and_public_points(curve):
    assert scalar_multiply(curve, 2, curve.generator) == Point(6, 3)
    assert scalar_multiply(curve, 3, curve.generator) == Point(10, 6)
    assert scalar_multiply(curve, 9, curve.generator) == Point(7, 6)


def test_ecdh_shared_points_match(curve):
    alice_public, bob_public, alice_shared, bob_shared = ecdh_exchange(curve, 3, 9)
    assert alice_public == Point(10, 6)
    assert bob_public == Point(7, 6)
    assert alice_shared == Point(13, 7)
    assert bob_shared == Point(13, 7)


def test_invalid_inputs_are_rejected(curve):
    with pytest.raises(ValueError):
        curve.validate_point(Point(0, 0))
    with pytest.raises(ValueError):
        scalar_multiply(curve, 0, curve.generator)
