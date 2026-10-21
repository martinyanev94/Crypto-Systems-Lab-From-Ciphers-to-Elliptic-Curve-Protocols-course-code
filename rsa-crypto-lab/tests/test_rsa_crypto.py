import pytest

from cli import main
from rsa_crypto import decrypt, encrypt, generate_keypair, mod_inverse


def test_reference_round_trip() -> None:
    public_key, private_key = generate_keypair(101, 67, 2407)
    assert encrypt(88, public_key) == 6621
    assert decrypt(6621, private_key) == 88


def test_source_and_reduced_exponents_match_for_reference_message() -> None:
    assert pow(88, 9007, 6767) == pow(88, 2407, 6767) == 6621


def test_mod_inverse() -> None:
    assert mod_inverse(2407, 6600) == 3943


def test_cli_encrypt_invocation(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["encrypt", "88"]) == 0
    assert capsys.readouterr().out == "encrypt=6621\n"


def test_message_must_fit_modulus() -> None:
    with pytest.raises(ValueError):
        encrypt(6767, (6767, 2407))


def test_bad_prime_inputs_are_rejected() -> None:
    with pytest.raises(ValueError):
        generate_keypair(100, 67, 7)


def test_non_coprime_exponent_is_rejected() -> None:
    with pytest.raises(ValueError):
        generate_keypair(101, 67, 6)
