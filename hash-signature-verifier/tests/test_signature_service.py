from signature_service import PRIVATE, PUBLIC, sign, verify


def test_valid_signature_is_accepted() -> None:
    message = "pay invoice 42"
    signature = sign(message, PRIVATE)

    assert verify(message, signature, PUBLIC) is True


def test_altered_message_is_rejected() -> None:
    signature = sign("pay invoice 42", PRIVATE)

    assert verify("pay invoice 43", signature, PUBLIC) is False


def test_altered_signature_is_rejected() -> None:
    message = "pay invoice 42"
    signature = sign(message, PRIVATE)

    assert verify(message, signature + 1, PUBLIC) is False


def test_out_of_range_signature_is_rejected() -> None:
    assert verify("pay invoice 42", PUBLIC.n, PUBLIC) is False
