from elgamal import decrypt, encrypt, make_keypair, message_ratio


def test_round_trip_with_injected_ephemeral_values():
    keypair = make_keypair()
    first = encrypt(keypair.public, 88, ephemeral_k=23)
    second = encrypt(keypair.public, 91, ephemeral_k=41)

    assert decrypt(keypair.private, first) == 88
    assert decrypt(keypair.private, second) == 91
    assert first.y1 != second.y1


def test_reused_ephemeral_value_reveals_message_ratio():
    keypair = make_keypair()
    first = encrypt(keypair.public, 88, ephemeral_k=23)
    second = encrypt(keypair.public, 91, ephemeral_k=23)

    assert first.y1 == second.y1
    observed = message_ratio(first, second, keypair.public.p)
    expected = 88 * pow(91, -1, keypair.public.p) % keypair.public.p
    assert observed == expected


def test_invalid_message_is_rejected():
    keypair = make_keypair()
    for invalid in (0, keypair.public.p):
        try:
            encrypt(keypair.public, invalid, ephemeral_k=23)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid message was accepted")
