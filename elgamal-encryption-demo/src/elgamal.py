from dataclasses import dataclass
import secrets


@dataclass(frozen=True)
class PublicKey:
    p: int
    g: int
    value: int


@dataclass(frozen=True)
class PrivateKey:
    p: int
    exponent: int


@dataclass(frozen=True)
class KeyPair:
    public: PublicKey
    private: PrivateKey


@dataclass(frozen=True)
class Ciphertext:
    y1: int
    y2: int


def make_keypair(p: int = 200003, g: int = 7, private_exponent: int = 2367) -> KeyPair:
    if p <= 3 or not 1 <= private_exponent <= p - 2:
        raise ValueError("invalid teaching parameters")
    public_value = pow(g, private_exponent, p)
    return KeyPair(
        public=PublicKey(p=p, g=g, value=public_value),
        private=PrivateKey(p=p, exponent=private_exponent),
    )


def encrypt(public_key: PublicKey, message: int, *, ephemeral_k: int | None = None) -> Ciphertext:
    p, g, B = public_key.p, public_key.g, public_key.value
    if not 1 <= message <= p - 1:
        raise ValueError("message must be in the multiplicative group")
    k = ephemeral_k if ephemeral_k is not None else secrets.randbelow(p - 2) + 1
    if not 1 <= k <= p - 2:
        raise ValueError("ephemeral_k must be in [1, p-2]")
    y1 = pow(g, k, p)
    mask = pow(B, k, p)
    y2 = (message * mask) % p
    return Ciphertext(y1=y1, y2=y2)


def decrypt(private_key: PrivateKey, ciphertext: Ciphertext) -> int:
    p = private_key.p
    mask = pow(ciphertext.y1, private_key.exponent, p)
    return (ciphertext.y2 * pow(mask, -1, p)) % p


def message_ratio(first: Ciphertext, second: Ciphertext, p: int) -> int:
    """Return y2_1 / y2_2 modulo p; meaningful when k was reused."""
    return first.y2 * pow(second.y2, -1, p) % p
