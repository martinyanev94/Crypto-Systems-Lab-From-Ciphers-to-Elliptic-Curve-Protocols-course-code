from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

@dataclass(frozen=True)
class Point:
    x: int
    y: int

INFINITY = None
GENERATOR = Point(GX, GY)


def inverse(value: int, modulus: int) -> int:
    return pow(value % modulus, -1, modulus)


def is_on_curve(point: Point | None) -> bool:
    return point is None or (0 <= point.x < P and 0 <= point.y < P and point.y * point.y % P == (point.x ** 3 + 7) % P)


def point_add(left: Point | None, right: Point | None) -> Point | None:
    if left is None:
        return right
    if right is None:
        return left
    if left.x == right.x and (left.y + right.y) % P == 0:
        return INFINITY
    if left == right:
        slope = (3 * left.x * left.x) * inverse(2 * left.y, P) % P
    else:
        slope = (right.y - left.y) * inverse(right.x - left.x, P) % P
    x = (slope * slope - left.x - right.x) % P
    return Point(x, (slope * (left.x - x) - left.y) % P)


def scalar_multiply(scalar: int, point: Point | None = GENERATOR) -> Point | None:
    if scalar < 0:
        raise ValueError("scalar must be non-negative")
    result = INFINITY
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def derive_public_key(private_key: int) -> Point:
    if not 1 <= private_key < N:
        raise ValueError("private key out of range")
    result = scalar_multiply(private_key)
    assert result is not None
    return result


def compress_public_key(point: Point) -> bytes:
    if not is_on_curve(point):
        raise ValueError("public point is not on secp256k1")
    prefix = 2 if point.y % 2 == 0 else 3
    return bytes([prefix]) + point.x.to_bytes(32, "big")


def decompress_public_key(data: bytes) -> Point:
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError("invalid compressed public key")
    x = int.from_bytes(data[1:], "big")
    y = pow((x ** 3 + 7) % P, (P + 1) // 4, P)
    if y % 2 != data[0] % 2:
        y = P - y
    point = Point(x, y)
    if not is_on_curve(point):
        raise ValueError("public point is not on secp256k1")
    return point


def deterministic_nonce(private_key: int, digest: bytes) -> int:
    key = private_key.to_bytes(32, "big")
    k = b"\x00" * 32
    v = b"\x01" * 32
    k = hmac.new(k, v + b"\x00" + key + digest, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + key + digest, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(message: bytes, private_key: int) -> tuple[int, int]:
    if not 1 <= private_key < N:
        raise ValueError("private key out of range")
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    k = deterministic_nonce(private_key, hashlib.sha256(message).digest())
    r_point = scalar_multiply(k)
    assert r_point is not None
    r = r_point.x % N
    s = inverse(k, N) * (z + r * private_key) % N
    if r == 0 or s == 0:
        raise ValueError("invalid nonce produced zero signature value")
    if s > N // 2:
        s = N - s
    return r, s


def canonical_payload(message: bytes, public_key: bytes) -> bytes:
    body = {"message_hash": hashlib.sha256(message).hexdigest(), "public_key": public_key.hex()}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def serialize_artifact(message: bytes, public_key: bytes, r: int, s: int) -> bytes:
    body = json.loads(canonical_payload(message, public_key))
    body.update({"r": f"{r:064x}", "s": f"{s:064x}"})
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def verify_artifact(message: bytes, artifact: bytes) -> bool:
    try:
        body = json.loads(artifact)
        public_key = decompress_public_key(bytes.fromhex(body["public_key"]))
        r, s = int(body["r"], 16), int(body["s"], 16)
        if not (1 <= r < N and 1 <= s < N):
            return False
        expected = hashlib.sha256(message).hexdigest()
        if body["message_hash"] != expected:
            return False
        z = int(expected, 16) % N
        w = inverse(s, N)
        point = point_add(scalar_multiply(z * w % N), scalar_multiply(r * w % N, public_key))
        return point is not None and point.x % N == r
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        return False


def make_artifact(message: bytes, private_key: int) -> bytes:
    public_key = compress_public_key(derive_public_key(private_key))
    r, s = sign(message, private_key)
    return serialize_artifact(message, public_key, r, s)
