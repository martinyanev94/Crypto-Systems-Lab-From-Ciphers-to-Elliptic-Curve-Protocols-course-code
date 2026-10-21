from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Point:
    x: int | None
    y: int | None

    @property
    def is_infinity(self) -> bool:
        return self.x is None and self.y is None


class Curve:
    def __init__(self, p: int, a: int, b: int, generator: Point, order: int):
        if p <= 2:
            raise ValueError("p must be an odd prime-sized teaching modulus")
        if (4 * a**3 + 27 * b**2) % p == 0:
            raise ValueError("singular curve")
        self.p = p
        self.a = a % p
        self.b = b % p
        self.generator = generator
        self.infinity = Point(None, None)
        self.order = order
        self.validate_point(generator)

    def validate_point(self, point: Point) -> None:
        if point.is_infinity:
            return
        if point.x is None or point.y is None:
            raise ValueError("point must contain both coordinates or be infinity")
        if not (0 <= point.x < self.p and 0 <= point.y < self.p):
            raise ValueError("point coordinates must be reduced modulo p")
        if (point.y * point.y - (point.x**3 + self.a * point.x + self.b)) % self.p:
            raise ValueError("point is not on the curve")

    def validate_scalar(self, scalar: int) -> None:
        if not isinstance(scalar, int) or not 1 <= scalar < self.order:
            raise ValueError("scalar must be an integer in [1, order)")

    def add(self, left: Point, right: Point) -> Point:
        self.validate_point(left)
        self.validate_point(right)
        if left.is_infinity:
            return right
        if right.is_infinity:
            return left
        if left.x == right.x and (left.y + right.y) % self.p == 0:
            return self.infinity
        if left == right:
            denominator = (2 * left.y) % self.p
            if denominator == 0:
                return self.infinity
            slope = ((3 * left.x * left.x + self.a) * pow(denominator, -1, self.p)) % self.p
        else:
            denominator = (right.x - left.x) % self.p
            slope = ((right.y - left.y) * pow(denominator, -1, self.p)) % self.p
        x = (slope * slope - left.x - right.x) % self.p
        y = (slope * (left.x - x) - left.y) % self.p
        return Point(x, y)


def scalar_multiply(curve: Curve, scalar: int, point: Point) -> Point:
    curve.validate_scalar(scalar)
    curve.validate_point(point)
    result = curve.infinity
    current = point
    remaining = scalar
    while remaining:
        if remaining & 1:
            result = curve.add(result, current)
        current = curve.add(current, current)
        remaining >>= 1
    return result


def ecdh_exchange(curve: Curve, alpha: int, beta: int) -> tuple[Point, Point, Point, Point]:
    curve.validate_scalar(alpha)
    curve.validate_scalar(beta)
    alice_public = scalar_multiply(curve, alpha, curve.generator)
    bob_public = scalar_multiply(curve, beta, curve.generator)
    alice_shared = scalar_multiply(curve, alpha, bob_public)
    bob_shared = scalar_multiply(curve, beta, alice_public)
    return alice_public, bob_public, alice_shared, bob_shared
