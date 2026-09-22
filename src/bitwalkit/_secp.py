"""Minimal secp256k1 public-key arithmetic used by bitwalkit.

The implementation is intentionally limited to parsing, serializing, adding,
and multiplying public curve points. It is variable-time and must not be used
with private or otherwise secret scalars.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

__all__ = ["G", "GE"]

_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


@dataclass(frozen=True, slots=True)
class GE:
    """A secp256k1 curve point, or infinity when coordinates are absent."""

    x: int | None = None
    y: int | None = None

    ORDER: ClassVar[int] = _ORDER

    def __post_init__(self) -> None:
        if self.x is None or self.y is None:
            if self.x is not None or self.y is not None:
                raise ValueError("both point coordinates must be present")
            return
        if not (0 <= self.x < _FIELD and 0 <= self.y < _FIELD):
            raise ValueError("point coordinate out of range")
        if (self.y * self.y - self.x * self.x * self.x - 7) % _FIELD:
            raise ValueError("point is not on secp256k1")

    @property
    def infinity(self) -> bool:
        """Whether this is the point at infinity."""
        return self.x is None

    def __add__(self, other: object) -> GE:
        """Add two curve points."""
        if not isinstance(other, GE):
            return NotImplemented
        if self.infinity:
            return other
        if other.infinity:
            return self

        x1, y1, x2, y2 = self.x, self.y, other.x, other.y
        assert x1 is not None and y1 is not None
        assert x2 is not None and y2 is not None

        if x1 == x2:
            if y1 != y2 or y1 == 0:
                return GE()
            numerator = 3 * x1 * x1
            denominator = 2 * y1
        else:
            numerator = y2 - y1
            denominator = x2 - x1

        slope = numerator * pow(denominator % _FIELD, -1, _FIELD) % _FIELD
        x3 = (slope * slope - x1 - x2) % _FIELD
        y3 = (slope * (x1 - x3) - y1) % _FIELD
        return GE(x3, y3)

    def __rmul__(self, scalar: object) -> GE:
        """Multiply this point by an integer using double-and-add."""
        if not isinstance(scalar, int):
            return NotImplemented

        scalar %= self.ORDER
        if not scalar or self.infinity:
            return GE()
        assert self.x is not None and self.y is not None

        def add(left, right):
            if left is None:
                return right
            if right is None:
                return left
            x1, y1, z1 = left
            x2, y2, z2 = right
            z1_squared = z1 * z1 % _FIELD
            z2_squared = z2 * z2 % _FIELD
            u1 = x1 * z2_squared % _FIELD
            u2 = x2 * z1_squared % _FIELD
            s1 = y1 * z2 * z2_squared % _FIELD
            s2 = y2 * z1 * z1_squared % _FIELD
            if u1 == u2:
                if s1 != s2:
                    return None
                return double(left)
            h = (u2 - u1) % _FIELD
            r = (s2 - s1) % _FIELD
            h_squared = h * h % _FIELD
            h_cubed = h * h_squared % _FIELD
            u1_h_squared = u1 * h_squared % _FIELD
            x3 = (r * r - h_cubed - 2 * u1_h_squared) % _FIELD
            y3 = (r * (u1_h_squared - x3) - s1 * h_cubed) % _FIELD
            return x3, y3, h * z1 * z2 % _FIELD

        def double(point):
            x, y, z = point
            if not y:
                return None
            y_squared = y * y % _FIELD
            s = 4 * x * y_squared % _FIELD
            m = 3 * x * x % _FIELD
            x3 = (m * m - 2 * s) % _FIELD
            y3 = (m * (s - x3) - 8 * y_squared * y_squared) % _FIELD
            return x3, y3, 2 * y * z % _FIELD

        result = None
        addend = self.x, self.y, 1
        while scalar:
            if scalar & 1:
                result = add(result, addend)
            addend = double(addend)
            scalar >>= 1
        if result is None:
            return GE()
        x, y, z = result
        inverse = pow(z, -1, _FIELD)
        inverse_squared = inverse * inverse % _FIELD
        return GE(x * inverse_squared % _FIELD, y * inverse_squared * inverse % _FIELD)

    @classmethod
    def lift_x(cls, x: int) -> GE:
        """Lift an x-coordinate to the curve point whose y-coordinate is even."""
        if not isinstance(x, int) or not 0 <= x < _FIELD:
            raise ValueError("x-coordinate out of range")
        y_squared = (pow(x, 3, _FIELD) + 7) % _FIELD
        y = pow(y_squared, (_FIELD + 1) // 4, _FIELD)
        if y * y % _FIELD != y_squared:
            raise ValueError("x-coordinate is not on secp256k1")
        if y & 1:
            y = _FIELD - y
        return cls(x, y)

    @classmethod
    def from_bytes_compressed(cls, encoded: bytes) -> GE:
        """Parse a 33-byte compressed public key."""
        if len(encoded) != 33 or encoded[0] not in (2, 3):
            raise ValueError("invalid compressed public key")
        point = cls.lift_x(int.from_bytes(encoded[1:], "big"))
        assert point.x is not None and point.y is not None
        if (point.y & 1) != (encoded[0] & 1):
            return cls(point.x, _FIELD - point.y)
        return point

    def to_bytes_compressed(self) -> bytes:
        """Serialize a finite point as a 33-byte compressed public key."""
        if self.infinity:
            raise ValueError("cannot serialize the point at infinity")
        assert self.x is not None and self.y is not None
        return bytes([2 | (self.y & 1)]) + self.x.to_bytes(32, "big")

    def to_bytes_xonly(self) -> bytes:
        """Serialize the x-coordinate of a finite point."""
        if self.infinity:
            raise ValueError("cannot serialize the point at infinity")
        assert self.x is not None
        return self.x.to_bytes(32, "big")


G = GE(_GX, _GY)
