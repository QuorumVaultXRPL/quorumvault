"""Shared money-precision helper: never let a bare float carry a currency amount.

XRPL's own wire format represents Amounts as strings precisely so client code
doesn't have to round-trip through a binary float and risk losing precision at
the smallest units. Everywhere QuorumVault handles an amount, a rate, or a
threshold, it should be a :class:`~decimal.Decimal`, not a ``float`` -- floats
are fine for read-only timestamps, but a threshold comparison, an exchange
rate, or a transferred amount is exactly the kind of value binary floating
point silently rounds.

:func:`to_decimal` accepts whatever a caller passes (int, str, Decimal, or a
literal float already in code) and normalizes it to an exact Decimal. Floats
are converted via ``str()`` rather than ``Decimal(float)`` directly, because
``Decimal(0.1)`` reproduces the float's true (ugly, inexact) binary value,
while ``Decimal(str(0.1))`` gives the clean decimal a human actually wrote.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Union

Numeric = Union[int, float, str, Decimal]


def to_decimal(value: Numeric) -> Decimal:
    """Normalize any numeric input to an exact Decimal."""
    if isinstance(value, Decimal):
        return value
    if isinstance(value, float):
        return Decimal(str(value))
    return Decimal(value)
