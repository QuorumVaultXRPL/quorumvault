"""Value conversion for policy decisions — injectable, not a hardcoded constant.

Every value-based decision in QuorumVault (which tier a payment routes to, the
fast-path ceiling, the risk engine's value threshold) rests on converting the
transaction's asset into a common RLUSD-equivalent. If that conversion is a
fixed constant, a real move in XRP's price silently pushes transactions into the
wrong band — e.g. a payment that is really over the fast-path ceiling gets
auto-co-signed because the stale rate makes it look smaller. That is a routing
*security* bug, not a cosmetic one.

So the rate is a :class:`RateProvider`, injected wherever value is judged:

* :class:`StaticRateProvider` — an explicit, clearly-labelled placeholder. Fine
  for Testnet; ``is_live`` is ``False`` so an audit can detect its use.
* :class:`CallableRateProvider` — wraps a live price function, with an optional
  staleness guard that refuses to answer with a too-old price rather than
  misrouting on it.

All amounts and rates here are :class:`~decimal.Decimal`, not ``float`` — see
:mod:`quorumvault.policy.money`. ``to_rlusd`` coerces defensively at the
boundary so a caller handing it a raw ``float`` or ``int`` (bypassing
``PaymentIntent``) still gets an exact Decimal result, never a binary-float
rounding artifact.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from decimal import Decimal
from typing import Callable, Optional, Tuple, Union

from .money import Numeric, to_decimal


class StaleRateError(Exception):
    """A live price was older than the allowed maximum age; refusing to route on it."""


class RateProvider(ABC):
    """Convert an asset amount to its RLUSD-equivalent for policy decisions."""

    @abstractmethod
    def to_rlusd(self, asset: str, amount: Numeric) -> Decimal: ...

    @property
    def is_live(self) -> bool:
        """False for placeholders; production value-routing should require True."""
        return False


class StaticRateProvider(RateProvider):
    """A fixed XRP->RLUSD rate. A placeholder for Testnet, not a price feed."""

    def __init__(self, xrp_to_rlusd: Numeric, source: str = "static-placeholder"):
        xrp_to_rlusd = to_decimal(xrp_to_rlusd)
        if xrp_to_rlusd <= 0:
            raise ValueError("xrp_to_rlusd must be positive")
        self.xrp_to_rlusd = xrp_to_rlusd
        self.source = source

    def to_rlusd(self, asset: str, amount: Numeric) -> Decimal:
        amount = to_decimal(amount)
        if asset == "RLUSD":
            return amount
        if asset == "XRP":
            return amount * self.xrp_to_rlusd
        return amount


class CallableRateProvider(RateProvider):
    """Wrap a live XRP price function for production value-routing.

    ``price_fn`` returns either the current XRP->RLUSD rate, or a
    ``(rate, as_of_epoch_seconds)`` tuple. If ``max_age_s`` is set and the
    reported price is older than that, :class:`StaleRateError` is raised instead
    of quietly routing on a stale number.
    """

    def __init__(
        self,
        price_fn: Callable[[], Union[float, Tuple[float, float]]],
        *,
        max_age_s: Optional[float] = None,
        clock: Callable[[], float] = time.time,
    ):
        self._price_fn = price_fn
        self._max_age_s = max_age_s
        self._clock = clock

    @property
    def is_live(self) -> bool:
        return True

    def _rate(self) -> Decimal:
        result = self._price_fn()
        if isinstance(result, tuple):
            rate, as_of = result
            if self._max_age_s is not None and (self._clock() - as_of) > self._max_age_s:
                raise StaleRateError(
                    f"XRP price is {self._clock() - as_of:.0f}s old, exceeding the "
                    f"{self._max_age_s:.0f}s max age; refusing to route on a stale rate."
                )
        else:
            rate = result
        rate = to_decimal(rate)
        if rate <= 0:
            raise StaleRateError("Live XRP price returned a non-positive rate.")
        return rate

    def to_rlusd(self, asset: str, amount: Numeric) -> Decimal:
        amount = to_decimal(amount)
        if asset == "RLUSD":
            return amount
        if asset == "XRP":
            return amount * self._rate()
        return amount


def default_rate_provider() -> RateProvider:
    """The Testnet default: a labelled static placeholder (0.55). NOT for real funds."""
    return StaticRateProvider(Decimal("0.55"), source="testnet-default-placeholder")
