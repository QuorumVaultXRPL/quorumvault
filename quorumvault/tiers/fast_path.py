"""Velocity-Bounded Fast Path - mid-value payments, lighter audit, on-ledger expiry.

"Lighter" relaxes *policy scrutiny* (within a value ceiling and a velocity limit
the auditor co-signs automatically instead of running the full review/override),
NOT the cryptography: funds still leave the multisig treasury under a real 2-of-2
signature. Expiry is enforced on-ledger via LastLedgerSequence so a co-signed but
un-broadcast approval cannot be replayed and land later at a stale price.

The value ceiling is a :class:`~decimal.Decimal` — see
:mod:`quorumvault.policy.money` — for the same reason the router's ceilings are:
a threshold that decides whether a transaction gets the lighter path must not be
settled by a binary-float rounding artifact.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from decimal import Decimal
from typing import List, Optional

from xrpl.models.transactions import Payment

from ..policy.intent import PaymentIntent
from ..policy.money import Numeric, to_decimal
from ..policy.pricing import RateProvider, default_rate_provider


@dataclass
class FastPathDecision:
    approved: bool
    escalate_to_quorum: bool
    reasons: List[str] = field(default_factory=list)
    last_ledger_sequence: Optional[int] = None


class VelocityBoundedFastPath:
    def __init__(
        self,
        mid_value_cap_rlusd: Numeric,
        expiry_ledgers: int = 4,
        frequency_window_s: float = 60.0,
        frequency_limit: int = 5,
        rate_provider: RateProvider = None,
    ):
        if expiry_ledgers <= 0:
            raise ValueError("expiry_ledgers must be positive")
        self.mid_value_cap_rlusd = to_decimal(mid_value_cap_rlusd)
        self.expiry_ledgers = expiry_ledgers
        self.frequency_window_s = frequency_window_s
        self.frequency_limit = frequency_limit
        self.rate_provider = rate_provider or default_rate_provider()
        self._recent: deque = deque()

    def _prune(self, now: float) -> None:
        while self._recent and (now - self._recent[0]) > self.frequency_window_s:
            self._recent.popleft()

    def evaluate(self, intent: PaymentIntent, current_ledger_index: int) -> FastPathDecision:
        value = self.rate_provider.to_rlusd(intent.asset, intent.amount)

        if value > self.mid_value_cap_rlusd:
            return FastPathDecision(
                approved=False,
                escalate_to_quorum=True,
                reasons=["exceeds_fast_path_ceiling"],
            )

        self._prune(intent.timestamp)
        if len(self._recent) + 1 > self.frequency_limit:
            return FastPathDecision(
                approved=False,
                escalate_to_quorum=True,
                reasons=["fast_path_velocity_exceeded"],
            )
        self._recent.append(intent.timestamp)

        return FastPathDecision(
            approved=True,
            escalate_to_quorum=False,
            reasons=["auto_cosign_mid_value"],
            last_ledger_sequence=current_ledger_index + self.expiry_ledgers,
        )

    def build_expiring_payment(
        self,
        treasury_address: str,
        intent: PaymentIntent,
        current_ledger_index: int,
        sequence: int,
        fee: int,
        amount,
    ) -> Payment:
        return Payment(
            account=treasury_address,
            destination=intent.destination,
            amount=amount,
            sequence=sequence,
            fee=str(fee),
            last_ledger_sequence=current_ledger_index + self.expiry_ledgers,
            signing_pub_key="",
        )
