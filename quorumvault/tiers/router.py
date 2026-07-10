"""TierRouter - pick the assurance lane from the transaction's own stakes.

Value bands (RLUSD-equivalent, via an injectable rate provider):
    value <= channel_ceiling                     -> Channel-Custody lane
    channel_ceiling < value <= fast_path_ceiling -> Velocity-Bounded Fast Path
    value > fast_path_ceiling                    -> 2-of-2 quorum backstop

RWA transfers always escalate to the quorum backstop: tokenized real-world
assets carry compliance obligations that must be checked on every transfer, so
they never use the un-audited channel or the lighter fast path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List

from ..policy.intent import PaymentIntent
from ..policy.pricing import RateProvider, default_rate_provider


class Tier(Enum):
    CHANNEL_CUSTODY = "channel_custody"
    FAST_PATH = "fast_path"
    QUORUM_BACKSTOP = "quorum_backstop"


@dataclass
class RoutingDecision:
    tier: Tier
    value_rlusd: float
    reasons: List[str] = field(default_factory=list)


class TierRouter:
    def __init__(
        self,
        channel_ceiling_rlusd: float,
        fast_path_ceiling_rlusd: float,
        rate_provider: RateProvider = None,
    ):
        if not (0 < channel_ceiling_rlusd < fast_path_ceiling_rlusd):
            raise ValueError(
                "require 0 < channel_ceiling_rlusd < fast_path_ceiling_rlusd"
            )
        self.channel_ceiling_rlusd = channel_ceiling_rlusd
        self.fast_path_ceiling_rlusd = fast_path_ceiling_rlusd
        # Injectable: for real funds pass a live CallableRateProvider. The default
        # is a labelled Testnet placeholder (is_live == False).
        self.rate_provider = rate_provider or default_rate_provider()

    def route(self, intent: PaymentIntent) -> RoutingDecision:
        value = self.rate_provider.to_rlusd(intent.asset, intent.amount)

        if intent.rwa is not None and intent.rwa.is_rwa:
            return RoutingDecision(
                Tier.QUORUM_BACKSTOP,
                value,
                ["rwa_requires_full_compliance_review"],
            )

        if value <= self.channel_ceiling_rlusd:
            return RoutingDecision(Tier.CHANNEL_CUSTODY, value, ["low_value_high_frequency"])
        if value <= self.fast_path_ceiling_rlusd:
            return RoutingDecision(Tier.FAST_PATH, value, ["mid_value"])
        return RoutingDecision(Tier.QUORUM_BACKSTOP, value, ["high_value"])
