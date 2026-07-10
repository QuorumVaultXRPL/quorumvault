"""The v2 tiered assurance model.

Different stakes get different assurance, with the v1 2-of-2 quorum kept
underneath as the high-value backstop:

  * :class:`~quorumvault.tiers.channel_custody.ChannelCustodyLane` — high-
    frequency / low-value agent payments via XRPL Payment Channels; audited only
    at channel open and close, never per-payment.
  * :class:`~quorumvault.tiers.fast_path.VelocityBoundedFastPath` — mid-value
    payments with a lighter (auto co-sign) audit and on-ledger expiry via
    ``LastLedgerSequence``.
  * :class:`~quorumvault.tiers.router.TierRouter` — routes a payment intent to
    the correct lane by value, escalating anything above the mid-value ceiling
    to the full 2-of-2 quorum.
"""

from .channel_custody import ChannelCustodyLane, ChannelExposureError, ChannelState
from .fast_path import FastPathDecision, VelocityBoundedFastPath
from .router import Tier, TierRouter

__all__ = [
    "ChannelCustodyLane",
    "ChannelExposureError",
    "ChannelState",
    "VelocityBoundedFastPath",
    "FastPathDecision",
    "TierRouter",
    "Tier",
]
