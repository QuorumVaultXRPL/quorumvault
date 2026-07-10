"""TierRouter: value banding, with RWA always escalated to the quorum backstop."""

from quorumvault.policy.intent import PaymentIntent, RwaTransfer
from quorumvault.tiers.router import Tier, TierRouter

DEST = "rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"


def _router():
    return TierRouter(channel_ceiling_rlusd=100, fast_path_ceiling_rlusd=2000)


def _intent(amount, asset="RLUSD", rwa=None):
    return PaymentIntent(destination=DEST, asset=asset, amount=amount, rwa=rwa)


def test_low_value_routes_to_channel():
    assert _router().route(_intent(50)).tier == Tier.CHANNEL_CUSTODY


def test_mid_value_routes_to_fast_path():
    assert _router().route(_intent(500)).tier == Tier.FAST_PATH


def test_high_value_routes_to_quorum():
    assert _router().route(_intent(50_000)).tier == Tier.QUORUM_BACKSTOP


def test_rwa_always_routes_to_quorum_even_when_tiny():
    decision = _router().route(_intent(5, rwa=RwaTransfer()))
    assert decision.tier == Tier.QUORUM_BACKSTOP
    assert "rwa_requires_full_compliance_review" in decision.reasons


def test_xrp_conversion_affects_band():
    # 200 XRP * 0.55 = 110 RLUSD -> just over the 100 channel ceiling -> fast path
    assert _router().route(_intent(200, asset="XRP")).tier == Tier.FAST_PATH


def test_boundaries_are_inclusive_on_lower_tier():
    r = _router()
    assert r.route(_intent(100)).tier == Tier.CHANNEL_CUSTODY  # == channel ceiling
    assert r.route(_intent(2000)).tier == Tier.FAST_PATH  # == fast-path ceiling
