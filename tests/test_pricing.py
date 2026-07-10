"""Injectable rate provider: no hardcoded rate can silently misroute value."""

import pytest

from quorumvault.policy.intent import PaymentIntent
from quorumvault.policy.pricing import (
    CallableRateProvider,
    StaleRateError,
    StaticRateProvider,
)
from quorumvault.policy.risk_engine import RiskEngine, RiskLevel
from quorumvault.tiers.fast_path import VelocityBoundedFastPath
from quorumvault.tiers.router import Tier, TierRouter

DEST = "rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"


def test_static_provider_converts_and_is_not_live():
    p = StaticRateProvider(0.55)
    assert p.to_rlusd("XRP", 100) == pytest.approx(55)
    assert p.to_rlusd("RLUSD", 100) == 100
    assert p.is_live is False


def test_callable_provider_uses_live_value_each_call():
    prices = iter([0.5, 3.0])
    p = CallableRateProvider(lambda: next(prices))
    assert p.is_live is True
    assert p.to_rlusd("XRP", 100) == 50
    assert p.to_rlusd("XRP", 100) == 300  # fresh read, not cached


def test_callable_provider_rejects_stale_price():
    now = 1000.0
    stale = CallableRateProvider(lambda: (0.5, 900.0), max_age_s=50, clock=lambda: now)
    with pytest.raises(StaleRateError):
        stale.to_rlusd("XRP", 100)  # 100s old > 50s max
    fresh = CallableRateProvider(lambda: (0.5, 980.0), max_age_s=50, clock=lambda: now)
    assert fresh.to_rlusd("XRP", 100) == 50  # 20s old, fine


def test_injected_rate_changes_router_band():
    intent = PaymentIntent(destination=DEST, asset="XRP", amount=60)
    cheap = TierRouter(100, 2000, rate_provider=StaticRateProvider(0.55))
    dear = TierRouter(100, 2000, rate_provider=StaticRateProvider(2.0))
    assert cheap.route(intent).tier == Tier.CHANNEL_CUSTODY  # 33 RLUSD
    assert dear.route(intent).tier == Tier.FAST_PATH  # 120 RLUSD -> over channel ceiling


def test_injected_rate_changes_value_threshold():
    intent = PaymentIntent(destination=DEST, asset="XRP", amount=8000)
    low = RiskEngine([DEST], amount_threshold_rlusd=5000, rate_provider=StaticRateProvider(0.55))
    high = RiskEngine([DEST], amount_threshold_rlusd=5000, rate_provider=StaticRateProvider(0.80))
    assert low.evaluate(intent)["risk_level"] == RiskLevel.GREEN  # 4400 < 5000
    assert high.evaluate(intent)["risk_level"] == RiskLevel.YELLOW  # 6400 > 5000


def test_injected_rate_changes_fast_path_ceiling():
    intent = PaymentIntent(destination=DEST, asset="XRP", amount=3000)
    fp_low = VelocityBoundedFastPath(2000, rate_provider=StaticRateProvider(0.55))
    fp_high = VelocityBoundedFastPath(2000, rate_provider=StaticRateProvider(0.80))
    assert fp_low.evaluate(intent, 1).approved  # 1650 <= 2000
    assert fp_high.evaluate(intent, 1).escalate_to_quorum 