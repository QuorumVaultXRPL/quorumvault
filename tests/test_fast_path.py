"""Velocity-Bounded Fast Path: value ceiling, velocity limit, on-ledger expiry."""

from quorumvault.policy.intent import PaymentIntent
from quorumvault.tiers.fast_path import VelocityBoundedFastPath

TREASURY = "rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce"
DEST = "rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"


def _intent(amount, asset="RLUSD", ts=1000.0):
    return PaymentIntent(destination=DEST, asset=asset, amount=amount, timestamp=ts)


def test_mid_value_is_auto_cosigned_with_expiry():
    fp = VelocityBoundedFastPath(mid_value_cap_rlusd=2000, expiry_ledgers=4)
    decision = fp.evaluate(_intent(1500), current_ledger_index=100)
    assert decision.approved and not decision.escalate_to_quorum
    assert decision.last_ledger_sequence == 104


def test_over_ceiling_escalates_to_quorum():
    fp = VelocityBoundedFastPath(mid_value_cap_rlusd=2000)
    decision = fp.evaluate(_intent(5000), current_ledger_index=100)
    assert decision.escalate_to_quorum
    assert "exceeds_fast_path_ceiling" in decision.reasons


def test_velocity_limit_escalates():
    fp = VelocityBoundedFastPath(
        mid_value_cap_rlusd=2000, frequency_window_s=60, frequency_limit=3
    )
    for _ in range(3):
        assert fp.evaluate(_intent(100), current_ledger_index=100).approved
    # 4th within the window exceeds the limit
    decision = fp.evaluate(_intent(100), current_ledger_index=100)
    assert decision.escalate_to_quorum
    assert "fast_path_velocity_exceeded" in decision.reasons


def test_xrp_converted_for_ceiling():
    fp = VelocityBoundedFastPath(mid_value_cap_rlusd=2000)  # rate 0.55
    # 5000 XRP * 0.55 = 2750 RLUSD -> over ceiling
    assert fp.evaluate(_intent(5000, asset="XRP"), current_ledger_index=1).escalate_to_quorum
    # 3000 XRP * 0.55 = 1650 RLUSD -> within ceiling
    assert fp.evaluate(_intent(3000, asset="XRP"), current_ledger_index=1).approved


def test_build_expiring_payment_sets_last_ledger_sequence():
    fp = VelocityBoundedFastPath(mid_value_cap_rlusd=2000, expiry_ledgers=5)
    payment = fp.build_expiring_payment(
        TREASURY, _intent(1000), current_ledger_index=200, sequence=9, fee=20,
        amount="1000000",
    )
    assert payment.last_ledger_sequence == 205
    assert payment.amount == "1000000"
    assert payment.destination == DEST
