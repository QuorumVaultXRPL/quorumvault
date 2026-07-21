"""Refusal alerting: observational only.

A wired sink is notified on a refusal (with the recorded decision) and NOT on a
successful signature; a sink that fails to deliver produces an
AlertDeliveryFailedWarning and never changes the outcome (sign still raises
ExternalSignerRefused); NullAlertSink is inert; WebhookAlertSink builds and POSTs
the right payload. Mocked HTTP only - no live network.
"""

from __future__ import annotations

import pytest
from xrpl.models.transactions import Payment, SignerListSet
from xrpl.models.transactions.signer_list_set import SignerEntry

from quorumvault.integrations.alerts import (
    AlertDeliveryFailedWarning,
    NullAlertSink,
    RefusalAlertSink,
    WebhookAlertSink,
)
from quorumvault.integrations.external_signer import (
    ExternalSignerRefused,
    QuorumVaultExternalSigner,
    SignDecision,
)
from quorumvault.policy.risk_engine import RiskEngine
from quorumvault.signing.local_keystore import LocalEncryptedKeystoreBackend
from quorumvault.signing.quorum_signer import QuorumSigner
from quorumvault.tiers.router import TierRouter

TREASURY = "rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce"
DEST = "rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"
OTHER = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"


class RecordingSink(RefusalAlertSink):
    def __init__(self):
        self.calls = []

    def notify(self, decision, *, tx_type):
        self.calls.append((decision, tx_type))

    @property
    def is_live(self):
        return True


class RaisingSink(RefusalAlertSink):
    def notify(self, decision, *, tx_type):
        raise RuntimeError("alert channel down")

    @property
    def is_live(self):
        return True


def _signer(keystore, passphrase, *, whitelist=(DEST,), alert_sink=None):
    backends = [
        LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase),
        LocalEncryptedKeystoreBackend(keystore, "auditor_signer", passphrase),
    ]
    return QuorumVaultExternalSigner(
        treasury_address=TREASURY,
        quorum_signer=QuorumSigner(backends),
        risk_engine=RiskEngine(
            whitelist=list(whitelist), amount_threshold_rlusd=5000, frequency_limit=50
        ),
        router=TierRouter(channel_ceiling_rlusd=100, fast_path_ceiling_rlusd=5000),
        alert_sink=alert_sink,
    )


def _green_payment():
    return Payment(
        account=TREASURY, amount="1000000", destination=DEST,
        sequence=1, fee="20", last_ledger_sequence=100_000, signing_pub_key="",
    )


def _untrusted_payment():
    # Pays a non-whitelisted destination -> RED -> refused.
    return Payment(
        account=TREASURY, amount="1000000", destination=OTHER,
        sequence=1, fee="20", last_ledger_sequence=100_000, signing_pub_key="",
    )


def _signerlistset():
    return SignerListSet(
        account=TREASURY, signer_quorum=2,
        signer_entries=[
            SignerEntry(account=DEST, signer_weight=1),
            SignerEntry(account=OTHER, signer_weight=1),
        ],
    )


# -- sink is notified on refusal, with the recorded decision ----------------


def test_sink_notified_on_non_green_refusal_with_recorded_decision(keystore, passphrase):
    sink = RecordingSink()
    signer = _signer(keystore, passphrase, alert_sink=sink)
    with pytest.raises(ExternalSignerRefused):
        signer.sign(_untrusted_payment())
    assert len(sink.calls) == 1
    decision, tx_type = sink.calls[0]
    assert tx_type == "Payment"
    assert decision.risk_level == "RED"
    assert "untrusted_destination" in decision.fired_reasons


def test_sink_notified_on_unsupported_type_refusal(keystore, passphrase):
    sink = RecordingSink()
    signer = _signer(keystore, passphrase, alert_sink=sink)
    with pytest.raises(ExternalSignerRefused):
        signer.sign(_signerlistset())
    assert len(sink.calls) == 1
    decision, tx_type = sink.calls[0]
    assert tx_type == "SignerListSet"
    assert "unsupported_transaction_type:SignerListSet" in decision.fired_reasons


# -- a wired sink is NOT called on a successful signature -------------------


def test_sink_not_called_on_successful_signature(keystore, passphrase):
    sink = RecordingSink()
    signer = _signer(keystore, passphrase, alert_sink=sink)
    out = signer.sign(_green_payment())
    assert set(out) == {"tx_blob", "hash"}
    assert sink.calls == []


# -- delivery failure is isolated: warn, never change the outcome -----------


def test_sink_failure_warns_and_still_refuses(keystore, passphrase):
    signer = _signer(keystore, passphrase, alert_sink=RaisingSink())
    with pytest.warns(AlertDeliveryFailedWarning):
        with pytest.raises(ExternalSignerRefused):
            signer.sign(_untrusted_payment())


def test_sink_failure_does_not_convert_a_success_or_swallow_refusal(keystore, passphrase):
    # The refusal must still be the exception the caller sees, not the alert error.
    signer = _signer(keystore, passphrase, alert_sink=RaisingSink())
    with pytest.raises(ExternalSignerRefused):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            signer.sign(_untrusted_payment())


# -- no sink wired: no alert, no warning ------------------------------------


def test_no_sink_wired_is_a_silent_no_op(keystore, passphrase, recwarn):
    signer = _signer(keystore, passphrase, alert_sink=None)
    with pytest.raises(ExternalSignerRefused):
        signer.sign(_untrusted_payment())
    # A MISSING sink is deliberately not a *NotWired condition (unlike guard/identity).
    assert not any(
        issubclass(w.category, AlertDeliveryFailedWarning) for w in recwarn.list
    )


def test_null_sink_is_inert(keystore, passphrase):
    sink = NullAlertSink()
    assert sink.is_live is False
    signer = _signer(keystore, passphrase, alert_sink=sink)
    with pytest.raises(ExternalSignerRefused):
        signer.sign(_untrusted_payment())  # no error from the inert sink


# -- WebhookAlertSink unit behavior -----------------------------------------


def test_webhook_builds_expected_payload():
    sink = WebhookAlertSink("https://example.test/hook", http_post=lambda *a, **k: None)
    decision = SignDecision(tier="quorum_backstop", risk_level="RED", fired_reasons=["untrusted_destination"])
    payload = sink.build_payload(decision, tx_type="Payment")
    assert payload == {
        "event": "quorumvault.refusal",
        "tx_type": "Payment",
        "tier": "quorum_backstop",
        "risk_level": "RED",
        "fired_reasons": ["untrusted_destination"],
    }


def test_webhook_posts_url_body_and_timeout():
    captured = {}

    def http_post(url, body, *, timeout_s):
        captured["url"] = url
        captured["body"] = body
        captured["timeout_s"] = timeout_s

    sink = WebhookAlertSink("https://example.test/hook", timeout_s=3.0, http_post=http_post)
    decision = SignDecision(tier="refused", risk_level="REFUSED", fired_reasons=["x"])
    sink.notify(decision, tx_type="Payment")
    assert captured["url"] == "https://example.test/hook"
    assert captured["timeout_s"] == 3.0
    import json
    assert json.loads(captured["body"].decode())["risk_level"] == "REFUSED"


def test_webhook_delivery_failure_warns_and_does_not_raise():
    def boom(url, body, *, timeout_s):
        raise RuntimeError("connection refused")

    sink = WebhookAlertSink("https://example.test/hook", http_post=boom)
    decision = SignDecision(tier="refused", risk_level="REFUSED", fired_reasons=["x"])
    with pytest.warns(AlertDeliveryFailedWarning):
        sink.notify(decision, tx_type="Payment")  # must NOT raise


def test_webhook_is_live_true_and_empty_url_rejected():
    assert WebhookAlertSink("https://example.test/hook", http_post=lambda *a, **k: None).is_live is True
    with pytest.raises(ValueError):
        WebhookAlertSink("")
