"""Adversarial tests for the x402 payer: every path that must refuse, refuses.

Mirrors test_external_signer_adversarial.py. The x402 signer must fail closed —
an unsupported quote, an un-valuable amount, a missing payee/invoice/issuer, or
any non-GREEN Auditor verdict produces NO signature and NO payment header, never
a partial or zero-value payment. Refusals happen in the risk gate / validation,
before any network call.
"""

import dataclasses

import pytest
from x402_xrpl.types import PaymentRequirements

from quorumvault.integrations import x402_signer as x402mod
from quorumvault.integrations.x402_signer import QuorumVaultX402Signer, X402PaymentRefused
from quorumvault.policy.risk_engine import RiskEngine
from quorumvault.signing.local_keystore import LocalEncryptedKeystoreBackend
from quorumvault.signing.quorum_signer import QuorumSigner
from quorumvault.tiers.router import TierRouter

TREASURY = "rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce"
DEST = "rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"
EVIL = "rEvilDest00000000000000000000000000"
ISSUER = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    monkeypatch.setattr(x402mod, "get_latest_validated_ledger_sequence", lambda client: 1000)
    monkeypatch.setattr(
        x402mod, "autofill", lambda tx, client, signers_count=None: dataclasses.replace(tx, fee="30", sequence=42)
    )


def _reqs(*, amount="1000000", asset="XRP", extra=None, network="xrpl:1", pay_to=DEST, invoice="INV-1"):
    e = dict(extra or {})
    if invoice is not None:
        e["invoiceId"] = invoice
    return PaymentRequirements.from_dict(
        {"scheme": "exact", "network": network, "amount": amount, "asset": asset,
         "payTo": pay_to, "maxTimeoutSeconds": 600, "extra": e}
    )


def _bad_scheme_reqs():
    return PaymentRequirements.from_dict(
        {"scheme": "upto", "network": "xrpl:1", "amount": "1000000", "asset": "XRP",
         "payTo": DEST, "maxTimeoutSeconds": 600, "extra": {"invoiceId": "INV-1"}}
    )


def _signer(keystore, passphrase, *, whitelist=(DEST,), threshold="5000"):
    backends = [
        LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase),
        LocalEncryptedKeystoreBackend(keystore, "auditor_signer", passphrase),
    ]
    return QuorumVaultX402Signer(
        treasury_address=TREASURY,
        quorum_signer=QuorumSigner(backends),
        risk_engine=RiskEngine(whitelist=list(whitelist), amount_threshold_rlusd=threshold, frequency_limit=50),
        router=TierRouter(channel_ceiling_rlusd=100, fast_path_ceiling_rlusd=5000),
        xrpl_client=object(),
    )


# -- unsupported quotes -----------------------------------------------------


def test_refuses_unsupported_scheme(keystore, passphrase):
    with pytest.raises(X402PaymentRefused):
        _signer(keystore, passphrase).create_payment_header(_bad_scheme_reqs())


def test_refuses_non_xrpl_network(keystore, passphrase):
    with pytest.raises(X402PaymentRefused):
        _signer(keystore, passphrase).create_payment_header(_reqs(network="base-sepolia"))


def test_refuses_iou_without_issuer(keystore, passphrase):
    with pytest.raises(X402PaymentRefused):
        _signer(keystore, passphrase, threshold="100000").create_payment_header(
            _reqs(amount="1", asset="USD")  # no extra['issuer']
        )


def test_refuses_invalid_currency_code(keystore, passphrase):
    with pytest.raises(X402PaymentRefused):
        _signer(keystore, passphrase, threshold="100000").create_payment_header(
            _reqs(amount="1", asset="TOOLONG", extra={"issuer": ISSUER})
        )


def test_refuses_missing_invoice_id(keystore, passphrase):
    with pytest.raises(X402PaymentRefused):
        _signer(keystore, passphrase).create_payment_header(_reqs(invoice=None))


# -- un-valuable amounts (fail closed, never zero-default) ------------------


def test_refuses_unparseable_amount(keystore, passphrase):
    with pytest.raises(X402PaymentRefused):
        _signer(keystore, passphrase, threshold="100000").create_payment_header(
            _reqs(amount="not-a-number", asset="USD", extra={"issuer": ISSUER})
        )


def test_refuses_non_integer_xrp_drops(keystore, passphrase):
    with pytest.raises(X402PaymentRefused):
        _signer(keystore, passphrase).create_payment_header(_reqs(amount="100.5"))


def test_refuses_non_integer_source_tag(keystore, passphrase):
    signer = _signer(keystore, passphrase)
    with pytest.raises(X402PaymentRefused):
        signer.create_payment_header(_reqs(extra={"sourceTag": "not-an-int"}))


# -- non-GREEN Auditor verdicts --------------------------------------------


def test_refuses_untrusted_destination(keystore, passphrase):
    signer = _signer(keystore, passphrase, whitelist=(DEST,))  # EVIL not whitelisted
    with pytest.raises(X402PaymentRefused):
        signer.create_payment_header(_reqs(pay_to=EVIL))
    assert signer.last_decision.risk_level == "RED"
    assert "untrusted_destination" in signer.last_decision.fired_reasons
    assert signer.last_blob is None  # no signature produced


def test_refuses_over_value_threshold(keystore, passphrase):
    # 100 XRP * 0.55 = 55 RLUSD; threshold 10 -> YELLOW -> refuse.
    signer = _signer(keystore, passphrase, whitelist=(DEST,), threshold="10")
    with pytest.raises(X402PaymentRefused):
        signer.create_payment_header(_reqs(amount="100000000"))  # 100 XRP in drops
    assert signer.last_decision.risk_level == "YELLOW"
    assert "value_threshold_exceeded" in signer.last_decision.fired_reasons


def test_tripped_breaker_freezes_subsequent_payments(keystore, passphrase):
    signer = _signer(keystore, passphrase, whitelist=(DEST,))
    with pytest.raises(X402PaymentRefused):
        signer.create_payment_header(_reqs(pay_to=EVIL))  # RED trips the breaker
    # A now-clean, whitelisted payment is still frozen RED.
    with pytest.raises(X402PaymentRefused):
        signer.create_payment_header(_reqs(pay_to=DEST))
    assert "circuit_breaker_frozen" in signer.last_decision.fired_reasons
