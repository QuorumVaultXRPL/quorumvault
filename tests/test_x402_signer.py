"""QuorumVault as the risk-gated x402 payer (happy path).

Proves the payer-side integration: a merchant's x402 PaymentRequirements is
risk-gated through the same PaymentIntent/RiskEngine/TierRouter/QuorumSigner
stack, and — on GREEN — produces a real 2-of-2 multisigned presigned-Payment
blob wrapped in the SDK's own PAYMENT-SIGNATURE envelope. Network calls
(autofill, current-ledger) are monkeypatched; everything else is real, including
the x402-xrpl envelope helper.
"""

import base64
import dataclasses
import json

import pytest
from x402_xrpl.client.presigned_payment_payer import build_payment_header_for_signed_blob
from x402_xrpl.types import PaymentRequirements
from xrpl.core.binarycodec import decode
from xrpl.models.transactions.transaction import Transaction

from quorumvault.integrations import x402_signer as x402mod
from quorumvault.integrations.x402_signer import (
    QuorumVaultX402Signer,
    X402_DEFAULT_SOURCE_TAG,
)
from quorumvault.policy.risk_engine import RiskEngine
from quorumvault.signing.local_keystore import LocalEncryptedKeystoreBackend
from quorumvault.signing.quorum_signer import QuorumSigner
from quorumvault.tiers.router import TierRouter

TREASURY = "rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce"
DEST = "rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"
ISSUER = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    monkeypatch.setattr(x402mod, "get_latest_validated_ledger_sequence", lambda client: 1000)

    def fake_autofill(tx, client, signers_count=None):
        # Real autofill fills Fee/Sequence from the network; here we set them so
        # the multisign step is exercised fully offline. LastLedgerSequence is
        # already set by the signer, mirroring real autofill leaving it alone.
        return dataclasses.replace(tx, fee="30", sequence=42)

    monkeypatch.setattr(x402mod, "autofill", fake_autofill)


def _reqs(*, amount="1000000", asset="XRP", extra=None, network="xrpl:1", pay_to=DEST):
    e = {"invoiceId": "INV-1"}
    if extra:
        e.update(extra)
    return PaymentRequirements.from_dict(
        {
            "scheme": "exact",
            "network": network,
            "amount": amount,
            "asset": asset,
            "payTo": pay_to,
            "maxTimeoutSeconds": 600,
            "extra": e,
        }
    )


_UNSET = object()


def _signer(keystore, passphrase, *, whitelist=(DEST,), threshold="5000", audit_memo=_UNSET):
    backends = [
        LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase),
        LocalEncryptedKeystoreBackend(keystore, "auditor_signer", passphrase),
    ]
    kwargs = dict(
        treasury_address=TREASURY,
        quorum_signer=QuorumSigner(backends),
        risk_engine=RiskEngine(
            whitelist=list(whitelist), amount_threshold_rlusd=threshold, frequency_limit=50
        ),
        router=TierRouter(channel_ceiling_rlusd=100, fast_path_ceiling_rlusd=5000),
        xrpl_client=object(),
    )
    # _UNSET means "don't pass audit_memo at all" so tests can observe
    # QuorumVaultX402Signer's own real default rather than one silently
    # reinstated by this test helper.
    if audit_memo is not _UNSET:
        kwargs["audit_memo"] = audit_memo
    return QuorumVaultX402Signer(**kwargs)


def _tx_and_env(header):
    env = json.loads(base64.b64decode(header))
    tx = Transaction.from_xrpl(decode(env["payload"]["signedTxBlob"]))
    return tx, env


def _memos(tx):
    return [bytes.fromhex(m["Memo"]["MemoData"]).decode() for m in tx.to_xrpl().get("Memos", [])]


def test_xrp_header_is_real_2of2_multisig(keystore, passphrase):
    signer = _signer(keystore, passphrase)
    header = signer.create_payment_header(_reqs(amount="1000000"))  # 1 XRP
    tx, env = _tx_and_env(header)
    assert len(tx.signers) == 2  # genuine 2-of-2
    assert (tx.signing_pub_key or "") == ""  # multisig: no single-sig pubkey
    assert env["payload"]["signedTxBlob"] == signer.last_blob
    assert env["x402Version"] == 2
    assert env["accepted"] == _reqs(amount="1000000").to_dict()
    assert signer.last_decision.risk_level == "GREEN"


def test_header_envelope_byte_matches_sdk_helper(keystore, passphrase):
    signer = _signer(keystore, passphrase)
    reqs = _reqs(amount="1000000")
    header = signer.create_payment_header(reqs)
    expected = build_payment_header_for_signed_blob(
        req=reqs, signed_tx_blob=signer.last_blob, invoice_id="INV-1"
    )
    assert header == expected  # envelope fidelity to the SDK's own format


def test_source_tag_defaults_to_x402_and_honors_requirements(keystore, passphrase):
    tx, _ = _tx_and_env(_signer(keystore, passphrase).create_payment_header(_reqs()))
    assert tx.source_tag == X402_DEFAULT_SOURCE_TAG  # protocol-owned default 804681468

    tx2, _ = _tx_and_env(
        _signer(keystore, passphrase).create_payment_header(_reqs(extra={"sourceTag": 424242}))
    )
    assert tx2.source_tag == 424242  # honors the merchant's tag (verify would else reject)


def test_iou_payment_has_issued_amount_and_sendmax(keystore, passphrase):
    signer = _signer(keystore, passphrase, threshold="100000")
    reqs = _reqs(amount="1.25", asset="USD", extra={"issuer": ISSUER})
    tx, _ = _tx_and_env(signer.create_payment_header(reqs))
    x = tx.to_xrpl()
    assert isinstance(x["Amount"], dict)
    assert x["Amount"]["value"] == "1.25" and x["Amount"]["issuer"] == ISSUER
    assert x["SendMax"]["value"] == "1.25"  # SDK IOU policy: SendMax present
    assert len(tx.signers) == 2


def test_audit_memo_is_opt_in_and_preserves_invoice_binding(keystore, passphrase):
    on = _signer(keystore, passphrase, audit_memo=True)
    tx_on, _ = _tx_and_env(on.create_payment_header(_reqs()))
    memos_on = _memos(tx_on)
    assert "INV-1" in memos_on  # invoice-binding memo still present
    assert any("quorumvault" in m for m in memos_on)  # audit memo appended

    off = _signer(keystore, passphrase, audit_memo=False)
    tx_off, _ = _tx_and_env(off.create_payment_header(_reqs()))
    assert all("quorumvault" not in m for m in _memos(tx_off))  # default: no audit memo


def test_audit_memo_defaults_to_on(keystore, passphrase):
    # Live-verified against T54's Testnet facilitator (2026-07-13): both /verify
    # and /settle accept a tx carrying the audit memo alongside the invoice
    # binding, so the default reflects that rather than an unverified guess.
    signer = _signer(keystore, passphrase)  # no explicit audit_memo=...
    tx, _ = _tx_and_env(signer.create_payment_header(_reqs()))
    assert any("quorumvault" in m for m in _memos(tx))


def test_create_payment_header_is_usable_as_factory(keystore, passphrase):
    signer = _signer(keystore, passphrase)
    factory = signer.create_payment_header  # what x402_requests(payment_header_factory=...) wants
    header = factory(_reqs())
    assert isinstance(header, str) and json.loads(base64.b64decode(header))["x402Version"] == 2
