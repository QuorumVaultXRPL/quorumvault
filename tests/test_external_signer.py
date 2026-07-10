"""QuorumVault as the skill's ExternalSigner: contract shape, risk gate, ceremony."""

import dataclasses

import pytest
from xrpl.core.binarycodec import decode, encode_for_multisigning
from xrpl.core.keypairs import is_valid_message
from xrpl.models.transactions import Payment
from xrpl.models.transactions.transaction import Transaction

from quorumvault.integrations.agent_wallet_ceremony import (
    XRPL_STARTER_KIT_SOURCE_TAG,
    apply_default_source_tag,
    render_preview,
    run_ceremony,
)
from quorumvault.integrations.external_signer import (
    ExternalSignerRefused,
    QuorumVaultExternalSigner,
)
from quorumvault.policy.risk_engine import RiskEngine
from quorumvault.signing.local_keystore import LocalEncryptedKeystoreBackend
from quorumvault.signing.quorum_signer import QuorumSigner
from quorumvault.tiers.router import TierRouter

TREASURY = "rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce"
DEST = "rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"


@pytest.fixture
def signer(keystore, passphrase):
    backends = [
        LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase),
        LocalEncryptedKeystoreBackend(keystore, "auditor_signer", passphrase),
    ]
    return QuorumVaultExternalSigner(
        treasury_address=TREASURY,
        quorum_signer=QuorumSigner(backends),
        risk_engine=RiskEngine(whitelist=[DEST], amount_threshold_rlusd=100_000, frequency_limit=50),
        router=TierRouter(channel_ceiling_rlusd=100, fast_path_ceiling_rlusd=5000),
    )


def _autofilled_payment(destination=DEST):
    # Stand in for the output of client.autofill(): Fee/Sequence/LLS populated.
    return Payment(
        account=TREASURY,
        amount="1000000",
        destination=destination,
        sequence=42,
        fee="20",
        last_ledger_sequence=100_000,
        signing_pub_key="",
    )


def test_address_is_treasury_and_two_signers(signer):
    assert signer.address == TREASURY
    assert signer.signers_count == 2


def test_sign_returns_contract_shape_and_valid_multisig(signer):
    tx = _autofilled_payment()
    out = signer.sign(tx)
    assert set(out) == {"tx_blob", "hash"}
    assert len(out["hash"]) == 64
    reconstructed = Transaction.from_xrpl(decode(out["tx_blob"]))
    assert len(reconstructed.signers) == 2
    assert reconstructed.get_hash() == out["hash"]
    # each Signer's signature validates against its own key
    for s in reconstructed.signers:
        blob = bytes.fromhex(encode_for_multisigning(tx.to_xrpl(), s.account))
        assert is_valid_message(blob, bytes.fromhex(s.txn_signature), s.signing_pub_key)


def test_auditor_refuses_non_green_destination(signer):
    tx = _autofilled_payment(destination="rUnknownDestination0000000000000000")
    with pytest.raises(ExternalSignerRefused):
        signer.sign(tx)
    assert signer.last_decision.risk_level == "RED"
    assert "untrusted_destination" in signer.last_decision.fired_reasons


def test_green_sign_records_decision(signer):
    signer.sign(_autofilled_payment())
    assert signer.last_decision.risk_level == "GREEN"


# -- ceremony pieces --------------------------------------------------------


def test_apply_default_source_tag_sets_when_absent():
    tx = _autofilled_payment()
    assert tx.source_tag is None
    tagged = apply_default_source_tag(tx)
    assert tagged.source_tag == XRPL_STARTER_KIT_SOURCE_TAG


def test_apply_default_source_tag_respects_zero_and_existing():
    zero = dataclasses.replace(_autofilled_payment(), source_tag=0)
    assert apply_default_source_tag(zero).source_tag == 0
    custom = dataclasses.replace(_autofilled_payment(), source_tag=777)
    assert apply_default_source_tag(custom).source_tag == 777


def test_preview_has_exact_rows_and_conversions():
    tx = apply_default_source_tag(_autofilled_payment())
    preview = render_preview(tx.to_xrpl(), "testnet", current_ledger_index=99_990)
    for row in ["Network", "Type", "From", "To", "Amount", "Fee", "Sequence",
                "LastLedgerSequence", "Flags", "Memos", "Other fields"]:
        assert row in preview
    assert TREASURY in preview and DEST in preview  # full addresses, no truncation
    assert "1 XRP" in preview  # 1000000 drops -> 1 XRP
    assert "expires in ~10 ledgers (~40 seconds)" in preview  # 100000 - 99990 = 10
    assert "SourceTag=20260530" in preview  # under Other fields
    assert "Sign and submit? (yes / no)" in preview


def test_run_ceremony_rejects_address_mismatch(signer):
    # signer controls TREASURY; hand it a tx for a different account -> stop.
    wrong = dataclasses.replace(_autofilled_payment(), account="rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh")
    with pytest.raises(ValueError):
        run_ceremony(client=None, signer=signer, tx=wrong)
