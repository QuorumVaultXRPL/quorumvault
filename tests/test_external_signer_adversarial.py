"""Adversarial tests for the ExternalSigner refusal gate.

Targets the confirmed bug (amount=0.0 fallback made the value check vacuous for
non-Payment types AND for IOU/MPT payments) and the RWA-bypass finding (MPT
transfers skipped the RWA rule entirely). Each test tries to obtain a false
GREEN / a real signature for something that must be refused.
"""

import pytest
from xrpl.models.amounts import IssuedCurrencyAmount, MPTAmount
from xrpl.models.transactions import AccountSet, Payment, SignerListSet
from xrpl.models.transactions.signer_list_set import SignerEntry

from quorumvault.integrations.external_signer import (
    ExternalSignerRefused,
    QuorumVaultExternalSigner,
)
from quorumvault.policy.intent import Credential, RwaTransfer
from quorumvault.policy.ledger_reader import StaticComplianceReader
from quorumvault.policy.risk_engine import RiskEngine
from quorumvault.signing.local_keystore import LocalEncryptedKeystoreBackend
from quorumvault.signing.quorum_signer import QuorumSigner
from quorumvault.tiers.router import TierRouter

TREASURY = "rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce"
DEST = "rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"
OTHER = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
ISSUANCE = "000004C463C52827307480341125DA0577DEFC38405B0E3E"


def _signer(keystore, passphrase, *, whitelist=(DEST,), reader=None, req_creds=None, domain=None):
    backends = [
        LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase),
        LocalEncryptedKeystoreBackend(keystore, "auditor_signer", passphrase),
    ]
    return QuorumVaultExternalSigner(
        treasury_address=TREASURY,
        quorum_signer=QuorumSigner(backends),
        risk_engine=RiskEngine(whitelist=list(whitelist), amount_threshold_rlusd=5000, frequency_limit=50),
        router=TierRouter(channel_ceiling_rlusd=100, fast_path_ceiling_rlusd=5000),
        compliance_reader=reader,
        rwa_required_credentials=req_creds,
        rwa_domain_id=domain,
    )


def _signerlistset():
    return SignerListSet(
        account=TREASURY, signer_quorum=2,
        signer_entries=[SignerEntry(account=DEST, signer_weight=1), SignerEntry(account=OTHER, signer_weight=1)],
    )


# -- non-Payment types are refused deliberately, not by coincidence ---------


def test_refuses_signerlistset(keystore, passphrase):
    signer = _signer(keystore, passphrase)
    with pytest.raises(ExternalSignerRefused):
        signer.sign(_signerlistset())
    assert "unsupported_transaction_type:SignerListSet" in signer.last_decision.fired_reasons


def test_refuses_signerlistset_even_when_treasury_is_whitelisted(keystore, passphrase):
    # The whole point: the refusal must NOT depend on the treasury being absent
    # from the whitelist. Whitelist it, and a SignerListSet is STILL refused.
    signer = _signer(keystore, passphrase, whitelist=(DEST, TREASURY))
    with pytest.raises(ExternalSignerRefused):
        signer.sign(_signerlistset())
    assert signer.last_decision.risk_level == "REFUSED"


def test_refuses_accountset(keystore, passphrase):
    signer = _signer(keystore, passphrase, whitelist=(DEST, TREASURY))
    with pytest.raises(ExternalSignerRefused):
        signer.sign(AccountSet(account=TREASURY, set_flag=4))  # disable master key


# -- IOU/MPT payments are valued, not zeroed --------------------------------


def test_large_iou_payment_is_valued_not_zeroed(keystore, passphrase):
    # 10,000,000 USD to a whitelisted destination. Under the bug this valued as
    # 0 -> GREEN -> auto-signed. It must exceed the value threshold instead.
    signer = _signer(keystore, passphrase, whitelist=(DEST,))
    iou = Payment(
        account=TREASURY,
        amount=IssuedCurrencyAmount(currency="USD", issuer=OTHER, value="10000000"),
        destination=DEST, sequence=1, fee="20", signing_pub_key="",
    )
    with pytest.raises(ExternalSignerRefused):
        signer.sign(iou)
    assert signer.last_decision.risk_level == "YELLOW"
    assert "value_threshold_exceeded" in signer.last_decision.fired_reasons
    assert signer.last_decision.tier == "quorum_backstop"  # not channel_custody


# -- RWA gating cannot be routed around via the ExternalSigner --------------


def _mpt_payment(value="100"):
    return Payment(
        account=TREASURY, amount=MPTAmount(mpt_issuance_id=ISSUANCE, value=value),
        destination=DEST, sequence=1, fee="20", signing_pub_key="",
    )


def test_mpt_payment_refused_without_compliance_reader(keystore, passphrase):
    signer = _signer(keystore, passphrase, whitelist=(DEST,))  # no reader wired
    with pytest.raises(ExternalSignerRefused) as exc:
        signer.sign(_mpt_payment())
    assert "no compliance reader" in str(exc.value)


def test_mpt_payment_unauthorized_holder_refused(keystore, passphrase):
    reader = StaticComplianceReader(
        RwaTransfer(is_rwa=True, requires_authorization=True, destination_authorized=False)
    )
    signer = _signer(keystore, passphrase, whitelist=(DEST,), reader=reader)
    with pytest.raises(ExternalSignerRefused):
        signer.sign(_mpt_payment())
    assert "rwa_destination_not_authorized" in signer.last_decision.fired_reasons
    assert signer.last_decision.tier == "quorum_backstop"


def test_mpt_payment_compliant_signs(keystore, passphrase):
    reader = StaticComplianceReader(
        RwaTransfer(
            is_rwa=True, requires_authorization=True, destination_authorized=True,
            transfer_disabled=False, clawback_enabled=False,
        )
    )
    signer = _signer(keystore, passphrase, whitelist=(DEST,), reader=reader)
    out = signer.sign(_mpt_payment())
    assert set(out) == {"tx_blob", "hash"}
    assert signer.last_decision.risk_level == "GREEN"


# -- unparseable / payee-less transactions fail closed ----------------------


class _StubTx:
    """A Payment-typed object whose to_xrpl() omits Destination."""

    class _T:
        value = "Payment"

    transaction_type = _T()

    def to_xrpl(self):
        return {"TransactionType": "Payment", "Account": TREASURY, "Amount": "1000000"}


def test_payment_without_destination_refused(keystore, passphrase):
    signer = _signer(keystore, passphrase)
    with pytest.raises(ExternalSignerRefused):
        signer.sign(_StubTx())
