"""Adversarial tests for the ExternalSigner refusal gate.

Targets the confirmed bug (amount=0.0 fallback made the value check vacuous for
non-Payment types AND for IOU/MPT payments) and the RWA-bypass finding (MPT
transfers skipped the RWA rule entirely). Each test tries to obtain a false
GREEN / a real signature for something that must be refused.
"""

import pytest
from xrpl.models.amounts import IssuedCurrencyAmount, MPTAmount
from xrpl.models.response import Response, ResponseStatus, ResponseType
from xrpl.models.transactions import AccountSet, Payment, SetRegularKey, SignerListSet
from xrpl.models.transactions.signer_list_set import SignerEntry

from quorumvault.integrations.external_signer import (
    ExternalSignerRefused,
    QuorumVaultExternalSigner,
)
from quorumvault.policy.intent import Credential, RwaTransfer
from quorumvault.integrations.alerts import (
    AlertDeliveryFailedWarning,
    NullAlertSink,
    RefusalAlertSink,
)
from quorumvault.policy.agent_identity import (
    LSF_CREDENTIAL_ACCEPTED,
    AgentIdentityNotWiredWarning,
    StaticAgentIdentityVerifier,
    XrplAgentIdentityVerifier,
    normalize_credential_type,
)
from quorumvault.policy.ledger_reader import StaticComplianceReader
from quorumvault.policy.treasury_guard import (
    LSF_DISABLE_MASTER,
    StaticTreasuryConfigVerifier,
    TreasuryGuardNotWiredWarning,
    XrplTreasuryConfigVerifier,
)
from quorumvault.policy.risk_engine import RiskEngine
from quorumvault.signing.local_keystore import LocalEncryptedKeystoreBackend
from quorumvault.signing.quorum_signer import QuorumSigner
from quorumvault.tiers.router import TierRouter

TREASURY = "rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce"
DEST = "rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"
OTHER = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
ISSUANCE = "000004C463C52827307480341125DA0577DEFC38405B0E3E"


def _signer(
    keystore, passphrase, *, whitelist=(DEST,), reader=None, req_creds=None,
    domain=None, guard=None, identity=None, issuers=(), cred_type=None,
    alert_sink=None,
):
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
        treasury_guard=guard,
        agent_identity_verifier=identity,
        recognized_credential_issuers=issuers,
        required_credential_type=cred_type,
        alert_sink=alert_sink,
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


# -- SetRegularKey is refused explicitly (Wietse: "bypass with regular key") -


def test_refuses_setregularkey(keystore, passphrase):
    signer = _signer(keystore, passphrase, whitelist=(DEST, TREASURY))
    with pytest.raises(ExternalSignerRefused):
        signer.sign(SetRegularKey(account=TREASURY, regular_key=OTHER))
    assert (
        "unsupported_transaction_type:SetRegularKey"
        in signer.last_decision.fired_reasons
    )


def test_refuses_setregularkey_removal(keystore, passphrase):
    # Even *removing* a regular key (regular_key omitted) is not the payment path's
    # job; it is a governance change that must be authorized out of band.
    signer = _signer(keystore, passphrase, whitelist=(DEST, TREASURY))
    with pytest.raises(ExternalSignerRefused):
        signer.sign(SetRegularKey(account=TREASURY))
    assert signer.last_decision.risk_level == "REFUSED"


# -- live treasury-config guard vetoes a would-be-GREEN payment -------------


def _green_payment():
    return Payment(
        account=TREASURY, amount="1000000", destination=DEST,
        sequence=1, fee="20", last_ledger_sequence=100_000, signing_pub_key="",
    )


def test_treasury_guard_blocks_green_payment_when_config_tampered(keystore, passphrase):
    # The Auditor would say GREEN, but the live-config guard vetoes: no signature.
    signer = _signer(
        keystore, passphrase, whitelist=(DEST,),
        guard=StaticTreasuryConfigVerifier(ok=False, reason="signer list changed"),
    )
    with pytest.raises(ExternalSignerRefused) as exc:
        signer.sign(_green_payment())
    assert "config guard blocked" in str(exc.value)
    assert signer.last_decision.risk_level == "REFUSED"
    assert any(
        "treasury_config_violation" in r for r in signer.last_decision.fired_reasons
    )


def test_treasury_guard_allows_green_payment_when_config_ok(keystore, passphrase, recwarn):
    signer = _signer(
        keystore, passphrase, whitelist=(DEST,),
        guard=StaticTreasuryConfigVerifier(ok=True),
    )
    out = signer.sign(_green_payment())
    assert set(out) == {"tx_blob", "hash"}
    assert signer.last_decision.risk_level == "GREEN"
    # A wired guard means the 'not wired' warning is NOT emitted.
    assert not any(
        issubclass(w.category, TreasuryGuardNotWiredWarning) for w in recwarn.list
    )


class _FakeAcctInfoClient:
    """Minimal xrpl-py-style client for one account_info call in a wiring test."""

    def __init__(self, result):
        self._result = result

    def request(self, request):
        return Response(
            status=ResponseStatus.SUCCESS, result=self._result, type=ResponseType.RESPONSE
        )


def test_live_guard_regular_key_blocks_green_payment(keystore, passphrase):
    # End to end: a live XrplTreasuryConfigVerifier over a fake account_info that
    # reports a RegularKey on the treasury -> a GREEN payment is refused.
    result = {
        "account_data": {
            "Account": TREASURY,
            "Flags": LSF_DISABLE_MASTER,
            "RegularKey": OTHER,
        },
        "signer_lists": [],
    }
    signer = _signer(
        keystore, passphrase, whitelist=(DEST,),
        guard=XrplTreasuryConfigVerifier(_FakeAcctInfoClient(result)),
    )
    with pytest.raises(ExternalSignerRefused) as exc:
        signer.sign(_green_payment())
    assert "RegularKey" in str(exc.value)


# -- agent identity: "is this agent legitimate / who controls it" ------------

AGENT_CRED_TYPE = "AGENT_OPERATOR"
TRUSTED_ISSUER = "ra5nK24KXen9AHvsdFTKHSANinZseWnPcX"
UNTRUSTED_ISSUER = "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW"


class _FakeCredClient:
    """xrpl-py-style client returning one credential page for account_objects.

    Echoes the requested account back as Subject so it works for whichever
    signer address the ExternalSigner asks about.
    """

    def __init__(self, *, issuer, accepted=True, cred_type=None):
        self._issuer = issuer
        self._accepted = accepted
        self._type = cred_type or normalize_credential_type(AGENT_CRED_TYPE)

    def request(self, request):
        subject = getattr(request, "account")
        obj = {
            "LedgerEntryType": "Credential",
            "Subject": subject,
            "Issuer": self._issuer,
            "CredentialType": self._type,
            "Flags": LSF_CREDENTIAL_ACCEPTED if self._accepted else 0,
        }
        return Response(
            status=ResponseStatus.SUCCESS,
            result={"account_objects": [obj]},
            type=ResponseType.RESPONSE,
        )


def test_refuses_green_payment_when_agent_identity_unverified(keystore, passphrase):
    signer = _signer(
        keystore, passphrase, whitelist=(DEST,),
        identity=StaticAgentIdentityVerifier(ok=False, reason="unaccredited agent"),
    )
    with pytest.raises(ExternalSignerRefused) as exc:
        signer.sign(_green_payment())
    assert "agent identity could not be verified" in str(exc.value)
    assert signer.last_decision.risk_level == "REFUSED"
    assert any(
        "agent_identity_unverified" in r for r in signer.last_decision.fired_reasons
    )


def test_signs_green_payment_when_agent_identity_verified(keystore, passphrase, recwarn):
    signer = _signer(
        keystore, passphrase, whitelist=(DEST,),
        identity=StaticAgentIdentityVerifier(ok=True),
    )
    out = signer.sign(_green_payment())
    assert set(out) == {"tx_blob", "hash"}
    assert signer.last_decision.risk_level == "GREEN"
    # A wired verifier means the 'not wired' warning is NOT emitted.
    assert not any(
        issubclass(w.category, AgentIdentityNotWiredWarning) for w in recwarn.list
    )


def test_live_identity_verifier_accepts_recognized_issuer(keystore, passphrase):
    signer = _signer(
        keystore, passphrase, whitelist=(DEST,),
        identity=XrplAgentIdentityVerifier(_FakeCredClient(issuer=TRUSTED_ISSUER)),
        issuers=(TRUSTED_ISSUER,),
        cred_type=AGENT_CRED_TYPE,
    )
    out = signer.sign(_green_payment())
    assert set(out) == {"tx_blob", "hash"}


def test_live_identity_verifier_refuses_untrusted_issuer(keystore, passphrase):
    # End to end: the agents hold a credential of the right type, but from an
    # issuer this treasury does not recognize -> no signature.
    signer = _signer(
        keystore, passphrase, whitelist=(DEST,),
        identity=XrplAgentIdentityVerifier(_FakeCredClient(issuer=UNTRUSTED_ISSUER)),
        issuers=(TRUSTED_ISSUER,),
        cred_type=AGENT_CRED_TYPE,
    )
    with pytest.raises(ExternalSignerRefused) as exc:
        signer.sign(_green_payment())
    assert "recognized-issuer set" in str(exc.value)


def test_live_identity_verifier_refuses_unaccepted_credential(keystore, passphrase):
    signer = _signer(
        keystore, passphrase, whitelist=(DEST,),
        identity=XrplAgentIdentityVerifier(
            _FakeCredClient(issuer=TRUSTED_ISSUER, accepted=False)
        ),
        issuers=(TRUSTED_ISSUER,),
        cred_type=AGENT_CRED_TYPE,
    )
    with pytest.raises(ExternalSignerRefused) as exc:
        signer.sign(_green_payment())
    assert "NOT accepted" in str(exc.value)


# -- refusal alerting: observational, never changes the refusal --------------


class _RecordingSink(RefusalAlertSink):
    def __init__(self):
        self.calls = []

    def notify(self, decision, *, tx_type):
        self.calls.append((decision, tx_type))

    @property
    def is_live(self):
        return True


class _RaisingSink(RefusalAlertSink):
    def notify(self, decision, *, tx_type):
        raise RuntimeError("alert channel down")


def test_alert_sink_fires_on_refusal(keystore, passphrase):
    sink = _RecordingSink()
    signer = _signer(keystore, passphrase, whitelist=(DEST, TREASURY), alert_sink=sink)
    with pytest.raises(ExternalSignerRefused):
        signer.sign(_signerlistset())
    assert len(sink.calls) == 1
    decision, tx_type = sink.calls[0]
    assert tx_type == "SignerListSet"
    assert "unsupported_transaction_type:SignerListSet" in decision.fired_reasons


def test_alert_delivery_failure_never_changes_refusal(keystore, passphrase):
    signer = _signer(keystore, passphrase, whitelist=(DEST, TREASURY), alert_sink=_RaisingSink())
    with pytest.warns(AlertDeliveryFailedWarning):
        with pytest.raises(ExternalSignerRefused):
            signer.sign(_signerlistset())


def test_null_alert_sink_is_inert_on_refusal(keystore, passphrase):
    signer = _signer(keystore, passphrase, whitelist=(DEST, TREASURY), alert_sink=NullAlertSink())
    with pytest.raises(ExternalSignerRefused):
        signer.sign(_signerlistset())
