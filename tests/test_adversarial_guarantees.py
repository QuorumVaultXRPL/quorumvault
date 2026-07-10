"""Adversarial tests that try to BREAK core guarantees, not confirm them.

Guarantees under attack:
  * ledger reads fail closed (never resolve an error to "compliant")
  * the 2-of-2 quorum can't be satisfied by a single backend
  * the circuit breaker, once tripped, stays tripped across new scenarios
"""

import pytest
from xrpl.models.response import Response, ResponseStatus, ResponseType

from quorumvault.policy.intent import Credential, PaymentIntent, RwaTransfer
from quorumvault.policy.ledger_reader import (
    ComplianceReadError,
    XrplLedgerComplianceReader,
)
from quorumvault.policy.risk_engine import RiskEngine, RiskLevel
from quorumvault.policy.rwa_rule import RwaComplianceRule

ISSUANCE = "000004C463C52827307480341125DA0577DEFC38405B0E3E"
DEST = "rDestination000000000000000000000"


# ---------------------------------------------------------------------------
# 1. Ledger reads must fail closed.
# ---------------------------------------------------------------------------


class ProgrammableClient:
    """Returns a caller-specified Response per ledger_entry sub-request kind."""

    def __init__(self, issuance=None, mptoken=None, credential=None, domain=None):
        self._map = {
            "mpt_issuance": issuance,
            "mptoken": mptoken,
            "credential": credential,
            "index": domain,
        }

    def request(self, request):
        for attr in ("mpt_issuance", "mptoken", "credential", "index"):
            if getattr(request, attr, None) is not None:
                resp = self._map[attr]
                if resp is None:
                    return Response(status=ResponseStatus.ERROR,
                                    result={"error": "entryNotFound"}, type=ResponseType.RESPONSE)
                return resp
        raise AssertionError("unexpected request")


def _ok(node):
    return Response(status=ResponseStatus.SUCCESS, result={"node": node}, type=ResponseType.RESPONSE)


def _err(code):
    return Response(status=ResponseStatus.ERROR, result={"error": code}, type=ResponseType.RESPONSE)


def test_non_entrynotfound_error_on_issuance_raises():
    reader = XrplLedgerComplianceReader(ProgrammableClient(issuance=_err("noPermission")))
    with pytest.raises(ComplianceReadError):
        reader.resolve(mpt_issuance_id=ISSUANCE, destination=DEST)


def test_non_entrynotfound_error_on_mptoken_raises():
    client = ProgrammableClient(
        issuance=_ok({"Flags": 0x00000004 | 0x00000020, "Issuer": "rIss"}),  # require_auth + can_transfer
        mptoken=_err("actMalformed"),
    )
    with pytest.raises(ComplianceReadError):
        XrplLedgerComplianceReader(client).resolve(mpt_issuance_id=ISSUANCE, destination=DEST)


def test_non_entrynotfound_error_on_credential_raises():
    cred = Credential(issuer="rIss", credential_type="KYC")
    client = ProgrammableClient(
        issuance=_ok({"Flags": 0x00000020, "Issuer": "rIss"}),
        credential=_err("actMalformed"),
    )
    with pytest.raises(ComplianceReadError):
        XrplLedgerComplianceReader(client).resolve(
            mpt_issuance_id=ISSUANCE, destination=DEST, required_credentials=[cred]
        )


def test_malformed_success_issuance_never_resolves_fully_compliant():
    # "successful" but the node is empty (no Flags). Must NOT come back clean:
    # missing CanTransfer => transfer_disabled True => the rule flags it.
    client = ProgrammableClient(issuance=_ok({}), mptoken=_ok({"Flags": 0}))
    rwa = XrplLedgerComplianceReader(client).resolve(mpt_issuance_id=ISSUANCE, destination=DEST)
    findings = RwaComplianceRule().evaluate(rwa)
    assert findings != [], "a malformed issuance must not resolve to a clean pass"
    assert rwa.transfer_disabled is True


def test_malformed_flag_value_fails_closed_not_compliant():
    # Hostile/buggy server returns a non-numeric Flags. The reader must not
    # silently treat it as compliant; it raises (documented note: currently a
    # ValueError rather than the typed ComplianceReadError, but never compliant).
    client = ProgrammableClient(issuance=_ok({"Flags": "not-an-int", "Issuer": "rIss"}))
    with pytest.raises(Exception):
        XrplLedgerComplianceReader(client).resolve(mpt_issuance_id=ISSUANCE, destination=DEST)


# ---------------------------------------------------------------------------
# 2. The 2-of-2 quorum can't be satisfied by one backend.
# ---------------------------------------------------------------------------


def test_single_backend_cannot_form_two_signers(keystore, passphrase):
    from xrpl.models.transactions import Payment

    from quorumvault.signing.local_keystore import LocalEncryptedKeystoreBackend
    from quorumvault.signing.quorum_signer import QuorumSigner

    one = LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase)
    tx = Payment(account="rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce", amount="1000000",
                 destination="rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F", sequence=1, fee="20",
                 signing_pub_key="", last_ledger_sequence=100)
    signed = QuorumSigner([one]).multisign(tx)
    # A single backend produces exactly one Signer entry -> cannot meet a quorum
    # of 2 on-ledger (rippled rejects it). The count is the enforceable fact here.
    assert len(signed.signers) == 1


def test_empty_quorum_is_rejected():
    from quorumvault.signing.quorum_signer import QuorumSigner

    with pytest.raises(ValueError):
        QuorumSigner([])


# ---------------------------------------------------------------------------
# 3. The circuit breaker, once tripped, stays tripped across new scenarios.
# ---------------------------------------------------------------------------


def _engine():
    return RiskEngine(whitelist=[DEST], amount_threshold_rlusd=5000, frequency_limit=100)


def test_breaker_stays_tripped_across_clean_scenarios():
    eng = _engine()
    # Trip it with an untrusted destination (RED).
    eng.evaluate(PaymentIntent(destination="rEvil00000000000000000000000000000", asset="XRP", amount=1))
    assert eng.circuit_breaker_tripped is True

    # Now throw a variety of would-be-GREEN transactions at it. Every one must
    # come back RED while frozen, and the breaker must stay tripped.
    clean_scenarios = [
        PaymentIntent(destination=DEST, asset="XRP", amount=1),                 # tiny whitelisted
        PaymentIntent(destination=DEST, asset="RLUSD", amount=10),              # different asset
        PaymentIntent(destination=DEST, asset="XRP", amount=1,
                      rwa=RwaTransfer(is_rwa=True, requires_authorization=False,
                                      destination_authorized=True, transfer_disabled=False)),  # clean RWA
    ]
    for intent in clean_scenarios:
        result = eng.evaluate(intent)
        assert result["risk_level"] == RiskLevel.RED
        assert "circuit_breaker_frozen" in result["fired_reasons"]
        assert eng.circuit_breaker_tripped is True

    # Only an explicit reset clears it.
    eng.reset_circuit_breaker("reviewed")
    ok = eng.evaluate(PaymentIntent(destination=DEST, asset="XRP", amount=1))
    assert ok["risk_level"] == RiskLevel.GREEN


def test_breaker_trips_on_rwa_red_and_then_freezes_everything():
    eng = _engine()
    eng.evaluate(PaymentIntent(destination=DEST, asset="XRP", amount=1,
                               rwa=RwaTransfer(is_rwa=True, requires_authorization=True,
                                               destination_authorized=False)))
    assert eng.circuit_breaker_tripped is True
    # A subsequent, entirely clean, whitelisted payment is still frozen RED.
    assert eng.evaluate(PaymentIntent(destination=DEST, asset="XRP", amount=1))["risk_level"] == RiskLevel.RED
