"""Live RWA ledger reads — exercised against a fake XRPL client, not a
network. Mirrors the FakeKms pattern in conftest.py: a realistic stand-in for
the real client's request/response shape, so these tests prove the flag- and
object-parsing logic is correct without adding any network dependency to the
suite. Combined with test_rwa_rule.py, this closes the loop end-to-end: real
ledger JSON shapes in -> RwaTransfer -> RwaComplianceRule findings.
"""

from __future__ import annotations

import time

import pytest
from xrpl.models.response import Response, ResponseStatus, ResponseType

from quorumvault.policy.intent import Credential, PaymentIntent, RwaTransfer
from quorumvault.policy.ledger_reader import (
    LSF_CREDENTIAL_ACCEPTED,
    LSF_MPT_CAN_CLAWBACK,
    LSF_MPT_CAN_TRANSFER,
    LSF_MPT_REQUIRE_AUTH,
    LSF_MPTOKEN_AUTHORIZED,
    RIPPLE_EPOCH_OFFSET,
    ComplianceReadError,
    StaticComplianceReader,
    XrplLedgerComplianceReader,
    _credential_type_from_hex,
    _credential_type_to_hex,
)
from quorumvault.policy.risk_engine import RiskEngine, RiskLevel
from quorumvault.policy.rwa_rule import RwaComplianceRule

ISSUER = "rIssuer00000000000000000000000000"
DEST = "rDestination000000000000000000000"
ISSUANCE = "000004C463C52827307480341125DA0577DEFC38405B0E3E"
DOMAIN = "3DFA1DDEA27AF7E466DE395CCB16158E07ECA6BC4EB5580F75EBD39DE833645F"
ACCRED = Credential(issuer=ISSUER, credential_type="ACCREDITED")
KYC = Credential(issuer=ISSUER, credential_type="KYC")


class FakeXrplClient:
    """Stands in for an xrpl-py sync Client (e.g. JsonRpcClient).

    Configured directly with the ledger JSON each lookup should return (or
    None for "object does not exist"), so tests exercise
    XrplLedgerComplianceReader's parsing against realistic on-ledger shapes.
    """

    def __init__(self):
        self.issuances: dict[str, dict] = {}
        self.mptokens: dict[tuple, dict] = {}
        self.domains: dict[str, dict] = {}
        self.credentials: dict[tuple, dict] = {}
        self.raise_on_request: Exception | None = None

    def request(self, request):
        if self.raise_on_request is not None:
            raise self.raise_on_request
        if getattr(request, "mpt_issuance", None) is not None:
            return self._respond(self.issuances.get(request.mpt_issuance))
        if getattr(request, "mptoken", None) is not None:
            key = (request.mptoken.mpt_issuance_id, request.mptoken.account)
            return self._respond(self.mptokens.get(key))
        if getattr(request, "credential", None) is not None:
            c = request.credential
            key = (c.subject, c.issuer, c.credential_type)
            return self._respond(self.credentials.get(key))
        if getattr(request, "index", None) is not None:
            return self._respond(self.domains.get(request.index))
        raise AssertionError(f"FakeXrplClient doesn't know how to handle {request!r}")

    @staticmethod
    def _respond(node):
        if node is None:
            return Response(
                status=ResponseStatus.ERROR,
                result={"error": "entryNotFound"},
                type=ResponseType.RESPONSE,
            )
        return Response(
            status=ResponseStatus.SUCCESS,
            result={"node": node},
            type=ResponseType.RESPONSE,
        )


def _issuance(flags: int, issuer: str = ISSUER) -> dict:
    return {
        "LedgerEntryType": "MPTokenIssuance",
        "Flags": flags,
        "Issuer": issuer,
        "AssetScale": 2,
        "OutstandingAmount": "100",
    }


def _mptoken(flags: int) -> dict:
    return {"LedgerEntryType": "MPToken", "Account": DEST, "Flags": flags, "MPTAmount": "0"}


def _credential_node(accepted: bool, expiration: int | None = None) -> dict:
    node = {
        "LedgerEntryType": "Credential",
        "Flags": LSF_CREDENTIAL_ACCEPTED if accepted else 0,
    }
    if expiration is not None:
        node["Expiration"] = expiration
    return node


def _domain(accepted_credentials: list) -> dict:
    return {
        "LedgerEntryType": "PermissionedDomain",
        "Owner": ISSUER,
        "Sequence": 1,
        "AcceptedCredentials": [
            {"Credential": {"Issuer": c.issuer, "CredentialType": _credential_type_to_hex(c.credential_type)}}
            for c in accepted_credentials
        ],
    }


def _client_with(
    *,
    issuance_flags: int,
    dest_mptoken_flags: int | None = 0,
    domain_credentials: list | None = None,
    held_credentials: dict | None = None,
):
    """Build a FakeXrplClient pre-loaded with one issuance/destination pair.

    held_credentials maps Credential -> (accepted: bool, expiration: int|None);
    absent entries mean "no Credential object exists" (entryNotFound).
    """
    client = FakeXrplClient()
    client.issuances[ISSUANCE] = _issuance(issuance_flags)
    if dest_mptoken_flags is not None:
        client.mptokens[(ISSUANCE, DEST)] = _mptoken(dest_mptoken_flags)
    if domain_credentials is not None:
        client.domains[DOMAIN] = _domain(domain_credentials)
    for cred, (accepted, expiration) in (held_credentials or {}).items():
        key = (DEST, cred.issuer, _credential_type_to_hex(cred.credential_type))
        client.credentials[key] = _credential_node(accepted, expiration)
    return client


# -- flag/field parsing ---------------------------------------------------


def test_fully_compliant_mpt_resolves_clean_and_matches_rule():
    client = _client_with(
        issuance_flags=LSF_MPT_REQUIRE_AUTH | LSF_MPT_CAN_TRANSFER,
        dest_mptoken_flags=LSF_MPTOKEN_AUTHORIZED,
        domain_credentials=[ACCRED],
        held_credentials={ACCRED: (True, None)},
    )
    reader = XrplLedgerComplianceReader(client)
    rwa = reader.resolve(
        mpt_issuance_id=ISSUANCE,
        destination=DEST,
        required_credentials=[ACCRED],
        domain_id=DOMAIN,
    )
    assert rwa.requires_authorization is True
    assert rwa.destination_authorized is True
    assert rwa.transfer_disabled is False
    assert rwa.clawback_enabled is False
    assert rwa.destination_in_domain is True
    assert rwa.destination_credentials == [ACCRED]
    assert RwaComplianceRule().evaluate(rwa) == []


def test_no_mptoken_object_means_not_authorized_not_an_error():
    client = _client_with(
        issuance_flags=LSF_MPT_REQUIRE_AUTH | LSF_MPT_CAN_TRANSFER,
        dest_mptoken_flags=None,  # no MPToken object at all for this holder
    )
    reader = XrplLedgerComplianceReader(client)
    rwa = reader.resolve(mpt_issuance_id=ISSUANCE, destination=DEST)
    assert rwa.destination_authorized is False
    codes = [f.code for f in RwaComplianceRule().evaluate(rwa)]
    assert "rwa_destination_not_authorized" in codes


def test_mptoken_exists_but_authorized_flag_unset():
    client = _client_with(
        issuance_flags=LSF_MPT_REQUIRE_AUTH | LSF_MPT_CAN_TRANSFER,
        dest_mptoken_flags=0,  # object exists, lsfMPTAuthorized not set
    )
    reader = XrplLedgerComplianceReader(client)
    rwa = reader.resolve(mpt_issuance_id=ISSUANCE, destination=DEST)
    assert rwa.destination_authorized is False


def test_transfer_disabled_unless_destination_is_issuer():
    client = _client_with(issuance_flags=0)  # lsfMPTCanTransfer NOT set
    reader = XrplLedgerComplianceReader(client)
    rwa = reader.resolve(mpt_issuance_id=ISSUANCE, destination=DEST)
    assert rwa.transfer_disabled is True
    assert rwa.destination_is_issuer is False

    rwa_to_issuer = reader.resolve(mpt_issuance_id=ISSUANCE, destination=ISSUER)
    assert rwa_to_issuer.destination_is_issuer is True


def test_clawback_flag_surfaces_as_yellow_via_rule():
    client = _client_with(issuance_flags=LSF_MPT_CAN_TRANSFER | LSF_MPT_CAN_CLAWBACK)
    reader = XrplLedgerComplianceReader(client)
    rwa = reader.resolve(mpt_issuance_id=ISSUANCE, destination=DEST)
    assert rwa.clawback_enabled is True
    findings = RwaComplianceRule().evaluate(rwa)
    assert [f.severity for f in findings] == ["YELLOW"]
    assert findings[0].code == "rwa_clawback_exposure"


# -- domain membership: OR semantics ---------------------------------------


def test_domain_membership_is_or_not_and():
    client = _client_with(
        issuance_flags=LSF_MPT_CAN_TRANSFER,
        domain_credentials=[ACCRED, KYC],
        held_credentials={ACCRED: (True, None)},  # holds only ONE of the two
    )
    reader = XrplLedgerComplianceReader(client)
    rwa = reader.resolve(mpt_issuance_id=ISSUANCE, destination=DEST, domain_id=DOMAIN)
    assert rwa.destination_in_domain is True  # any one accepted credential is sufficient


def test_domain_membership_false_when_no_accepted_credential_held():
    client = _client_with(
        issuance_flags=LSF_MPT_CAN_TRANSFER,
        domain_credentials=[ACCRED, KYC],
        held_credentials={},  # holds neither
    )
    reader = XrplLedgerComplianceReader(client)
    rwa = reader.resolve(mpt_issuance_id=ISSUANCE, destination=DEST, domain_id=DOMAIN)
    assert rwa.destination_in_domain is False
    codes = [f.code for f in RwaComplianceRule().evaluate(rwa)]
    assert "rwa_destination_outside_permissioned_domain" in codes


# -- credential validity: accepted + not expired ---------------------------


def test_credential_not_yet_accepted_does_not_count():
    client = _client_with(
        issuance_flags=LSF_MPT_CAN_TRANSFER,
        held_credentials={ACCRED: (False, None)},  # issued, not yet accepted
    )
    reader = XrplLedgerComplianceReader(client)
    rwa = reader.resolve(
        mpt_issuance_id=ISSUANCE, destination=DEST, required_credentials=[ACCRED]
    )
    assert rwa.destination_credentials == []


def test_expired_credential_does_not_count():
    expired = int(time.time()) - RIPPLE_EPOCH_OFFSET - 10  # 10s in the past
    client = _client_with(
        issuance_flags=LSF_MPT_CAN_TRANSFER,
        held_credentials={ACCRED: (True, expired)},
    )
    reader = XrplLedgerComplianceReader(client)
    rwa = reader.resolve(
        mpt_issuance_id=ISSUANCE, destination=DEST, required_credentials=[ACCRED]
    )
    assert rwa.destination_credentials == []


def test_unexpired_credential_counts():
    future = int(time.time()) - RIPPLE_EPOCH_OFFSET + 3600  # 1h from now
    client = _client_with(
        issuance_flags=LSF_MPT_CAN_TRANSFER,
        held_credentials={ACCRED: (True, future)},
    )
    reader = XrplLedgerComplianceReader(client)
    rwa = reader.resolve(
        mpt_issuance_id=ISSUANCE, destination=DEST, required_credentials=[ACCRED]
    )
    assert rwa.destination_credentials == [ACCRED]


def test_required_credentials_use_and_semantics():
    client = _client_with(
        issuance_flags=LSF_MPT_CAN_TRANSFER,
        held_credentials={ACCRED: (True, None)},  # missing KYC
    )
    reader = XrplLedgerComplianceReader(client)
    rwa = reader.resolve(
        mpt_issuance_id=ISSUANCE,
        destination=DEST,
        required_credentials=[ACCRED, KYC],
    )
    assert rwa.destination_credentials == [ACCRED]
    codes = [f.code for f in RwaComplianceRule().evaluate(rwa)]
    assert "rwa_missing_required_credential" in codes


# -- fail-closed behaviour ---------------------------------------------------


def test_missing_issuance_raises_compliance_read_error():
    client = FakeXrplClient()  # nothing registered -> entryNotFound
    reader = XrplLedgerComplianceReader(client)
    with pytest.raises(ComplianceReadError):
        reader.resolve(mpt_issuance_id=ISSUANCE, destination=DEST)


def test_missing_domain_raises_compliance_read_error():
    client = _client_with(issuance_flags=LSF_MPT_CAN_TRANSFER)  # domain never registered
    reader = XrplLedgerComplianceReader(client)
    with pytest.raises(ComplianceReadError):
        reader.resolve(mpt_issuance_id=ISSUANCE, destination=DEST, domain_id=DOMAIN)


def test_network_failure_raises_compliance_read_error_not_silent_compliance():
    client = _client_with(issuance_flags=LSF_MPT_CAN_TRANSFER)
    client.raise_on_request = ConnectionError("server unreachable")
    reader = XrplLedgerComplianceReader(client)
    with pytest.raises(ComplianceReadError):
        reader.resolve(mpt_issuance_id=ISSUANCE, destination=DEST)


def test_unrecognized_server_error_raises_rather_than_assumes_false():
    client = FakeXrplClient()
    client.issuances[ISSUANCE] = _issuance(LSF_MPT_CAN_TRANSFER)
    # Simulate a non-"entryNotFound" server error on the MPToken lookup.
    orig_request = client.request

    def flaky_request(request):
        if getattr(request, "mptoken", None) is not None:
            return Response(
                status=ResponseStatus.ERROR,
                result={"error": "noPermission"},
                type=ResponseType.RESPONSE,
            )
        return orig_request(request)

    client.request = flaky_request
    reader = XrplLedgerComplianceReader(client)
    with pytest.raises(ComplianceReadError):
        reader.resolve(mpt_issuance_id=ISSUANCE, destination=DEST)


# -- StaticComplianceReader (dry-run placeholder) ---------------------------


def test_static_compliance_reader_returns_fixed_transfer_and_is_not_live():
    fixed = RwaTransfer(requires_authorization=True, destination_authorized=True)
    reader = StaticComplianceReader(fixed, source="demo-fixture")
    result = reader.resolve(mpt_issuance_id=ISSUANCE, destination=DEST)
    assert result is fixed
    assert reader.is_live is False
    assert reader.source == "demo-fixture"


def test_xrpl_reader_is_live():
    client = _client_with(issuance_flags=LSF_MPT_CAN_TRANSFER)
    assert XrplLedgerComplianceReader(client).is_live is True


# -- credential_type hex round trip -----------------------------------------


def test_credential_type_hex_round_trip():
    assert _credential_type_from_hex(_credential_type_to_hex("ACCREDITED")) == "ACCREDITED"


def test_credential_type_from_hex_falls_back_safely_on_non_utf8():
    # 0xFF alone is not valid UTF-8 -> falls back to the raw hex rather than raising.
    assert _credential_type_from_hex("FF") == "FF"


# -- end-to-end through the risk engine -------------------------------------


def test_engine_integration_live_resolved_transfer_trips_breaker():
    client = _client_with(
        issuance_flags=LSF_MPT_REQUIRE_AUTH | LSF_MPT_CAN_TRANSFER,
        dest_mptoken_flags=None,  # unauthorized holder
    )
    reader = XrplLedgerComplianceReader(client)
    rwa = reader.resolve(mpt_issuance_id=ISSUANCE, destination=DEST)

    engine = RiskEngine(whitelist=[DEST], amount_threshold_rlusd=5000, frequency_limit=10)
    intent = PaymentIntent(destination=DEST, asset="RLUSD", amount=100, rwa=rwa)
    result = engine.evaluate(intent)
    assert result["risk_level"] == RiskLevel.RED
    assert "rwa_destination_not_authorized" in result["fired_reasons"]
    assert engine.circuit_breaker_tripped is True
