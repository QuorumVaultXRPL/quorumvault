"""AgentIdentityVerifier: the XLS-70 credential check, against a fake XRPL client
(no network). Mirrors the FakeXrplClient/Response pattern in
tests/test_ledger_reader.py and the structure of tests/test_treasury_guard.py.

Answers the two questions the risk engine and treasury guard do not: is this
agent legitimate, and who vouches for it.
"""

from __future__ import annotations

import time

import pytest
from xrpl.models.response import Response, ResponseStatus, ResponseType

from quorumvault.policy.agent_identity import (
    LSF_CREDENTIAL_ACCEPTED,
    RIPPLE_EPOCH_OFFSET,
    AgentIdentityError,
    StaticAgentIdentityVerifier,
    XrplAgentIdentityVerifier,
    normalize_credential_type,
)

SIGNER = "rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"
TRUSTED_ISSUER = "ra5nK24KXen9AHvsdFTKHSANinZseWnPcX"
OTHER_TRUSTED = "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW"
UNTRUSTED_ISSUER = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
SOMEONE_ELSE = "rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce"

CRED_TYPE = "AGENT_OPERATOR"
CRED_HEX = normalize_credential_type(CRED_TYPE)
OTHER_HEX = normalize_credential_type("SOMETHING_ELSE")
NOW_RIPPLE = int(time.time()) - RIPPLE_EPOCH_OFFSET


class FakeCredentialClient:
    """Stands in for an xrpl-py sync Client for account_objects(type=credential).

    Configured with a list of ``(objects, marker)`` pages so the verifier's
    parsing and pagination run against realistic response shapes, no network.
    """

    def __init__(self, pages=None, *, error=None, raise_exc=None):
        self.pages = pages if pages is not None else [([], None)]
        self.error = error
        self.raise_exc = raise_exc
        self.calls = 0
        self.last_request = None

    def request(self, request):
        self.last_request = request
        if self.raise_exc is not None:
            raise self.raise_exc
        if self.error is not None:
            return Response(
                status=ResponseStatus.ERROR,
                result={"error": self.error},
                type=ResponseType.RESPONSE,
            )
        objects, marker = self.pages[self.calls]
        self.calls += 1
        result = {"account": SIGNER, "account_objects": objects}
        if marker:
            result["marker"] = marker
        return Response(
            status=ResponseStatus.SUCCESS, result=result, type=ResponseType.RESPONSE
        )


def _credential(
    *, issuer=TRUSTED_ISSUER, subject=SIGNER, cred_type=CRED_HEX,
    accepted=True, expiration=None,
):
    entry = {
        "LedgerEntryType": "Credential",
        "Subject": subject,
        "Issuer": issuer,
        "CredentialType": cred_type,
        "Flags": LSF_CREDENTIAL_ACCEPTED if accepted else 0,
    }
    if expiration is not None:
        entry["Expiration"] = expiration
    return entry


def _verify(client, *, issuers=(TRUSTED_ISSUER,), cred_type=CRED_TYPE):
    XrplAgentIdentityVerifier(client).verify(
        signer_address=SIGNER,
        recognized_issuers=issuers,
        required_credential_type=cred_type,
    )


# -- happy path -------------------------------------------------------------


def test_valid_credential_passes():
    _verify(FakeCredentialClient([([_credential()], None)]))


def test_valid_credential_with_future_expiration_passes():
    _verify(
        FakeCredentialClient([([_credential(expiration=NOW_RIPPLE + 3600)], None)])
    )


def test_valid_from_any_recognized_issuer_passes():
    _verify(
        FakeCredentialClient([([_credential(issuer=OTHER_TRUSTED)], None)]),
        issuers=(TRUSTED_ISSUER, OTHER_TRUSTED),
    )


def test_request_filters_to_credential_type():
    client = FakeCredentialClient([([_credential()], None)])
    _verify(client)
    assert getattr(client.last_request, "account") == SIGNER
    assert getattr(client.last_request, "type").value == "credential"


# -- the credential is missing ----------------------------------------------


def test_no_credential_at_all_is_rejected():
    with pytest.raises(AgentIdentityError) as exc:
        _verify(FakeCredentialClient([([], None)]))
    assert "no credential of the required type" in str(exc.value)


def test_revoked_credential_is_rejected():
    # XLS-70 revocation == CredentialDelete == the entry is removed from the
    # ledger. A revoked credential is therefore the SAME observable state as one
    # that never existed; both must refuse. The message says so explicitly rather
    # than pretending the ledger can tell them apart.
    with pytest.raises(AgentIdentityError) as exc:
        _verify(FakeCredentialClient([([], None)]))
    assert "revoked" in str(exc.value)


# -- the credential exists but is not usable --------------------------------


def test_untrusted_issuer_is_rejected():
    with pytest.raises(AgentIdentityError) as exc:
        _verify(FakeCredentialClient([([_credential(issuer=UNTRUSTED_ISSUER)], None)]))
    assert "not in the recognized-issuer set" in str(exc.value)


def test_wrong_credential_type_is_rejected():
    with pytest.raises(AgentIdentityError) as exc:
        _verify(FakeCredentialClient([([_credential(cred_type=OTHER_HEX)], None)]))
    assert "not of the required type" in str(exc.value)


def test_issued_but_not_accepted_is_rejected():
    # lsfAccepted unset: the issuer created it, the subject never accepted it.
    # xrpl.org: "meaning it is not yet valid". Issuance alone is insufficient.
    with pytest.raises(AgentIdentityError) as exc:
        _verify(FakeCredentialClient([([_credential(accepted=False)], None)]))
    assert "NOT accepted" in str(exc.value)


def test_expired_credential_is_rejected():
    with pytest.raises(AgentIdentityError) as exc:
        _verify(
            FakeCredentialClient([([_credential(expiration=NOW_RIPPLE - 60)], None)])
        )
    assert "expired" in str(exc.value)


def test_credential_this_account_issued_to_someone_else_does_not_count():
    # account_objects returns an entry for BOTH its Subject and its Issuer.
    # A credential this signer ISSUED must never be mistaken for one it HOLDS.
    with pytest.raises(AgentIdentityError):
        _verify(
            FakeCredentialClient(
                [([_credential(subject=SOMEONE_ELSE, issuer=SIGNER)], None)]
            )
        )


# -- pagination -------------------------------------------------------------


def test_empty_page_with_marker_keeps_paging():
    # xrpl.org warns account_objects may return an EMPTY page while more data
    # remains; only a missing marker means the end. Stopping early would
    # false-negative a perfectly valid credential.
    client = FakeCredentialClient([([], "marker-1"), ([_credential()], None)])
    _verify(client)
    assert client.calls == 2


def test_paging_beyond_max_pages_fails_closed():
    verifier = XrplAgentIdentityVerifier(
        FakeCredentialClient([([], "m")] * 5), max_pages=3
    )
    with pytest.raises(AgentIdentityError) as exc:
        verifier.verify(
            signer_address=SIGNER,
            recognized_issuers=(TRUSTED_ISSUER,),
            required_credential_type=CRED_TYPE,
        )
    assert "exceeded" in str(exc.value)


# -- misconfiguration and read failures fail closed -------------------------


def test_empty_recognized_issuer_set_is_rejected():
    # An empty trusted-issuer set must never mean "trust anybody".
    with pytest.raises(AgentIdentityError) as exc:
        _verify(FakeCredentialClient([([_credential()], None)]), issuers=())
    assert "no recognized credential issuers" in str(exc.value)


def test_missing_required_credential_type_is_rejected():
    with pytest.raises(AgentIdentityError) as exc:
        _verify(FakeCredentialClient([([_credential()], None)]), cred_type="")
    assert "no required_credential_type" in str(exc.value)


def test_account_not_found_fails_closed():
    with pytest.raises(AgentIdentityError) as exc:
        _verify(FakeCredentialClient(error="actNotFound"))
    assert "does not exist on-ledger" in str(exc.value)


def test_generic_read_error_fails_closed():
    with pytest.raises(AgentIdentityError):
        _verify(FakeCredentialClient(error="lgrNotFound"))


def test_transport_exception_fails_closed():
    with pytest.raises(AgentIdentityError):
        _verify(FakeCredentialClient(raise_exc=RuntimeError("connection reset")))


# -- placeholder + is_live --------------------------------------------------


def test_static_verifier_ok_passes_and_is_not_live():
    verifier = StaticAgentIdentityVerifier(ok=True)
    assert verifier.is_live is False
    verifier.verify(
        signer_address=SIGNER,
        recognized_issuers=(TRUSTED_ISSUER,),
        required_credential_type=CRED_TYPE,
    )  # no raise


def test_static_verifier_fail_raises():
    with pytest.raises(AgentIdentityError):
        StaticAgentIdentityVerifier(ok=False, reason="unaccredited").verify(
            signer_address=SIGNER,
            recognized_issuers=(TRUSTED_ISSUER,),
            required_credential_type=CRED_TYPE,
        )


def test_xrpl_verifier_is_live():
    assert XrplAgentIdentityVerifier(FakeCredentialClient()).is_live is True


def test_credential_type_is_hex_encoded_exactly():
    # CredentialType is a hex Blob on-ledger and matched on exact bytes;
    # XLS-70 defines no wildcard or hierarchy.
    assert normalize_credential_type("AGENT_OPERATOR") == (
        "AGENT_OPERATOR".encode("utf-8").hex().upper()
    )
    assert normalize_credential_type("4142", already_hex=True) == "4142"
