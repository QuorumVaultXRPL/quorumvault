"""Agent identity verification — is the signing agent legitimate, and who vouches for it?

QuorumVault already answers *what* an agent may spend (``risk_engine.py``, the
tier router, ``rwa_rule.py``) and *whether custody is intact* (``treasury_guard.py``).
It does not, by itself, answer **"is this agent legitimate"** or **"who controls
it"**. This module is that check — a *verifier* in the runtime / controller /
verifier split: before QuorumVault co-signs anything, confirm the account holding
the signing keys is the subject of a live, accepted, unexpired XRPL Credential
(XLS-70) issued by an issuer the treasury operator recognizes.

Deliberate scope boundary: QuorumVault **consumes** credentials, it never issues
them. There is no issuer, registry, or revocation-management code here and there
should not be — deciding *who counts as legitimate* is somebody else's job
(a KYC/KYB issuer). QuorumVault stays the controller/enforcer.

Same injectable-seam pattern already proven twice in this codebase
(``policy/ledger_reader.py``, ``policy/treasury_guard.py``):

* :class:`AgentIdentityVerifier` — the abstract seam. Callers depend on this,
  never on ``xrpl-py`` directly.
* :class:`XrplAgentIdentityVerifier` — the real implementation over any
  ``xrpl-py`` sync ``Client``; which network it points at is entirely the
  caller's choice, never hardcoded here.
* :class:`StaticAgentIdentityVerifier` — a labelled placeholder for dry runs and
  demos (``is_live == False``).

**Nothing here is hardcoded.** Recognized issuers and the required credential
type are always caller-supplied, exactly like ``expected_signers`` /
``expected_quorum`` in ``treasury_guard.py``. QuorumVault ships no opinion about
who is a trustworthy identity issuer. An *empty* recognized-issuer set is treated
as a configuration error and refused, never as "trust anyone".

Fail closed, never fail open (mirrors ``ComplianceReadError`` /
``TreasuryConfigError``): any read failure, malformed response, or unmet
condition raises :class:`AgentIdentityError`.

Empirical field/flag references (verified 2026-07-21 against primary sources,
not memory):

* **Read method.** ``account_objects(account=<subject>, type="credential")`` —
  ``AccountObjectType.CREDENTIAL`` exists in the installed xrpl-py 5.0.0
  (enum inspection). This is used in preference to the
  ``ledger_entry(credential=...)`` lookup that ``ledger_reader.py`` uses for the
  RWA destination check, and the difference is deliberate: ``ledger_entry``
  answers only "does this exact (subject, issuer, type) triple exist", which
  collapses *untrusted issuer* and *wrong type* into an indistinguishable
  "not found", and would need one round-trip per recognized issuer. One
  ``account_objects`` call covers every recognized issuer at once and preserves
  the distinction, which matters for an auditable refusal reason.
* **Paging trap.** xrpl.org's account_objects reference warns the
  ``account_objects`` array "may be empty even if there are additional ledger
  entries to retrieve... especially likely when using ``type`` to filter"; the
  presence of ``marker`` — not a non-empty page — is what signals more data.
  This implementation keeps paging while a ``marker`` is returned.
* **Ownership trap.** account_objects returns a credential for *both* its
  ``Subject`` and its ``Issuer`` (the entry is linked into both owner
  directories — see ``SubjectNode``/``IssuerNode`` on the Credential entry), so
  every object is filtered on ``Subject == signer_address``. Without that filter
  a credential this account *issued to somebody else* would be miscounted as a
  credential it *holds*.
* **Credential entry fields** (xrpl.org Credential ledger-entry reference):
  ``Subject`` and ``Issuer`` (AccountID, required), ``CredentialType``
  (**hex-encoded** Blob, required), ``Expiration`` (UInt32, optional, seconds
  since the Ripple Epoch), ``URI`` (optional).
* **Accepted vs merely issued.** ``lsfAccepted = 0x00010000`` (65536): "If
  enabled, the subject of the credential has accepted the credential. Otherwise,
  the issuer created the credential but the subject has not yet accepted it,
  **meaning it is not yet valid**." Issuance alone is therefore NOT sufficient.
* **Revocation.** ``CredentialDelete`` *removes the entry from the ledger*
  ("effectively revoking it"; the concept page: "To revoke a credential, Isabel
  can delete it from the ledger"). Consequence, stated plainly because it shapes
  the API: **a revoked credential and a never-issued credential are the same
  observable state** — the entry is simply absent. Current ledger state cannot
  distinguish them, so this module does not pretend to; both produce the same
  "no valid credential" refusal. (Distinguishing them would require scanning
  transaction history for a ``CredentialDelete``, which is unbounded and
  unavailable on non-full-history servers — deliberately out of scope.) An
  *expired but not yet deleted* credential IS distinguishable and gets its own
  refusal reason.
* **Matching is exact.** A Credential entry's ID is the SHA-512Half of
  (``0x0044`` space key, ``Subject``, ``Issuer``, ``CredentialType``), so the
  type is matched on exact bytes. XLS-70 defines no hierarchy or wildcard for
  ``CredentialType``; any such notion would be caller-side policy, not protocol.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable, List, Optional

from xrpl.models.requests import AccountObjects
from xrpl.models.requests.account_objects import AccountObjectType

# --- Credential ledger-object flags (XLS-70) --------------------------------
# Verified against xrpl.org's Credential ledger-entry "Flags" table (2026-07-21).
# Intentionally re-declared here rather than imported from ledger_reader.py so
# this module stays self-contained; the values are identical by construction.
LSF_CREDENTIAL_ACCEPTED = 0x00010000

# Ripple Epoch (2000-01-01T00:00:00Z) offset from the Unix epoch, in seconds.
RIPPLE_EPOCH_OFFSET = 946684800

# Safety bound on account_objects pagination. A signer account holding more
# credential pages than this is refused rather than decided on partial data.
DEFAULT_MAX_CREDENTIAL_PAGES = 20


class AgentIdentityError(Exception):
    """The signing agent's identity could not be verified against a recognized issuer.

    Raised on any read failure, malformed response, missing configuration, OR any
    of: no credential of the required type from a recognized issuer, a credential
    that exists but has not been accepted by its subject, or one that has expired.
    Never defaulted to "assume the agent is legitimate" — callers must treat this
    as a hard reason not to sign.
    """


class AgentIdentityNotWiredWarning(UserWarning):
    """Emitted when a signature is produced with no agent-identity verifier wired.

    Not an error (offline demos and the existing test fixtures sign without a live
    server), but a loud, non-silent signal that a production deployment claiming
    to be identity-aware MUST wire an :class:`XrplAgentIdentityVerifier`.
    """


def _credential_type_to_hex(credential_type: str) -> str:
    """Encode a plain-string credential type as the hex XRPL stores on-ledger.

    ``CredentialType`` is a hex-encoded Blob on the ledger; callers configure a
    human-readable string like ``"AGENT_OPERATOR"``. Matches the encoding
    convention already used for the RWA credential check in ``ledger_reader.py``.
    A caller who already has hex may pass it through
    :func:`normalize_credential_type` instead.
    """
    return credential_type.encode("utf-8").hex().upper()


def normalize_credential_type(credential_type: str, *, already_hex: bool = False) -> str:
    """Return the canonical uppercase hex form of a credential type."""
    if already_hex:
        return credential_type.upper()
    return _credential_type_to_hex(credential_type)


class AgentIdentityVerifier(ABC):
    """Verify that a signing agent holds a recognized, valid identity credential."""

    @abstractmethod
    def verify(
        self,
        *,
        signer_address: str,
        recognized_issuers: Iterable[str],
        required_credential_type: str,
    ) -> None:
        """Return ``None`` if the agent's identity checks out; else raise
        :class:`AgentIdentityError`.

        Deliberately returns nothing rather than a boolean: a silent ``False`` a
        caller might forget to check is exactly the fail-open mode this verifier
        exists to prevent (same discipline as :class:`TreasuryConfigVerifier`).
        """

    @property
    def is_live(self) -> bool:
        """False for placeholders; production gating should require True."""
        return False


class StaticAgentIdentityVerifier(AgentIdentityVerifier):
    """A fixed, explicitly-labelled verifier for offline tests and demos.

    Mirrors ``StaticComplianceReader`` / ``StaticTreasuryConfigVerifier``: NOT a
    live ledger read; ``is_live`` is False so an audit can detect its use.
    ``ok=True`` passes silently; ``ok=False`` raises, so both branches are
    exercisable without a server.
    """

    def __init__(self, *, ok: bool = True, reason: str = "static-placeholder"):
        self._ok = ok
        self._reason = reason

    def verify(
        self, *, signer_address, recognized_issuers, required_credential_type
    ) -> None:
        if not self._ok:
            raise AgentIdentityError(
                f"StaticAgentIdentityVerifier configured to fail: {self._reason}"
            )


class XrplAgentIdentityVerifier(AgentIdentityVerifier):
    """Verifies an agent's XLS-70 Credential from a real XRPL server via ``xrpl-py``.

    Takes any ``xrpl-py`` sync ``Client`` (e.g. ``xrpl.clients.JsonRpcClient``) —
    or, for tests, anything exposing ``.request(request) -> Response``. Which
    network it points at is entirely the caller's decision, never hardcoded here.

    Issues one ``account_objects(type="credential")`` read per verified address
    (plus one per extra page, if the account holds many credentials) — a pre-sign
    gate, not a hot loop.
    """

    def __init__(self, client: Any, *, max_pages: int = DEFAULT_MAX_CREDENTIAL_PAGES):
        self._client = client
        self._max_pages = max_pages

    @property
    def is_live(self) -> bool:
        return True

    def verify(
        self,
        *,
        signer_address: str,
        recognized_issuers: Iterable[str],
        required_credential_type: str,
    ) -> None:
        issuers = {i for i in (recognized_issuers or []) if i}
        if not issuers:
            # An empty issuer set must never mean "trust anybody".
            raise AgentIdentityError(
                "no recognized credential issuers configured; refusing rather than "
                "accepting a credential from any issuer. QuorumVault does not ship "
                "a default trusted-issuer list - the treasury operator supplies one."
            )
        if not required_credential_type:
            raise AgentIdentityError(
                "no required_credential_type configured; refusing rather than "
                "accepting a credential of any type."
            )
        required_hex = normalize_credential_type(required_credential_type)

        credentials = self._fetch_credentials(signer_address)

        # Track the most specific near-miss so the refusal is actually auditable.
        saw_not_accepted = False
        saw_expired = False
        saw_untrusted_issuer = False
        saw_wrong_type = False

        for cred in credentials:
            cred_type = str(cred.get("CredentialType", "")).upper()
            issuer = cred.get("Issuer")
            type_matches = cred_type == required_hex
            issuer_recognized = issuer in issuers

            if type_matches and issuer_recognized:
                if not self._is_accepted(cred):
                    saw_not_accepted = True
                    continue
                if self._is_expired(cred):
                    saw_expired = True
                    continue
                return  # valid, accepted, unexpired, recognized issuer -> pass
            if type_matches and not issuer_recognized:
                saw_untrusted_issuer = True
            elif issuer_recognized and not type_matches:
                saw_wrong_type = True

        raise AgentIdentityError(
            self._refusal_reason(
                signer_address=signer_address,
                required_credential_type=required_credential_type,
                saw_not_accepted=saw_not_accepted,
                saw_expired=saw_expired,
                saw_untrusted_issuer=saw_untrusted_issuer,
                saw_wrong_type=saw_wrong_type,
            )
        )

    # -- reasoning ------------------------------------------------------
    @staticmethod
    def _refusal_reason(
        *,
        signer_address: str,
        required_credential_type: str,
        saw_not_accepted: bool,
        saw_expired: bool,
        saw_untrusted_issuer: bool,
        saw_wrong_type: bool,
    ) -> str:
        who = f"signer {signer_address} credential {required_credential_type!r}"
        if saw_not_accepted:
            return (
                f"{who}: a matching credential exists from a recognized issuer but "
                "the subject has NOT accepted it (lsfAccepted unset), so it is not "
                "yet valid. Issuance alone is not sufficient."
            )
        if saw_expired:
            return f"{who}: the matching credential from a recognized issuer has expired."
        if saw_untrusted_issuer:
            return (
                f"{who}: a credential of the required type exists, but its issuer is "
                "not in the recognized-issuer set configured for this treasury."
            )
        if saw_wrong_type:
            return (
                f"{who}: the signer holds a credential from a recognized issuer, but "
                "not of the required type (CredentialType is matched on exact bytes; "
                "XLS-70 defines no wildcard or hierarchy)."
            )
        return (
            f"{who}: no credential of the required type from any recognized issuer. "
            "Note: an absent credential is indistinguishable on-ledger between "
            "'never issued' and 'revoked' - CredentialDelete removes the entry."
        )

    # -- individual checks ---------------------------------------------
    @staticmethod
    def _is_accepted(credential: Dict[str, Any]) -> bool:
        flags = int(credential.get("Flags", 0) or 0)
        return bool(flags & LSF_CREDENTIAL_ACCEPTED)

    @staticmethod
    def _is_expired(credential: Dict[str, Any]) -> bool:
        expiration = credential.get("Expiration")
        if expiration is None:
            return False  # no expiry set == does not expire
        now_ripple_epoch = int(time.time()) - RIPPLE_EPOCH_OFFSET
        return now_ripple_epoch >= int(expiration)

    # -- read -----------------------------------------------------------
    def _fetch_credentials(self, signer_address: str) -> List[Dict[str, Any]]:
        """All Credential entries where ``signer_address`` is the **Subject**."""
        found: List[Dict[str, Any]] = []
        marker: Optional[Any] = None
        for _page in range(self._max_pages):
            request = (
                AccountObjects(
                    account=signer_address,
                    type=AccountObjectType.CREDENTIAL,
                    marker=marker,
                )
                if marker is not None
                else AccountObjects(
                    account=signer_address, type=AccountObjectType.CREDENTIAL
                )
            )
            response = self._request(request)
            if not response.is_successful():
                error = (
                    response.result.get("error")
                    if isinstance(response.result, dict)
                    else response.result
                )
                if error == "actNotFound":
                    raise AgentIdentityError(
                        f"signer account {signer_address} does not exist on-ledger; "
                        "cannot verify the identity of an account that isn't real."
                    )
                raise AgentIdentityError(
                    f"account_objects(credential) for {signer_address} failed: {error}"
                )
            result = response.result
            if not isinstance(result, dict):
                raise AgentIdentityError(
                    "account_objects response has no result object."
                )
            for obj in result.get("account_objects") or []:
                if not isinstance(obj, dict):
                    continue
                entry_type = obj.get("LedgerEntryType")
                if entry_type is not None and entry_type != "Credential":
                    continue
                # Only credentials this account HOLDS, not ones it issued to others.
                if obj.get("Subject") != signer_address:
                    continue
                found.append(obj)
            marker = result.get("marker")
            # An empty page does NOT mean the end: only a missing marker does.
            if not marker:
                return found
        raise AgentIdentityError(
            f"account_objects paging for {signer_address} exceeded "
            f"{self._max_pages} pages; refusing rather than deciding on partial data."
        )

    def _request(self, request: Any) -> Any:
        try:
            return self._client.request(request)
        except Exception as exc:  # network/transport failure of any kind
            raise AgentIdentityError(
                f"credential read failed ({type(exc).__name__}): {exc}"
            ) from exc
