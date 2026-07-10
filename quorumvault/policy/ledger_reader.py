"""Live XRPL ledger reads for the RWA compliance rule — an injectable seam.

``RwaComplianceRule.evaluate()`` (``rwa_rule.py``) is a pure function over an
already-resolved :class:`~quorumvault.policy.intent.RwaTransfer`. It never
touches the network, by design, so it stays fast and fully testable offline.
Something still has to *produce* that ``RwaTransfer`` from real chain state in
production. That is this module's only job, following the same
injectable-seam pattern already used elsewhere in QuorumVault for value
conversion (``RateProvider``, ``policy/pricing.py``) and signing
(``SignerBackend``, ``signing/backend.py``):

* :class:`LedgerComplianceReader` — the abstract seam. The engine/caller
  depends on this, never on ``xrpl-py`` directly.
* :class:`XrplLedgerComplianceReader` — the real implementation, backed by
  any ``xrpl-py`` sync ``Client`` (e.g. ``xrpl.clients.JsonRpcClient``
  pointed at Testnet or Mainnet — the network is entirely the caller's
  choice, never hardcoded here, same rule already applied to signing
  backends and rate providers).
* :class:`StaticComplianceReader` — a fixed, explicitly-labelled
  placeholder for dry runs and demos, mirroring ``StaticRateProvider``.

Field and flag names below (``lsfMPTRequireAuth``, ``lsfMPTCanTransfer``,
``lsfMPTCanClawback``, ``lsfMPTAuthorized``, ``lsfAccepted``,
``AcceptedCredentials``, ...) are taken directly from the current XRPL
ledger-format reference (xrpl.org), not reconstructed from memory, and
verified against the ``account_objects``/``ledger_entry`` request models
shipped in the locally installed ``xrpl-py`` 5.0.0.

Fail-closed, not fail-open. If a ledger read errors for any reason other than
a well-formed "this object doesn't exist" response, :class:`ComplianceReadError`
is raised rather than guessing. A treasury control that quietly defaults an
unreadable compliance check to "compliant" is worse than one that blocks and
asks a human to look. A confirmed "doesn't exist" (no ``MPToken`` object for
this holder, no matching ``Credential``) is a real, valid negative answer, not
a read failure, and resolves to the correct ``False``/empty value.

Known limitation: this reader handles MPT-based RWAs only (``token_kind ==
"MPT"``), matching everything actually implemented elsewhere in this
codebase today. IOU-based clawback exposure (the other half of the
``token_kind`` field on ``RwaTransfer``) is out of scope until something
in QuorumVault actually issues or moves IOUs — see the root README roadmap.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any, List, Optional

from xrpl.models.requests.ledger_entry import Credential as _LedgerEntryCredentialQuery
from xrpl.models.requests.ledger_entry import LedgerEntry
from xrpl.models.requests.ledger_entry import MPToken as _LedgerEntryMPTokenQuery

from .intent import Credential, RwaTransfer

# --- MPTokenIssuance ledger-object flags (XLS-33) --------------------------
LSF_MPT_LOCKED = 0x00000001
LSF_MPT_CAN_LOCK = 0x00000002
LSF_MPT_REQUIRE_AUTH = 0x00000004
LSF_MPT_CAN_ESCROW = 0x00000008
LSF_MPT_CAN_TRADE = 0x00000010
LSF_MPT_CAN_TRANSFER = 0x00000020
LSF_MPT_CAN_CLAWBACK = 0x00000040

# --- MPToken (per-holder) ledger-object flags -------------------------------
LSF_MPTOKEN_LOCKED = 0x00000001
LSF_MPTOKEN_AUTHORIZED = 0x00000002

# --- Credential ledger-object flags (XLS-70) --------------------------------
LSF_CREDENTIAL_ACCEPTED = 0x00010000

# Ripple Epoch (2000-01-01T00:00:00Z) offset from Unix epoch, in seconds.
RIPPLE_EPOCH_OFFSET = 946684800


class ComplianceReadError(Exception):
    """A live ledger read could not be resolved to a trustworthy answer.

    Raised on network/transport failure, or on any server response that is
    neither a clean success nor a well-formed "object not found" — i.e.
    whenever the reader cannot honestly say True or False. Callers must treat
    this as a reason to block the transfer, never as a reason to assume
    compliance.
    """


def _credential_type_to_hex(credential_type: str) -> str:
    """Encode a plain-string credential type as the hex XRPL expects on-ledger.

    ``RwaTransfer``/``Credential`` (``intent.py``) deal in human-readable
    strings like ``"ACCREDITED"`` (see ``tests/test_rwa_rule.py``); the ledger
    stores ``CredentialType`` as an arbitrary hex blob. Round-tripped by
    :func:`_credential_type_from_hex` below.
    """
    return credential_type.encode("utf-8").hex().upper()


def _credential_type_from_hex(hex_value: str) -> str:
    """Best-effort decode of an on-ledger hex ``CredentialType`` back to a
    plain string, so it equality-matches caller-supplied ``Credential``
    objects. ``CredentialType`` is documented as "arbitrary data" — if it
    isn't valid UTF-8, fall back to the raw hex rather than raising. That
    fallback simply will not equality-match a plain-string requirement,
    which is the safe failure mode (treated as a different/unknown
    credential), not a crash.
    """
    try:
        return bytes.fromhex(hex_value).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return hex_value


class LedgerComplianceReader(ABC):
    """Resolve a live :class:`RwaTransfer` compliance context from XRPL state.

    The engine and :class:`~quorumvault.policy.rwa_rule.RwaComplianceRule`
    never depend on this directly — they depend on the ``RwaTransfer`` it
    produces. Swapping a live reader for a test double is invisible above
    this seam, exactly like ``RateProvider`` and ``SignerBackend``.
    """

    @abstractmethod
    def resolve(
        self,
        *,
        mpt_issuance_id: str,
        destination: str,
        required_credentials: Optional[List[Credential]] = None,
        domain_id: Optional[str] = None,
    ) -> RwaTransfer:
        """Build a fully-resolved ``RwaTransfer`` for one proposed transfer.

        Args:
            mpt_issuance_id: The ``MPTokenIssuanceID`` of the asset being
                moved (hex string).
            destination: The classic address receiving the transfer.
            required_credentials: Credentials policy requires the
                destination to hold, independent of any permissioned domain.
                AND semantics: every one of these must be present, accepted,
                and unexpired.
            domain_id: If the asset is restricted to a Permissioned Domain,
                its ledger object ID. Domain membership is OR semantics per
                XRPL's own rule (xrpl.org: "Any account that holds *at least
                one* matching credential automatically gains access to the
                domain") — holding any one of the domain's accepted
                credentials is sufficient.
        """

    @property
    def is_live(self) -> bool:
        """False for placeholders; production RWA gating should require True."""
        return False


class StaticComplianceReader(LedgerComplianceReader):
    """A fixed, explicitly-labelled ``RwaTransfer`` for dry runs and demos.

    Mirrors ``StaticRateProvider``: NOT a live ledger read. ``is_live`` is
    False so an audit can detect its use. Useful for offline demo scripts
    that want to exercise the RWA-aware code path without a live server.
    """

    def __init__(self, transfer: RwaTransfer, source: str = "static-placeholder"):
        self._transfer = transfer
        self.source = source

    def resolve(
        self,
        *,
        mpt_issuance_id: str,
        destination: str,
        required_credentials: Optional[List[Credential]] = None,
        domain_id: Optional[str] = None,
    ) -> RwaTransfer:
        return self._transfer


class XrplLedgerComplianceReader(LedgerComplianceReader):
    """Resolves ``RwaTransfer`` context from a real XRPL server via ``xrpl-py``.

    Takes any ``xrpl-py`` sync ``Client`` (e.g. ``xrpl.clients.JsonRpcClient``)
    — or, for tests, anything exposing the same ``.request(request) ->
    Response`` method. Which network it points at (Testnet, Devnet, Mainnet)
    is entirely the caller's decision, never hardcoded here.

    Issues up to a handful of ``ledger_entry`` reads per :meth:`resolve` call
    (the issuance, the destination's ``MPToken``, optionally the domain and
    each credential involved) — appropriate for a pre-transfer compliance
    gate, not a hot loop.
    """

    def __init__(self, client: Any):
        self._client = client

    @property
    def is_live(self) -> bool:
        return True

    def resolve(
        self,
        *,
        mpt_issuance_id: str,
        destination: str,
        required_credentials: Optional[List[Credential]] = None,
        domain_id: Optional[str] = None,
    ) -> RwaTransfer:
        required_credentials = list(required_credentials or [])

        issuance = self._get_mpt_issuance(mpt_issuance_id)
        flags = int(issuance.get("Flags", 0))
        issuer = issuance.get("Issuer", "")

        requires_authorization = bool(flags & LSF_MPT_REQUIRE_AUTH)
        transfer_disabled = not bool(flags & LSF_MPT_CAN_TRANSFER)
        clawback_enabled = bool(flags & LSF_MPT_CAN_CLAWBACK)
        destination_is_issuer = destination == issuer

        destination_authorized = self._get_destination_authorized(
            mpt_issuance_id, destination
        )

        destination_credentials = [
            cred for cred in required_credentials if self._holds_credential(destination, cred)
        ]

        destination_in_domain: Optional[bool] = None
        if domain_id:
            accepted = self._get_domain_accepted_credentials(domain_id)
            destination_in_domain = any(
                self._holds_credential(destination, cred) for cred in accepted
            )

        return RwaTransfer(
            is_rwa=True,
            token_kind="MPT",
            requires_authorization=requires_authorization,
            destination_authorized=destination_authorized,
            transfer_disabled=transfer_disabled,
            destination_is_issuer=destination_is_issuer,
            clawback_enabled=clawback_enabled,
            required_credentials=required_credentials,
            destination_credentials=destination_credentials,
            domain_id=domain_id,
            destination_in_domain=destination_in_domain,
        )

    # -- individual ledger reads --------------------------------------

    def _request(self, request: Any) -> Any:
        try:
            return self._client.request(request)
        except Exception as exc:  # network/transport failure of any kind
            raise ComplianceReadError(
                f"ledger read failed ({type(exc).__name__}): {exc}"
            ) from exc

    def _get_mpt_issuance(self, mpt_issuance_id: str) -> dict:
        response = self._request(LedgerEntry(mpt_issuance=mpt_issuance_id))
        if response.is_successful():
            return response.result.get("node", response.result)
        error = response.result.get("error")
        if error == "entryNotFound":
            raise ComplianceReadError(
                f"MPTokenIssuance {mpt_issuance_id} does not exist on-ledger; "
                "cannot evaluate RWA compliance for an asset that isn't real."
            )
        raise ComplianceReadError(f"ledger_entry(mpt_issuance) failed: {error}")

    def _get_destination_authorized(self, mpt_issuance_id: str, destination: str) -> bool:
        query = _LedgerEntryMPTokenQuery(
            mpt_issuance_id=mpt_issuance_id, account=destination
        )
        response = self._request(LedgerEntry(mptoken=query))
        if response.is_successful():
            node = response.result.get("node", response.result)
            flags = int(node.get("Flags", 0))
            return bool(flags & LSF_MPTOKEN_AUTHORIZED)
        error = response.result.get("error")
        if error == "entryNotFound":
            # No MPToken object for this holder at all -> definitely not an
            # authorized holder. A real, valid negative, not a read failure.
            return False
        raise ComplianceReadError(f"ledger_entry(mptoken) failed: {error}")

    def _get_domain_accepted_credentials(self, domain_id: str) -> List[Credential]:
        response = self._request(LedgerEntry(index=domain_id))
        if not response.is_successful():
            error = response.result.get("error")
            if error == "entryNotFound":
                raise ComplianceReadError(
                    f"PermissionedDomain {domain_id} does not exist on-ledger."
                )
            raise ComplianceReadError(
                f"ledger_entry(permissioned_domain) failed: {error}"
            )
        node = response.result.get("node", response.result)
        accepted: List[Credential] = []
        for entry in node.get("AcceptedCredentials", []):
            cred = entry.get("Credential", entry)
            accepted.append(
                Credential(
                    issuer=cred["Issuer"],
                    credential_type=_credential_type_from_hex(cred["CredentialType"]),
                )
            )
        return accepted

    def _holds_credential(self, destination: str, credential: Credential) -> bool:
        query = _LedgerEntryCredentialQuery(
            subject=destination,
            issuer=credential.issuer,
            credential_type=_credential_type_to_hex(credential.credential_type),
        )
        response = self._request(LedgerEntry(credential=query))
        if not response.is_successful():
            error = response.result.get("error")
            if error == "entryNotFound":
                return False
            raise ComplianceReadError(f"ledger_entry(credential) failed: {error}")
        node = response.result.get("node", response.result)
        flags = int(node.get("Flags", 0))
        if not (flags & LSF_CREDENTIAL_ACCEPTED):
            return False  # issued but not yet accepted by the subject
        expiration = node.get("Expiration")
        if expiration is not None:
            now_ripple_epoch = int(time.time()) - RIPPLE_EPOCH_OFFSET
            if now_ripple_epoch >= int(expiration):
                return False  # expired
        return True
