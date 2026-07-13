"""Live treasury-configuration guard — verify the multisig account is really 2-of-2.

Wietse Wind's review flagged "the different scenarios to take into account when
people change their signer list / remove / bypass with regular key". The
ExternalSigner already refuses every non-Payment, so ``SignerListSet`` /
``AccountSet`` / ``SetRegularKey`` are never auto-signed through the payment path
(see ``integrations/external_signer.py`` and
``tests/test_external_signer_adversarial.py``). That closes the half where
QuorumVault itself would *make* a bypass.

The other half is a *live* check: before QuorumVault actually co-signs, confirm
the treasury account's real on-ledger state still makes the 2-of-2 the only way
to move funds. This module is that check, following the exact injectable-seam
pattern of ``policy/ledger_reader.py``:

* :class:`TreasuryConfigVerifier` — the abstract seam. Callers depend on this,
  never on ``xrpl-py`` directly.
* :class:`XrplTreasuryConfigVerifier` — the real implementation over any
  ``xrpl-py`` sync ``Client``; which network it points at is entirely the
  caller's choice, never hardcoded here.
* :class:`StaticTreasuryConfigVerifier` — a fixed, explicitly-labelled
  placeholder for dry runs and demos (``is_live == False``), mirroring
  ``StaticComplianceReader``.

It verifies three things about the treasury AccountRoot and its SignerList:

1. **No Regular Key.** A ``RegularKey`` on the account is an alternate single-key
   authorization path that bypasses the 2-of-2 entirely. An absent field means
   none is set (the safe state).
2. **Master key disabled.** ``lsfDisableMaster`` must be set in ``Flags``, or the
   account's own master key can still sign a transaction unilaterally.
3. **SignerList is the expected quorum.** Exactly one SignerList, whose members
   are exactly ``expected_signers``, whose ``SignerQuorum`` equals
   ``expected_quorum``, and in which no single signer's weight alone meets quorum
   (the no-unilateral invariant that is QuorumVault's whole reason to exist).

Fail closed, never fail open (mirrors ``ComplianceReadError``): any read failure,
malformed response, or unmet condition raises :class:`TreasuryConfigError`. A
treasury control that silently treats an unreadable or altered account as "still
safe" is worse than one that blocks and asks a human to look.

Empirical field/flag references (verified 2026-07-14 against primary sources, not
memory):

* Request model: ``xrpl.models.requests.AccountInfo(account=..., signer_lists=True)``
  — confirmed by ``inspect.getsource`` on the installed xrpl-py 5.0.0; ``signer_lists``
  is a real request field there.
* ``RegularKey`` — AccountRoot field, JSON key ``"RegularKey"`` (AccountID; optional,
  omitted when unset). xrpl.org AccountRoot ledger-entry reference.
* ``lsfDisableMaster = 0x00100000`` (decimal 1048576) — xrpl.org AccountRoot "Flags"
  table (corresponds to ``asfDisableMaster``). xrpl-py 5.0.0 exports no constant for
  this ledger flag, so it is defined here from the primary source. (Several unrelated
  *transaction* ``tf`` flags happen to share the value 0x00100000 in their own
  namespaces; this is the AccountRoot *ledger* flag, a distinct namespace.)
* SignerList shape — the ``signer_lists`` array holds exactly one SignerList with
  ``SignerEntries`` (each ``{"SignerEntry": {"Account", "SignerWeight"}}``) and a
  top-level ``SignerQuorum``. xrpl.org SignerList ledger-entry + account_info method
  references. ``account_info`` returns ``signer_lists`` at the response root under
  API v2 (the installed xrpl-py default) and nested under ``account_data`` under API
  v1 — both locations are handled below rather than assuming one.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterable, Optional, Set, Tuple

from xrpl.models.requests import AccountInfo

# AccountRoot ledger flag: master key disabled. Verified against xrpl.org's
# AccountRoot "Flags" reference (2026-07-14): lsfDisableMaster = 0x00100000.
LSF_DISABLE_MASTER = 0x00100000


class TreasuryConfigError(Exception):
    """The treasury's live on-ledger config is not the expected, unbypassable 2-of-2.

    Raised on any read failure, malformed response, OR any of: a RegularKey set,
    the master key still enabled, or a SignerList that does not exactly match the
    expected signers/quorum (including a single signer heavy enough to meet quorum
    alone). Never defaulted to "assume the account is safe" — callers must treat
    this as a hard reason not to sign.
    """


class TreasuryGuardNotWiredWarning(UserWarning):
    """Emitted when a signature is produced with no treasury guard wired.

    Not an error (offline demos and the existing test fixtures sign without a live
    server), but a loud, non-silent signal that any real treasury MUST wire an
    :class:`XrplTreasuryConfigVerifier`.
    """


class TreasuryConfigVerifier(ABC):
    """Verify that a treasury account's live config makes the 2-of-2 unbypassable."""

    @abstractmethod
    def verify(
        self,
        *,
        treasury_address: str,
        expected_signers: Iterable[str],
        expected_quorum: int,
    ) -> None:
        """Return ``None`` if the config is exactly as expected; else raise
        :class:`TreasuryConfigError`.

        Deliberately returns nothing rather than a boolean: a silent ``False`` that
        a caller might forget to check is exactly the fail-open mode this guard
        exists to prevent.
        """

    @property
    def is_live(self) -> bool:
        """False for placeholders; production gating should require True."""
        return False


class StaticTreasuryConfigVerifier(TreasuryConfigVerifier):
    """A fixed, explicitly-labelled verifier for offline tests and demos.

    Mirrors ``StaticComplianceReader``: NOT a live ledger read; ``is_live`` is
    False so an audit can detect its use. ``ok=True`` passes silently; ``ok=False``
    raises, so a demo or test can exercise both branches without a server.
    """

    def __init__(self, *, ok: bool = True, reason: str = "static-placeholder"):
        self._ok = ok
        self._reason = reason

    def verify(self, *, treasury_address, expected_signers, expected_quorum) -> None:
        if not self._ok:
            raise TreasuryConfigError(
                f"StaticTreasuryConfigVerifier configured to fail: {self._reason}"
            )


class XrplTreasuryConfigVerifier(TreasuryConfigVerifier):
    """Verifies treasury config from a real XRPL server via ``xrpl-py``.

    Takes any ``xrpl-py`` sync ``Client`` (e.g. ``xrpl.clients.JsonRpcClient``) —
    or, for tests, anything exposing ``.request(request) -> Response``. Which
    network it points at (Testnet, Devnet, Mainnet) is entirely the caller's
    decision, never hardcoded here. Issues a single ``account_info`` request (with
    ``signer_lists=True``) per :meth:`verify` — a pre-sign gate, not a hot loop.
    """

    def __init__(self, client: Any):
        self._client = client

    @property
    def is_live(self) -> bool:
        return True

    def verify(self, *, treasury_address, expected_signers, expected_quorum) -> None:
        account_data, signer_lists = self._read_account(treasury_address)
        self._check_no_regular_key(account_data)
        self._check_master_disabled(account_data)
        self._check_signer_list(
            signer_lists, set(expected_signers), int(expected_quorum)
        )

    # -- read -----------------------------------------------------------
    def _read_account(self, treasury_address: str) -> Tuple[dict, Optional[list]]:
        try:
            response = self._client.request(
                AccountInfo(account=treasury_address, signer_lists=True)
            )
        except Exception as exc:  # network/transport failure of any kind
            raise TreasuryConfigError(
                f"account_info read failed ({type(exc).__name__}): {exc}"
            ) from exc
        if not response.is_successful():
            error = (
                response.result.get("error")
                if isinstance(response.result, dict)
                else response.result
            )
            raise TreasuryConfigError(
                f"account_info for treasury {treasury_address} failed: {error}"
            )
        result = response.result
        if not isinstance(result, dict):
            raise TreasuryConfigError("account_info response has no result object.")
        account_data = result.get("account_data")
        if not isinstance(account_data, dict):
            raise TreasuryConfigError(
                "account_info response missing account_data; cannot verify treasury config."
            )
        # signer_lists lives at the response root under API v2 (installed xrpl-py
        # default) and nested under account_data under API v1. Check both.
        signer_lists = result.get("signer_lists")
        if signer_lists is None:
            signer_lists = account_data.get("signer_lists")
        return account_data, signer_lists

    # -- individual checks ---------------------------------------------
    @staticmethod
    def _check_no_regular_key(account_data: dict) -> None:
        regular_key = account_data.get("RegularKey")
        if regular_key:
            raise TreasuryConfigError(
                f"treasury has a RegularKey set ({regular_key}); that is a single-key "
                "authorization path around the 2-of-2 quorum. Refusing to sign."
            )

    @staticmethod
    def _check_master_disabled(account_data: dict) -> None:
        flags = int(account_data.get("Flags", 0))
        if not (flags & LSF_DISABLE_MASTER):
            raise TreasuryConfigError(
                "treasury master key is NOT disabled (lsfDisableMaster unset in "
                f"Flags={flags}); the master key could sign unilaterally. Refusing."
            )

    @staticmethod
    def _check_signer_list(
        signer_lists: Optional[list], expected_signers: Set[str], expected_quorum: int
    ) -> None:
        if not signer_lists:
            raise TreasuryConfigError(
                "treasury has no SignerList on-ledger; the 2-of-2 quorum is not "
                "configured. Refusing to sign."
            )
        if len(signer_lists) != 1:
            raise TreasuryConfigError(
                f"treasury has {len(signer_lists)} SignerLists; expected exactly one."
            )
        signer_list = signer_lists[0]
        if not isinstance(signer_list, dict):
            raise TreasuryConfigError(
                "malformed SignerList object in account_info response."
            )

        quorum = signer_list.get("SignerQuorum")
        if quorum != expected_quorum:
            raise TreasuryConfigError(
                f"treasury SignerQuorum is {quorum!r}; expected {expected_quorum}. "
                "The quorum weight has changed. Refusing."
            )

        entries = signer_list.get("SignerEntries")
        if not isinstance(entries, list) or not entries:
            raise TreasuryConfigError("SignerList has no SignerEntries. Refusing.")

        actual_signers: Set[str] = set()
        for wrapped in entries:
            entry = wrapped.get("SignerEntry") if isinstance(wrapped, dict) else None
            if not isinstance(entry, dict):
                raise TreasuryConfigError(
                    "malformed SignerEntry in treasury SignerList. Refusing."
                )
            account = entry.get("Account")
            if not account:
                raise TreasuryConfigError("SignerEntry missing Account. Refusing.")
            weight = int(entry.get("SignerWeight", 0))
            # No single signer may meet quorum alone — the no-unilateral invariant
            # that is the whole point of a 2-of-2 treasury.
            if weight >= expected_quorum:
                raise TreasuryConfigError(
                    f"signer {account} has weight {weight} >= quorum {expected_quorum}; "
                    "it could authorize a transaction alone. Refusing."
                )
            actual_signers.add(account)

        if actual_signers != expected_signers:
            raise TreasuryConfigError(
                f"treasury SignerList members {sorted(actual_signers)} do not match "
                f"the expected quorum {sorted(expected_signers)}. Signers have been "
                "added/removed/changed. Refusing."
            )
