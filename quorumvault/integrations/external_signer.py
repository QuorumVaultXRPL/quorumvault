"""QuorumVault as an ExternalSigner for the XRPL Agent Wallet Skill.

The skill (https://xrpl.org/docs/agents/xrpl-agent-wallet-skill) is explicit that
it does not handle multisig:

    "Multisig. Not in scope. If you're handed a multisig transaction (one
     expecting a Signers array), refuse and tell the human that multisig signing
     is not handled by this skill - the developer needs a dedicated multisig flow."

QuorumVault IS that dedicated multisig flow. Rather than fork or reimplement the
skill, this module plugs QuorumVault into the skill's own production signing
seam, the ExternalSigner contract it defines for HSM/KMS-style signers:

    interface ExternalSigner {
      address: string;
      sign(tx): Promise<{ tx_blob: string; hash: string }>;
    }

Inside sign(), the skill's single "sign" step becomes QuorumVault's full,
risk-gated 2-of-2 multisig: the Auditor Agent (RiskEngine) evaluates the
transaction, the TierRouter records the assurance lane, and only a GREEN verdict
produces a co-signature. A non-GREEN verdict raises ExternalSignerRefused - the
auditor withholding Signature_2.

SCOPE OF THIS SIGNER (a deliberate control, not an incidental one).
This ExternalSigner risk-gates *value movements* (Payment transactions). It
refuses every other transaction type by default. That refusal is explicit and
independent of the risk score, because the risk engine reasons about value, and
administrative/governance transactions - SignerListSet (changes who is in the
quorum), AccountSet (e.g. disabling the master key), SetRegularKey, etc. - carry
no "amount" for it to threshold-check. Auto-signing those through the payment
path would let the value gate go vacuous; they must be authorized out of band.
Likewise, an amount this signer cannot parse into a real number is refused, never
defaulted to zero (a zero amount would make the value threshold structurally
unable to fire and route to the least-scrutinized lane).

LIVE TREASURY-CONFIG GUARD (optional, but required for real treasuries).
Refusing governance transactions stops QuorumVault from *creating* a bypass, but
not one created out of band. An optional injected
:class:`~quorumvault.policy.treasury_guard.TreasuryConfigVerifier` closes that:
before any signature is produced it confirms the treasury's live on-ledger state
still makes the 2-of-2 the only authorization path - no ``RegularKey``, master
key disabled (``lsfDisableMaster``), and a ``SignerList`` that exactly matches the
expected signers and quorum. Following the same precedent as the RWA compliance
reader, a missing guard is not silently treated as safe: signing without one
emits a ``TreasuryGuardNotWiredWarning``.

AGENT IDENTITY (optional, but required for any identity-aware deployment).
The treasury guard answers "is custody intact"; it does not answer "is this
agent legitimate" or "who controls it". An optional injected
:class:`~quorumvault.policy.agent_identity.AgentIdentityVerifier` closes that:
before any signature is produced it confirms each signing agent's account is
the subject of a live, accepted, unexpired XLS-70 Credential issued by an
issuer the treasury operator recognizes. Recognized issuers and the required
credential type are always caller-supplied; QuorumVault consumes credentials
and never issues them. Absent verifier is not silently treated as verified: it
emits an ``AgentIdentityNotWiredWarning``.

Amounts are parsed straight into :class:`~decimal.Decimal` from XRPL's own wire
format (the drops string for XRP, the ``"value"`` decimal string for IOU/MPT) —
never routed through ``float`` at all. See :mod:`quorumvault.policy.money` for
why a bare float has no business carrying a currency amount anywhere in this
codebase; a value the network itself sends as an exact string should stay exact.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import FrozenSet, Iterable, List, Optional

from xrpl.core.binarycodec import encode
from xrpl.models.transactions.transaction import Transaction

from ..policy.agent_identity import (
    AgentIdentityError,
    AgentIdentityNotWiredWarning,
    AgentIdentityVerifier,
)
from ..policy.intent import PaymentIntent
from ..policy.risk_engine import RiskEngine, RiskLevel
from ..policy.treasury_guard import (
    TreasuryConfigError,
    TreasuryConfigVerifier,
    TreasuryGuardNotWiredWarning,
)
from ..signing.quorum_signer import QuorumSigner
from ..tiers.router import TierRouter

# Transaction types this signer will risk-gate and (possibly) co-sign. Everything
# else is refused outright. Default-deny near funds: adding a type here is a
# deliberate decision, not an accident of a fallback value.
DEFAULT_SIGNABLE_TX_TYPES: FrozenSet[str] = frozenset({"Payment"})


class ExternalSignerRefused(Exception):
    """QuorumVault refused to produce a signature.

    Raised when the Auditor withholds its co-signature (a non-GREEN verdict),
    when the transaction type is not one this signer will handle, or when the
    transaction cannot be understood well enough to risk-gate honestly. In every
    case the safe outcome is the same: no signature is produced.
    """


@dataclass
class SignDecision:
    """What QuorumVault decided on the last sign() call (for logging/audit)."""

    tier: str
    risk_level: str
    fired_reasons: List[str] = field(default_factory=list)


class QuorumVaultExternalSigner:
    """A drop-in ``ExternalSigner`` backed by QuorumVault's risk-gated 2-of-2.

    ``address`` is the treasury (multisig) account the transactions are signed
    *for*; the actual signing keys live in the injected ``QuorumSigner`` backends
    (local encrypted keystore, HSM/KMS, or a mix) and never surface here.
    """

    def __init__(
        self,
        *,
        treasury_address: str,
        quorum_signer: QuorumSigner,
        risk_engine: RiskEngine,
        router: Optional[TierRouter] = None,
        signable_transaction_types: Optional[Iterable[str]] = None,
        compliance_reader=None,
        rwa_required_credentials=None,
        rwa_domain_id: Optional[str] = None,
        treasury_guard: Optional[TreasuryConfigVerifier] = None,
        expected_signers: Optional[Iterable[str]] = None,
        expected_signer_quorum: Optional[int] = None,
        agent_identity_verifier: Optional[AgentIdentityVerifier] = None,
        recognized_credential_issuers: Optional[Iterable[str]] = None,
        required_credential_type: Optional[str] = None,
        identity_subjects: Optional[Iterable[str]] = None,
    ):
        self._address = treasury_address
        self._quorum = quorum_signer
        self._risk = risk_engine
        self._router = router
        # Live treasury-config guard: optional injected dependency, same
        # precedent as compliance_reader. When wired, sign() verifies the
        # treasury's live on-ledger 2-of-2 config before co-signing; when
        # absent, sign() still works but emits TreasuryGuardNotWiredWarning
        # (never a silent 'assume safe'). Required for any real treasury.
        self._treasury_guard = treasury_guard
        self._expected_signers = (
            set(expected_signers) if expected_signers is not None else None
        )
        self._expected_signer_quorum = expected_signer_quorum
        # Agent-identity verification - the "is this agent legitimate / who
        # controls it" question the treasury guard does not answer. Optional
        # injected dependency, same precedent as treasury_guard. Recognized
        # issuers and the required credential type are ALWAYS caller-supplied:
        # QuorumVault ships no trusted-issuer list and issues no credentials.
        # Defaults to verifying every signer account in the quorum (the agents
        # themselves); point it elsewhere with identity_subjects.
        self._agent_identity_verifier = agent_identity_verifier
        self._recognized_credential_issuers = list(recognized_credential_issuers or [])
        self._required_credential_type = required_credential_type
        self._identity_subjects = (
            set(identity_subjects) if identity_subjects is not None else None
        )
        # RWA compliance path. If an MPT transfer arrives and no reader is wired,
        # the signer refuses rather than signing an RWA transfer with no
        # compliance check (a deliberate control, not a caller's memory).
        self._compliance_reader = compliance_reader
        self._rwa_required_credentials = list(rwa_required_credentials or [])
        self._rwa_domain_id = rwa_domain_id
        self._signable_types: FrozenSet[str] = (
            frozenset(signable_transaction_types)
            if signable_transaction_types is not None
            else DEFAULT_SIGNABLE_TX_TYPES
        )
        self.last_decision: Optional[SignDecision] = None

    # -- ExternalSigner contract ----------------------------------------
    @property
    def address(self) -> str:
        return self._address

    def sign(self, tx: Transaction) -> dict:
        """Risk-gate, then 2-of-2 multisign. Returns ``{tx_blob, hash}``.

        Raises :class:`ExternalSignerRefused` on an unsupported transaction type,
        an un-valuable transaction, any non-GREEN Auditor verdict, a live
        treasury-config guard violation, or an unverified agent identity.
        """
        tx_type = getattr(tx.transaction_type, "value", str(tx.transaction_type))

        # Deliberate type gate, evaluated before (and independent of) the risk
        # score: this signer only risk-gates value-movement Payments.
        if tx_type not in self._signable_types:
            self.last_decision = SignDecision(
                tier="refused",
                risk_level="REFUSED",
                fired_reasons=[f"unsupported_transaction_type:{tx_type}"],
            )
            raise ExternalSignerRefused(
                f"QuorumVault ExternalSigner refuses to auto-sign a {tx_type}. "
                "Only value-movement Payments are risk-gated here; administrative "
                "or governance transactions that alter custody (SignerListSet, "
                "AccountSet, SetRegularKey, ...) must be authorized out of band, "
                "not through the automated payment path."
            )

        intent = self._intent_from_tx(tx)  # raises if it can't value the tx
        tier = self._router.route(intent).tier.value if self._router else "quorum_backstop"
        verdict = self._risk.evaluate(intent)
        self.last_decision = SignDecision(
            tier=tier,
            risk_level=verdict["risk_level"].value,
            fired_reasons=list(verdict["fired_reasons"]),
        )
        if verdict["risk_level"] != RiskLevel.GREEN:
            raise ExternalSignerRefused(
                "QuorumVault Auditor withheld Signature_2: "
                f"{verdict['risk_level'].value} "
                f"({', '.join(verdict['fired_reasons']) or 'policy violation'})."
            )
        # Final gate before a signature exists: confirm the treasury's live
        # on-ledger config still makes the 2-of-2 the only way to move funds
        # (no RegularKey, master key disabled, SignerList == expected quorum).
        # Directly answers Wietse Wind's signer-list / regular-key bypass point.
        self._verify_treasury_config()
        # ...and confirm the agents themselves are who they claim to be: a
        # live, accepted, unexpired XLS-70 credential from a recognized issuer.
        self._verify_agent_identity()
        signed = self._quorum.multisign(tx)
        return {"tx_blob": encode(signed.to_xrpl()), "hash": signed.get_hash()}

    # -- helpers --------------------------------------------------------
    @property
    def signers_count(self) -> int:
        """How many signatures this signer contributes (multisig fee sizing)."""
        return len(self._quorum.signer_addresses)

    def _verify_treasury_config(self) -> None:
        """Verify the treasury's live 2-of-2 config, or refuse.

        Optional injected guard (same precedent as the RWA compliance reader).
        With a guard wired, a config violation (RegularKey set, master key still
        enabled, or a SignerList that no longer matches the expected quorum)
        raises :class:`ExternalSignerRefused` and no signature is produced. With
        no guard wired the signer still operates but emits a
        :class:`~quorumvault.policy.treasury_guard.TreasuryGuardNotWiredWarning`:
        never a silent 'assume safe'. A live guard is required for any real
        (non-demo) treasury.
        """
        expected_signers = (
            self._expected_signers
            if self._expected_signers is not None
            else set(self._quorum.signer_addresses)
        )
        expected_quorum = (
            self._expected_signer_quorum
            if self._expected_signer_quorum is not None
            else len(self._quorum.signer_addresses)
        )
        if self._treasury_guard is None:
            warnings.warn(
                TreasuryGuardNotWiredWarning(
                    "QuorumVaultExternalSigner produced a signature with no "
                    "treasury_guard wired: the treasury's live on-ledger config "
                    "(RegularKey / lsfDisableMaster / SignerList) was NOT "
                    "verified. Wire an XrplTreasuryConfigVerifier for any real "
                    "treasury."
                ),
                stacklevel=3,
            )
            return
        try:
            self._treasury_guard.verify(
                treasury_address=self._address,
                expected_signers=expected_signers,
                expected_quorum=expected_quorum,
            )
        except TreasuryConfigError as exc:
            self.last_decision = SignDecision(
                tier="refused",
                risk_level="REFUSED",
                fired_reasons=[f"treasury_config_violation:{exc}"],
            )
            raise ExternalSignerRefused(
                "QuorumVault refused: the treasury's live config guard blocked "
                f"signing. {exc}"
            ) from exc

    def _verify_agent_identity(self) -> None:
        """Verify each signing agent holds a recognized identity credential, or refuse.

        Answers the two questions the risk engine and treasury guard do not:
        *is this agent legitimate* and *who controls it*. Optional injected
        verifier, same precedent as ``treasury_guard``. Every subject must pass:
        in a 2-of-2, one unaccredited agent invalidates the quorum's legitimacy
        claim, so a single failure refuses the whole signature. With no verifier
        wired the signer still operates but emits an
        :class:`~quorumvault.policy.agent_identity.AgentIdentityNotWiredWarning`:
        never a silent 'assume legitimate'.
        """
        subjects = (
            self._identity_subjects
            if self._identity_subjects is not None
            else set(self._quorum.signer_addresses)
        )
        if self._agent_identity_verifier is None:
            warnings.warn(
                AgentIdentityNotWiredWarning(
                    "QuorumVaultExternalSigner produced a signature with no "
                    "agent_identity_verifier wired: the signing agents' identity "
                    "credentials were NOT verified. Wire an "
                    "XrplAgentIdentityVerifier for any identity-aware deployment."
                ),
                stacklevel=3,
            )
            return
        for subject in sorted(subjects):
            try:
                self._agent_identity_verifier.verify(
                    signer_address=subject,
                    recognized_issuers=self._recognized_credential_issuers,
                    required_credential_type=self._required_credential_type or "",
                )
            except AgentIdentityError as exc:
                self.last_decision = SignDecision(
                    tier="refused",
                    risk_level="REFUSED",
                    fired_reasons=[f"agent_identity_unverified:{exc}"],
                )
                raise ExternalSignerRefused(
                    "QuorumVault refused: signing agent identity could not be "
                    f"verified. {exc}"
                ) from exc

    def _resolve_rwa(self, mpt_issuance_id: str, destination: str):
        """Resolve RWA compliance context for an MPT transfer, or refuse.

        Fails closed: an MPT (real-world-asset) transfer with no compliance
        reader wired is refused, never signed with the RWA rule silently skipped.
        With a reader, the resolved RwaTransfer is attached to the intent so the
        RiskEngine's RWA rule actually runs (and the router treats it as RWA).
        """
        if self._compliance_reader is None:
            raise ExternalSignerRefused(
                f"MPT/RWA transfer (issuance {mpt_issuance_id}) but no compliance "
                "reader is wired into this signer; refusing rather than signing an "
                "RWA transfer with no on-ledger compliance check."
            )
        return self._compliance_reader.resolve(
            mpt_issuance_id=mpt_issuance_id,
            destination=destination,
            required_credentials=self._rwa_required_credentials or None,
            domain_id=self._rwa_domain_id,
        )

    @staticmethod
    def _parse_decimal(raw: str, *, what: str) -> Decimal:
        """Parse an XRPL wire-format numeric string into an exact Decimal.

        Never falls through to ``float`` and never defaults to zero: a value
        this signer can't parse is refused, matching the class-level contract.
        """
        try:
            return Decimal(raw)
        except (InvalidOperation, TypeError, ValueError):
            raise ExternalSignerRefused(
                f"Could not parse {what} ({raw!r}) into a real number; refusing "
                "rather than defaulting to a zero (vacuous) value that would "
                "bypass the value gate."
            )

    def _intent_from_tx(self, tx: Transaction) -> PaymentIntent:
        """Build a value-bearing intent from a Payment.

        Parses the amount from the canonical XRPL form (``to_xrpl()``), so IOU and
        MPT amounts - which xrpl-py stores as objects, not dicts - are valued
        correctly rather than falling through to zero. Amounts are parsed
        directly into :class:`~decimal.Decimal` from XRPL's own precise wire-
        format strings (never via ``float``), so no binary-rounding artifact can
        creep into a risk-relevant amount. An amount this method cannot turn into
        a real number, or a missing destination, is refused: it must never be
        defaulted to a value that makes the risk checks vacuous.
        """
        xrpl = tx.to_xrpl()
        destination = xrpl.get("Destination")
        if not destination:
            raise ExternalSignerRefused(
                "Payment has no Destination; refusing to sign a transfer with no payee."
            )
        amount = xrpl.get("Amount")
        if isinstance(amount, str):  # XRP, in drops - an exact integer string
            drops = self._parse_decimal(amount, what="XRP drops amount")
            return PaymentIntent(
                destination=destination, asset="XRP", amount=drops / Decimal(1_000_000)
            )
        if isinstance(amount, dict) and "value" in amount:
            if "mpt_issuance_id" in amount:
                mpt_id = str(amount.get("mpt_issuance_id"))
                rwa = self._resolve_rwa(mpt_id, destination)
                value = self._parse_decimal(amount["value"], what="MPT amount")
                return PaymentIntent(
                    destination=destination,
                    asset="MPT:" + mpt_id,
                    amount=value,
                    rwa=rwa,
                )
            asset = amount.get("currency", "?")
            value = self._parse_decimal(amount["value"], what="IOU amount")
            return PaymentIntent(destination=destination, asset=asset, amount=value)
        raise ExternalSignerRefused(
            f"Unrecognized Payment Amount shape ({amount!r}); refusing rather than "
            "defaulting to a zero (vacuous) value that would bypass the value gate."
        )
