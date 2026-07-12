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

Amounts are parsed straight into :class:`~decimal.Decimal` from XRPL's own wire
format (the drops string for XRP, the ``"value"`` decimal string for IOU/MPT) —
never routed through ``float`` at all. See :mod:`quorumvault.policy.money` for
why a bare float has no business carrying a currency amount anywhere in this
codebase; a value the network itself sends as an exact string should stay exact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import FrozenSet, Iterable, List, Optional

from xrpl.core.binarycodec import encode
from xrpl.models.transactions.transaction import Transaction

from ..policy.intent import PaymentIntent
from ..policy.risk_engine import RiskEngine, RiskLevel
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
    ):
        self._address = treasury_address
        self._quorum = quorum_signer
        self._risk = risk_engine
        self._router = router
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
        an un-valuable transaction, or any non-GREEN Auditor verdict.
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
        signed = self._quorum.multisign(tx)
        return {"tx_blob": encode(signed.to_xrpl()), "hash": signed.get_hash()}

    # -- helpers --------------------------------------------------------
    @property
    def signers_count(self) -> int:
        """How many signatures this signer contributes (multisig fee sizing)."""
        return len(self._quorum.signer_addresses)

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
