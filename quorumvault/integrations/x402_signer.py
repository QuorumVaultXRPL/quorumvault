"""QuorumVault as the risk-gated payer for XRPL-native x402 (agentic commerce).

x402 is the HTTP-402 "pay-and-retry" rail for machine-to-machine commerce. The
XRPL implementation is T54's published ``x402-xrpl`` package (PyPI), whose payer
side today signs with a bare ``xrpl.wallet.Wallet`` — one unprotected key in
process memory, no risk gate, no circuit breaker, no second signature. That is
the *exact* gap QuorumVault already fills for the Agent Wallet Skill, on a
different rail: this module is the second front door onto the same brain
(``PaymentIntent`` → ``RiskEngine`` → ``TierRouter`` → ``QuorumSigner``), not a
new chain and not a new signer.

HOW IT PLUGS IN (verified against x402-xrpl 0.1.4 source, not docs prose).

* ``x402_requests(wallet, ...)`` couples to the real ``Wallet`` only through
  xrpl-py's single-signature ``sign(filled, wallet)``, which structurally cannot
  emit a ``Signers`` array. So a duck-typed wallet shim can't carry a 2-of-2
  blob. But the SDK exposes a first-class "bring your own signed blob" seam: the
  public ``build_payment_header_for_signed_blob(req, signed_tx_blob, invoice_id)``
  helper, and the ``payment_header_factory`` hook on ``x402_requests`` (when a
  factory is supplied, the wallet is never touched). QuorumVault produces its own
  2-of-2 multisigned blob via ``QuorumSigner.multisign`` and wraps it with that
  helper — no fork, no Wallet-internals coupling.
* The SDK's ``FacilitatorClient.verify/settle`` forward the ``signedTxBlob``
  opaquely (base64 JSON) to a *remote* facilitator; the published package carries
  no single-signature assumption. The actual verify body lives in T54's unshipped
  ``app.services.xrpl_x402_presigned_payment_facilitator`` and is not inspectable
  from the sdist. Its shipped tests validate transaction *fields* (amount,
  SourceTag == requirements, invoice binding, SendMax, a Fee upper bound,
  LastLedgerSequence) and assert nothing about single-signature structure — so a
  correctly-fielded 2-of-2 blob should pass verify and settle on-ledger (the
  treasury has a real ``SignerList``). Whether the facilitator derives the
  expected payer from the tx ``Account`` (multisig-safe) or from ``SigningPubKey``
  (single-sig only) can NOT be determined from the published source; that is the
  one external unknown, flagged for a live check / possible upstream note.

SOURCETAG (decided from the verify tests, not guessed). The facilitator rejects a
tx whose ``SourceTag`` does not equal ``requirements.extra["sourceTag"]``
(default ``804681468``) with ``source_tag_mismatch``. So on this rail the
SourceTag is protocol-owned — QuorumVault honors it and never substitutes its own
(the Agent Wallet Skill's ``20260530`` would be *rejected* here). QuorumVault's
"which agent / why" attribution goes into a Memo instead (see
:func:`build_audit_memo`), ON by default (see LIVE VERIFICATION below).

LIVE VERIFICATION (2026-07-13, XRPL Testnet, T54's public testnet facilitator).
Both open questions above were resolved empirically, not just from source
review: a real ``QuorumVaultX402Signer`` produced two genuine 2-of-2 multisigned
presigned-Payment blobs (treasury ``rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce``, real
``SignerList`` quorum 2) against the live Testnet ledger, one with
``audit_memo=False`` and one with ``audit_memo=True``. Both were POSTed to
``https://xrpl-facilitator-testnet.t54.ai``:

* ``/verify`` returned ``{"isValid": true, "payer": "rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce"}``
  for *both* — confirming the facilitator derives ``payer`` from the tx
  ``Account`` (multisig-safe), not from ``SigningPubKey``, and that an extra
  audit Memo alongside the invoice-binding one does not fail verification.
* ``/settle`` on the no-memo blob returned ``{"success": true, "transaction":
  "7C4C...2647"}``, and that hash was independently confirmed on-ledger via a
  direct ``tx`` call to Testnet: ``TransactionResult: tesSUCCESS``,
  ``validated: true``, a real ``Signers`` array with both quorum members, empty
  ``SigningPubKey`` (genuine multisig, not single-sig), correct balance deltas.

Given this, ``audit_memo`` defaults to ``True``: the on-chain compliance
rationale is real, live-verified as tolerated by the facilitator, and worth
having by default rather than opted into per-caller.

DISCIPLINE INHERITED FROM THE REST OF THE CODEBASE. Amounts are parsed straight
into :class:`~decimal.Decimal` from x402's wire strings (never through
``float``); an amount that can't be parsed, a missing payee, an unsupported
scheme/asset, or any non-GREEN Auditor verdict *refuses* (raises
:class:`X402PaymentRefused`) rather than defaulting to a value that makes a risk
check vacuous or emitting a partial/zero payment.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, List, Mapping, Optional

from xrpl.ledger import get_latest_validated_ledger_sequence
from xrpl.core.binarycodec import encode
from xrpl.models.amounts import IssuedCurrencyAmount
from xrpl.models.transactions import Memo, Payment
from xrpl.transaction import autofill

from ..policy.intent import PaymentIntent
from ..policy.money import to_decimal
from ..policy.risk_engine import RiskEngine, RiskLevel
from ..signing.quorum_signer import QuorumSigner
from ..tiers.router import TierRouter

# x402-xrpl is an optional dependency: only this one integration surface needs it,
# so the base package stays dependency-free. Import lazily-ish and surface a
# clear, actionable error if a caller uses this module without it installed.
try:
    from x402_xrpl.client.presigned_payment_payer import (
        DEFAULT_SOURCE_TAG as X402_DEFAULT_SOURCE_TAG,
        build_payment_header_for_signed_blob,
        invoice_id_to_invoice_id_field,
        invoice_id_to_memo_hex,
        to_currency_hex,
    )

    _X402_IMPORT_ERROR: Optional[ImportError] = None
except ImportError as _exc:  # pragma: no cover - exercised only without the SDK
    X402_DEFAULT_SOURCE_TAG = 804_681_468
    build_payment_header_for_signed_blob = None  # type: ignore[assignment]
    invoice_id_to_invoice_id_field = None  # type: ignore[assignment]
    invoice_id_to_memo_hex = None  # type: ignore[assignment]
    to_currency_hex = None  # type: ignore[assignment]
    _X402_IMPORT_ERROR = _exc

_SUPPORTED_NETWORKS = frozenset({"xrpl:0", "xrpl:1", "xrpl:2"})


class X402PaymentRefused(Exception):
    """QuorumVault refused to produce an x402 payment.

    The x402 analogue of :class:`~quorumvault.integrations.external_signer.ExternalSignerRefused`:
    raised on an unsupported requirement, an un-valuable amount, a missing payee
    or invoice id, or any non-GREEN Auditor verdict. In every case no signature
    and no payment header are produced — the 402 simply stands.
    """


@dataclass
class X402Decision:
    """What QuorumVault decided on the last x402 payment attempt (for logging/audit)."""

    tier: str
    risk_level: str
    fired_reasons: List[str] = field(default_factory=list)
    rlusd_equivalent: str = "0"  # Decimal rendered as a string; never a float


def build_audit_memo(decision: X402Decision, *, invoice_id: Optional[str] = None) -> Memo:
    """Encode a QuorumVault risk decision as a structured on-chain ``Memo``.

    Follows xrpl.org/docs/agents/track-agent-behavior's ``build_memo`` pattern
    (compact JSON, hex-uppercase ``MemoData``). This puts the compliance rationale
    — tier, RLUSD-equivalent, fired reasons — on the public ledger, independently
    verifiable via any block explorer or XRPL data API, not just in QuorumVault's
    own logs. Only GREEN payments are ever signed, so a memo that reaches the
    ledger attests a passed audit at a specific tier and value.
    """
    payload = {
        "src": "quorumvault",
        "v": 1,
        "kind": "risk_decision",
        "risk": decision.risk_level,
        "tier": decision.tier,
        "rlusd": decision.rlusd_equivalent,
        "reasons": list(decision.fired_reasons),
    }
    if invoice_id:
        payload["invoiceId"] = invoice_id
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return Memo(memo_data=data.encode("utf-8").hex().upper())


class QuorumVaultX402Signer:
    """Risk-gated x402 payer: build a ``PAYMENT-SIGNATURE`` header, or refuse.

    ``treasury_address`` is the multisig account the payment is signed *for*; the
    keys live in the injected :class:`QuorumSigner` backends and never surface
    here. ``xrpl_client`` is any xrpl-py sync client (for autofill + the current
    validated ledger index). ``audit_memo`` defaults to ``True`` — live-verified
    against T54's Testnet facilitator as tolerated; see the module docstring.
    """

    def __init__(
        self,
        *,
        treasury_address: str,
        quorum_signer: QuorumSigner,
        risk_engine: RiskEngine,
        xrpl_client: Any,
        router: Optional[TierRouter] = None,
        invoice_binding: str = "both",
        audit_memo: bool = True,
    ):
        if _X402_IMPORT_ERROR is not None:
            raise ImportError(
                "QuorumVaultX402Signer requires the 'x402-xrpl' package "
                "(pip install x402-xrpl). It is an optional dependency of this "
                f"integration surface only. Original import error: {_X402_IMPORT_ERROR}"
            )
        if invoice_binding not in ("memos", "invoice_id", "both"):
            raise ValueError("invoice_binding must be one of: memos, invoice_id, both")
        self._address = treasury_address
        self._quorum = quorum_signer
        self._risk = risk_engine
        self._router = router
        self._client = xrpl_client
        self._invoice_binding = invoice_binding
        self._audit_memo = audit_memo
        self.last_decision: Optional[X402Decision] = None
        self.last_blob: Optional[str] = None
        self.last_hash: Optional[str] = None

    # -- public API -----------------------------------------------------
    @property
    def address(self) -> str:
        return self._address

    def create_payment_header(self, requirements: Any, *, invoice_id: Optional[str] = None) -> str:
        """Risk-gate an x402 quote and return a ``PAYMENT-SIGNATURE`` header.

        Suitable as ``x402_requests(..., payment_header_factory=signer.create_payment_header)``.
        Raises :class:`X402PaymentRefused` on refusal — note the SDK session wrapper
        *fails open* (swallows the exception and returns the original 402), so the
        refusal reason is recorded on :pyattr:`last_decision` for the caller.
        """
        self._require_supported(requirements)
        inv = invoice_id or requirements.invoice_id()
        if not inv:
            raise X402PaymentRefused(
                "x402 requirements carry no invoiceId (extra['invoiceId']); refusing "
                "to sign a payment with nothing binding it to the merchant's quote."
            )

        # --- risk gate (no network) ---
        intent = self._intent_from_requirements(requirements)
        tier = self._router.route(intent).tier.value if self._router else "quorum_backstop"
        verdict = self._risk.evaluate(intent)
        decision = X402Decision(
            tier=tier,
            risk_level=verdict["risk_level"].value,
            fired_reasons=list(verdict["fired_reasons"]),
            rlusd_equivalent=str(verdict["rlusd_equivalent"]),
        )
        self.last_decision = decision
        if verdict["risk_level"] != RiskLevel.GREEN:
            raise X402PaymentRefused(
                "QuorumVault Auditor withheld the x402 payment: "
                f"{decision.risk_level} "
                f"({', '.join(decision.fired_reasons) or 'policy violation'})."
            )

        # --- build the facilitator-compatible Payment, multisign, wrap ---
        payment_tx = self._build_payment(requirements, inv, decision)
        prepared = autofill(
            payment_tx, self._client, signers_count=len(self._quorum.signer_addresses)
        )
        signed = self._quorum.multisign(prepared)
        blob = encode(signed.to_xrpl())
        self.last_blob = blob
        self.last_hash = signed.get_hash()
        return build_payment_header_for_signed_blob(
            req=requirements, signed_tx_blob=blob, invoice_id=inv
        )

    # -- helpers --------------------------------------------------------
    def _require_supported(self, req: Any) -> None:
        scheme = getattr(req, "scheme", None)
        if scheme != "exact":
            raise X402PaymentRefused(
                f"x402 scheme {scheme!r} is not supported; QuorumVault signs the "
                "XRPL 'exact' presigned-Payment scheme only."
            )
        network = getattr(req, "network", None)
        if network not in _SUPPORTED_NETWORKS:
            raise X402PaymentRefused(
                f"x402 network {network!r} is not an XRPL network ({sorted(_SUPPORTED_NETWORKS)})."
            )
        asset = str(getattr(req, "asset", None) or "XRP")
        if asset.upper() != "XRP":
            # IOU: a valid currency code AND an issuer are both required; refuse
            # rather than sign an under-specified issued-currency payment.
            try:
                to_currency_hex(asset)
            except ValueError:
                raise X402PaymentRefused(
                    f"x402 IOU asset {asset!r} is not a valid XRPL currency code "
                    "(expected 3 chars or 40-hex)."
                )
            if not self._issuer_for(req):
                raise X402PaymentRefused(
                    "x402 IOU payment is missing extra['issuer']; an issued currency "
                    "is (currency, issuer) — refusing to sign without the issuer."
                )

    def _intent_from_requirements(self, req: Any) -> PaymentIntent:
        destination = getattr(req, "pay_to", None)
        if not destination:
            raise X402PaymentRefused("x402 requirements missing payTo; refusing.")
        asset = str(getattr(req, "asset", None) or "XRP")
        if asset.upper() == "XRP":
            drops = self._parse_drops(req.amount)
            return PaymentIntent(
                destination=destination, asset="XRP", amount=drops / Decimal(1_000_000)
            )
        value = self._parse_decimal(req.amount, what="IOU amount")
        # Face value for the RLUSD-equivalent (correct for a ~$1 stablecoin like
        # RLUSD; the rate provider treats any non-XRP/non-RLUSD asset as face
        # value, a documented limitation shared with the rest of the engine).
        return PaymentIntent(destination=destination, asset=asset, amount=value)

    def _build_payment(self, req: Any, invoice_id: str, decision: X402Decision) -> Payment:
        memos: List[Memo] = []
        if self._invoice_binding in ("memos", "both"):
            memos.append(Memo(memo_data=invoice_id_to_memo_hex(invoice_id)))
        if self._audit_memo:
            memos.append(build_audit_memo(decision, invoice_id=invoice_id))
        invoice_id_field = (
            invoice_id_to_invoice_id_field(invoice_id)
            if self._invoice_binding in ("invoice_id", "both")
            else None
        )

        source_tag = self._source_tag_for(req)
        destination_tag = self._destination_tag_for(req)

        asset = str(getattr(req, "asset", None) or "XRP")
        if asset.upper() == "XRP":
            drops = self._parse_drops(req.amount)
            amount: Any = str(int(drops))
            send_max: Any = None
        else:
            issuer = self._issuer_for(req)
            currency_hex = to_currency_hex(asset)
            value = str(self._parse_decimal(req.amount, what="IOU amount"))
            amount = IssuedCurrencyAmount(currency=currency_hex, issuer=issuer, value=value)
            # Mirror the SDK's IOU policy: SendMax (same currency+issuer, >= value).
            send_max = IssuedCurrencyAmount(currency=currency_hex, issuer=issuer, value=value)

        current = get_latest_validated_ledger_sequence(self._client)
        max_ledger_delta = int(math.ceil(int(req.max_timeout_seconds) / 5.0) + 2)
        last_ledger_sequence = int(current) + max_ledger_delta

        return Payment(
            account=self._address,
            destination=req.pay_to,
            amount=amount,
            send_max=send_max,
            memos=memos or None,
            invoice_id=invoice_id_field,
            source_tag=source_tag,
            destination_tag=destination_tag,
            last_ledger_sequence=last_ledger_sequence,
        )

    def _source_tag_for(self, req: Any) -> int:
        extra = getattr(req, "extra", None)
        if isinstance(extra, Mapping) and extra.get("sourceTag") is not None:
            try:
                return int(extra["sourceTag"])
            except (TypeError, ValueError):
                raise X402PaymentRefused(
                    "x402 extra['sourceTag'] is not an integer; refusing rather than "
                    "sending a tx the facilitator will reject with source_tag_mismatch."
                )
        return int(X402_DEFAULT_SOURCE_TAG)

    def _destination_tag_for(self, req: Any) -> Optional[int]:
        extra = getattr(req, "extra", None)
        if isinstance(extra, Mapping) and extra.get("destinationTag") is not None:
            try:
                return int(extra["destinationTag"])
            except (TypeError, ValueError):
                raise X402PaymentRefused(
                    "x402 extra['destinationTag'] is not an integer; refusing."
                )
        return None

    @staticmethod
    def _issuer_for(req: Any) -> Optional[str]:
        extra = getattr(req, "extra", None)
        if isinstance(extra, Mapping):
            issuer = extra.get("issuer")
            if isinstance(issuer, str) and issuer:
                return issuer
        return None

    @staticmethod
    def _parse_decimal(raw: Any, *, what: str) -> Decimal:
        try:
            return to_decimal(raw)
        except (InvalidOperation, TypeError, ValueError):
            raise X402PaymentRefused(
                f"Could not parse {what} ({raw!r}) into a real number; refusing rather "
                "than defaulting to a zero (vacuous) value that would bypass the value gate."
            )

    @classmethod
    def _parse_drops(cls, raw: Any) -> Decimal:
        drops = cls._parse_decimal(raw, what="XRP drops amount")
        if drops < 0 or drops != drops.to_integral_value():
            raise X402PaymentRefused(
                f"XRP amount ({raw!r}) is not a non-negative integer number of drops; refusing."
            )
        return drops
