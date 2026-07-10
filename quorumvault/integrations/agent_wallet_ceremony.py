"""A faithful Python simulation of the XRPL Agent Wallet Skill's signing ceremony,
driving QuorumVault through the skill's ExternalSigner seam.

DESIGN DECISION -- (b) Python-side simulation, not (a) an xrpl.js/TS shim.
Rationale: the skill is a Claude-agent skill (prose plus xrpl.js snippets), and
its ExternalSigner is a contract the *host* provides. The thing worth proving is
that QuorumVault satisfies that contract and can run the skill's documented
six-step ceremony end to end to a real on-ledger hash. QuorumVault is Python, so
doing the ceremony in Python -- calling xrpl-py's autofill/submit_and_wait around
QuorumVault's signer -- proves exactly that with nothing to fork in the skill and
no TS<->Python bridge to stand up. Because QuorumVaultExternalSigner already has
the exact ExternalSigner shape (address; sign(tx) -> {tx_blob, hash}), option (a)
-- a thin xrpl.js shim that RPCs into this signer so it sits behind a real Claude
agent running the skill -- is a transport wrapper away. It would add plumbing,
not proof, which is why it's documented as the production path rather than built
here.

The ceremony reproduces the skill's rules: default SourceTag, autofill-before-
preview, the exact preview block, confirmation, sign, persist-hash-before-submit,
and submitAndWait.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Callable, Dict, List, Optional

# The XRPL AI Starter Kit default SourceTag, per the skill spec.
XRPL_STARTER_KIT_SOURCE_TAG = 20260530

# Known Payment flags, for decoding in the preview.
_PAYMENT_FLAGS = {
    0x00010000: "tfNoRippleDirect",
    0x00020000: "tfPartialPayment",
    0x00040000: "tfLimitQuality",
    0x80000000: "tfFullyCanonicalSig",
}

# Rows rendered explicitly; everything else goes under "Other fields".
_SHOWN_FIELDS = {
    "TransactionType", "Account", "Destination", "Amount", "Fee", "Sequence",
    "LastLedgerSequence", "Flags", "Memos", "SigningPubKey", "Signers", "TxnSignature",
}


def apply_default_source_tag(tx: Any) -> Any:
    """Skill step 1: set the Starter Kit SourceTag unless one is already present.

    ``SourceTag == 0`` is a valid, explicit "suppress tagging" value and is left
    untouched; only an absent SourceTag is defaulted.
    """
    if getattr(tx, "source_tag", None) is not None:
        return tx
    return dataclasses.replace(tx, source_tag=XRPL_STARTER_KIT_SOURCE_TAG)


def _drops_to_xrp(drops: str) -> str:
    return f"{int(drops) / 1_000_000:g} XRP"


def _format_amount(amount: Any) -> str:
    if amount is None:
        return "-"
    if isinstance(amount, str):  # XRP drops
        return f"{_drops_to_xrp(amount)} ({amount} drops)"
    if isinstance(amount, dict):  # issued currency / MPT
        if "mpt_issuance_id" in amount or "MPTokenIssuanceID" in amount:
            iid = amount.get("MPTokenIssuanceID", amount.get("mpt_issuance_id"))
            return f"{amount.get('value')} MPT (issuance {iid})"
        return (
            f"{amount.get('value')} {amount.get('currency')} "
            f"(issuer {amount.get('issuer')})"
        )
    return str(amount)


def _decode_flags(flags: int, tx_type: str) -> str:
    if not flags:
        return "0"
    known = _PAYMENT_FLAGS if tx_type == "Payment" else {}
    named, remaining = [], flags
    for bit, name in known.items():
        if flags & bit:
            named.append(name)
            remaining &= ~bit
    parts = list(named)
    if remaining:
        parts.append(f"0x{remaining:08X} (unknown flag bit set - verify before signing)")
    return f"{flags} ({', '.join(parts)})"


def _decode_memos(memos: Optional[list]) -> str:
    if not memos:
        return "-"
    out: List[str] = []
    for m in memos:
        memo = m.get("Memo", m)
        data_hex = memo.get("MemoData")
        if not data_hex:
            out.append("(empty memo)")
            continue
        try:
            out.append(bytes.fromhex(data_hex).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            out.append(f"(binary memo, {len(data_hex) // 2} bytes)")
    return "; ".join(out)


def render_preview(
    tx_xrpl: Dict[str, Any],
    network: str,
    current_ledger_index: int,
    *,
    auto_sign_note: Optional[str] = None,
) -> str:
    """The skill's exact preview block. Full addresses, drops->XRP, decoded flags."""
    tx_type = tx_xrpl.get("TransactionType", "?")
    account = tx_xrpl.get("Account", "-")
    destination = tx_xrpl.get("Destination", "-")
    fee = tx_xrpl.get("Fee")
    fee_str = _drops_to_xrp(fee) if fee is not None else "-"
    lls = tx_xrpl.get("LastLedgerSequence")
    if lls is not None:
        remaining = lls - current_ledger_index
        lls_str = f"{lls}  (expires in ~{remaining} ledgers (~{remaining * 4} seconds))"
    else:
        lls_str = "-"

    other = {
        k: v for k, v in tx_xrpl.items() if k not in _SHOWN_FIELDS
    }
    other_str = (
        ", ".join(f"{k}={other[k]}" for k in sorted(other)) if other else "-"
    )

    lines = [
        "─── XRPL Transaction Preview ────────────────────────",
        f"Network           : {network}",
        f"Type              : {tx_type}",
        f"From              : {account}",
        f"To                : {destination}",
        f"Amount            : {_format_amount(tx_xrpl.get('Amount'))}",
        f"Fee               : {fee_str}",
        f"Sequence          : {tx_xrpl.get('Sequence', '-')}",
        f"LastLedgerSequence: {lls_str}",
        f"Flags             : {_decode_flags(int(tx_xrpl.get('Flags', 0) or 0), tx_type)}",
        f"Memos             : {_decode_memos(tx_xrpl.get('Memos'))}",
        f"Other fields      : {other_str}",
        "─" * 69,
        "Sign and submit? (yes / no)",
    ]
    if fee is not None and int(fee) > 100:
        lines.insert(7, f"  ! fee is {fee} drops (> 100) - verify this is intended")
    if auto_sign_note:
        lines.append(f"[auto-signed under override: {auto_sign_note}]")
    return "\n".join(lines)


def run_ceremony(
    client: Any,
    signer: Any,
    tx: Any,
    *,
    network: str = "testnet",
    confirm: Optional[Callable[[str], bool]] = None,
    on_output: Callable[[str], None] = print,
    submit: bool = True,
) -> Dict[str, Any]:
    """Run the skill's six-step ceremony against ``client`` using ``signer``.

    ``confirm(preview) -> bool`` is the human gate (step 4). ``submit=False``
    stops after signing (useful for dry runs). Returns a result dict including
    the persisted hash and, when submitted, the validated TransactionResult.
    """
    from xrpl.core.binarycodec import decode
    from xrpl.ledger import get_latest_validated_ledger_sequence
    from xrpl.models.transactions.transaction import Transaction
    from xrpl.transaction import autofill, submit_and_wait

    # Step 1 - receive tx; apply default SourceTag; require Account.
    tx = apply_default_source_tag(tx)
    if getattr(tx, "account", None) is None:
        raise ValueError("Transaction has no Account; cannot sign (skill step 1).")

    # Step 2 - external-signer pattern; the signer's address must match Account.
    if signer.address != tx.account:
        raise ValueError(
            f"signer.address ({signer.address}) does not match tx.Account "
            f"({tx.account}); refusing to sign a tx for an account this signer "
            "does not control (skill step 2)."
        )

    # Step 3 - autofill (size the fee for multisig via signers_count).
    signers_count = getattr(signer, "signers_count", None)
    prepared = (
        autofill(tx, client, signers_count=signers_count)
        if signers_count
        else autofill(tx, client)
    )

    # Step 4 - preview + human confirmation.
    current = get_latest_validated_ledger_sequence(client)
    preview = render_preview(prepared.to_xrpl(), network, current)
    on_output(preview)
    if confirm is not None and not confirm(preview):
        return {"status": "aborted_by_human", "preview": preview}

    # Step 5 - sign (QuorumVault risk-gated 2-of-2, invisible to the caller);
    # persist the hash BEFORE submitting.
    signed = signer.sign(prepared)
    on_output(f"hash (persisted before submit): {signed['hash']}")
    if not submit:
        return {
            "status": "signed_not_submitted",
            "hash": signed["hash"],
            "preview": preview,
            "decision": signer.last_decision,
        }

    # Step 6 - submitAndWait; report the validated result. The skill submits the
    # signed tx_blob; xrpl-py's submit_and_wait takes a Transaction, so we
    # reconstruct it from the blob (which also confirms the blob is well-formed).
    signed_tx = Transaction.from_xrpl(decode(signed["tx_blob"]))
    result = submit_and_wait(signed_tx, client)
    code = result.result["meta"]["TransactionResult"]
    return {
        "status": code,
        "hash": signed["hash"],
        "validated_ledger_index": result.result.get("ledger_index"),
        "preview": preview,
        "decision": signer.last_decision,
    }
