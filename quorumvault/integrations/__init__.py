"""Integrations that expose QuorumVault through other systems' contracts.

* The XRPL Agent Wallet Skill's ExternalSigner seam
  (xrpl.org/docs/agents/xrpl-agent-wallet-skill) — the skill refuses multisig and
  tells the developer to bring "a dedicated multisig flow"; QuorumVault is that
  flow, plugged into the skill's own production signing interface.
* XRPL-native x402 (agentic commerce) — QuorumVault risk-gates the payer side of
  T54's ``x402-xrpl`` presigned-Payment scheme, producing a 2-of-2 multisigned
  blob where the SDK's quickstart uses one unprotected in-memory key.
  ``x402-xrpl`` is an optional dependency of that surface only.
"""

from .external_signer import (
    ExternalSignerRefused,
    QuorumVaultExternalSigner,
    SignDecision,
)
from .x402_signer import (
    QuorumVaultX402Signer,
    X402Decision,
    X402PaymentRefused,
    build_audit_memo,
)

__all__ = [
    "QuorumVaultExternalSigner",
    "ExternalSignerRefused",
    "SignDecision",
    "QuorumVaultX402Signer",
    "X402PaymentRefused",
    "X402Decision",
    "build_audit_memo",
]
