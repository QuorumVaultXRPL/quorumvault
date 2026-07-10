"""Integrations that expose QuorumVault through other systems' contracts.

Currently: the XRPL Agent Wallet Skill's ExternalSigner seam
(xrpl.org/docs/agents/xrpl-agent-wallet-skill). The skill refuses multisig and
tells the developer to bring "a dedicated multisig flow" — QuorumVault is that
flow, plugged in through the skill's own production signing interface.
"""

from .external_signer import (
    ExternalSignerRefused,
    QuorumVaultExternalSigner,
    SignDecision,
)

__all__ = [
    "QuorumVaultExternalSigner",
    "ExternalSignerRefused",
    "SignDecision",
]
