"""QuorumVault — XRPL AI treasury multisig auditor.

This package promotes the proven v1 2-of-2 Testnet quorum into:

  * a swappable, production-grade signing abstraction (``quorumvault.signing``)
    where no plaintext private-key material ever touches disk or logs, and the
    signing backend (local encrypted keystore vs. HSM/KMS) can be swapped
    without changing the auditor/quorum logic above it; and

  * a tiered assurance model (``quorumvault.tiers``): a Channel-Custody lane and
    a Velocity-Bounded Fast Path for lower/mid-value flows, with the existing
    2-of-2 quorum kept underneath as the high-value backstop.

Nothing in this package moves real funds. All on-ledger interaction targets
XRPL Testnet and live submission is opt-in and explicit.
"""

__version__ = "2.0.0-dev"

__all__ = ["__version__"]
