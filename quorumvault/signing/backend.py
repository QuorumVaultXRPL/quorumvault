"""The core signing seam: :class:`SignerBackend`.

Everything above the signing layer (the auditor, the quorum, the tier router)
depends only on this interface. It never sees a private key, a seed, or a
keystore passphrase — only a signer's *public* identity and the ability to turn
a canonical XRPL signing blob into a ``TxnSignature`` hex string.

Swapping a local encrypted keystore for an HSM/KMS is therefore invisible to
callers: they hold a ``SignerBackend`` either way.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from xrpl.core.binarycodec import encode_for_signing_claim


class SignerBackend(ABC):
    """One signer identity that can produce XRPL signatures.

    A backend is bound to exactly one key/account. ``sign`` receives the raw
    bytes to be signed (already prefixed/encoded by the caller using xrpl-py's
    canonical encoders) and returns the ``TxnSignature`` as an uppercase hex
    string, exactly as xrpl-py's ``keypairs.sign`` would.
    """

    @property
    @abstractmethod
    def public_key(self) -> str:
        """XRPL public key hex (33-byte secp256k1 ``02/03…`` or ``ED…`` ed25519)."""

    @property
    @abstractmethod
    def classic_address(self) -> str:
        """The ``r…`` classic address derived from :pyattr:`public_key`."""

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """``"ed25519"`` or ``"secp256k1"``."""

    @abstractmethod
    def sign(self, signing_blob: bytes) -> str:
        """Sign ``signing_blob`` and return the ``TxnSignature`` hex string.

        Implementations MUST NOT log, print, or otherwise persist any private
        key material, and MUST return a *fully canonical* (low-S, for secp256k1)
        signature so the XRPL will accept it.
        """

    def __repr__(self) -> str:  # never leaks secrets
        return (
            f"{type(self).__name__}(address={self.classic_address}, "
            f"algorithm={self.algorithm})"
        )


def authorize_channel_claim(
    backend: SignerBackend, channel_id: str, amount_drops: int
) -> str:
    """Produce an off-ledger Payment Channel claim authorization.

    This is what powers the Channel-Custody lane's high-frequency path: the
    payer's backend signs ``(channel_id, cumulative_amount)`` off-ledger, with
    no per-payment on-ledger transaction and no per-payment audit. The signature
    is redeemable by the payee via ``PaymentChannelClaim`` up to the channel's
    (audited) capacity.
    """
    if amount_drops < 0:
        raise ValueError("amount_drops must be non-negative")
    blob = bytes.fromhex(
        encode_for_signing_claim({"channel": channel_id, "amount": str(amount_drops)})
    )
    return backend.sign(blob)
