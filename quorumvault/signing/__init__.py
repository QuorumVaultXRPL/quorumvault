"""Production-grade, swappable XRPL signing.

The single seam the rest of the system depends on is :class:`SignerBackend`:
an object that knows one signer's public key / classic address and can turn a
canonical XRPL signing blob into a ``TxnSignature`` hex string — without ever
exposing the private key to the caller.

Backends:
  * :class:`LocalEncryptedKeystoreBackend` — seed encrypted at rest (AES-256-GCM
    + scrypt), decrypted only transiently in memory. Works with ed25519 or
    secp256k1. This is the minimum acceptable posture near real funds.
  * :class:`AwsKmsSignerBackend` — non-exportable secp256k1 key; the key never
    leaves the HSM/KMS. Reference for the strongest production posture.
  * :class:`AwsKmsEd25519SignerBackend` — non-exportable ed25519 KMS key
    (spec ``ECC_NIST_EDWARDS25519``, native to KMS since 2025-11-07), letting
    the existing ed25519 signers adopt KMS with no curve migration.

:class:`QuorumSigner` combines backends into a multisigned transaction that is
byte-for-byte identical to xrpl-py's own ``sign(multisign=True)`` + ``multisign``
flow — verified in the test suite.
"""

from .backend import SignerBackend, authorize_channel_claim
from .errors import (
    SigningError,
    KeystoreError,
    KeystoreLockedError,
    BackendConfigError,
)
from .keystore import EncryptedKeystore, KeystoreEntry
from .local_keystore import LocalEncryptedKeystoreBackend
from .quorum_signer import QuorumSigner

__all__ = [
    "SignerBackend",
    "authorize_channel_claim",
    "QuorumSigner",
    "EncryptedKeystore",
    "KeystoreEntry",
    "LocalEncryptedKeystoreBackend",
    "SigningError",
    "KeystoreError",
    "KeystoreLockedError",
    "BackendConfigError",
]

# The AWS KMS backends are imported lazily so users who only need the local
# keystore path never trigger the kms_backend import.
def __getattr__(name: str):  # pragma: no cover - thin lazy import shim
    if name in ("AwsKmsSignerBackend", "AwsKmsEd25519SignerBackend"):
        from . import kms_backend

        return getattr(kms_backend, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
