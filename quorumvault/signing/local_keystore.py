"""Local encrypted-keystore signing backend.

Holds no secret in memory between operations: on every ``sign`` it decrypts the
seed from the keystore, derives the keypair, signs, and best-effort wipes the
seed and derived private key. Public identity (address, public key, algorithm)
is cached because it is not secret.

This backend works with the project's existing ed25519 Testnet signers with no
key migration. It is the minimum acceptable posture near funds; the residual
in-memory exposure is closed only by the AWS KMS backend (kms_backend.py).
"""

from __future__ import annotations

from typing import Callable, Optional

from xrpl.core.keypairs import derive_classic_address, derive_keypair
from xrpl.core.keypairs import sign as keypairs_sign

from .backend import SignerBackend
from .errors import BackendConfigError
from .keystore import EncryptedKeystore, zeroize


class LocalEncryptedKeystoreBackend(SignerBackend):
    """A SignerBackend backed by one entry in an encrypted keystore."""

    def __init__(
        self,
        keystore: EncryptedKeystore,
        alias: str,
        passphrase: Optional[str] = None,
        *,
        passphrase_provider: Optional[Callable[[], Optional[str]]] = None,
    ):
        if passphrase is not None and passphrase_provider is not None:
            raise BackendConfigError(
                "Pass either passphrase or passphrase_provider, not both."
            )
        self._keystore = keystore
        self._alias = alias
        # Resolve the passphrase on demand instead of holding it for the backend's
        # lifetime. With neither argument (the production path) we pass None so the
        # keystore reads QUORUMVAULT_KEYSTORE_PASSPHRASE fresh on each call and this
        # object stores no secret at all. An explicit provider (e.g. an OS-keyring
        # lookup) is invoked per signature; an explicit string is a dev convenience
        # that lives only inside the closure below, never as a named attribute.
        if passphrase_provider is not None:
            self._resolve_passphrase = passphrase_provider
        elif passphrase is not None:
            self._resolve_passphrase = lambda: passphrase
        else:
            self._resolve_passphrase = lambda: None

        entry = keystore.entry(alias)
        self._address = entry.address
        self._algorithm = entry.algorithm

        # Derive the public key once (transiently touching the seed) and verify
        # it matches the stored address - a cheap integrity check that also
        # surfaces a wrong passphrase immediately instead of at first signing.
        seed = keystore.decrypt_seed(alias, self._resolve_passphrase())
        try:
            public_key, _private_key = derive_keypair(bytes(seed).decode("utf-8"))
        finally:
            zeroize(seed)
        if derive_classic_address(public_key) != self._address:
            raise BackendConfigError(
                f"Keystore entry {alias!r} public key does not derive to its "
                f"stored address {self._address!r}."
            )
        self._public_key = public_key

    @property
    def public_key(self) -> str:
        return self._public_key

    @property
    def classic_address(self) -> str:
        return self._address

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def sign(self, signing_blob: bytes) -> str:
        seed = self._keystore.decrypt_seed(self._alias, self._resolve_passphrase())
        try:
            # derive_keypair needs the seed as str; this immutable copy is the
            # one place we cannot wipe (documented tradeoff of the keystore tier).
            _public_key, private_key = derive_keypair(bytes(seed).decode("utf-8"))
            return keypairs_sign(signing_blob, private_key)
        finally:
            zeroize(seed)
