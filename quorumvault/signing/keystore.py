"""Encrypted keystore for XRPL signing seeds — no plaintext on disk.

Seeds are encrypted at rest with AES-256-GCM under a 32-byte key derived from a
passphrase via scrypt (N=2**15, r=8, p=1). The passphrase is supplied
out-of-band (env var / OS keyring / interactive prompt) and is *never* written
to the keystore file. Each entry is sealed with a unique nonce and bound to its
own metadata via AES-GCM associated data, so entries cannot be swapped.

Decrypted seed bytes are returned to the caller in a ``bytearray`` whose
lifetime the caller is expected to keep as short as possible and then
``zeroize``. This is best-effort: Python cannot guarantee that no copy of the
secret lingers in memory (immutable ``str`` intermediates, the interpreter's
allocator, core dumps). That residual exposure is exactly what an HSM/KMS
removes — see ``kms_backend.py``. This module implements the *minimum*
acceptable posture ("secrets-manager-backed keystore"), not the strongest one.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import KeystoreError, KeystoreLockedError

_MAGIC = "quorumvault-keystore"
_VERSION = 1
_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_DKLEN = 32
_SALT_LEN = 16
_NONCE_LEN = 12
_ENV_PASSPHRASE = "QUORUMVAULT_KEYSTORE_PASSPHRASE"


def zeroize(buf: bytearray) -> None:
    """Best-effort wipe of a mutable byte buffer."""
    for i in range(len(buf)):
        buf[i] = 0


def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=_DKLEN, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P).derive(
        passphrase
    )


def _resolve_passphrase(passphrase: Optional[str]) -> bytes:
    if passphrase is None:
        passphrase = os.environ.get(_ENV_PASSPHRASE)
    if not passphrase:
        raise KeystoreLockedError(
            "No keystore passphrase supplied. Pass one explicitly or set "
            f"the {_ENV_PASSPHRASE} environment variable. The keystore will "
            "not fall back to any plaintext source."
        )
    return passphrase.encode("utf-8")


def _aad(alias: str, address: str, algorithm: str) -> bytes:
    # Bind ciphertext to its slot so entries cannot be transplanted.
    return f"{alias}:{address}:{algorithm}".encode("utf-8")


@dataclass(frozen=True)
class KeystoreEntry:
    """Public (non-secret) metadata for one sealed seed."""

    alias: str
    address: str
    algorithm: str  # "ed25519" | "secp256k1"
    nonce: str  # hex
    ciphertext: str  # hex (AES-GCM ciphertext incl. 16-byte tag)


class EncryptedKeystore:
    """A file-backed collection of AES-GCM-sealed XRPL seeds."""

    def __init__(self, path: str, salt: bytes, entries: Dict[str, KeystoreEntry]):
        self.path = path
        self._salt = salt
        self._entries = entries

    # -- construction ----------------------------------------------------
    @classmethod
    def create(cls, path: str) -> "EncryptedKeystore":
        """Create a new, empty keystore (with a fresh random salt) in memory."""
        return cls(path=path, salt=os.urandom(_SALT_LEN), entries={})

    @classmethod
    def load(cls, path: str) -> "EncryptedKeystore":
        if not os.path.exists(path):
            raise KeystoreError(f"Keystore not found: {path}")
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if raw.get("magic") != _MAGIC:
            raise KeystoreError(f"Not a QuorumVault keystore: {path}")
        if raw.get("version") != _VERSION:
            raise KeystoreError(f"Unsupported keystore version: {raw.get('version')}")
        kdf = raw.get("kdf", {})
        if kdf.get("name") != "scrypt":
            raise KeystoreError(f"Unsupported KDF: {kdf.get('name')}")
        salt = bytes.fromhex(kdf["salt"])
        entries = {
            alias: KeystoreEntry(
                alias=alias,
                address=e["address"],
                algorithm=e["algorithm"],
                nonce=e["nonce"],
                ciphertext=e["ciphertext"],
            )
            for alias, e in raw.get("entries", {}).items()
        }
        return cls(path=path, salt=salt, entries=entries)

    # -- persistence -----------------------------------------------------
    def save(self, path: Optional[str] = None) -> str:
        target = path or self.path
        payload = {
            "magic": _MAGIC,
            "version": _VERSION,
            "kdf": {
                "name": "scrypt",
                "n": _SCRYPT_N,
                "r": _SCRYPT_R,
                "p": _SCRYPT_P,
                "dklen": _DKLEN,
                "salt": self._salt.hex(),
            },
            "cipher": "AES-256-GCM",
            "entries": {
                alias: {
                    "address": e.address,
                    "algorithm": e.algorithm,
                    "nonce": e.nonce,
                    "ciphertext": e.ciphertext,
                }
                for alias, e in self._entries.items()
            },
        }
        tmp = f"{target}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, target)
        try:
            os.chmod(target, 0o600)
        except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
            pass
        return target

    # -- entries ---------------------------------------------------------
    def aliases(self) -> List[str]:
        return list(self._entries.keys())

    def entry(self, alias: str) -> KeystoreEntry:
        try:
            return self._entries[alias]
        except KeyError:
            raise KeystoreError(f"No keystore entry named {alias!r}")

    def add_seed(
        self,
        alias: str,
        seed: str,
        address: str,
        algorithm: str,
        passphrase: Optional[str] = None,
    ) -> KeystoreEntry:
        """Encrypt and store a seed. ``seed`` is consumed and best-effort wiped."""
        key = _derive_key(_resolve_passphrase(passphrase), self._salt)
        seed_buf = bytearray(seed.encode("utf-8"))
        try:
            nonce = os.urandom(_NONCE_LEN)
            ct = AESGCM(key).encrypt(
                nonce, bytes(seed_buf), _aad(alias, address, algorithm)
            )
        finally:
            zeroize(seed_buf)
            zeroize(bytearray(key))
        entry = KeystoreEntry(
            alias=alias,
            address=address,
            algorithm=algorithm,
            nonce=nonce.hex(),
            ciphertext=ct.hex(),
        )
        self._entries[alias] = entry
        return entry

    def decrypt_seed(self, alias: str, passphrase: Optional[str] = None) -> bytearray:
        """Return decrypted seed bytes. Caller MUST ``zeroize`` when done."""
        entry = self.entry(alias)
        key = _derive_key(_resolve_passphrase(passphrase), self._salt)
        try:
            plaintext = AESGCM(key).decrypt(
                bytes.fromhex(entry.nonce),
                bytes.fromhex(entry.ciphertext),
                _aad(entry.alias, entry.address, entry.algorithm),
            )
        except InvalidTag:
            raise KeystoreLockedError(
                f"Wrong passphrase or corrupted entry for alias {alias!r}."
            )
        finally:
            zeroize(bytearray(key))
        return bytearray(plaintext)
