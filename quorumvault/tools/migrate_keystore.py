"""Migrate the plaintext ``wallets_checkpoint.json`` into an encrypted keystore.

Usage::

    export QUORUMVAULT_KEYSTORE_PASSPHRASE='...'          # never echoed/stored
    python -m quorumvault.tools.migrate_keystore \
        --checkpoint wallets_checkpoint.json \
        --keystore keystore.json \
        [--include-treasury] [--shred]

By default the treasury seed is *skipped*: the treasury's master key is disabled
on-ledger, so its seed can no longer authorize anything and is pure liability.
The signer seeds are imported, the keystore is verified to round-trip (decrypt +
re-derive the same address), and only then — if ``--shred`` is given — is the
plaintext checkpoint securely overwritten and deleted.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Dict, List, Optional, Tuple

from xrpl.core.addresscodec import decode_seed
from xrpl.core.keypairs import derive_classic_address, derive_keypair

from ..signing.keystore import EncryptedKeystore, zeroize

# checkpoint alias -> (seed field, address field)
_SIGNER_FIELDS = {
    "exec_signer": ("exec_signer_seed", "exec_signer_address"),
    "auditor_signer": ("auditor_signer_seed", "auditor_signer_address"),
}
_TREASURY_FIELDS = ("treasury_seed", "treasury_address")


def _algorithm_of(seed: str) -> str:
    _decoded, algorithm = decode_seed(seed)
    return algorithm.value  # "ed25519" | "secp256k1"


def _verify_seed_matches_address(seed: str, address: str) -> None:
    public_key, _priv = derive_keypair(seed)
    if derive_classic_address(public_key) != address:
        raise ValueError(
            f"Seed does not derive to expected address {address!r}; refusing to migrate."
        )


def migrate_checkpoint(
    checkpoint_path: str,
    keystore_path: str,
    passphrase: Optional[str] = None,
    include_treasury: bool = False,
) -> Tuple[EncryptedKeystore, List[str]]:
    """Import signer seeds into a new encrypted keystore. Returns (keystore, aliases)."""
    with open(checkpoint_path, "r", encoding="utf-8") as fh:
        checkpoint = json.load(fh)

    keystore = EncryptedKeystore.create(keystore_path)
    imported: List[str] = []

    items = dict(_SIGNER_FIELDS)
    if include_treasury:
        items["treasury"] = _TREASURY_FIELDS

    for alias, (seed_field, addr_field) in items.items():
        if seed_field not in checkpoint:
            continue
        seed = checkpoint[seed_field]
        address = checkpoint[addr_field]
        _verify_seed_matches_address(seed, address)
        keystore.add_seed(
            alias=alias,
            seed=seed,
            address=address,
            algorithm=_algorithm_of(seed),
            passphrase=passphrase,
        )
        imported.append(alias)

    return keystore, imported


def verify_roundtrip(
    keystore: EncryptedKeystore, aliases: List[str], passphrase: Optional[str] = None
) -> None:
    """Decrypt each entry and confirm it re-derives the stored address."""
    for alias in aliases:
        entry = keystore.entry(alias)
        seed = keystore.decrypt_seed(alias, passphrase)
        try:
            public_key, _priv = derive_keypair(bytes(seed).decode("utf-8"))
        finally:
            zeroize(seed)
        if derive_classic_address(public_key) != entry.address:
            raise ValueError(f"Round-trip verification failed for alias {alias!r}.")


def secure_shred(path: str, passes: int = 3) -> None:
    """Best-effort secure delete: overwrite the file's bytes, then unlink.

    Note: on copy-on-write / journaling / SSD-wear-levelled filesystems this
    cannot guarantee the original bytes are unrecoverable. Treat any machine
    that ever held the plaintext seeds as needing key rotation for real funds.
    """
    if not os.path.exists(path):
        return
    length = os.path.getsize(path)
    with open(path, "r+b", buffering=0) as fh:
        for _ in range(passes):
            fh.seek(0)
            fh.write(os.urandom(length))
            fh.flush()
            os.fsync(fh.fileno())
    os.remove(path)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", default="wallets_checkpoint.json")
    parser.add_argument("--keystore", default="keystore.json")
    parser.add_argument("--include-treasury", action="store_true")
    parser.add_argument(
        "--shred",
        action="store_true",
        help="Securely delete the plaintext checkpoint after verified migration.",
    )
    args = parser.parse_args(argv)

    keystore, imported = migrate_checkpoint(
        args.checkpoint, args.keystore, include_treasury=args.include_treasury
    )
    verify_roundtrip(keystore, imported)
    keystore.save()
    print(f"Encrypted keystore written to {args.keystore} with entries: {imported}")

    if args.shred:
        secure_shred(args.checkpoint)
        print(f"Securely shredded plaintext checkpoint: {args.checkpoint}")
        print(
            "NOTE: filesystem-level recovery may still be possible on SSD/CoW/"
            "journaled volumes. For real funds, rotate these keys."
        )
    else:
        print(
            "Left plaintext checkpoint in place. Re-run with --shred once you have "
            "confirmed the keystore works, or delete it yourself."
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
