"""Migration from plaintext checkpoint to encrypted keystore, then secure shred."""

import json
import os

from xrpl.constants import CryptoAlgorithm
from xrpl.wallet import Wallet

from quorumvault.tools.migrate_keystore import (
    migrate_checkpoint,
    secure_shred,
    verify_roundtrip,
)


def _synthetic_checkpoint(tmp_path):
    wallets = {a: Wallet.create(CryptoAlgorithm.ED25519) for a in ("t", "e", "a")}
    data = {
        "treasury_seed": wallets["t"].seed,
        "treasury_address": wallets["t"].address,
        "exec_signer_seed": wallets["e"].seed,
        "exec_signer_address": wallets["e"].address,
        "auditor_signer_seed": wallets["a"].seed,
        "auditor_signer_address": wallets["a"].address,
    }
    path = str(tmp_path / "wallets_checkpoint.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path, wallets


def test_migrate_skips_treasury_by_default(tmp_path, passphrase):
    checkpoint, _ = _synthetic_checkpoint(tmp_path)
    keystore, imported = migrate_checkpoint(
        checkpoint, str(tmp_path / "ks.json"), passphrase=passphrase
    )
    assert set(imported) == {"exec_signer", "auditor_signer"}
    assert "treasury" not in keystore.aliases()


def test_migrate_can_include_treasury(tmp_path, passphrase):
    checkpoint, _ = _synthetic_checkpoint(tmp_path)
    keystore, imported = migrate_checkpoint(
        checkpoint,
        str(tmp_path / "ks.json"),
        passphrase=passphrase,
        include_treasury=True,
    )
    assert "treasury" in imported


def test_migrated_keystore_roundtrips_and_hides_plaintext(tmp_path, passphrase):
    checkpoint, wallets = _synthetic_checkpoint(tmp_path)
    ks_path = str(tmp_path / "ks.json")
    keystore, imported = migrate_checkpoint(checkpoint, ks_path, passphrase=passphrase)
    verify_roundtrip(keystore, imported, passphrase=passphrase)
    keystore.save()
    with open(ks_path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    for wallet in wallets.values():
        assert wallet.seed not in raw


def test_secure_shred_removes_file(tmp_path):
    checkpoint, _ = _synthetic_checkpoint(tmp_path)
    assert os.path.exists(checkpoint)
    secure_shred(checkpoint)
    assert not os.path.exists(checkpoint)
