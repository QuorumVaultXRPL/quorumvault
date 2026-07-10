"""The encrypted keystore must never leak plaintext and must fail closed."""

import json

import pytest

from quorumvault.signing.errors import KeystoreLockedError
from quorumvault.signing.keystore import EncryptedKeystore, zeroize


def test_no_plaintext_seed_on_disk(keystore, keystore_path, ed25519_wallets):
    with open(keystore_path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    for wallet in ed25519_wallets.values():
        assert wallet.seed not in raw, "plaintext seed leaked into keystore file"
    # And the seed field name from the old checkpoint format is gone entirely.
    assert "treasury_seed" not in raw


def test_roundtrip_returns_correct_seed(keystore, ed25519_wallets, passphrase):
    for alias, wallet in ed25519_wallets.items():
        buf = keystore.decrypt_seed(alias, passphrase)
        try:
            assert bytes(buf).decode() == wallet.seed
        finally:
            zeroize(buf)


def test_wrong_passphrase_fails_closed(keystore):
    with pytest.raises(KeystoreLockedError):
        keystore.decrypt_seed("exec_signer", "not-the-passphrase")


def test_missing_passphrase_raises(keystore, monkeypatch):
    monkeypatch.delenv("QUORUMVAULT_KEYSTORE_PASSPHRASE", raising=False)
    with pytest.raises(KeystoreLockedError):
        keystore.decrypt_seed("exec_signer")


def test_tampered_metadata_breaks_aad(keystore, keystore_path, passphrase):
    # Swapping the bound address must make the AES-GCM tag fail (entries can't
    # be transplanted or relabeled).
    with open(keystore_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    data["entries"]["exec_signer"]["address"] = data["entries"]["auditor_signer"][
        "address"
    ]
    with open(keystore_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    ks = EncryptedKeystore.load(keystore_path)
    with pytest.raises(KeystoreLockedError):
        ks.decrypt_seed("exec_signer", passphrase)


def test_env_passphrase_is_used(keystore, ed25519_wallets, passphrase, monkeypatch):
    monkeypatch.setenv("QUORUMVAULT_KEYSTORE_PASSPHRASE", passphrase)
    buf = keystore.decrypt_seed("exec_signer")  # no explicit passphrase
    try:
        assert bytes(buf).decode() == ed25519_wallets["exec_signer"].seed
    finally:
        zeroize(buf)
