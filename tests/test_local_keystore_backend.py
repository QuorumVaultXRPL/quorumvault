"""LocalEncryptedKeystoreBackend: correct identity, valid signatures, fail-closed."""

import pytest
from xrpl.core.binarycodec import encode_for_multisigning
from xrpl.core.keypairs import is_valid_message
from xrpl.models.transactions import Payment

from quorumvault.signing.errors import KeystoreLockedError
from quorumvault.signing.local_keystore import LocalEncryptedKeystoreBackend


def _multisign_blob(tx, signer_address):
    return bytes.fromhex(encode_for_multisigning(tx.to_xrpl(), signer_address))


def test_identity_matches_wallet(keystore, ed25519_wallets, passphrase):
    backend = LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase)
    wallet = ed25519_wallets["exec_signer"]
    assert backend.classic_address == wallet.address
    assert backend.public_key == wallet.public_key
    assert backend.algorithm == "ed25519"


def test_sign_produces_valid_xrpl_signature(keystore, passphrase):
    backend = LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase)
    tx = Payment(
        account="rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce",
        amount="1000000",
        destination=backend.classic_address,
        sequence=1,
        fee="20",
        signing_pub_key="",
    )
    blob = _multisign_blob(tx, backend.classic_address)
    signature = backend.sign(blob)
    assert is_valid_message(blob, bytes.fromhex(signature), backend.public_key)


def test_wrong_passphrase_rejected_at_construction(keystore):
    with pytest.raises(KeystoreLockedError):
        LocalEncryptedKeystoreBackend(keystore, "exec_signer", "wrong")


def test_repr_has_no_secret(keystore, passphrase):
    backend = LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase)
    text = repr(backend)
    assert "exec_signer" not in text or "seed" not in text.lower()
    assert backend.classic_address in text
