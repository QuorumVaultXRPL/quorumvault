"""The swappability claim, proven: one quorum, two different backends AND two
different signature schemes (local ed25519 + KMS secp256k1), and the auditor/
quorum layer above is identical."""

from xrpl.core.binarycodec import encode_for_multisigning
from xrpl.core.keypairs import is_valid_message
from xrpl.models.transactions import Payment

from quorumvault.signing.kms_backend import (
    AwsKmsEd25519SignerBackend,
    AwsKmsSignerBackend,
)
from quorumvault.signing.local_keystore import LocalEncryptedKeystoreBackend
from quorumvault.signing.quorum_signer import QuorumSigner

TREASURY = "rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce"


def test_mixed_ed25519_local_and_secp256k1_kms_quorum(keystore, passphrase, fake_kms):
    local = LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase)  # ed25519
    kms = AwsKmsSignerBackend(fake_kms, "key-1")  # secp256k1, non-exportable

    assert local.algorithm == "ed25519"
    assert kms.algorithm == "secp256k1"

    tx = Payment(
        account=TREASURY,
        amount="1000000",
        destination=local.classic_address,
        sequence=1,
        fee="20",
        signing_pub_key="",
        last_ledger_sequence=100_000,
    )
    signed = QuorumSigner([local, kms]).multisign(tx)
    assert len(signed.signers) == 2

    # Each signer's signature must validate against its own key over its own
    # canonical multisigning blob — regardless of scheme or backend.
    by_account = {s.account: s for s in signed.signers}
    for backend in (local, kms):
        blob = bytes.fromhex(
            encode_for_multisigning(tx.to_xrpl(), backend.classic_address)
        )
        signer = by_account[backend.classic_address]
        assert signer.signing_pub_key == backend.public_key
        assert is_valid_message(
            blob, bytes.fromhex(signer.txn_signature), backend.public_key
        )


def test_mixed_ed25519_local_and_ed25519_kms_quorum(keystore, passphrase, fake_kms_ed25519):
    """Same scheme (ed25519), two different backends: local keystore + KMS."""
    local = LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase)
    kms = AwsKmsEd25519SignerBackend(fake_kms_ed25519, "key-ed")  # non-exportable

    assert local.algorithm == "ed25519"
    assert kms.algorithm == "ed25519"

    tx = Payment(
        account=TREASURY,
        amount="1000000",
        destination=local.classic_address,
        sequence=1,
        fee="20",
        signing_pub_key="",
        last_ledger_sequence=100_000,
    )
    signed = QuorumSigner([local, kms]).multisign(tx)
    assert len(signed.signers) == 2

    by_account = {s.account: s for s in signed.signers}
    for backend in (local, kms):
        blob = bytes.fromhex(
            encode_for_multisigning(tx.to_xrpl(), backend.classic_address)
        )
        signer = by_account[backend.classic_address]
        assert signer.signing_pub_key == backend.public_key
        assert is_valid_message(
            blob, bytes.fromhex(signer.txn_signature), backend.public_key
        )


def test_three_way_mixed_scheme_quorum(keystore, passphrase, fake_kms, fake_kms_ed25519):
    """Three backends, two schemes, one quorum: ed25519 local + secp256k1 KMS +
    ed25519 KMS. The auditor/quorum layer above is identical for all three."""
    local = LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase)  # ed25519
    kms_secp = AwsKmsSignerBackend(fake_kms, "key-1")  # secp256k1
    kms_ed = AwsKmsEd25519SignerBackend(fake_kms_ed25519, "key-ed")  # ed25519

    assert sorted(b.algorithm for b in (local, kms_secp, kms_ed)) == [
        "ed25519",
        "ed25519",
        "secp256k1",
    ]

    tx = Payment(
        account=TREASURY,
        amount="1000000",
        destination=local.classic_address,
        sequence=1,
        fee="20",
        signing_pub_key="",
        last_ledger_sequence=100_000,
    )
    signed = QuorumSigner([local, kms_secp, kms_ed]).multisign(tx)
    assert len(signed.signers) == 3

    by_account = {s.account: s for s in signed.signers}
    for backend in (local, kms_secp, kms_ed):
        blob = bytes.fromhex(
            encode_for_multisigning(tx.to_xrpl(), backend.classic_address)
        )
        signer = by_account[backend.classic_address]
        assert signer.signing_pub_key == backend.public_key
        assert is_valid_message(
            blob, bytes.fromhex(signer.txn_signature), backend.public_key
        )
