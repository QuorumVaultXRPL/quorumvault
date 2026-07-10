"""The swappability claim, proven: one quorum, two different backends AND two
different signature schemes (local ed25519 + KMS secp256k1), and the auditor/
quorum layer above is identical."""

from xrpl.core.binarycodec import encode_for_multisigning
from xrpl.core.keypairs import is_valid_message
from xrpl.models.transactions import Payment

from quorumvault.signing.kms_backend import AwsKmsSignerBackend
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
