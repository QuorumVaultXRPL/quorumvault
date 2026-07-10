"""The signing abstraction must reproduce xrpl-py's own multisign, byte-for-byte."""

from xrpl.core.binarycodec import encode
from xrpl.models.transactions import Payment
from xrpl.transaction import multisign, sign

from quorumvault.signing.local_keystore import LocalEncryptedKeystoreBackend
from quorumvault.signing.quorum_signer import QuorumSigner


def _payment(treasury_address, destination):
    return Payment(
        account=treasury_address,
        amount="1000000",
        destination=destination,
        sequence=42,
        fee="20",
        signing_pub_key="",
        last_ledger_sequence=100_000,
    )


def test_quorum_signer_matches_xrpl_multisign(keystore, ed25519_wallets, passphrase):
    treasury = "rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce"
    exec_w = ed25519_wallets["exec_signer"]
    aud_w = ed25519_wallets["auditor_signer"]
    tx = _payment(treasury, exec_w.address)

    # Reference: xrpl-py with in-memory Wallets (the current demo's flow).
    ref = multisign(
        tx, [sign(tx, exec_w, multisign=True), sign(tx, aud_w, multisign=True)]
    )

    # Ours: identical transaction, signatures sourced from encrypted keystore.
    backends = [
        LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase),
        LocalEncryptedKeystoreBackend(keystore, "auditor_signer", passphrase),
    ]
    ours = QuorumSigner(backends).multisign(tx)

    assert encode(ours.to_xrpl()) == encode(ref.to_xrpl())


def test_signers_are_canonically_sorted(keystore, passphrase):
    tx = _payment("rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce", "rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F")
    # Deliberately reverse the backend order; output must still be canonical.
    backends = [
        LocalEncryptedKeystoreBackend(keystore, "auditor_signer", passphrase),
        LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase),
    ]
    signed = QuorumSigner(backends).multisign(tx)
    signer_accounts = [s.account for s in signed.signers]
    assert signer_accounts == sorted(
        signer_accounts,
        key=lambda a: __import__("xrpl").core.addresscodec.decode_classic_address(a),
    )
