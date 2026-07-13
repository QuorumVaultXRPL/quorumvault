"""AwsKmsEd25519SignerBackend: ed25519 identity, RAW PureEdDSA signing, byte-for-
byte parity with xrpl-py, and fail-closed refusal of every malformed input.

Mirror of tests/test_kms_backend.py for the ed25519 sibling. The FakeKmsEd25519
client (conftest) is backed by a real Ed25519 key derived from the same xrpl-py
keypair, so its signatures actually verify and can be compared byte-for-byte to
xrpl-py's own output.
"""

import pytest
from xrpl.core.binarycodec import encode_for_multisigning
from xrpl.core.keypairs import is_valid_message
from xrpl.core.keypairs import sign as keypairs_sign
from xrpl.models.transactions import Payment

from quorumvault.signing.errors import BackendConfigError, SigningError
from quorumvault.signing.kms_backend import AwsKmsEd25519SignerBackend


def _blob(backend):
    tx = Payment(
        account="rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce",
        amount="1000000",
        destination=backend.classic_address,
        sequence=7,
        fee="20",
        signing_pub_key="",
    )
    return bytes.fromhex(encode_for_multisigning(tx.to_xrpl(), backend.classic_address))


def test_public_key_is_ed25519(fake_kms_ed25519):
    backend = AwsKmsEd25519SignerBackend(fake_kms_ed25519, "key-ed")
    assert backend.algorithm == "ed25519"
    assert backend.public_key[:2] == "ED"
    assert len(backend.public_key) == 66
    assert backend.public_key == fake_kms_ed25519.xrpl_public_key
    assert backend.classic_address.startswith("r")


def test_signature_is_byte_for_byte_xrpl(fake_kms_ed25519):
    # The core guarantee: KMS-backed ed25519 output == xrpl-py's own signing.
    backend = AwsKmsEd25519SignerBackend(fake_kms_ed25519, "key-ed")
    blob = _blob(backend)
    kms_sig = backend.sign(blob)
    xrpl_sig = keypairs_sign(blob, fake_kms_ed25519.xrpl_private_key)
    assert kms_sig == xrpl_sig
    # A raw 64-byte signature (no DER wrapping, no low-S mangling).
    assert len(bytes.fromhex(kms_sig)) == 64


def test_signature_validates_on_xrpl(fake_kms_ed25519):
    backend = AwsKmsEd25519SignerBackend(fake_kms_ed25519, "key-ed")
    blob = _blob(backend)
    signature = backend.sign(blob)
    assert is_valid_message(blob, bytes.fromhex(signature), backend.public_key)


def test_explicit_public_key_accepted_and_normalized(fake_kms_ed25519):
    derived = AwsKmsEd25519SignerBackend(fake_kms_ed25519, "key-ed").public_key
    backend = AwsKmsEd25519SignerBackend(fake_kms_ed25519, "key-ed", public_key=derived)
    assert backend.public_key == derived
    lower = AwsKmsEd25519SignerBackend(
        fake_kms_ed25519, "key-ed", public_key=derived.lower()
    )
    assert lower.public_key == derived  # lowercase input normalized to upper


def test_secp256k1_key_spec_rejected_by_ed25519_path(fake_kms):
    # fake_kms returns a secp256k1 SPKI; the ed25519 backend must fail closed.
    with pytest.raises(BackendConfigError):
        AwsKmsEd25519SignerBackend(fake_kms, "key-1")


def test_secp256k1_pubkey_string_rejected(fake_kms_ed25519):
    with pytest.raises(BackendConfigError):
        AwsKmsEd25519SignerBackend(
            fake_kms_ed25519, "key-ed", public_key="02" + "00" * 32
        )


@pytest.mark.parametrize(
    "bad",
    [
        "ED" + "00" * 31,   # too short (64 chars)
        "ED" + "00" * 33,   # too long (68 chars)
        "EDZZ" + "00" * 31,  # right length, non-hex body
        "ED",               # nonsense
    ],
)
def test_malformed_public_key_rejected(fake_kms_ed25519, bad):
    with pytest.raises(BackendConfigError):
        AwsKmsEd25519SignerBackend(fake_kms_ed25519, "key-ed", public_key=bad)


def test_malformed_kms_signature_rejected(fake_kms_ed25519_malformed):
    backend = AwsKmsEd25519SignerBackend(fake_kms_ed25519_malformed, "key-ed")
    with pytest.raises(BackendConfigError):
        backend.sign(_blob(backend))


def test_oversized_blob_fails_closed(fake_kms_ed25519):
    backend = AwsKmsEd25519SignerBackend(fake_kms_ed25519, "key-ed")
    with pytest.raises(SigningError):
        backend.sign(b"\x00" * 4097)


def test_repr_leaks_no_secret(fake_kms_ed25519):
    backend = AwsKmsEd25519SignerBackend(fake_kms_ed25519, "key-ed")
    text = repr(backend)
    assert backend.classic_address in text
    assert "ed25519" in text
