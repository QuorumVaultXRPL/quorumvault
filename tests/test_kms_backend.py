"""AwsKmsSignerBackend: secp256k1 identity, low-S canonicalization, XRPL validity."""

import pytest
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from xrpl.core.binarycodec import encode_for_multisigning
from xrpl.core.keypairs import is_valid_message
from xrpl.models.transactions import Payment

from quorumvault.signing.errors import BackendConfigError
from quorumvault.signing.kms_backend import AwsKmsSignerBackend, _SECP256K1_N

_HALF_N = _SECP256K1_N // 2


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


def test_public_key_is_compressed_secp256k1(fake_kms):
    backend = AwsKmsSignerBackend(fake_kms, "key-1")
    assert backend.algorithm == "secp256k1"
    assert backend.public_key[:2] in ("02", "03")
    assert len(backend.public_key) == 66
    assert backend.classic_address.startswith("r")


def test_signature_validates_on_xrpl(fake_kms):
    backend = AwsKmsSignerBackend(fake_kms, "key-1")
    blob = _blob(backend)
    signature = backend.sign(blob)
    assert is_valid_message(blob, bytes.fromhex(signature), backend.public_key)


def test_high_s_is_normalized_to_low_s(fake_kms_high_s):
    backend = AwsKmsSignerBackend(fake_kms_high_s, "key-1")
    blob = _blob(backend)
    signature = backend.sign(blob)
    _r, s = decode_dss_signature(bytes.fromhex(signature))
    assert s <= _HALF_N, "signature must be canonical (low-S) for XRPL"
    # Still valid despite the KMS having emitted a high-S value.
    assert is_valid_message(blob, bytes.fromhex(signature), backend.public_key)


def test_ed25519_public_key_rejected(fake_kms):
    # An ED-prefixed key is not a valid secp256k1 compressed point.
    with pytest.raises(BackendConfigError):
        AwsKmsSignerBackend(fake_kms, "key-1", public_key="ED" + "00" * 32)


def test_explicit_compressed_public_key_accepted(fake_kms):
    derived = AwsKmsSignerBackend(fake_kms, "key-1").public_key
    backend = AwsKmsSignerBackend(fake_kms, "key-1", public_key=derived)
    assert backend.public_key == derived
