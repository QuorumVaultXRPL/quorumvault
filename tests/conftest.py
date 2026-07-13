"""Shared fixtures: self-contained wallets, an encrypted keystore, and a fake KMS.

Tests never touch the real ``wallets_checkpoint.json``; every key here is
freshly generated in-process.
"""

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from xrpl.constants import CryptoAlgorithm
from xrpl.core.keypairs import derive_keypair
from xrpl.wallet import Wallet

from quorumvault.signing.keystore import EncryptedKeystore

PASSPHRASE = "correct-horse-battery-staple"
_SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@pytest.fixture
def passphrase():
    return PASSPHRASE


@pytest.fixture
def ed25519_wallets():
    return {
        alias: Wallet.create(CryptoAlgorithm.ED25519)
        for alias in ("exec_signer", "auditor_signer")
    }


@pytest.fixture
def keystore_path(tmp_path):
    return str(tmp_path / "keystore.json")


@pytest.fixture
def keystore(keystore_path, ed25519_wallets, passphrase):
    ks = EncryptedKeystore.create(keystore_path)
    for alias, wallet in ed25519_wallets.items():
        ks.add_seed(alias, wallet.seed, wallet.address, "ed25519", passphrase=passphrase)
    ks.save()
    return EncryptedKeystore.load(keystore_path)


class FakeKms:
    """Stands in for a boto3 KMS client, backed by a real secp256k1 key.

    Signatures actually verify, so tests exercise the full XRPL crypto path.
    ``force_high_s`` guarantees a non-canonical signature so we can prove the
    backend normalizes it.
    """

    def __init__(self, force_high_s: bool = False):
        self._priv = ec.generate_private_key(ec.SECP256K1())
        self.force_high_s = force_high_s

    def get_public_key(self, KeyId):  # noqa: N803 (boto3 casing)
        der = self._priv.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        return {"PublicKey": der}

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):  # noqa: N803
        assert MessageType == "DIGEST"
        assert len(Message) == 32  # XRPL SHA-512Half
        sig = self._priv.sign(Message, ec.ECDSA(Prehashed(hashes.SHA256())))
        if self.force_high_s:
            r, s = decode_dss_signature(sig)
            if s <= _SECP_N // 2:
                s = _SECP_N - s
            sig = encode_dss_signature(r, s)
        return {"Signature": sig}


@pytest.fixture
def fake_kms():
    return FakeKms()


@pytest.fixture
def fake_kms_high_s():
    return FakeKms(force_high_s=True)


class FakeKmsEd25519:
    """Stands in for a boto3 KMS client backed by a real ECC_NIST_EDWARDS25519 key.

    Built from an xrpl-py ed25519 keypair so its raw 64-byte signatures are
    byte-for-byte what xrpl-py itself produces — the whole point of the parity
    test. ``malform`` forces a wrong-length signature so we can prove the backend
    fails closed instead of emitting garbage near funds.
    """

    def __init__(
        self, xrpl_public_key: str, xrpl_private_key: str, malform: bool = False
    ):
        assert xrpl_private_key.startswith("ED")
        self.xrpl_public_key = xrpl_public_key
        self.xrpl_private_key = xrpl_private_key
        self._priv = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(xrpl_private_key[2:])
        )
        self.malform = malform

    def get_public_key(self, KeyId):  # noqa: N803 (boto3 casing)
        der = self._priv.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        return {"PublicKey": der, "KeySpec": "ECC_NIST_EDWARDS25519"}

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):  # noqa: N803
        # QuorumVault's ed25519 path must sign the RAW blob with ED25519_SHA_512.
        assert MessageType == "RAW"
        assert SigningAlgorithm == "ED25519_SHA_512"
        sig = self._priv.sign(Message)  # raw 64-byte R||S
        if self.malform:
            sig = sig[:-1]  # 63 bytes: wrong length, must be rejected
        return {"Signature": sig}


def _fresh_ed25519_kms(malform: bool = False) -> FakeKmsEd25519:
    wallet = Wallet.create(CryptoAlgorithm.ED25519)
    public_key, private_key = derive_keypair(wallet.seed)
    return FakeKmsEd25519(public_key, private_key, malform=malform)


@pytest.fixture
def fake_kms_ed25519():
    return _fresh_ed25519_kms()


@pytest.fixture
def fake_kms_ed25519_malformed():
    return _fresh_ed25519_kms(malform=True)
