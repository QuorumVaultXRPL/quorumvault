"""AWS KMS signing backend — non-exportable secp256k1 key.

This is the strongest production posture: the private key is generated inside
AWS KMS with key spec ``ECC_SECG_P256K1`` and *never leaves the HSM*. KMS
performs the ECDSA operation internally and returns only a signature.

Three correctness details this backend gets right, each a known footgun:

1. **Digest.** XRPL signs the *SHA-512Half* of the blob (first 32 bytes of
   SHA-512), not SHA-256. We compute that digest ourselves and call KMS with
   ``MessageType="DIGEST"`` so KMS signs exactly those 32 bytes.
2. **Low-S canonicalization.** KMS returns a DER ECDSA signature with a random
   ``k`` and does **not** guarantee a low-S value; XRPL rejects non-canonical
   (high-S) signatures. We normalize ``s`` to the lower half of the curve order.
3. **Compressed public key.** XRPL wants the 33-byte compressed secp256k1 point
   (``02/03…``); KMS hands back an SPKI DER blob. We compress it.

Constraint worth flagging loudly: **AWS KMS cannot sign ed25519.** The project's
current Testnet signers are ed25519, so adopting this backend means either
migrating a signer to a secp256k1 key (add it to the ``SignerListSet`` — can be
done one signer at a time) or using an ed25519-capable backend (e.g. HashiCorp
Vault transit). See the module README.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import load_der_public_key
from xrpl.core.keypairs import derive_classic_address

from .backend import SignerBackend
from .errors import BackendConfigError

# Order of the secp256k1 curve.
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_HALF_N = _SECP256K1_N // 2


def _sha512half(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()[:32]


def _compress_spki_public_key(der_spki: bytes) -> str:
    """Turn a KMS SPKI DER EC public key into an XRPL compressed hex pubkey."""
    pub = load_der_public_key(der_spki)
    try:
        numbers = pub.public_numbers()
        curve_name = numbers.curve.name
    except AttributeError as exc:  # not an EC key at all
        raise BackendConfigError("KMS key is not an EC public key") from exc
    if curve_name != "secp256k1":
        raise BackendConfigError(
            f"KMS key curve is {curve_name!r}; QuorumVault's KMS backend requires "
            "secp256k1 (ECC_SECG_P256K1). ed25519 signers must use a different backend."
        )
    prefix = b"\x02" if (numbers.y % 2 == 0) else b"\x03"
    return (prefix + numbers.x.to_bytes(32, "big")).hex().upper()


def _canonical_der(der_signature: bytes) -> str:
    """Return a low-S canonical DER signature as uppercase hex."""
    r, s = decode_dss_signature(der_signature)
    if s > _HALF_N:
        s = _SECP256K1_N - s
    return encode_dss_signature(r, s).hex().upper()


class AwsKmsSignerBackend(SignerBackend):
    """A :class:`SignerBackend` whose key lives in (and never leaves) AWS KMS.

    ``kms_client`` is any object exposing ``sign`` (and optionally
    ``get_public_key``) with the boto3 KMS shape, so tests can inject a fake.
    """

    def __init__(
        self,
        kms_client: Any,
        key_id: str,
        public_key: Optional[str] = None,
    ):
        self._kms = kms_client
        self._key_id = key_id

        if public_key is None:
            resp = kms_client.get_public_key(KeyId=key_id)
            public_key = _compress_spki_public_key(resp["PublicKey"])
        else:
            public_key = public_key.upper()
            if public_key[:2] not in ("02", "03") or len(public_key) != 66:
                raise BackendConfigError(
                    "public_key must be a 33-byte compressed secp256k1 hex "
                    "(66 hex chars, 02/03 prefix)."
                )

        self._public_key = public_key
        self._address = derive_classic_address(public_key)

    @property
    def public_key(self) -> str:
        return self._public_key

    @property
    def classic_address(self) -> str:
        return self._address

    @property
    def algorithm(self) -> str:
        return "secp256k1"

    def sign(self, signing_blob: bytes) -> str:
        digest = _sha512half(signing_blob)
        resp = self._kms.sign(
            KeyId=self._key_id,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        return _canonical_der(resp["Signature"])
