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

Historical note (constraint lifted 2025-11-07): AWS KMS **now signs ed25519
natively.** Using key spec ``ECC_NIST_EDWARDS25519`` with signing algorithm
``ED25519_SHA_512`` and ``MessageType="RAW"`` (PureEdDSA over the actual
signing blob), KMS produces a raw 64-byte ed25519 signature that is exactly
what XRPL expects. The sibling backend :class:`AwsKmsEd25519SignerBackend`
(below) implements this, so the project's existing ed25519 Testnet signers can
move to a non-exportable KMS key with **no secp256k1 migration and no
``SignerListSet`` change**. The earlier "KMS cannot sign ed25519" limitation
that motivated the secp256k1-only posture no longer holds.

Verified against AWS primary sources (2026-07-13): the KMS ``Sign`` and
``GetPublicKey`` API reference (``SigningAlgorithm`` enum includes
``ED25519_SHA_512``/``ED25519_PH_SHA_512``; ``KeySpec`` enum includes
``ECC_NIST_EDWARDS25519``) and the "Key spec reference" developer guide, which
states ``ED25519_SHA_512`` requires ``MessageType="RAW"``. Announced in "AWS
KMS now supports EdDSA" (Nov 7, 2025), available in all AWS Regions.

This class (:class:`AwsKmsSignerBackend`) remains **secp256k1-only** by design;
ed25519 keys use the sibling class.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)
from xrpl.core.keypairs import derive_classic_address

from .backend import SignerBackend
from .errors import BackendConfigError, SigningError

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


# --- ed25519 (ECC_NIST_EDWARDS25519) support --------------------------------
# AWS KMS added native EdDSA/Ed25519 signing on 2025-11-07. Unlike the secp256k1
# path above, PureEdDSA hashes the full message *inside* the signing algorithm,
# so there is NO separate SHA-512Half pre-hash: we sign the RAW blob with
# SigningAlgorithm="ED25519_SHA_512" + MessageType="RAW" and take the raw 64-byte
# R||S signature straight back. No DER unwrap and no low-S normalization apply
# (ed25519 signatures are not malleable the way raw ECDSA is; XRPL requires no
# low-S canonicalization for ed25519). This mirrors exactly what xrpl-py's
# keypairs.sign does for an ed25519 key, so the TxnSignature is byte-identical.

# AWS KMS Sign accepts a RAW Message of at most 4096 bytes. An XRPL multisigning
# blob for a Payment is ~100 bytes, but we fail closed rather than forward an
# oversized blob to KMS.
_KMS_MAX_RAW_MESSAGE_BYTES = 4096


def _ed25519_pubkey_from_spki(der_spki: bytes) -> str:
    """Turn a KMS SPKI DER ed25519 public key into an XRPL ``ED…`` hex pubkey.

    ``GetPublicKey`` returns a DER ``SubjectPublicKeyInfo`` for every key spec;
    for ``ECC_NIST_EDWARDS25519`` the payload is the raw 32-byte Ed25519 public
    key (not an EC point with x/y coordinates), so ``cryptography`` parses it to
    an :class:`Ed25519PublicKey`. Fails closed if the key is anything else.
    """
    pub = load_der_public_key(der_spki)
    if not isinstance(pub, Ed25519PublicKey):
        raise BackendConfigError(
            f"KMS key parsed as {type(pub).__name__}, not an Ed25519 public key; "
            "QuorumVault's ed25519 KMS backend requires an ECC_NIST_EDWARDS25519 "
            "key. secp256k1 keys must use AwsKmsSignerBackend."
        )
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    if len(raw) != 32:  # defensive: RFC 8032 ed25519 public keys are 32 bytes
        raise BackendConfigError(
            f"Ed25519 public key is {len(raw)} bytes; expected 32."
        )
    return "ED" + raw.hex().upper()


class AwsKmsEd25519SignerBackend(SignerBackend):
    """A :class:`SignerBackend` whose non-exportable **ed25519** key lives in AWS KMS.

    Sibling to :class:`AwsKmsSignerBackend` (secp256k1), with the same constructor
    shape and the same ``SignerBackend`` contract, so :class:`QuorumSigner` uses it
    with zero changes. It signs with key spec ``ECC_NIST_EDWARDS25519`` using
    ``ED25519_SHA_512`` + ``MessageType="RAW"`` — PureEdDSA over the actual signing
    blob, exactly what xrpl-py's ``keypairs.sign`` does for an ed25519 key, so the
    resulting ``TxnSignature`` is byte-for-byte identical (proven in the tests).

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
            public_key = _ed25519_pubkey_from_spki(resp["PublicKey"])
        else:
            public_key = public_key.upper()
            if not public_key.startswith("ED") or len(public_key) != 66:
                raise BackendConfigError(
                    "public_key must be a 33-byte XRPL ed25519 hex (66 hex chars, "
                    "'ED' prefix). secp256k1 keys must use AwsKmsSignerBackend."
                )
            try:
                body = bytes.fromhex(public_key[2:])
            except ValueError as exc:
                raise BackendConfigError("public_key is not valid hex.") from exc
            if len(body) != 32:
                raise BackendConfigError(
                    "ed25519 public key body must be exactly 32 bytes."
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
        return "ed25519"

    def sign(self, signing_blob: bytes) -> str:
        # PureEdDSA signs the whole message; KMS requires MessageType="RAW" for
        # ED25519_SHA_512. Fail closed on an oversized blob rather than send it.
        if len(signing_blob) > _KMS_MAX_RAW_MESSAGE_BYTES:
            raise SigningError(
                f"signing blob is {len(signing_blob)} bytes; AWS KMS RAW Sign "
                f"accepts at most {_KMS_MAX_RAW_MESSAGE_BYTES}."
            )
        resp = self._kms.sign(
            KeyId=self._key_id,
            Message=signing_blob,
            MessageType="RAW",
            SigningAlgorithm="ED25519_SHA_512",
        )
        signature = resp["Signature"]
        # KMS returns a raw 64-byte R||S ed25519 signature (not DER); no low-S
        # normalization applies. Fail closed if it is not exactly 64 bytes.
        sig_len = len(signature) if isinstance(signature, (bytes, bytearray)) else -1
        if sig_len != 64:
            raise BackendConfigError(
                f"KMS returned a {sig_len}-byte ed25519 signature; expected "
                "exactly 64 (R||S)."
            )
        return bytes(signature).hex().upper()
