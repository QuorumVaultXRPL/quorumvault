"""Exception types for the signing layer.

These are deliberately narrow so callers can distinguish a *configuration*
problem (fixable by an operator) from a *cryptographic* failure (which should
never be papered over near funds).
"""

from __future__ import annotations


class SigningError(Exception):
    """Base class for all signing-layer failures."""


class KeystoreError(SigningError):
    """The keystore file is missing, malformed, or fails integrity checks."""


class KeystoreLockedError(SigningError):
    """No passphrase was supplied (or it was wrong) to decrypt seed material.

    Raised instead of silently falling back to any plaintext source.
    """


class BackendConfigError(SigningError):
    """A signing backend was constructed with inconsistent parameters.

    For example: an AWS KMS key whose scheme is not secp256k1, or a public key
    that does not derive to the address the backend claims to represent.
    """
