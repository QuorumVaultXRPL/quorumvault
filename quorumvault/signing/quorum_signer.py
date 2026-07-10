"""Combine independent :class:`SignerBackend` signatures into one multisigned tx.

This is the drop-in replacement for the demo's
``Wallet.from_seed(...) -> sign(tx, wallet, multisign=True) -> multisign(...)``
sequence. The only thing that changes versus xrpl-py's own flow is *where each
signature comes from* (a backend instead of an in-memory ``Wallet``). The
serialized result is byte-for-byte identical to xrpl-py's ``multisign`` output
— asserted in ``tests/test_quorum_signer.py``.
"""

from __future__ import annotations

from typing import List, Sequence

from xrpl.asyncio.transaction.main import _prepare_transaction
from xrpl.core.binarycodec import encode_for_multisigning
from xrpl.models.transactions.transaction import Transaction
from xrpl.transaction import multisign as _xrpl_multisign

from .backend import SignerBackend


class QuorumSigner:
    """Produce a multisigned transaction from a set of signer backends.

    The auditor/quorum logic above this class is unchanged: it decides *whether*
    to co-sign and hands the approved transaction here. Whether the underlying
    keys live in a local keystore or an HSM is invisible at this layer.
    """

    def __init__(self, backends: Sequence[SignerBackend]):
        if not backends:
            raise ValueError("QuorumSigner requires at least one backend")
        self._backends: List[SignerBackend] = list(backends)

    @property
    def signer_addresses(self) -> List[str]:
        return [b.classic_address for b in self._backends]

    def _sign_one(self, tx: Transaction, backend: SignerBackend) -> Transaction:
        tx_json = _prepare_transaction(tx)
        blob = bytes.fromhex(
            encode_for_multisigning(tx_json, backend.classic_address)
        )
        signature = backend.sign(blob)
        tx_json["Signers"] = [
            {
                "Signer": {
                    "Account": backend.classic_address,
                    "TxnSignature": signature,
                    "SigningPubKey": backend.public_key,
                }
            }
        ]
        return Transaction.from_xrpl(tx_json)

    def multisign(self, tx: Transaction) -> Transaction:
        """Return ``tx`` multisigned by every configured backend."""
        signed = [self._sign_one(tx, backend) for backend in self._backends]
        # Reuse xrpl-py's own combiner (dedupes/sorts Signers canonically).
        return _xrpl_multisign(tx, signed)
