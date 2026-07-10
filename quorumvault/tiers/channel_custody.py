"""Channel-Custody Lane — high-frequency / low-value payments via Payment Channels.

The security model, stated plainly:

* **Open is audited and is where the risk budget is set.** A ``PaymentChannelCreate``
  moves ``capacity`` drops out of the multisig treasury, so it is signed by the
  full 2-of-2 quorum. Because per-payment claims are *not* audited, the channel
  capacity *is* the un-audited exposure window — so the auditor bounds it here
  (``capacity <= capacity_cap_drops``); anything larger must route to the quorum
  as an ordinary high-value transfer.
* **Payments inside the channel are off-ledger and un-audited.** The Execution
  Agent's channel key single-signs an increasing cumulative claim, up to
  capacity. No per-payment ledger transaction, no per-payment audit — this is
  what makes the lane high-frequency. The class refuses to authorize beyond
  capacity and refuses to go backwards.
* **Close/claim is audited.** The payee redeems the latest signed claim with a
  ``PaymentChannelClaim``; the auditor reviews the settled balance at that point.

This module builds and signs transactions; it never submits them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from xrpl.models.transactions import PaymentChannelClaim, PaymentChannelCreate
from xrpl.models.transactions.transaction import Transaction

from ..signing.backend import SignerBackend, authorize_channel_claim
from ..signing.quorum_signer import QuorumSigner


class ChannelExposureError(Exception):
    """A channel operation would exceed its audited exposure budget."""


@dataclass
class ChannelState:
    payer: str
    payee: str
    capacity_drops: int
    channel_public_key: str
    channel_id: Optional[str] = None  # set from the ledger after open confirms
    authorized_drops: int = 0  # cumulative claim authorized so far


class ChannelCustodyLane:
    def __init__(self, capacity_cap_drops: int):
        if capacity_cap_drops <= 0:
            raise ValueError("capacity_cap_drops must be positive")
        self.capacity_cap_drops = capacity_cap_drops

    # -- open (AUDITED, 2-of-2) -----------------------------------------
    def open_channel(
        self,
        quorum_signer: QuorumSigner,
        treasury_address: str,
        channel_key: SignerBackend,
        payee_address: str,
        capacity_drops: int,
        settle_delay: int,
        sequence: int,
        fee: int,
        last_ledger_sequence: Optional[int] = None,
        cancel_after: Optional[int] = None,
        audit: Optional[Callable[[dict], bool]] = None,
    ):
        """Build a 2-of-2-signed ``PaymentChannelCreate``. Returns (signed_tx, state)."""
        if capacity_drops > self.capacity_cap_drops:
            raise ChannelExposureError(
                f"Requested channel capacity {capacity_drops} drops exceeds the "
                f"audited cap {self.capacity_cap_drops}; route this as a high-value "
                "2-of-2 quorum transfer instead of a channel."
            )
        if audit is not None and not audit(
            {"op": "open", "capacity_drops": capacity_drops, "payee": payee_address}
        ):
            raise ChannelExposureError("Auditor rejected channel open.")

        tx = PaymentChannelCreate(
            account=treasury_address,
            amount=str(capacity_drops),
            destination=payee_address,
            settle_delay=settle_delay,
            public_key=channel_key.public_key,
            sequence=sequence,
            fee=str(fee),
            last_ledger_sequence=last_ledger_sequence,
            cancel_after=cancel_after,
        )
        signed = quorum_signer.multisign(tx)
        state = ChannelState(
            payer=treasury_address,
            payee=payee_address,
            capacity_drops=capacity_drops,
            channel_public_key=channel_key.public_key,
        )
        return signed, state

    # -- pay (NOT audited, off-ledger, single-sig) ----------------------
    def authorize_payment(
        self,
        channel_key: SignerBackend,
        state: ChannelState,
        cumulative_drops: int,
    ) -> str:
        """Off-ledger claim authorization. Deliberately takes no auditor.

        ``cumulative_drops`` is the total claimable amount to date (claims are
        cumulative, not per-payment). Must be non-decreasing and within capacity.
        """
        if state.channel_id is None:
            raise ChannelExposureError(
                "Channel id unknown; the on-ledger open must confirm before "
                "claims can be authorized."
            )
        if cumulative_drops > state.capacity_drops:
            raise ChannelExposureError(
                f"Cumulative claim {cumulative_drops} exceeds channel capacity "
                f"{state.capacity_drops}."
            )
        if cumulative_drops < state.authorized_drops:
            raise ChannelExposureError(
                "Cumulative claim cannot decrease "
                f"({cumulative_drops} < {state.authorized_drops})."
            )
        if channel_key.public_key != state.channel_public_key:
            raise ChannelExposureError(
                "Signing key does not match the channel's claim public key."
            )
        signature = authorize_channel_claim(channel_key, state.channel_id, cumulative_drops)
        state.authorized_drops = cumulative_drops
        return signature

    # -- close / claim (AUDITED) ----------------------------------------
    def build_claim(
        self,
        state: ChannelState,
        balance_drops: int,
        signature: str,
        sequence: int,
        fee: int,
        audit: Optional[Callable[[dict], bool]] = None,
    ) -> Transaction:
        """Build the payee's ``PaymentChannelClaim`` to settle the channel."""
        if state.channel_id is None:
            raise ChannelExposureError("Channel id unknown; cannot build a claim.")
        if balance_drops > state.capacity_drops:
            raise ChannelExposureError("Claim balance exceeds channel capacity.")
        if audit is not None and not audit(
            {"op": "claim", "balance_drops": balance_drops, "channel": state.channel_id}
        ):
            raise ChannelExposureError("Auditor rejected channel claim.")
        return PaymentChannelClaim(
            account=state.payee,
            channel=state.channel_id,
            balance=str(balance_drops),
            amount=str(balance_drops),
            signature=signature,
            public_key=state.channel_public_key,
            sequence=sequence,
            fee=str(fee),
        )
