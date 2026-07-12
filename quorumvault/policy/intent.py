"""Transaction intent models fed to the risk engine and the tier router.

``PaymentIntent`` is the neutral description of "an agent wants to move value X
to destination Y". When the value being moved is a tokenized real-world asset,
the optional ``rwa`` field carries the compliance context the RWA rule needs.

None of these fields are secrets; they are the auditable description of intent.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import List, Optional

from .money import to_decimal


@dataclass(frozen=True)
class Credential:
    """An XRPL Credential, identified by its issuer and type (XLS-70)."""

    issuer: str
    credential_type: str


@dataclass
class RwaTransfer:
    """Compliance context for a tokenized real-world-asset transfer.

    In production these fields are populated from ledger reads (the MPT
    issuance flags, the destination's authorized/credential objects, permissioned
    domain membership). Here they are explicit so the rule is deterministic and
    testable without a live ledger.
    """

    is_rwa: bool = True
    token_kind: str = "MPT"  # "MPT" | "IOU"

    # MPT issuance flags (XLS-33)
    requires_authorization: bool = False  # lsfMPTRequireAuth
    destination_authorized: Optional[bool] = None  # holder has MPToken + auth
    transfer_disabled: bool = False  # lsfMPTCanTransfer NOT set
    destination_is_issuer: bool = False
    clawback_enabled: bool = False  # lsfMPTCanClawback (or IOU AllowClawback)

    # Credentials (XLS-70) required by policy or by a permissioned domain
    required_credentials: List[Credential] = field(default_factory=list)
    destination_credentials: List[Credential] = field(default_factory=list)

    # Permissioned Domain (XLS-80)
    domain_id: Optional[str] = None
    destination_in_domain: Optional[bool] = None


@dataclass
class PaymentIntent:
    """A proposed outbound transfer from the treasury.

    ``amount`` is normalized to :class:`~decimal.Decimal` in ``__post_init__``,
    whatever type it arrives as (int, str, a float literal, or already a
    Decimal). Money is never left as a bare float past construction here — a
    binary float silently rounds in a way a decimal amount must not. See
    :mod:`quorumvault.policy.money` for the coercion rule and why.
    """

    destination: str
    asset: str
    amount: Decimal
    purpose: str = "unspecified"
    timestamp: float = field(default_factory=time.time)
    rwa: Optional[RwaTransfer] = None
    tx_id: Optional[str] = None

    def __post_init__(self) -> None:
        self.amount = to_decimal(self.amount)
