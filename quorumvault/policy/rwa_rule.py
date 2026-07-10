"""The fourth risk-policy rule: RWA compliance.

This rule reasons about XRPL's *native* compliance primitives for tokenized
real-world assets, rather than treating an RWA transfer as a bare value move:

* **MPT authorization (XLS-33).** If the token sets ``lsfMPTRequireAuth``, the
  destination must hold an authorized ``MPToken``. Sending to an unauthorized
  holder is non-compliant and will not settle -> RED.
* **MPT transferability (XLS-33).** If ``lsfMPTCanTransfer`` is not set, only
  issuer<->holder transfers are allowed; a holder-to-holder move is blocked -> RED.
* **Credentials (XLS-70).** If policy (or a permissioned domain) requires the
  destination to hold specific credentials, and it does not, the transfer is
  non-compliant -> RED.
* **Permissioned Domains (XLS-80).** If the asset is restricted to a domain and
  the destination is not a member, the transfer is out of policy -> RED.
* **Clawback (XLS-39/CanClawback).** If the asset is clawback-enabled, holding it
  carries issuer-clawback settlement risk. This is legitimate but material for a
  treasury, so it is surfaced -> YELLOW.

Findings compose with the existing value/whitelist/velocity rules via the
engine's compound-reason accumulation; any RED finding trips the circuit breaker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .intent import RwaTransfer

RED = "RED"
YELLOW = "YELLOW"


@dataclass(frozen=True)
class RwaFinding:
    code: str
    severity: str  # "RED" | "YELLOW"
    message: str


class RwaComplianceRule:
    """Evaluate an :class:`RwaTransfer` context into a list of findings."""

    def evaluate(self, rwa: RwaTransfer) -> List[RwaFinding]:
        findings: List[RwaFinding] = []
        if rwa is None or not rwa.is_rwa:
            return findings

        if rwa.requires_authorization and rwa.destination_authorized is not True:
            findings.append(
                RwaFinding(
                    "rwa_destination_not_authorized",
                    RED,
                    "the token requires issuer authorization and the destination "
                    "is not an authorized holder",
                )
            )

        if rwa.transfer_disabled and not rwa.destination_is_issuer:
            findings.append(
                RwaFinding(
                    "rwa_transfer_not_permitted",
                    RED,
                    "the token is non-transferable between holders (CanTransfer "
                    "is not set) and the destination is not the issuer",
                )
            )

        missing = [
            c for c in rwa.required_credentials if c not in rwa.destination_credentials
        ]
        if missing:
            names = ", ".join(f"{c.credential_type}@{c.issuer[:8]}…" for c in missing)
            findings.append(
                RwaFinding(
                    "rwa_missing_required_credential",
                    RED,
                    f"the destination is missing required credential(s): {names}",
                )
            )

        if rwa.domain_id and rwa.destination_in_domain is not True:
            findings.append(
                RwaFinding(
                    "rwa_destination_outside_permissioned_domain",
                    RED,
                    "the asset is restricted to a permissioned domain the "
                    "destination is not a member of",
                )
            )

        if rwa.clawback_enabled:
            findings.append(
                RwaFinding(
                    "rwa_clawback_exposure",
                    YELLOW,
                    "the asset is clawback-enabled; the issuer can reverse this "
                    "holding after settlement",
                )
            )

        return findings
