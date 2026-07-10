"""RiskEngine - the v1 three rules plus the v2 RWA rule, unified.

Ported from xrpl_auditor_production_blueprint.py with its behavior intact:
compound-reason accumulation, and a persistent RED circuit-breaker freeze that
forces every subsequent transaction RED until a human reset. The RWA rule is
folded in as a fourth rule so its findings accumulate and trip the breaker the
same way the whitelist and velocity rules do. The value threshold uses the same
injectable rate provider as the router/fast-path, so a stale XRP price can't
silently skip it.
"""

from __future__ import annotations

from collections import deque
from enum import Enum
from typing import List, Optional, Tuple

from .intent import PaymentIntent
from .pricing import RateProvider, default_rate_provider
from .rwa_rule import RwaComplianceRule


class RiskLevel(Enum):
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"


class RiskEngine:
    def __init__(
        self,
        whitelist,
        amount_threshold_rlusd: float = 5000.0,
        frequency_window_s: float = 60.0,
        frequency_limit: int = 3,
        rwa_rule: Optional[RwaComplianceRule] = None,
        rate_provider: RateProvider = None,
    ):
        self.whitelist = set(whitelist)
        self.amount_threshold_rlusd = amount_threshold_rlusd
        self.frequency_window_s = frequency_window_s
        self.frequency_limit = frequency_limit
        self.rwa_rule = rwa_rule or RwaComplianceRule()
        self.rate_provider = rate_provider or default_rate_provider()

        self._recent_tx_log: deque = deque()
        self.circuit_breaker_tripped = False
        self.trip_reasons: List[str] = []
        self.audit_log: List[dict] = []

    def _to_rlusd_equivalent(self, asset: str, amount: float) -> float:
        return self.rate_provider.to_rlusd(asset, amount)

    def _prune_log(self, now: float) -> None:
        while (
            self._recent_tx_log
            and (now - self._recent_tx_log[0][0]) > self.frequency_window_s
        ):
            self._recent_tx_log.popleft()

    def evaluate(self, intent: PaymentIntent) -> dict:
        rlusd_equiv = self._to_rlusd_equivalent(intent.asset, intent.amount)
        amount_flag = rlusd_equiv > self.amount_threshold_rlusd
        overage = max(0.0, rlusd_equiv - self.amount_threshold_rlusd)
        whitelist_flag = intent.destination not in self.whitelist

        self._prune_log(intent.timestamp)
        matches = [
            t
            for t in self._recent_tx_log
            if t[1] == intent.destination
            and t[2] == intent.asset
            and t[3] == intent.amount
        ]
        repeat_count = len(matches) + 1
        frequency_flag = repeat_count > self.frequency_limit
        self._recent_tx_log.append(
            (intent.timestamp, intent.destination, intent.asset, intent.amount)
        )

        fired: List[Tuple[str, str]] = []
        if amount_flag:
            fired.append(("value_threshold_exceeded", "YELLOW"))
        if whitelist_flag:
            fired.append(("untrusted_destination", "RED"))
        if frequency_flag:
            fired.append(("transaction_loop_detected", "RED"))

        rwa_findings = self.rwa_rule.evaluate(intent.rwa) if intent.rwa else []
        for finding in rwa_findings:
            fired.append((finding.code, finding.severity))

        severities = {sev for _code, sev in fired}
        if "RED" in severities:
            risk_level = RiskLevel.RED
        elif "YELLOW" in severities:
            risk_level = RiskLevel.YELLOW
        else:
            risk_level = RiskLevel.GREEN

        breaker_was_already_tripped = self.circuit_breaker_tripped
        if breaker_was_already_tripped:
            risk_level = RiskLevel.RED
            if not any(code == "circuit_breaker_frozen" for code, _s in fired):
                fired.append(("circuit_breaker_frozen", "RED"))

        breaker_tripped_now = False
        if risk_level == RiskLevel.RED and not self.circuit_breaker_tripped:
            self.circuit_breaker_tripped = True
            breaker_tripped_now = True
            self.trip_reasons = [code for code, _s in fired]

        result = {
            "intent": intent,
            "risk_level": risk_level,
            "rlusd_equivalent": rlusd_equiv,
            "amount_overage": overage,
            "amount_flag": amount_flag,
            "whitelist_flag": whitelist_flag,
            "frequency_flag": frequency_flag,
            "repeat_count": repeat_count,
            "rwa_findings": rwa_findings,
            "fired_reasons": [code for code, _s in fired],
            "breaker_was_already_tripped": breaker_was_already_tripped,
            "circuit_breaker_tripped": self.circuit_breaker_tripped,
            "breaker_tripped_by_this_tx": breaker_tripped_now,
            "trip_reasons": list(self.trip_reasons),
        }
        self.audit_log.append(result)
        return result

    def reset_circuit_breaker(self, reason: str) -> None:
        """Clear the freeze. Authorization is the caller's responsibility.

        In production this is gated behind the human-override path (SSO +
        hardware MFA, override bound to the freeze episode).
        """
        self.circuit_breaker_tripped = False
        self.trip_reasons = []

    def explain_my_position(self, result: dict, execution_source: str) -> str:
        intent = result["intent"]
        level = result["risk_level"]
        head = (
            f'Execution agent "{execution_source}" is attempting to move '
            f"{intent.amount:,.2f} {intent.asset} to {intent.destination}."
        )
        if level == RiskLevel.GREEN:
            return head + " No risk rules violated; may proceed to the XRPL."

        detail = ", ".join(result["fired_reasons"])
        if level == RiskLevel.YELLOW:
            return (
                head + f" Flags: {detail}. The Auditor Agent is withholding its "
                "co-signature for this transaction; a verified human override is "
                "required to broadcast."
            )
        if result["breaker_was_already_tripped"] and not result["breaker_tripped_by_this_tx"]:
            return (
                head + " The circuit breaker is already frozen from a prior "
                f"violation ({', '.join(result['trip_reasons'])}); all transactions "
                "are blocked until a human resets it."
            )
        return (
            head + f" ACTION: circuit breaker TRIPPED, accumulating "
            f"{len(result['trip_reasons'])} risk factor(s): {detail}. Signature_2 "
            "withheld; the breaker stays frozen for all subsequent transactions "
            "until a human resets it."
        )
