"""
QuorumVault — XRPL AI Risk Auditor, production-realistic blueprint (v3)
==============================================================================

Three changes from the previous version:

1. YELLOW POLICY FIX
   `AuditorAgent.review_and_cosign()` now withholds Signature_2 for BOTH
   YELLOW and RED results, not just RED. Every transaction that crosses
   the value threshold now genuinely requires a human override to
   broadcast - the system's claims and its behavior now match. RED still
   additionally freezes the whole engine (`circuit_breaker_tripped`
   stays True across subsequent transactions) until a human explicitly
   resets it; YELLOW does not freeze anything, it's a per-transaction gate.

2. OVERRIDE TOKEN BOUND TO tx_hash, NOT TO FREE TEXT
   `HumanOverrideAuthority` now signs over a deterministic `tx_hash`
   (a stand-in for a real XRPL transaction hash) instead of the literal
   justification string. The justification is still captured and logged,
   but purely as metadata - a human no longer has to retype an exact
   string to reuse or verify an override, and the crypto binding is to
   the actual transaction being authorized, which is what actually
   matters for security.

3. APPENDED SYSTEM ARCHITECTURE SPEC
   A markdown blueprint at the bottom of this file (SYSTEM_ARCHITECTURE_SPEC)
   describing how this simulation maps onto a real production deployment:
   network separation between the Execution Agent and Auditor Agent, and
   why Key 2/2 must live in an HSM/KMS rather than in local process memory.

Standard library only.
"""

import hashlib
import hmac
import secrets
import time
from collections import deque
from enum import Enum


class RiskLevel(Enum):
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"


class MissingSignaturesError(Exception):
    """Raised when network_broadcast() does not receive two valid signatures
    (or one valid signature plus a verified human override)."""
    pass


# --------------------------------------------------------------------------
# Mock transaction payload
# --------------------------------------------------------------------------

class MockTransactionPayload:
    _counter = 0

    def __init__(self, destination, asset, amount, purpose, timestamp=None):
        MockTransactionPayload._counter += 1
        self.tx_id = f"tx-{MockTransactionPayload._counter:05d}"
        self.destination = destination
        self.asset = asset
        self.amount = float(amount)
        self.purpose = purpose
        self.timestamp = timestamp if timestamp is not None else time.time()

    @classmethod
    def from_dict(cls, raw):
        obj = cls(
            destination=raw["destination"], asset=raw["asset"], amount=raw["amount"],
            purpose=raw.get("purpose", "unspecified"), timestamp=raw.get("timestamp", time.time()),
        )
        if "tx_id" in raw:
            obj.tx_id = raw["tx_id"]
        return obj

    def canonical_message(self) -> str:
        return f"{self.tx_id}:{self.destination}:{self.asset}:{self.amount}:{self.timestamp}"


def compute_tx_hash(tx: MockTransactionPayload) -> str:
    """Deterministic stand-in for a real XRPL transaction hash - what a
    human override should actually be bound to, not to free text."""
    return hashlib.sha256(tx.canonical_message().encode()).hexdigest()


# --------------------------------------------------------------------------
# 1. Risk engine with compound accumulation + persistent RED freeze
# --------------------------------------------------------------------------

class RiskTelemetryEngine:
    XRP_TO_RLUSD_RATE = 0.55

    def __init__(self, whitelist, amount_threshold_rlusd=5000.0,
                 frequency_window_s=60.0, frequency_limit=3):
        self.whitelist = set(whitelist)
        self.amount_threshold_rlusd = amount_threshold_rlusd
        self.frequency_window_s = frequency_window_s
        self.frequency_limit = frequency_limit

        self._recent_tx_log = deque()
        self.circuit_breaker_tripped = False
        self.trip_reasons = []
        self.risk_reason_history = []
        self.audit_log = []
        self.reset_log = []

    def _to_rlusd_equivalent(self, asset, amount):
        if asset == "RLUSD":
            return amount
        if asset == "XRP":
            return amount * self.XRP_TO_RLUSD_RATE
        return amount

    def _prune_log(self, now):
        while self._recent_tx_log and (now - self._recent_tx_log[0][0]) > self.frequency_window_s:
            self._recent_tx_log.popleft()

    def evaluate(self, tx: MockTransactionPayload) -> dict:
        rlusd_equiv = self._to_rlusd_equivalent(tx.asset, tx.amount)

        amount_flag = rlusd_equiv > self.amount_threshold_rlusd
        overage = max(0.0, rlusd_equiv - self.amount_threshold_rlusd)

        whitelist_flag = tx.destination not in self.whitelist

        self._prune_log(tx.timestamp)
        matches = [t for t in self._recent_tx_log
                   if t[1] == tx.destination and t[2] == tx.asset and t[3] == tx.amount]
        repeat_count = len(matches) + 1
        frequency_flag = repeat_count > self.frequency_limit
        self._recent_tx_log.append((tx.timestamp, tx.destination, tx.asset, tx.amount))

        fired_reasons = []
        if amount_flag:
            fired_reasons.append(("value_threshold_exceeded", "YELLOW"))
        if whitelist_flag:
            fired_reasons.append(("untrusted_destination", "RED"))
        if frequency_flag:
            fired_reasons.append(("transaction_loop_detected", "RED"))
        self.risk_reason_history.extend(fired_reasons)

        if whitelist_flag or frequency_flag:
            risk_level = RiskLevel.RED
        elif amount_flag:
            risk_level = RiskLevel.YELLOW
        else:
            risk_level = RiskLevel.GREEN

        # Hard freeze: once RED has fired, every subsequent transaction is
        # forced RED regardless of its own individual profile, until a
        # human calls reset_circuit_breaker(). This is what makes it a
        # circuit breaker rather than a per-transaction filter.
        breaker_was_already_tripped = self.circuit_breaker_tripped
        if breaker_was_already_tripped:
            risk_level = RiskLevel.RED
            if not any(r == "circuit_breaker_frozen" for r, _s in fired_reasons):
                fired_reasons.append(("circuit_breaker_frozen", "RED"))

        breaker_tripped_now = False
        if risk_level == RiskLevel.RED and not self.circuit_breaker_tripped:
            self.circuit_breaker_tripped = True
            breaker_tripped_now = True
            self.trip_reasons = [reason for reason, _sev in fired_reasons]

        result = {
            "tx": tx,
            "risk_level": risk_level,
            "rlusd_equivalent": rlusd_equiv,
            "amount_threshold": self.amount_threshold_rlusd,
            "amount_flag": amount_flag,
            "amount_overage": overage,
            "whitelist_flag": whitelist_flag,
            "frequency_flag": frequency_flag,
            "repeat_count": repeat_count,
            "frequency_window_s": self.frequency_window_s,
            "frequency_limit": self.frequency_limit,
            "fired_reasons": [r for r, _s in fired_reasons],
            "breaker_was_already_tripped": breaker_was_already_tripped,
            "circuit_breaker_tripped": self.circuit_breaker_tripped,
            "breaker_tripped_by_this_tx": breaker_tripped_now,
            "trip_reasons": list(self.trip_reasons),
        }
        self.audit_log.append(result)
        return result

    def request_reset_hash(self) -> str:
        """Deterministic hash identifying 'the current freeze episode' -
        what a human's reset authorization is bound to, same pattern as
        a transaction override."""
        return hashlib.sha256(
            f"RESET:{id(self)}:{len(self.trip_reasons)}:{len(self.audit_log)}".encode()
        ).hexdigest()

    def reset_circuit_breaker(self, override_authority: "HumanOverrideAuthority",
                               override_token: str, reason: str) -> None:
        reset_hash = self.request_reset_hash()
        if not override_authority.verify_override(reset_hash, override_token):
            raise MissingSignaturesError("Invalid human override token; circuit breaker reset denied.")
        self.reset_log.append({
            "reset_at": time.time(), "reset_by": override_authority.officer_id,
            "reason": reason, "cleared_trip_reasons": list(self.trip_reasons),
        })
        override_authority.override_log.append({
            "action": "circuit_breaker_reset", "reset_hash": reset_hash,
            "reason": reason, "time": time.time(),
        })
        self.circuit_breaker_tripped = False
        self.trip_reasons = []

    def explain_my_position(self, result: dict, execution_source: str) -> str:
        tx = result["tx"]
        level = result["risk_level"]

        intent = (
            f'Your Automated Trading Agent ("{execution_source}") is attempting to move '
            f'{tx.amount:,.2f} {tx.asset} out of the treasury wallet'
            + (f", to {tx.purpose}." if tx.purpose and tx.purpose != "unspecified" else ".")
        )

        if level == RiskLevel.GREEN:
            return intent + " No corporate risk rules were violated; this transaction may proceed to the XRPL."

        if level == RiskLevel.YELLOW:
            return (
                intent + f" This exceeds the value threshold by {result['amount_overage']:,.2f} {tx.asset}. "
                "The Auditor Agent is withholding its multisig co-signature (Signature_2) for this "
                "transaction specifically. It requires a verified human override to broadcast."
            )

        # RED
        if result["breaker_was_already_tripped"] and not result["breaker_tripped_by_this_tx"]:
            return (
                intent + " The circuit breaker is already frozen from a prior violation "
                f"({', '.join(result['trip_reasons'])}) and has not been reset. All transactions, "
                "including this one, are blocked until a human explicitly resets it."
            )

        reason_sentences = []
        if "value_threshold_exceeded" in result["trip_reasons"]:
            reason_sentences.append(
                f"the capital allocation exceeds your corporate safety profile by "
                f"{result['amount_overage']:,.2f} {tx.asset}"
            )
        if "transaction_loop_detected" in result["trip_reasons"]:
            reason_sentences.append(
                f"it exhibits high-velocity loop behavior "
                f"({result['repeat_count']} identical requests in {result['frequency_window_s']:.0f} seconds)"
            )
        if "untrusted_destination" in result["trip_reasons"]:
            reason_sentences.append("the destination address is not on the approved corporate whitelist")
        reason_text = " and ".join(reason_sentences) if reason_sentences else "a critical risk rule was violated"

        return (
            f"{intent} ACTION TAKEN: The automated circuit breaker has been TRIPPED, accumulating "
            f"{len(result['trip_reasons'])} compound risk factor(s): {', '.join(result['trip_reasons'])}. "
            f"This transaction has been BLOCKED because {reason_text}. The Auditor Agent has withheld "
            f"its multisig co-signature (Signature_2), and the breaker will remain frozen for ALL "
            f"subsequent transactions until a human resets it."
        )


# --------------------------------------------------------------------------
# 2. Simulated 2-of-2 multisig custody, override bound to tx_hash
# --------------------------------------------------------------------------

class ExecutionAgent:
    def __init__(self, agent_id: str, secret_key: bytes = None):
        self.agent_id = agent_id
        self._secret_key = secret_key or secrets.token_bytes(32)

    def sign_transaction(self, tx: MockTransactionPayload) -> str:
        message = f"SIG1:{self.agent_id}:{tx.canonical_message()}"
        return hmac.new(self._secret_key, message.encode(), hashlib.sha256).hexdigest()

    def verify_signature(self, tx: MockTransactionPayload, signature: str) -> bool:
        if signature is None:
            return False
        return hmac.compare_digest(self.sign_transaction(tx), signature)


class AuditorAgent:
    def __init__(self, agent_id: str, risk_engine: RiskTelemetryEngine, secret_key: bytes = None):
        self.agent_id = agent_id
        self._secret_key = secret_key or secrets.token_bytes(32)
        self.risk_engine = risk_engine

    def _sign_transaction(self, tx: MockTransactionPayload) -> str:
        message = f"SIG2:{self.agent_id}:{tx.canonical_message()}"
        return hmac.new(self._secret_key, message.encode(), hashlib.sha256).hexdigest()

    def verify_signature(self, tx: MockTransactionPayload, signature: str) -> bool:
        if signature is None:
            return False
        return hmac.compare_digest(self._sign_transaction(tx), signature)

    def review_and_cosign(self, tx: MockTransactionPayload):
        """Signature_2 is now withheld for BOTH YELLOW and RED - only a
        GREEN result gets an automatic co-signature."""
        result = self.risk_engine.evaluate(tx)
        if result["risk_level"] in (RiskLevel.YELLOW, RiskLevel.RED):
            return None, result
        return self._sign_transaction(tx), result


class HumanOverrideAuthority:
    """Signs over an opaque action hash (a tx_hash for broadcasts, a reset
    hash for breaker resets) - never over free text. The justification
    string is recorded for logging only and plays no role in verification,
    so a human never has to retype an exact phrase to reuse a valid token
    against the transaction it was actually issued for."""

    def __init__(self, officer_id: str, secret_key: bytes = None):
        self.officer_id = officer_id
        self._secret_key = secret_key or secrets.token_bytes(32)
        self.override_log = []

    def issue_override(self, action_hash: str) -> str:
        message = f"OVERRIDE:{self.officer_id}:{action_hash}"
        return hmac.new(self._secret_key, message.encode(), hashlib.sha256).hexdigest()

    def verify_override(self, action_hash: str, token: str) -> bool:
        if token is None:
            return False
        return hmac.compare_digest(self.issue_override(action_hash), token)


def network_broadcast(tx: MockTransactionPayload,
                       execution_agent: ExecutionAgent, signature_1: str,
                       auditor_agent: AuditorAgent, signature_2: str,
                       override_authority: HumanOverrideAuthority = None,
                       override_token: str = None, override_reason: str = None) -> dict:
    sig1_valid = execution_agent.verify_signature(tx, signature_1)
    sig2_valid = auditor_agent.verify_signature(tx, signature_2)

    if sig1_valid and sig2_valid:
        return {
            "status": "BROADCAST_SUCCESS", "tx_id": tx.tx_id,
            "authorized_by": "2-of-2 multisig (Execution Agent + Auditor Agent)",
        }

    if sig1_valid and not sig2_valid and override_authority is not None:
        tx_hash = compute_tx_hash(tx)
        if override_authority.verify_override(tx_hash, override_token):
            override_authority.override_log.append({
                "action": "broadcast_override", "tx_id": tx.tx_id, "tx_hash": tx_hash,
                "reason": override_reason, "time": time.time(),
            })
            return {
                "status": "BROADCAST_SUCCESS", "tx_id": tx.tx_id,
                "authorized_by": f"1-of-2 multisig + HUMAN OVERRIDE ({override_authority.officer_id})",
                "warning": (
                    "Auditor Agent's Signature_2 was withheld. Submitted only because a human "
                    f"explicitly overrode it, bound to tx_hash {tx_hash[:12]}.... Reason on file: "
                    f"'{override_reason}'."
                ),
            }
        raise MissingSignaturesError(
            f"Override token invalid for tx_hash {compute_tx_hash(tx)[:12]}...; broadcast blocked."
        )

    missing = []
    if not sig1_valid:
        missing.append("Signature_1 (Execution Agent)")
    if not sig2_valid:
        missing.append(
            "Signature_2 (Auditor Agent) - WITHHELD" if signature_2 is None else "Signature_2 (Auditor Agent) - invalid"
        )
    raise MissingSignaturesError(
        f"XRPL 2-of-2 multisig requirement not met for {tx.tx_id}. Missing/invalid: {', '.join(missing)}."
    )


# --------------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------------

def run_demo():
    whitelist = ["rXrpEnterpriseStablePool0000000001"]
    risk_engine = RiskTelemetryEngine(
        whitelist=whitelist, amount_threshold_rlusd=5000.0,
        frequency_window_s=60.0, frequency_limit=2,
    )
    exec_agent = ExecutionAgent(agent_id="Trading_Agent_v4.2")
    auditor = AuditorAgent(agent_id="Risk_Auditor_v1", risk_engine=risk_engine)
    officer = HumanOverrideAuthority(officer_id="compliance_officer_jsmith")

    now = time.time()

    def propose_and_broadcast(destination, asset, amount, purpose, ts, with_override=False):
        tx = MockTransactionPayload.from_dict({
            "destination": destination, "asset": asset, "amount": amount,
            "purpose": purpose, "timestamp": ts,
        })
        sig1 = exec_agent.sign_transaction(tx)
        sig2, result = auditor.review_and_cosign(tx)

        print(f"\n--- {tx.tx_id} ---")
        print(risk_engine.explain_my_position(result, execution_source="Trading_Agent_v4.2"))
        print(f"Signature_1: {'present' if sig1 else 'MISSING'} | Signature_2: {'present' if sig2 else 'WITHHELD'}")

        try:
            outcome = network_broadcast(tx, exec_agent, sig1, auditor, sig2)
            print(f"BROADCAST RESULT: {outcome}")
            return tx
        except MissingSignaturesError as e:
            print(f"BROADCAST BLOCKED: {e}")
            if with_override:
                tx_hash = compute_tx_hash(tx)
                reason = "Manually verified; accepting flagged risk for this transaction."
                token = officer.issue_override(tx_hash)
                outcome = network_broadcast(
                    tx, exec_agent, sig1, auditor, sig2,
                    override_authority=officer, override_token=token, override_reason=reason,
                )
                print(f"OVERRIDE BROADCAST RESULT: {outcome}")
            return tx

    print("=" * 78)
    print("1) Clean, small transaction -> GREEN, auto multisig")
    print("=" * 78)
    propose_and_broadcast("rXrpEnterpriseStablePool0000000001", "RLUSD", 500, "routine settlement", now)

    print("\n" + "=" * 78)
    print("2) Over-threshold transaction -> YELLOW, Signature_2 withheld, needs override")
    print("=" * 78)
    propose_and_broadcast("rXrpEnterpriseStablePool0000000001", "RLUSD", 7500,
                           "liquidity pool participation", now + 5, with_override=True)

    print("\n" + "=" * 78)
    print("3) Second identical request -> still YELLOW, still needs its own override")
    print("=" * 78)
    propose_and_broadcast("rXrpEnterpriseStablePool0000000001", "RLUSD", 7500,
                           "liquidity pool participation", now + 10, with_override=True)

    print("\n" + "=" * 78)
    print("4) Third identical request -> compound RED (value + velocity), breaker freezes")
    print("=" * 78)
    tx4 = propose_and_broadcast("rXrpEnterpriseStablePool0000000001", "RLUSD", 7500,
                                 "liquidity pool participation", now + 15, with_override=True)

    print("\n" + "=" * 78)
    print("5) A totally clean, unrelated transaction -> still forced RED, engine is frozen")
    print("=" * 78)
    propose_and_broadcast("rXrpEnterpriseStablePool0000000001", "RLUSD", 10,
                           "petty cash", now + 20, with_override=True)

    print("\n" + "=" * 78)
    print("6) Human resets the circuit breaker")
    print("=" * 78)
    reset_hash = risk_engine.request_reset_hash()
    reset_token = officer.issue_override(reset_hash)
    risk_engine.reset_circuit_breaker(officer, reset_token, "Reviewed loop cause with trading desk; resetting.")
    print(f"Circuit breaker tripped after reset: {risk_engine.circuit_breaker_tripped}")

    print("\n" + "=" * 78)
    print("7) Clean transaction after reset -> back to normal GREEN auto-broadcast")
    print("=" * 78)
    propose_and_broadcast("rXrpEnterpriseStablePool0000000001", "RLUSD", 250, "routine settlement", now + 25)


if __name__ == "__main__":
    run_demo()


# ==============================================================================
# SYSTEM ARCHITECTURE SPEC — production deployment blueprint
# ==============================================================================
SYSTEM_ARCHITECTURE_SPEC = r"""
# QuorumVault — production system architecture

This file is a single-process logic simulation. Everything below describes
what changes when this stops being a demo and starts touching real funds.
The core principle carried over unchanged: **the entity that decides
whether a transaction is safe must not be the entity that can sign it
unilaterally.** Everything else in this document exists to make that
separation real instead of just structural within one Python process.

## 1. Network separation: Execution Agent vs. Auditor Agent

In this simulation, `ExecutionAgent` and `AuditorAgent` are two Python
objects living in the same process, trusting each other by construction.
In production these must be **two separate services on two separate
network identities**, communicating over an authenticated, encrypted
channel (mTLS) with no other path between them:

- **Execution Agent service**: runs the trading/allocation logic, has
  network access to market data and to *propose* transactions. It has NO
  network path to the Auditor's signing key or to the custody layer -
  only to the Auditor's public review API (`POST /review-transaction`),
  which returns a verdict object, never a key or a bypass.
- **Auditor Agent service**: exposes exactly one inbound API for the
  Execution Agent (`review-transaction`) and one for human operators
  (`request-override`, `reset-circuit-breaker`), both authenticated
  separately. It does not expose a generic "sign anything" endpoint.
  Internally, on a GREEN verdict, it does not sign directly - it forwards
  a signed policy-approval token to the custody layer (see below), which
  performs the actual signing.
- If the Execution Agent's service is fully compromised (RCE, poisoned
  model context, malicious dependency), the blast radius is capped at
  "can propose bad transactions" - it still cannot produce Signature_2,
  because it never had access to any component capable of producing it.
  This is the actual security property; the risk *rules* (velocity,
  whitelist, etc.) are policy on top of that boundary, not a substitute
  for it.

## 2. Key 2/2 must live in an HSM or KMS, not application memory

In this simulation, `AuditorAgent._secret_key` is a Python bytes object
sitting in process memory - anyone with process access (a debugger, a
core dump, a compromised dependency, a misconfigured logging library)
can exfiltrate it. In production:

- **The private key never leaves a Hardware Security Module or a cloud
  Key Management Service** (AWS CloudHSM/KMS, GCP Cloud HSM, Azure
  Managed HSM, or an MPC-based custody provider such as Fireblocks or
  Copper). The key is *non-exportable* - the HSM/KMS performs signing
  operations internally and only ever returns a signature, never the key
  material itself.
- **The Auditor service does not hold signing authority - it holds
  *policy* authority.** It evaluates the transaction and, on approval,
  calls the HSM/KMS's signing API with the transaction hash and a
  policy-approval token. The HSM/KMS (or a policy engine sitting directly
  in front of it) is configured to REFUSE to sign unless that token is
  present and valid - so even a fully compromised Auditor service cannot
  get a signature for a transaction it didn't actually approve, because
  the enforcement point is the HSM's key-use policy, not application code.
- **Every signing operation is logged immutably at the HSM/KMS layer**
  (e.g. AWS CloudTrail for KMS), independent of and in addition to this
  application's own audit log. Application-level logs can be tampered
  with by whoever compromises the application; HSM/KMS-layer logs cannot
  be altered by anything outside the HSM/KMS's own administrative plane.
- **XRPL specifics**: real signing uses actual XRPL-supported signature
  schemes (secp256k1 or ed25519) over the canonically serialized
  transaction blob per the XRPL binary transaction format - not the toy
  HMAC-over-a-formatted-string used in this simulation. The account is
  configured on-ledger via `SignerListSet` with the Execution Agent and
  Auditor (technically the HSM/KMS-backed identity representing it) as
  two signer entries with a quorum weight requiring both.

## 3. Human override, for real

`HumanOverrideAuthority` here is a bare HMAC key. In production, the
override path should look like:

- The compliance officer authenticates via SSO with hardware-backed MFA
  (a FIDO2/WebAuthn key, not a TOTP code, given what's at stake).
- Their approval action itself is either (a) a transaction co-signed with
  their own HSM/KMS-backed personal key, or (b) an approval recorded
  through a dedicated workflow tool (e.g. a policy engine or an
  approval-chain product) that itself calls the custody layer's KMS API
  with an audit-logged justification.
- The override is bound to a specific `tx_hash` (as in this simulation),
  never to free text, and never reusable for a different transaction.
- The override event is written to an append-only, tamper-evident log
  (e.g. a SIEM, or a hash-chained log service) separate from the
  application's own database, so a compromised application cannot retroactively
  edit its own override history.

## 4. What this simulation gets structurally right, and what it can't prove

Right: the separation of "who can propose" from "who can approve" from
"who can custody the key," the idea that risk severity should determine
whether a co-signature is even generated (not generated-then-revoked),
and binding human overrides to the specific action being authorized
rather than to arbitrary text.

Cannot prove, because a single Python file cannot: that the network
boundary between services actually holds under attack, that the HSM/KMS
policy engine is configured correctly (a misconfigured KMS key policy is
a common real-world failure mode), that the MFA/SSO integration resists
phishing or session hijacking, or that the audit log is genuinely
tamper-evident end to end. Those require actual infrastructure, a real
penetration test, and - given this is custody of funds - an independent
security audit before any of it touches a real XRPL account.
"""
