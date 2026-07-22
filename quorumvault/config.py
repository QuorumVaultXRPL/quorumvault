"""File-based, operator-editable risk & routing settings (JSON, stdlib only).

Today the risk-engine and tier-router parameters are plain Python constructor
arguments, hardcoded at each call site: changing a threshold means editing source
and redeploying - developer-facing, not client-facing. This module makes the
*business* risk & routing parameters - the whitelist, the value threshold, the
frequency window/limit, and the two tier ceilings - adjustable from a JSON file a
non-technical operator can open, edit, and save with no code change. It is purely
additive: no existing constructor signature changes, and code that never calls
this module behaves exactly as before.

Same discipline as the rest of the codebase (``RateProvider``,
``LedgerComplianceReader``, ``TreasuryConfigVerifier``, ``AgentIdentityVerifier``,
``RefusalAlertSink``): a typed settings object, a labelled default, convenience
builders, and a dedicated fail-closed exception (:class:`ConfigError`) that
pinpoints exactly what is wrong and never partially applies a bad file - either
the whole config loads cleanly or it raises.

Two money-precision points, both deliberate (``money.py``'s rule: ``Decimal``,
never a binary ``float``, anywhere near a currency amount or threshold):

* The file is parsed with ``json.load(fh, parse_float=Decimal)``. Python's stdlib
  ``json`` turns a bare numeric literal like ``5000.1`` into a binary ``float`` by
  default, which silently loses precision on longer values (demonstrated:
  ``json.loads('123456789.123456789')`` -> ``123456789.12345679``, wrong digits).
  ``parse_float=Decimal`` makes every fractional literal a :class:`~decimal.Decimal`
  straight from its source token - full precision, no intermediate float - so an
  operator writes natural JSON numbers and still gets exact money. Chosen over
  "require every money field to be a quoted string": it is more foolproof (the
  hazard is removed at the source for *every* numeric literal automatically, rather
  than relying on the operator remembering to quote) and lower-friction. A quoted
  numeric string is still accepted too (via :func:`~quorumvault.policy.money.to_decimal`),
  matching XRPL's own string-amount convention, so quoting is never punished.
* Every money field is normalized through ``to_decimal``, the one sanctioned money
  entry point. ``frequency_window_s`` is a *time duration* (``RiskEngine`` compares
  it against float epoch timestamps), not a money value, so it is a ``float`` - the
  same type ``RiskEngine`` itself uses; money never touches ``float``.

Scope is deliberately the risk & routing *business* parameters only. Trust anchors
and infra wiring - the treasury guard's expected signers/quorum, agent-identity's
recognized issuers / credential type, the alert webhook URL, KMS/signing selection
- are NOT configurable here. Those are a different, more sensitive kind of setting
(live signing authority, security trust anchors, credentials) deserving their own
deliberate treatment, not a casually-edited text file next to a risk threshold.
"""

from __future__ import annotations

import inspect
import json
import math
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, List, Optional

from .policy.money import to_decimal
from .policy.risk_engine import RiskEngine
from .tiers.router import TierRouter

# The de facto router-ceiling convention used by every production-representative
# call site (TierRouter itself ships no default). Codifies existing practice
# rather than inventing new numbers; the RiskEngine risk-field defaults are read
# live from source (see _riskengine_defaults) so they can never drift silently.
_DEFAULT_CHANNEL_CEILING_RLUSD = Decimal("100")
_DEFAULT_FAST_PATH_CEILING_RLUSD = Decimal("5000")

# Exactly the top-level keys a config file may contain. Anything else is a typo
# the operator will want to hear about, not have silently ignored.
_ALLOWED_KEYS = frozenset(
    {
        "whitelist",
        "amount_threshold_rlusd",
        "frequency_window_s",
        "frequency_limit",
        "channel_ceiling_rlusd",
        "fast_path_ceiling_rlusd",
    }
)


class ConfigError(Exception):
    """A settings file is missing, unreadable, malformed, or has an invalid field.

    Fails closed with a specific, human-readable message pinpointing exactly what
    is wrong (missing file, invalid JSON, a named missing/mis-typed field, or an
    invalid value). A bad config never partially applies and never silently falls
    back to a permissive default: it raises.
    """


@dataclass(frozen=True)
class QuorumVaultSettings:
    """The resolved, validated risk & routing parameters.

    Money fields are :class:`~decimal.Decimal`; ``frequency_window_s`` /
    ``frequency_limit`` are the same ``float`` / ``int`` types ``RiskEngine`` uses.
    Turn a settings object into ready-to-use instances with :meth:`build_risk_engine`
    / :meth:`build_router`.
    """

    whitelist: List[str]
    amount_threshold_rlusd: Decimal
    frequency_window_s: float
    frequency_limit: int
    channel_ceiling_rlusd: Decimal
    fast_path_ceiling_rlusd: Decimal

    def build_risk_engine(self, **overrides: Any) -> RiskEngine:
        """A ready ``RiskEngine`` from these settings.

        ``overrides`` pass through to ``RiskEngine`` for the fields this settings
        file deliberately does not own (``rwa_rule``, ``rate_provider``).
        """
        return RiskEngine(
            whitelist=list(self.whitelist),
            amount_threshold_rlusd=self.amount_threshold_rlusd,
            frequency_window_s=self.frequency_window_s,
            frequency_limit=self.frequency_limit,
            **overrides,
        )

    def build_router(self, **overrides: Any) -> TierRouter:
        """A ready ``TierRouter`` from these settings.

        ``overrides`` pass through for ``rate_provider`` (not owned by this file).
        """
        return TierRouter(
            channel_ceiling_rlusd=self.channel_ceiling_rlusd,
            fast_path_ceiling_rlusd=self.fast_path_ceiling_rlusd,
            **overrides,
        )


def _riskengine_defaults() -> dict:
    """RiskEngine's real built-in defaults, read from its signature (never retyped).

    Keeps :func:`default_settings` honest: if RiskEngine's defaults ever change,
    these follow automatically, and the guardrail test compares against this same
    source of truth.
    """
    params = inspect.signature(RiskEngine.__init__).parameters
    return {
        "amount_threshold_rlusd": to_decimal(params["amount_threshold_rlusd"].default),
        "frequency_window_s": float(params["frequency_window_s"].default),
        "frequency_limit": params["frequency_limit"].default,
    }


def default_settings(whitelist: Optional[List[str]] = None) -> QuorumVaultSettings:
    """Today's real-world effective defaults.

    Risk fields come from ``RiskEngine``'s own constructor defaults (read from
    source); the two ceilings codify the de facto ``100`` / ``5000`` convention
    used by every production-representative call site (``TierRouter`` ships no
    default of its own).

    ``whitelist`` defaults to empty. An empty whitelist is the *safe, maximally
    restrictive* state under ``RiskEngine`` semantics - ``destination not in
    whitelist`` fires RED, so an empty whitelist flags every destination - not a
    hole. (Contrast ``agent_identity``'s empty recognized-issuer set, which is a
    hard error precisely because there an empty set means "nothing is checked",
    the unsafe direction.)
    """
    defaults = _riskengine_defaults()
    return QuorumVaultSettings(
        whitelist=list(whitelist or []),
        amount_threshold_rlusd=defaults["amount_threshold_rlusd"],
        frequency_window_s=defaults["frequency_window_s"],
        frequency_limit=defaults["frequency_limit"],
        channel_ceiling_rlusd=_DEFAULT_CHANNEL_CEILING_RLUSD,
        fast_path_ceiling_rlusd=_DEFAULT_FAST_PATH_CEILING_RLUSD,
    )


# -- field validation (each raises ConfigError pinpointing the exact problem) --


def _money(raw: Any, field_name: str) -> Decimal:
    if isinstance(raw, bool):  # bool is an int subclass; a boolean is not money
        raise ConfigError(f"{field_name!r} must be a number, not a boolean ({raw!r}).")
    if not isinstance(raw, (int, float, str, Decimal)):
        raise ConfigError(
            f"{field_name!r} must be a number or numeric string, got "
            f"{type(raw).__name__}."
        )
    try:
        value = to_decimal(raw)
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ConfigError(f"{field_name!r} is not a valid number: {raw!r}.") from exc
    if not value.is_finite():
        raise ConfigError(f"{field_name!r} must be a finite number, got {raw!r}.")
    return value


def _positive_money(raw: Any, field_name: str) -> Decimal:
    value = _money(raw, field_name)
    if value <= 0:
        raise ConfigError(f"{field_name!r} must be positive, got {value}.")
    return value


def _positive_int(raw: Any, field_name: str) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ConfigError(
            f"{field_name!r} must be an integer, got {type(raw).__name__} ({raw!r})."
        )
    if raw <= 0:
        raise ConfigError(f"{field_name!r} must be positive, got {raw}.")
    return raw


def _positive_float(raw: Any, field_name: str) -> float:
    # A duration, not money: RiskEngine compares it against float epoch timestamps.
    if isinstance(raw, bool) or not isinstance(raw, (int, float, Decimal)):
        raise ConfigError(
            f"{field_name!r} must be a number, got {type(raw).__name__} ({raw!r})."
        )
    value = float(raw)
    if not math.isfinite(value):
        raise ConfigError(f"{field_name!r} must be a finite number, got {raw!r}.")
    if value <= 0:
        raise ConfigError(f"{field_name!r} must be positive, got {value}.")
    return value


def _whitelist(raw: Any) -> List[str]:
    if not isinstance(raw, list):
        raise ConfigError(
            f"'whitelist' must be a JSON array of address strings, got "
            f"{type(raw).__name__}."
        )
    result: List[str] = []
    for index, item in enumerate(raw):
        if not isinstance(item, str):
            raise ConfigError(
                f"'whitelist'[{index}] must be an address string, got "
                f"{type(item).__name__} ({item!r})."
            )
        result.append(item)
    return result


def load_settings(path: str) -> QuorumVaultSettings:
    """Load, validate, and resolve a settings JSON file into ``QuorumVaultSettings``.

    Raises :class:`ConfigError` - never a partial result - if the file is missing,
    unreadable, not valid JSON, not a JSON object, has an unknown or missing field,
    a mis-typed field, or an invalid value (non-positive number, or
    ``channel_ceiling_rlusd >= fast_path_ceiling_rlusd`` - mirroring ``TierRouter``'s
    own invariant so a bad config fails at load time, not construction time).
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw_text = handle.read()
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path!r}.") from exc
    except OSError as exc:
        raise ConfigError(f"could not read config file {path!r}: {exc}.") from exc

    try:
        # parse_float=Decimal so a bare numeric literal never becomes a binary float.
        data = json.loads(raw_text, parse_float=Decimal)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config file {path!r} is not valid JSON: {exc}.") from exc

    if not isinstance(data, dict):
        raise ConfigError(
            f"config file {path!r} must contain a JSON object, got "
            f"{type(data).__name__}."
        )

    unknown = set(data) - _ALLOWED_KEYS
    if unknown:
        raise ConfigError(
            f"config file {path!r} has unknown field(s): {sorted(unknown)}. "
            f"Allowed fields: {sorted(_ALLOWED_KEYS)}."
        )
    missing = _ALLOWED_KEYS - set(data)
    if missing:
        raise ConfigError(
            f"config file {path!r} is missing required field(s): {sorted(missing)}."
        )

    whitelist = _whitelist(data["whitelist"])
    amount_threshold = _positive_money(
        data["amount_threshold_rlusd"], "amount_threshold_rlusd"
    )
    frequency_window = _positive_float(data["frequency_window_s"], "frequency_window_s")
    frequency_limit = _positive_int(data["frequency_limit"], "frequency_limit")
    channel = _positive_money(data["channel_ceiling_rlusd"], "channel_ceiling_rlusd")
    fast_path = _positive_money(
        data["fast_path_ceiling_rlusd"], "fast_path_ceiling_rlusd"
    )
    if not (channel < fast_path):
        raise ConfigError(
            "'channel_ceiling_rlusd' must be strictly less than "
            f"'fast_path_ceiling_rlusd' (got {channel} >= {fast_path}); mirrors "
            "TierRouter's 0 < channel < fast_path invariant."
        )

    return QuorumVaultSettings(
        whitelist=whitelist,
        amount_threshold_rlusd=amount_threshold,
        frequency_window_s=frequency_window,
        frequency_limit=frequency_limit,
        channel_ceiling_rlusd=channel,
        fast_path_ceiling_rlusd=fast_path,
    )
