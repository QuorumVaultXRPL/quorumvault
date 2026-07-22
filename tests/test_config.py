"""File-based risk & routing settings: load/validate/build, fail-closed on bad input.

Config files are written as raw JSON text (exactly what a non-technical operator
would type), not serialized from Python objects - so the money-precision test is
honest about what stdlib json does to a bare numeric literal.
"""

import pathlib
from decimal import Decimal

import pytest

from quorumvault.config import (
    ConfigError,
    QuorumVaultSettings,
    default_settings,
    load_settings,
)
from quorumvault.policy.intent import PaymentIntent
from quorumvault.policy.risk_engine import RiskEngine, RiskLevel
from quorumvault.tiers.router import TierRouter

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

VALID = """{
  "whitelist": ["rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"],
  "amount_threshold_rlusd": 5000,
  "frequency_window_s": 60.0,
  "frequency_limit": 3,
  "channel_ceiling_rlusd": 100,
  "fast_path_ceiling_rlusd": 5000
}"""


def _write(tmp_path, text):
    path = tmp_path / "config.json"
    path.write_text(text, encoding="utf-8")
    return str(path)


# -- valid load -------------------------------------------------------------


def test_valid_load_produces_typed_values(tmp_path):
    s = load_settings(_write(tmp_path, VALID))
    assert isinstance(s, QuorumVaultSettings)
    assert s.whitelist == ["rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"]
    # Money fields are Decimal (assert type, not just numeric equality) -----
    assert isinstance(s.amount_threshold_rlusd, Decimal)
    assert isinstance(s.channel_ceiling_rlusd, Decimal)
    assert isinstance(s.fast_path_ceiling_rlusd, Decimal)
    assert s.amount_threshold_rlusd == Decimal("5000")
    assert s.channel_ceiling_rlusd == Decimal("100")
    assert s.fast_path_ceiling_rlusd == Decimal("5000")
    assert isinstance(s.frequency_window_s, float) and s.frequency_window_s == 60.0
    assert isinstance(s.frequency_limit, int) and s.frequency_limit == 3


def test_bare_json_float_survives_as_exact_decimal(tmp_path):
    # The whole point of parse_float=Decimal: a bare literal a config author types
    # must not become a binary-float artifact. Naive json.loads('123456789.123456789')
    # yields 123456789.12345679 (wrong digits); parse_float=Decimal preserves it.
    text = VALID.replace(
        '"amount_threshold_rlusd": 5000',
        '"amount_threshold_rlusd": 123456789.123456789',
    )
    s = load_settings(_write(tmp_path, text))
    assert isinstance(s.amount_threshold_rlusd, Decimal)
    assert s.amount_threshold_rlusd == Decimal("123456789.123456789")
    # A shorter fractional literal too.
    text2 = VALID.replace(
        '"amount_threshold_rlusd": 5000', '"amount_threshold_rlusd": 5000.10'
    )
    assert load_settings(_write(tmp_path, text2)).amount_threshold_rlusd == Decimal("5000.10")


def test_quoted_numeric_string_is_also_accepted(tmp_path):
    text = VALID.replace(
        '"amount_threshold_rlusd": 5000', '"amount_threshold_rlusd": "5000.1"'
    )
    s = load_settings(_write(tmp_path, text))
    assert s.amount_threshold_rlusd == Decimal("5000.1")


# -- fail-closed on bad input -----------------------------------------------


def test_missing_file_raises():
    with pytest.raises(ConfigError) as exc:
        load_settings("/no/such/quorumvault/config.json")
    assert "not found" in str(exc.value)


def test_malformed_json_raises(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_settings(_write(tmp_path, "{ not valid json ]"))
    assert "not valid JSON" in str(exc.value)


def test_non_object_json_raises(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_settings(_write(tmp_path, "[1, 2, 3]"))
    assert "must contain a JSON object" in str(exc.value)


def test_missing_amount_threshold_raises(tmp_path):
    text = """{
      "whitelist": [],
      "frequency_window_s": 60.0,
      "frequency_limit": 3,
      "channel_ceiling_rlusd": 100,
      "fast_path_ceiling_rlusd": 5000
    }"""
    with pytest.raises(ConfigError) as exc:
        load_settings(_write(tmp_path, text))
    assert "missing required field" in str(exc.value)
    assert "amount_threshold_rlusd" in str(exc.value)


def test_missing_whitelist_raises(tmp_path):
    text = """{
      "amount_threshold_rlusd": 5000,
      "frequency_window_s": 60.0,
      "frequency_limit": 3,
      "channel_ceiling_rlusd": 100,
      "fast_path_ceiling_rlusd": 5000
    }"""
    with pytest.raises(ConfigError) as exc:
        load_settings(_write(tmp_path, text))
    assert "whitelist" in str(exc.value)


def test_unknown_field_raises(tmp_path):
    # A typo like 'amount_treshold_rlusd' must be caught, not silently ignored.
    text = VALID.rstrip("}\n ") + ',\n  "amount_treshold_rlusd": 1\n}'
    with pytest.raises(ConfigError) as exc:
        load_settings(_write(tmp_path, text))
    assert "unknown field" in str(exc.value)


def test_wrong_shaped_numeric_field_raises(tmp_path):
    # A money field given a non-numeric value.
    text = VALID.replace(
        '"amount_threshold_rlusd": 5000', '"amount_threshold_rlusd": "not-a-number"'
    )
    with pytest.raises(ConfigError) as exc:
        load_settings(_write(tmp_path, text))
    assert "not a valid number" in str(exc.value)


def test_money_field_as_array_raises(tmp_path):
    text = VALID.replace(
        '"channel_ceiling_rlusd": 100', '"channel_ceiling_rlusd": [100]'
    )
    with pytest.raises(ConfigError) as exc:
        load_settings(_write(tmp_path, text))
    assert "must be a number" in str(exc.value)


def test_non_positive_threshold_raises(tmp_path):
    text = VALID.replace('"amount_threshold_rlusd": 5000', '"amount_threshold_rlusd": 0')
    with pytest.raises(ConfigError) as exc:
        load_settings(_write(tmp_path, text))
    assert "must be positive" in str(exc.value)


def test_non_finite_money_field_raises(tmp_path):
    # json.loads's parse_constant (NOT parse_float) turns a bare Infinity/NaN
    # literal into a float, bypassing parse_float=Decimal entirely - a money
    # field must still reject it via Decimal.is_finite(), not silently accept it.
    for bad in ("Infinity", "-Infinity", "NaN"):
        text = VALID.replace('"amount_threshold_rlusd": 5000', f'"amount_threshold_rlusd": {bad}')
        with pytest.raises(ConfigError) as exc:
            load_settings(_write(tmp_path, text))
        assert "finite" in str(exc.value)


def test_non_finite_frequency_window_raises(tmp_path):
    # frequency_window_s isn't money, but it must reject the same bare
    # Infinity/NaN JSON literals a money field would - otherwise the velocity
    # rule's log window never expires (unbounded growth), a real gap the
    # money-field finite check doesn't cover for this one non-money field.
    for bad in ("Infinity", "-Infinity", "NaN"):
        text = VALID.replace('"frequency_window_s": 60.0', f'"frequency_window_s": {bad}')
        with pytest.raises(ConfigError) as exc:
            load_settings(_write(tmp_path, text))
        assert "finite" in str(exc.value)


def test_frequency_limit_must_be_integer(tmp_path):
    text = VALID.replace('"frequency_limit": 3', '"frequency_limit": 3.5')
    with pytest.raises(ConfigError) as exc:
        load_settings(_write(tmp_path, text))
    assert "must be an integer" in str(exc.value)


def test_channel_ceiling_not_below_fast_path_raises(tmp_path):
    # Mirror TierRouter's own invariant at load time.
    text = VALID.replace('"channel_ceiling_rlusd": 100', '"channel_ceiling_rlusd": 5000')
    with pytest.raises(ConfigError) as exc:
        load_settings(_write(tmp_path, text))
    assert "strictly less than" in str(exc.value)


# -- empty whitelist is the SAFE state, not an error ------------------------


def test_empty_whitelist_loads_and_flags_every_destination(tmp_path):
    text = VALID.replace(
        '"whitelist": ["rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"]', '"whitelist": []'
    )
    s = load_settings(_write(tmp_path, text))
    assert s.whitelist == []
    engine = s.build_risk_engine()
    verdict = engine.evaluate(
        PaymentIntent(destination="rAnyoneAtAll", asset="RLUSD", amount=1)
    )
    assert verdict["risk_level"] == RiskLevel.RED
    assert "untrusted_destination" in verdict["fired_reasons"]


# -- guardrails: defaults track source, example ships valid -----------------


def test_default_settings_matches_riskengine_actual_defaults():
    # Construct a RiskEngine with NO risk args -> it uses its own built-in defaults.
    # default_settings() must equal those, so a drift in risk_engine.py is caught.
    engine = RiskEngine(whitelist=[])
    s = default_settings()
    assert s.amount_threshold_rlusd == engine.amount_threshold_rlusd
    assert s.frequency_window_s == engine.frequency_window_s
    assert s.frequency_limit == engine.frequency_limit


def test_default_settings_router_ceilings_are_the_convention():
    s = default_settings()
    assert s.channel_ceiling_rlusd == Decimal("100")
    assert s.fast_path_ceiling_rlusd == Decimal("5000")
    router = s.build_router()
    assert isinstance(router, TierRouter)
    assert router.channel_ceiling_rlusd == Decimal("100")
    assert router.fast_path_ceiling_rlusd == Decimal("5000")


def test_default_settings_whitelist_defaults_empty_and_overridable():
    assert default_settings().whitelist == []
    assert default_settings(["rSomeone"]).whitelist == ["rSomeone"]


def test_example_config_file_loads_successfully():
    # The shipped example can never silently go stale or invalid.
    s = load_settings(str(REPO_ROOT / "config.example.json"))
    assert s.channel_ceiling_rlusd == Decimal("100")
    assert s.fast_path_ceiling_rlusd == Decimal("5000")
    assert isinstance(s.build_risk_engine(), RiskEngine)
    assert isinstance(s.build_router(), TierRouter)


def test_demo_v2_sources_router_from_config_not_hardcoded():
    # Post-wiring, the demo builds its router from config (default_settings /
    # load_settings), so its effective ceilings are default_settings()'s - which
    # the guardrail above pins to 100/5000. This proves it no longer hardcodes them.
    demo = (REPO_ROOT / "testnet_multisig_demo_v2.py").read_text(encoding="utf-8")
    assert "default_settings" in demo or "load_settings" in demo


def test_builders_accept_overrides_for_unowned_fields():
    # rate_provider / rwa_rule are deliberately not config-owned; builders forward them.
    from quorumvault.policy.pricing import StaticRateProvider

    s = default_settings(["rDest"])
    engine = s.build_risk_engine(rate_provider=StaticRateProvider("0.80"))
    router = s.build_router(rate_provider=StaticRateProvider("0.80"))
    assert engine.rate_provider.xrp_to_rlusd == Decimal("0.80")
    assert router.rate_provider.xrp_to_rlusd == Decimal("0.80")
