"""Live XRP->USD price feed: mocked HTTP only (no live network in the suite).

Covers success, transport failure, malformed/non-JSON response, wrong shape,
non-positive rate, and the staleness path through the existing CallableRateProvider
``max_age_s`` mechanism. tests/test_pricing.py already covers CallableRateProvider
itself and is left untouched.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from quorumvault.integrations.price_feed import (
    COINBASE_XRP_USD_URL,
    DEFAULT_HTTP_TIMEOUT_S,
    PriceFeedError,
    fetch_xrp_usd_rate,
    live_rate_provider,
)
from quorumvault.policy.pricing import CallableRateProvider, StaleRateError

OK_BODY = '{"data":{"amount":"1.37215","base":"XRP","currency":"USD"}}'


def _get(body):
    def http_get(url, *, timeout_s):
        return body
    return http_get


def _raises(exc):
    def http_get(url, *, timeout_s):
        raise exc
    return http_get


# -- success ----------------------------------------------------------------


def test_fetch_success_returns_decimal_and_timestamp():
    rate, as_of = fetch_xrp_usd_rate(http_get=_get(OK_BODY), now=lambda: 1234.0)
    assert isinstance(rate, Decimal)
    assert rate == Decimal("1.37215")
    assert rate > 0
    assert as_of == 1234.0  # fetch time (Coinbase gives no source timestamp)


def test_fetch_passes_url_and_timeout_through():
    captured = {}

    def http_get(url, *, timeout_s):
        captured["url"] = url
        captured["timeout_s"] = timeout_s
        return OK_BODY

    fetch_xrp_usd_rate(http_get=http_get)
    assert captured["url"] == COINBASE_XRP_USD_URL
    assert captured["timeout_s"] == DEFAULT_HTTP_TIMEOUT_S


# -- failures all become PriceFeedError (a StaleRateError) ------------------


def test_transport_failure_raises_price_feed_error():
    with pytest.raises(PriceFeedError) as exc:
        fetch_xrp_usd_rate(http_get=_raises(TimeoutError("timed out")))
    assert isinstance(exc.value, StaleRateError)  # fails closed at the policy boundary


def test_non_json_body_raises_price_feed_error():
    with pytest.raises(PriceFeedError):
        fetch_xrp_usd_rate(http_get=_get("<html>rate limited</html>"))


def test_wrong_shape_raises_price_feed_error():
    with pytest.raises(PriceFeedError):
        fetch_xrp_usd_rate(http_get=_get('{"data":{"base":"XRP"}}'))


@pytest.mark.parametrize("amount", ["0", "-0.1", "-5"])
def test_non_positive_rate_raises_price_feed_error(amount):
    body = '{"data":{"amount":"%s","base":"XRP","currency":"USD"}}' % amount
    with pytest.raises(PriceFeedError) as exc:
        fetch_xrp_usd_rate(http_get=_get(body))
    assert "not positive" in str(exc.value)


def test_non_numeric_amount_raises_price_feed_error():
    body = '{"data":{"amount":"not-a-number","base":"XRP","currency":"USD"}}'
    with pytest.raises(PriceFeedError):
        fetch_xrp_usd_rate(http_get=_get(body))


# -- live_rate_provider wiring + staleness ----------------------------------


def test_live_rate_provider_is_live_and_converts():
    provider = live_rate_provider(http_get=_get(OK_BODY))
    assert isinstance(provider, CallableRateProvider)
    assert provider.is_live is True
    assert provider.to_rlusd("XRP", 100) == Decimal("1.37215") * 100


def test_live_rate_provider_rejects_stale_price():
    # as_of stamped at t=900, evaluated at t=1000, max_age_s=50 -> 100s old -> stale.
    provider = live_rate_provider(
        http_get=_get(OK_BODY), max_age_s=50, now=lambda: 900.0, clock=lambda: 1000.0
    )
    with pytest.raises(StaleRateError):
        provider.to_rlusd("XRP", 100)


def test_live_rate_provider_fresh_price_passes():
    provider = live_rate_provider(
        http_get=_get(OK_BODY), max_age_s=50, now=lambda: 980.0, clock=lambda: 1000.0
    )
    assert provider.to_rlusd("XRP", 100) == Decimal("1.37215") * 100  # 20s old, fine


def test_default_rate_provider_unchanged_and_not_live():
    # Guardrail: the live feed must not have altered the Testnet default.
    from quorumvault.policy.pricing import default_rate_provider

    provider = default_rate_provider()
    assert provider.is_live is False
    assert provider.to_rlusd("XRP", 100) == Decimal("0.55") * 100
