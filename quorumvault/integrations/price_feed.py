"""A live XRP->USD price feed for production value-routing.

``policy/pricing.py`` deliberately stays network-free (like every ``policy``
module) and already ships the wrapper this feeds into: ``CallableRateProvider``,
with its ``max_age_s`` staleness guard and ``StaleRateError``. The one missing
piece is a real ``price_fn`` that calls a live source. This module is that piece.
``default_rate_provider()`` is unchanged - it remains the labelled Testnet
placeholder; live pricing is opt-in via :func:`live_rate_provider` only.

Source (verified 2026-07-21 by fetching it, not from memory):
``GET https://api.coinbase.com/v2/prices/XRP-USD/spot`` -> HTTP 200,
``{"data":{"amount":"1.37215","base":"XRP","currency":"USD"}}``. Free, keyless,
no rate-limit friction observed. Chosen because it is the source I could confirm
is *currently* working without a key from this environment.

Three caveats, stated rather than hidden:

1. **No source timestamp.** Coinbase's spot endpoint returns only a current-moment
   price, no "as of" time. So the ``as_of`` this module returns is *the moment
   QuorumVault fetched the price*, not the moment Coinbase computed it.
   ``CallableRateProvider(max_age_s=...)`` therefore bounds fetch-to-use latency,
   not true source age; since ``CallableRateProvider`` fetches fresh on every
   call, that window is ~0 and the ``max_age_s`` guard is effectively inert with
   this source. The real freshness protections here are (a) a fresh fetch on
   every ``to_rlusd`` call and (b) a hard HTTP timeout so a hung request can't
   block signing. A source *with* a timestamp (e.g. CoinGecko's
   ``include_last_updated_at=true`` -> ``last_updated_at``) would make ``max_age_s``
   bite on true source age; CoinGecko was NOT confirmed keyless-working from this
   sandbox (empty response body; its current OpenAPI targets the keyed ``pro-api``
   host), so it was not chosen as the default - swapping the fetcher is a one-line
   change if a demo key is acceptable.
2. **USD as a proxy for RLUSD.** QuorumVault's rate is nominally "XRP->RLUSD".
   RLUSD is a USD-pegged stablecoin; Coinbase gives XRP->USD directly. This module
   treats XRP->USD as XRP->RLUSD, an explicit ~1:1 assumption. Neither Coinbase
   nor CoinGecko exposes a true XRP->RLUSD cross here.
3. **Fail closed on any fetch/parse failure.** Per the codebase's discipline, a
   network/HTTP/decode/shape/non-positive failure is raised as
   :class:`PriceFeedError` (a ``StaleRateError`` subclass), never a raw
   ``urllib``/JSON exception leaking up into the risk engine or tier router.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from decimal import Decimal, InvalidOperation
from typing import Callable, Tuple

from ..policy.pricing import CallableRateProvider, StaleRateError

COINBASE_XRP_USD_URL = "https://api.coinbase.com/v2/prices/XRP-USD/spot"

# A hung price fetch must never block signing indefinitely. 5s is generous for a
# healthy public-API round-trip yet bounds the worst-case latency this adds to a
# sign() call; XRP is liquid enough that no sane feed needs longer.
DEFAULT_HTTP_TIMEOUT_S = 5.0

# Forward-looking default staleness bound for CallableRateProvider. With Coinbase
# (no source timestamp) this is effectively inert (see module docstring, caveat 1);
# it becomes meaningful if a timestamped source is swapped in. 60s aligns with the
# typical free-tier price-update cadence: tight enough to catch a genuinely stale
# source, loose enough to tolerate normal update intervals.
DEFAULT_MAX_AGE_S = 60.0


class PriceFeedError(StaleRateError):
    """A live price fetch failed or returned an unusable value.

    Subclass of :class:`~quorumvault.policy.pricing.StaleRateError` on purpose: a
    fetch failure and a too-old price are the same decision at the policy boundary
    - refuse to route rather than route on a guess - and the risk engine / tier
    router already catch ``StaleRateError``. The distinct subclass name preserves
    "fetch/parse broke" vs "price too old" in logs and tests.
    """


def _default_http_get(url: str, *, timeout_s: float) -> str:
    """Minimal stdlib GET (no third-party HTTP dependency). Injectable for tests."""
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "QuorumVault/price_feed", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout_s) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset)


def fetch_xrp_usd_rate(
    *,
    http_get: Callable[..., str] = _default_http_get,
    timeout_s: float = DEFAULT_HTTP_TIMEOUT_S,
    url: str = COINBASE_XRP_USD_URL,
    now: Callable[[], float] = time.time,
) -> Tuple[Decimal, float]:
    """Fetch the current XRP->USD spot price as ``(rate, as_of_epoch_seconds)``.

    ``as_of`` is the fetch time (Coinbase provides no source timestamp - see the
    module docstring). Every failure mode - transport, HTTP, decode, JSON, missing
    field, non-numeric, non-positive - is raised as :class:`PriceFeedError`, never
    a raw lower-level exception, so it fails closed through the same path as a
    stale price. ``http_get`` is injected in tests so no live network is touched.
    """
    try:
        body = http_get(url, timeout_s=timeout_s)
    except Exception as exc:  # URLError, socket timeout, any transport failure
        raise PriceFeedError(
            f"XRP price fetch failed ({type(exc).__name__}): {exc}"
        ) from exc

    try:
        payload = json.loads(body)
        amount = payload["data"]["amount"]
    except (ValueError, TypeError, KeyError) as exc:
        raise PriceFeedError(
            f"XRP price response was not the expected shape ({type(exc).__name__}: {exc})."
        ) from exc

    try:
        rate = Decimal(str(amount))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise PriceFeedError(f"XRP price {amount!r} is not a valid decimal.") from exc

    if rate <= 0:
        raise PriceFeedError(
            f"XRP price {rate} is not positive; refusing to route on it."
        )
    return rate, now()


def live_rate_provider(
    *,
    max_age_s: float = DEFAULT_MAX_AGE_S,
    timeout_s: float = DEFAULT_HTTP_TIMEOUT_S,
    http_get: Callable[..., str] = _default_http_get,
    url: str = COINBASE_XRP_USD_URL,
    now: Callable[[], float] = time.time,
    clock: Callable[[], float] = time.time,
) -> CallableRateProvider:
    """A production :class:`CallableRateProvider` backed by the live XRP->USD feed.

    Opt-in only; ``default_rate_provider()`` stays the Testnet placeholder. See the
    module docstring for the ``max_age_s`` semantics with a timestamp-less source.
    ``http_get`` / ``now`` / ``clock`` are injectable so the wiring (including the
    staleness path) is testable without a live network.
    """
    return CallableRateProvider(
        lambda: fetch_xrp_usd_rate(
            http_get=http_get, timeout_s=timeout_s, url=url, now=now
        ),
        max_age_s=max_age_s,
        clock=clock,
    )
