"""Refusal alerting - make an existing refusal observable, without changing it.

When :class:`~quorumvault.integrations.external_signer.QuorumVaultExternalSigner`
refuses a transaction, the decision is recorded in ``last_decision`` and the
caller gets an ``ExternalSignerRefused`` - but if nobody is polling or reading
logs, a real block goes unnoticed. This module delivers a near-real-time
notification on a refusal.

It is **purely observational**. Two invariants, both enforced:

1. Alerting never changes whether a transaction is refused. The refusal has
   already happened by the time an alert is attempted.
2. An alert-delivery failure (channel down, timeout, HTTP error) is caught,
   never propagates, and is surfaced as :class:`AlertDeliveryFailedWarning` -
   never confused with, nor allowed to suppress, the original refusal.

Same injectable-seam shape as the rest of the codebase:

* :class:`RefusalAlertSink` - the abstract seam.
* :class:`WebhookAlertSink` - POSTs a JSON payload to a caller-supplied URL.
  Chosen over email deliberately: a generic webhook works unmodified with Slack,
  Discord (this project's actual, currently-used outreach channel), or any custom
  receiver; it needs no SMTP credentials and no email dependency.
* :class:`NullAlertSink` - ``is_live == False``, does nothing; for offline tests
  and deployments that don't want alerting wired yet.

Unlike ``treasury_guard`` / ``agent_identity_verifier``, a MISSING sink is not a
fail-closed condition - the refusal already happened correctly without it - so
there is deliberately no ``*NotWiredWarning`` for a missing sink. The only
warning here is :class:`AlertDeliveryFailedWarning`, for a *wired* sink that
fails to deliver.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import warnings
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:  # avoid a runtime import cycle with external_signer
    from .external_signer import SignDecision

# A refusal alert must not hang the caller. Short, since it runs after a refusal
# on a path the caller is already waiting on.
DEFAULT_ALERT_TIMEOUT_S = 5.0


class AlertDeliveryFailedWarning(UserWarning):
    """A refusal alert could not be delivered. The refusal itself is unaffected.

    Named to match the ``*NotWiredWarning`` precedent used elsewhere in this
    codebase. Emitting a warning (rather than swallowing silently) means a broken
    alert channel is itself observable.
    """


class RefusalAlertSink(ABC):
    """Deliver a notification that a signing request was refused."""

    @abstractmethod
    def notify(self, decision: "SignDecision", *, tx_type: str) -> None:
        """Deliver an alert for one refusal.

        Implementations MUST NOT raise on a delivery failure in a way that could
        reach the caller of ``sign()``; convert transport failures to an
        :class:`AlertDeliveryFailedWarning`. (The signer also defensively catches
        anything a misbehaving sink raises, but a well-behaved sink handles its
        own delivery failures.)
        """

    @property
    def is_live(self) -> bool:
        """False for inert placeholders; a real delivery channel returns True."""
        return False


class NullAlertSink(RefusalAlertSink):
    """A sink that does nothing. ``is_live == False``. For tests / no-alert setups."""

    def notify(self, decision: "SignDecision", *, tx_type: str) -> None:
        return None


class WebhookAlertSink(RefusalAlertSink):
    """POST a JSON refusal payload to a caller-supplied webhook URL.

    Works unmodified with Slack / Discord incoming webhooks or any receiver that
    accepts a JSON POST. ``http_post`` is injected in tests so no live network is
    touched. Delivery failures become :class:`AlertDeliveryFailedWarning`; they
    never raise out of :meth:`notify`.
    """

    def __init__(
        self,
        url: str,
        *,
        timeout_s: float = DEFAULT_ALERT_TIMEOUT_S,
        http_post: Optional[Callable[..., None]] = None,
    ):
        if not url:
            raise ValueError("WebhookAlertSink requires a non-empty webhook URL")
        self._url = url
        self._timeout_s = timeout_s
        self._http_post = http_post or _default_http_post

    @property
    def is_live(self) -> bool:
        return True

    def build_payload(self, decision: "SignDecision", *, tx_type: str) -> dict:
        """The JSON body POSTed for a refusal (kept separate for testability)."""
        return {
            "event": "quorumvault.refusal",
            "tx_type": tx_type,
            "tier": getattr(decision, "tier", None),
            "risk_level": getattr(decision, "risk_level", None),
            "fired_reasons": list(getattr(decision, "fired_reasons", []) or []),
        }

    def notify(self, decision: "SignDecision", *, tx_type: str) -> None:
        body = json.dumps(self.build_payload(decision, tx_type=tx_type)).encode("utf-8")
        try:
            self._http_post(self._url, body, timeout_s=self._timeout_s)
        except Exception as exc:  # transport/HTTP failure of any kind
            warnings.warn(
                AlertDeliveryFailedWarning(
                    f"webhook refusal alert to POST failed "
                    f"({type(exc).__name__}): {exc}. The refusal itself is unaffected."
                ),
                stacklevel=2,
            )


def _default_http_post(url: str, body: bytes, *, timeout_s: float) -> None:
    """Minimal stdlib POST (no third-party HTTP dependency). Injectable for tests."""
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "QuorumVault/alerts",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout_s) as response:
        response.read()  # drain and close
