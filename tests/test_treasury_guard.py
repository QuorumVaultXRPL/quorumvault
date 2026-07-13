"""TreasuryConfigVerifier: the live 2-of-2 guard, exercised against a fake XRPL
client (no network). Mirrors the FakeXrplClient/Response pattern in
tests/test_ledger_reader.py. Closes Wietse Wind's "signer list change / remove /
bypass with regular key" review point at the point QuorumVault actually signs.
"""

from __future__ import annotations

import pytest
from xrpl.models.response import Response, ResponseStatus, ResponseType

from quorumvault.policy.treasury_guard import (
    LSF_DISABLE_MASTER,
    StaticTreasuryConfigVerifier,
    TreasuryConfigError,
    XrplTreasuryConfigVerifier,
)

TREASURY = "rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce"
SIGNER_A = "rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"
SIGNER_B = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
INTRUDER = "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW"
EXPECTED = {SIGNER_A, SIGNER_B}


class FakeAccountInfoClient:
    """Stands in for an xrpl-py sync Client for one account_info(signer_lists=True)
    call. Configured with the raw result dict (or an error / exception) so the
    verifier's parsing runs against realistic response shapes, no network."""

    def __init__(self, *, result=None, error=None, raise_exc=None):
        self._result = result
        self._error = error
        self._raise = raise_exc
        self.last_request = None

    def request(self, request):
        self.last_request = request
        if self._raise is not None:
            raise self._raise
        if self._error is not None:
            return Response(
                status=ResponseStatus.ERROR,
                result={"error": self._error},
                type=ResponseType.RESPONSE,
            )
        return Response(
            status=ResponseStatus.SUCCESS,
            result=self._result,
            type=ResponseType.RESPONSE,
        )


def _account_data(*, regular_key=None, master_disabled=True, extra_flags=0):
    flags = extra_flags | (LSF_DISABLE_MASTER if master_disabled else 0)
    data = {"Account": TREASURY, "LedgerEntryType": "AccountRoot", "Flags": flags}
    if regular_key is not None:
        data["RegularKey"] = regular_key
    return data


def _signer_list(entries=((SIGNER_A, 1), (SIGNER_B, 1)), quorum=2):
    return [
        {
            "LedgerEntryType": "SignerList",
            "SignerQuorum": quorum,
            "SignerEntries": [
                {"SignerEntry": {"Account": acct, "SignerWeight": w}}
                for acct, w in entries
            ],
        }
    ]


def _result(account_data, signer_lists, *, api_v1_nested=False):
    result = {"account_data": dict(account_data)}
    if signer_lists is not None:
        if api_v1_nested:
            result["account_data"]["signer_lists"] = signer_lists
        else:
            result["signer_lists"] = signer_lists
    return result


def _verify(client):
    XrplTreasuryConfigVerifier(client).verify(
        treasury_address=TREASURY, expected_signers=EXPECTED, expected_quorum=2
    )


# -- happy path -------------------------------------------------------------


def test_correct_config_passes_api_v2_root():
    _verify(FakeAccountInfoClient(result=_result(_account_data(), _signer_list())))


def test_correct_config_passes_api_v1_nested():
    _verify(
        FakeAccountInfoClient(
            result=_result(_account_data(), _signer_list(), api_v1_nested=True)
        )
    )


def test_request_uses_signer_lists_true():
    client = FakeAccountInfoClient(result=_result(_account_data(), _signer_list()))
    _verify(client)
    assert getattr(client.last_request, "signer_lists") is True
    assert getattr(client.last_request, "account") == TREASURY


# -- regular key ------------------------------------------------------------


def test_regular_key_set_is_rejected():
    client = FakeAccountInfoClient(
        result=_result(_account_data(regular_key=INTRUDER), _signer_list())
    )
    with pytest.raises(TreasuryConfigError) as exc:
        _verify(client)
    assert "RegularKey" in str(exc.value)


# -- master key -------------------------------------------------------------


def test_master_key_not_disabled_is_rejected():
    client = FakeAccountInfoClient(
        result=_result(_account_data(master_disabled=False), _signer_list())
    )
    with pytest.raises(TreasuryConfigError) as exc:
        _verify(client)
    assert "lsfDisableMaster" in str(exc.value)


def test_master_check_isolated_from_other_flags():
    # lsfDefaultRipple (0x00800000) set but NOT lsfDisableMaster -> still rejected.
    client = FakeAccountInfoClient(
        result=_result(
            _account_data(master_disabled=False, extra_flags=0x00800000), _signer_list()
        )
    )
    with pytest.raises(TreasuryConfigError):
        _verify(client)


# -- signer list ------------------------------------------------------------


def test_missing_signer_list_is_rejected():
    with pytest.raises(TreasuryConfigError):
        _verify(FakeAccountInfoClient(result=_result(_account_data(), None)))


def test_wrong_quorum_is_rejected():
    client = FakeAccountInfoClient(result=_result(_account_data(), _signer_list(quorum=1)))
    with pytest.raises(TreasuryConfigError) as exc:
        _verify(client)
    assert "SignerQuorum" in str(exc.value)


def test_added_signer_is_rejected():
    client = FakeAccountInfoClient(
        result=_result(
            _account_data(),
            _signer_list(entries=((SIGNER_A, 1), (SIGNER_B, 1), (INTRUDER, 1)), quorum=2),
        )
    )
    with pytest.raises(TreasuryConfigError):
        _verify(client)


def test_removed_signer_is_rejected():
    client = FakeAccountInfoClient(
        result=_result(_account_data(), _signer_list(entries=((SIGNER_A, 1),), quorum=2))
    )
    with pytest.raises(TreasuryConfigError):
        _verify(client)


def test_swapped_signer_is_rejected():
    client = FakeAccountInfoClient(
        result=_result(_account_data(), _signer_list(entries=((SIGNER_A, 1), (INTRUDER, 1))))
    )
    with pytest.raises(TreasuryConfigError):
        _verify(client)


def test_single_heavy_signer_meeting_quorum_alone_is_rejected():
    # Same members, same quorum number, but A alone (weight 2) meets quorum 2 -
    # a unilateral-bypass config that set-equality + quorum-equality alone miss.
    client = FakeAccountInfoClient(
        result=_result(
            _account_data(), _signer_list(entries=((SIGNER_A, 2), (SIGNER_B, 1)), quorum=2)
        )
    )
    with pytest.raises(TreasuryConfigError) as exc:
        _verify(client)
    assert "alone" in str(exc.value)


# -- read failures fail closed ---------------------------------------------


def test_account_not_found_fails_closed():
    with pytest.raises(TreasuryConfigError):
        _verify(FakeAccountInfoClient(error="actNotFound"))


def test_transport_exception_fails_closed():
    with pytest.raises(TreasuryConfigError):
        _verify(FakeAccountInfoClient(raise_exc=RuntimeError("connection reset")))


def test_missing_account_data_fails_closed():
    with pytest.raises(TreasuryConfigError):
        _verify(FakeAccountInfoClient(result={"validated": True}))


# -- placeholder + is_live --------------------------------------------------


def test_static_verifier_ok_passes_and_is_not_live():
    verifier = StaticTreasuryConfigVerifier(ok=True)
    assert verifier.is_live is False
    verifier.verify(
        treasury_address=TREASURY, expected_signers=EXPECTED, expected_quorum=2
    )  # no raise


def test_static_verifier_fail_raises():
    with pytest.raises(TreasuryConfigError):
        StaticTreasuryConfigVerifier(ok=False, reason="tampered").verify(
            treasury_address=TREASURY, expected_signers=EXPECTED, expected_quorum=2
        )


def test_xrpl_verifier_is_live():
    assert XrplTreasuryConfigVerifier(FakeAccountInfoClient()).is_live is True
