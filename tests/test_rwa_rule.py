"""RWA compliance rule + its integration into the risk engine."""

from quorumvault.policy.intent import Credential, PaymentIntent, RwaTransfer
from quorumvault.policy.risk_engine import RiskEngine, RiskLevel
from quorumvault.policy.rwa_rule import RwaComplianceRule

WL = "rGoodDestination000000000000000000"
ACCRED = Credential(issuer="rIssuer00000000000000000000000000", credential_type="ACCREDITED")


def _clean_rwa():
    return RwaTransfer(
        requires_authorization=True,
        destination_authorized=True,
        required_credentials=[ACCRED],
        destination_credentials=[ACCRED],
        domain_id="DOMAIN1",
        destination_in_domain=True,
        clawback_enabled=False,
    )


def test_fully_compliant_transfer_has_no_findings():
    assert RwaComplianceRule().evaluate(_clean_rwa()) == []


def test_unauthorized_destination_is_red():
    rwa = _clean_rwa()
    rwa.destination_authorized = False
    codes = {f.code: f.severity for f in RwaComplianceRule().evaluate(rwa)}
    assert codes["rwa_destination_not_authorized"] == "RED"


def test_non_transferable_to_non_issuer_is_red_but_ok_to_issuer():
    rwa = _clean_rwa()
    rwa.transfer_disabled = True
    rwa.destination_is_issuer = False
    codes = [f.code for f in RwaComplianceRule().evaluate(rwa)]
    assert "rwa_transfer_not_permitted" in codes
    rwa.destination_is_issuer = True
    codes = [f.code for f in RwaComplianceRule().evaluate(rwa)]
    assert "rwa_transfer_not_permitted" not in codes


def test_missing_credential_is_red():
    rwa = _clean_rwa()
    rwa.destination_credentials = []  # lacks ACCRED
    codes = [f.code for f in RwaComplianceRule().evaluate(rwa)]
    assert "rwa_missing_required_credential" in codes


def test_outside_permissioned_domain_is_red():
    rwa = _clean_rwa()
    rwa.destination_in_domain = False
    codes = [f.code for f in RwaComplianceRule().evaluate(rwa)]
    assert "rwa_destination_outside_permissioned_domain" in codes


def test_clawback_is_yellow_not_red():
    rwa = _clean_rwa()
    rwa.clawback_enabled = True
    findings = RwaComplianceRule().evaluate(rwa)
    assert [f.severity for f in findings] == ["YELLOW"]
    assert findings[0].code == "rwa_clawback_exposure"


def test_compound_findings_accumulate():
    rwa = RwaTransfer(
        requires_authorization=True,
        destination_authorized=False,
        required_credentials=[ACCRED],
        destination_credentials=[],
        clawback_enabled=True,
    )
    codes = {f.code for f in RwaComplianceRule().evaluate(rwa)}
    assert {
        "rwa_destination_not_authorized",
        "rwa_missing_required_credential",
        "rwa_clawback_exposure",
    } <= codes


# -- engine integration ------------------------------------------------
def _engine():
    return RiskEngine(whitelist=[WL], amount_threshold_rlusd=5000, frequency_limit=10)


def test_engine_rwa_red_trips_breaker():
    eng = _engine()
    intent = PaymentIntent(
        destination=WL,
        asset="RLUSD",
        amount=100,
        rwa=RwaTransfer(requires_authorization=True, destination_authorized=False),
    )
    result = eng.evaluate(intent)
    assert result["risk_level"] == RiskLevel.RED
    assert "rwa_destination_not_authorized" in result["fired_reasons"]
    assert eng.circuit_breaker_tripped is True


def test_engine_rwa_clawback_is_yellow_and_does_not_freeze():
    eng = _engine()
    intent = PaymentIntent(
        destination=WL, asset="RLUSD", amount=100, rwa=RwaTransfer(clawback_enabled=True)
    )
    result = eng.evaluate(intent)
    assert result["risk_level"] == RiskLevel.YELLOW
    assert eng.circuit_breaker_tripped is False


def test_engine_compound_value_plus_rwa():
    eng = _engine()
    intent = PaymentIntent(
        destination=WL,
        asset="RLUSD",
        amount=9000,  # over threshold -> YELLOW
        rwa=RwaTransfer(requires_authorization=True, destination_authorized=False),  # RED
    )
    result = eng.evaluate(intent)
    assert result["risk_level"] == RiskLevel.RED
    assert "value_threshold_exceeded" in result["fired_reasons"]
    assert "rwa_destination_not_authorized" in result["fired_reasons"]
