import pytest
import time
from shared.models import (
    ScanRequest,
    UrlAgentResult,
    SenderAgentResult,
    IntentAgentResult,
    RiskTierEnum,
    ActionRequiredEnum,
    AgentStatusEnum,
    SenderCategoryEnum,
    DetectedIntentEnum,
    TldReputationEnum
)
from core.scoring_engine import compute_score, _compute_dynamic_weights


@pytest.fixture
def base_request():
    return ScanRequest(content="Test scan payload", sender="+919876543210")


def test_dynamic_weights_all_active():
    url_r = UrlAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)
    sender_r = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)
    intent_r = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)

    weights = _compute_dynamic_weights(url_r, sender_r, intent_r)
    assert weights["url_weight"] == 0.40
    assert weights["sender_weight"] == 0.30
    assert weights["intent_weight"] == 0.30


def test_dynamic_weights_url_skipped():
    url_r = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    sender_r = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)
    intent_r = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)

    weights = _compute_dynamic_weights(url_r, sender_r, intent_r)
    assert weights["url_weight"] == 0.0
    assert weights["sender_weight"] == 0.50
    assert weights["intent_weight"] == 0.50


def test_double_whammy_escalation(base_request):
    """High risk URL + High risk Sender must trigger CRITICAL escalation (score >= 92)."""
    url_r = UrlAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=85.0,
        is_typosquatting=True,
        target_brand="SBI"
    )
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=85.0,
        sender_category=SenderCategoryEnum.PERSONAL_GSM
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=40.0,
        detected_intent=DetectedIntentEnum.SUSPICIOUS
    )

    resp = compute_score(base_request, url_r, sender_r, intent_r)
    assert resp.overall_risk_score >= 92
    assert resp.risk_tier == RiskTierEnum.CRITICAL
    assert resp.action_required == ActionRequiredEnum.BLOCK_TRANSACTION
    assert any("CRITICAL_ESCALATION" in h for h in resp.audit_trail.synthesis_breakdown.heuristics_triggered)


def test_personal_gsm_bank_impersonation(base_request):
    """Personal GSM claiming bank with KYC urgency must escalate to CRITICAL."""
    url_r = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=75.0,
        sender_category=SenderCategoryEnum.PERSONAL_GSM,
        brand_claimed="State Bank of India",
        flags=["COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM"]
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=80.0,
        detected_intent=DetectedIntentEnum.KYC_VERIFICATION,
        manipulation_tactics=["False Urgency", "Account Suspension Threat"]
    )

    resp = compute_score(base_request, url_r, sender_r, intent_r)
    assert resp.overall_risk_score >= 88
    assert resp.risk_tier == RiskTierEnum.CRITICAL
    assert resp.action_required == ActionRequiredEnum.BLOCK_TRANSACTION


def test_otp_harvest_escalation(base_request):
    """Active OTP harvesting with suspicious link must escalate to CRITICAL."""
    url_r = UrlAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=60.0,
        tld_reputation=TldReputationEnum.HIGH_RISK
    )
    sender_r = SenderAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=70.0,
        detected_intent=DetectedIntentEnum.OTP_HARVEST,
        manipulation_tactics=["Requesting OTP verification"]
    )

    resp = compute_score(base_request, url_r, sender_r, intent_r)
    assert resp.overall_risk_score >= 90
    assert resp.risk_tier == RiskTierEnum.CRITICAL
    assert resp.action_required == ActionRequiredEnum.BLOCK_TRANSACTION


def test_benign_trai_header_override(base_request):
    """Certified TRAI header with no link and safe intent must cap at <= 15 and SAFE."""
    url_r = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=5.0,
        sender_category=SenderCategoryEnum.OFFICIAL_TRAI_HEADER,
        brand_claimed="HDFC Bank"
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=10.0,
        detected_intent=DetectedIntentEnum.BENIGN
    )

    resp = compute_score(base_request, url_r, sender_r, intent_r)
    assert resp.overall_risk_score <= 15
    assert resp.risk_tier == RiskTierEnum.SAFE
    assert resp.action_required == ActionRequiredEnum.ALLOW
    assert "Verified Authentic" in resp.verdict


def test_scoring_latency_benchmark(base_request):
    """Scoring engine execution must be under 10ms."""
    url_r = UrlAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=40.0)
    sender_r = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=40.0)
    intent_r = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=40.0)

    start = time.perf_counter()
    resp = compute_score(base_request, url_r, sender_r, intent_r)
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert elapsed_ms < 10.0
    assert resp.overall_risk_score == 40
    assert resp.risk_tier == RiskTierEnum.CAUTION
