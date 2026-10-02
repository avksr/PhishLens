import pytest
import time
from shared.models import (
    ScanRequest,
    UrlAgentResult,
    SenderAgentResult,
    IntentAgentResult,
    UpiAgentResult,
    RiskTierEnum,
    PrdVerdictEnum,
    ActionRequiredEnum,
    AgentStatusEnum,
    SenderCategoryEnum,
    DetectedIntentEnum,
    TldReputationEnum,
    ConfidenceLevelEnum
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


# --- Day 2 Enhanced Tests: Bilingual, Confidence, UPI ---

def test_bilingual_verdict_synthesis(base_request):
    """Verify that every verdict produces both English and Devanagari Hindi outputs."""
    url_r = UrlAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=90.0,
        is_typosquatting=True,
        target_brand="SBI"
    )
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=85.0,
        sender_category=SenderCategoryEnum.PERSONAL_GSM,
        brand_claimed="SBI"
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=85.0,
        detected_intent=DetectedIntentEnum.KYC_VERIFICATION
    )

    resp = compute_score(base_request, url_r, sender_r, intent_r)
    assert resp.verdict is not None and len(resp.verdict) > 0
    assert resp.verdict_hi is not None and len(resp.verdict_hi) > 0
    # Check that Hindi text contains Devanagari characters
    assert any('\u0900' <= char <= '\u097f' for char in resp.verdict_hi)
    assert any('\u0900' <= char <= '\u097f' for char in resp.recommendation_hi)
    assert "1930" in resp.recommendation
    assert "1930" in resp.recommendation_hi


def test_confidence_rating_scenarios(base_request):
    """Verify epistemic confidence rating across different agent completion states."""
    # Scenario 1: All active and decisive escalation -> HIGH
    url_r = UrlAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=85.0)
    sender_r = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=85.0)
    intent_r = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)
    resp_high = compute_score(base_request, url_r, sender_r, intent_r)
    assert resp_high.confidence == ConfidenceLevelEnum.HIGH

    # Scenario 2: One agent SKIPPED without critical escalation -> MEDIUM
    url_skipped = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    sender_ok = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=30.0)
    intent_ok = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=30.0)
    resp_med = compute_score(base_request, url_skipped, sender_ok, intent_ok)
    assert resp_med.confidence == ConfidenceLevelEnum.MEDIUM

    # Scenario 3: Two agents in ERROR -> LOW
    url_err = UrlAgentResult(status=AgentStatusEnum.ERROR, risk_score=0.0)
    sender_err = SenderAgentResult(status=AgentStatusEnum.ERROR, risk_score=0.0)
    intent_ok = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=40.0)
    resp_low = compute_score(base_request, url_err, sender_err, intent_ok)
    assert resp_low.confidence == ConfidenceLevelEnum.LOW


def test_upi_vector_integration(base_request):
    """Verify that passing an active UPI result dynamically reallocates weights and flags scams."""
    url_r = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    sender_r = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=40.0)
    intent_r = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=40.0)
    upi_r = UpiAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=85.0,
        detected_vpa="electricity-refund@paytm",
        is_spoofed_merchant=True,
        target_entity="Electricity Board",
        flags=["PERSONAL_VPA_CLAIMING_MERCHANT"]
    )

    resp = compute_score(base_request, url_r, sender_r, intent_r, upi_r)
    assert resp.overall_risk_score >= 90
    assert resp.risk_tier == RiskTierEnum.CRITICAL
    assert resp.action_required == ActionRequiredEnum.BLOCK_TRANSACTION
    assert resp.audit_trail.upi_analysis is not None
    assert resp.audit_trail.upi_analysis.detected_vpa == "electricity-refund@paytm"
    assert "UPI" in resp.verdict or "Payment" in resp.verdict
    assert "UPI" in resp.verdict_hi or "यूपीआई" in resp.verdict_hi
    assert "UPI" in resp.recommendation


def test_sub_millisecond_scoring_latency(base_request):
    """Verify that 100 iterations of full synthesis execute in < 1.0ms median latency."""
    url_r = UrlAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=85.0, latency_ms=0.5)
    sender_r = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=85.0, latency_ms=0.3)
    intent_r = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=80.0, latency_ms=0.4)

    durations = []
    for _ in range(100):
        t0 = time.perf_counter()
        resp = compute_score(base_request, url_r, sender_r, intent_r)
        durations.append((time.perf_counter() - t0) * 1000)

    median_duration = sorted(durations)[len(durations) // 2]
    assert median_duration < 1.0, f"Expected < 1.0ms, got {median_duration:.3f}ms"
    assert resp.confidence == ConfidenceLevelEnum.HIGH


# ─── AVIKA Sprint 5 — New Tests ─────────────────────────────────────────────


def test_fail_secure_all_agents_failed(base_request):
    """
    Fail-Secure Safety Net: When all 3 mandatory agents ERROR out (e.g., timeout/crash),
    scoring must return CAUTION/35/WARN_USER/LOW instead of falsely defaulting to SAFE/0.
    """
    url_r = UrlAgentResult(
        status=AgentStatusEnum.ERROR, risk_score=0.0,
        flags=["URL_AGENT_FAILED"], latency_ms=3500.0
    )
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.ERROR, risk_score=0.0,
        flags=["SENDER_AGENT_FAILED"], latency_ms=3500.0
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.ERROR, risk_score=0.0,
        flags=["INTENT_AGENT_FAILED"], latency_ms=3500.0
    )

    resp = compute_score(base_request, url_r, sender_r, intent_r)

    # Core fail-secure assertions
    assert resp.overall_risk_score == 35, (
        f"Expected fail-secure score=35, got {resp.overall_risk_score} "
        f"(false-SAFE bug: total agent failure was misclassified)"
    )
    assert resp.risk_tier == RiskTierEnum.CAUTION
    assert resp.action_required == ActionRequiredEnum.WARN_USER
    assert resp.confidence == ConfidenceLevelEnum.LOW

    # Verify bilingual output is populated
    assert resp.verdict is not None and "Analysis Unavailable" in resp.verdict
    assert resp.verdict_hi is not None
    assert any('\u0900' <= c <= '\u097f' for c in resp.verdict_hi), \
        "Hindi verdict must contain Devanagari characters"
    assert resp.recommendation is not None and "1930" in resp.recommendation
    assert resp.recommendation_hi is not None
    assert any('\u0900' <= c <= '\u097f' for c in resp.recommendation_hi), \
        "Hindi recommendation must contain Devanagari characters"

    # Verify heuristic audit trail records the fail-secure trigger
    heuristics = resp.audit_trail.synthesis_breakdown.heuristics_triggered
    assert len(heuristics) >= 1
    assert "FAIL_SECURE" in heuristics[0]


def test_confidence_signal_completeness(base_request):
    """
    Signal Completeness / Confidence Rating:
    Verify that confidence degrades based on the count of inactive (SKIPPED or ERROR)
    mandatory vectors, not just error-only counts.
    """
    # ── Scenario 1: All 3 active → HIGH (no decisive escalation path) ─────────
    url_ok = UrlAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=30.0)
    snd_ok = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=30.0)
    int_ok = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=30.0)
    resp_all = compute_score(base_request, url_ok, snd_ok, int_ok)
    assert resp_all.confidence == ConfidenceLevelEnum.HIGH, \
        "All 3 agents SUCCESS → HIGH confidence"

    # ── Scenario 2: 1 SKIPPED (natural: no URL) → MEDIUM ────────────────────
    url_skip = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    snd_ok2 = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=30.0)
    int_ok2 = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=30.0)
    resp_med = compute_score(base_request, url_skip, snd_ok2, int_ok2)
    assert resp_med.confidence == ConfidenceLevelEnum.MEDIUM, \
        "1 SKIPPED agent → MEDIUM confidence"

    # ── Scenario 3: 1 ERROR (timed out) → MEDIUM ─────────────────────────────
    url_err = UrlAgentResult(status=AgentStatusEnum.ERROR, risk_score=0.0)
    snd_ok3 = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=30.0)
    int_ok3 = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=30.0)
    resp_m2 = compute_score(base_request, url_err, snd_ok3, int_ok3)
    assert resp_m2.confidence == ConfidenceLevelEnum.MEDIUM, \
        "1 ERRORed agent → MEDIUM confidence"

    # ── Scenario 4: 2 ERRORed → LOW ──────────────────────────────────────────
    url_err2 = UrlAgentResult(status=AgentStatusEnum.ERROR, risk_score=0.0)
    snd_err2 = SenderAgentResult(status=AgentStatusEnum.ERROR, risk_score=0.0)
    int_ok4 = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=40.0)
    resp_low = compute_score(base_request, url_err2, snd_err2, int_ok4)
    assert resp_low.confidence == ConfidenceLevelEnum.LOW, \
        "2 ERRORed agents → LOW confidence"

    # ── Scenario 5: 1 SKIPPED + 1 ERROR → LOW ────────────────────────────────
    url_skip2 = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    snd_err3 = SenderAgentResult(status=AgentStatusEnum.ERROR, risk_score=0.0)
    int_ok5 = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=40.0)
    resp_low2 = compute_score(base_request, url_skip2, snd_err3, int_ok5)
    assert resp_low2.confidence == ConfidenceLevelEnum.LOW, \
        "1 SKIPPED + 1 ERRORed → LOW confidence"


def test_format_1930_complaint(base_request):
    """
    1930 Cyber Cell Complaint Generator: Verify the helper produces a copy-ready
    NCRP-aligned complaint block with all required sections and scan evidence.
    """
    from core.verdict_utils import format_1930_complaint

    url_r = UrlAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=88.0,
        url_analyzed="https://sbi-kyc-verify.top",
        is_typosquatting=True,
        target_brand="SBI",
        tld_reputation=TldReputationEnum.HIGH_RISK,
        flags=["HIGH_RISK_TLD", "TYPOSQUATTING_DETECTED"],
        latency_ms=320.0
    )
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=85.0,
        sender_analyzed="+919876543210",
        sender_category=SenderCategoryEnum.PERSONAL_GSM,
        brand_claimed="State Bank of India",
        flags=["COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM"]
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=90.0,
        detected_intent=DetectedIntentEnum.KYC_VERIFICATION,
        manipulation_tactics=["ARTIFICIAL_URGENCY", "CREDENTIAL_SOLICITATION"]
    )

    resp = compute_score(base_request, url_r, sender_r, intent_r)

    # ── Generate complaint with victim details ────────────────────────────────
    complaint = format_1930_complaint(
        resp,
        victim_name="Rahul Sharma",
        victim_phone="+919876543210",
        incident_date="2026-09-30"
    )

    # Required structural sections
    assert "SECTION A" in complaint, "Missing Section A — Complainant Details"
    assert "SECTION B" in complaint, "Missing Section B — Incident Description"
    assert "SECTION C" in complaint, "Missing Section C — Technical Evidence"
    assert "SECTION D" in complaint, "Missing Section D — Analysis Summary"
    assert "SECTION E" in complaint, "Missing Section E — Declaration"

    # Required content
    assert "1930" in complaint, "Must include 1930 helpline number"
    assert "cybercrime.gov.in" in complaint, "Must include NCRP portal URL"
    assert resp.scan_id in complaint, "Must embed PhishLens scan ID"
    assert "Rahul Sharma" in complaint, "Must include victim name"
    assert str(resp.overall_risk_score) in complaint, "Must include risk score"
    assert "sbi-kyc-verify.top" in complaint, "Must include analyzed URL"
    assert "+919876543210" in complaint, "Must include sender ID"
    assert "IT Act" in complaint or "Information Technology Act" in complaint, \
        "Must cite the IT Act"

    # ── Generate anonymized template (no victim info) ─────────────────────────
    complaint_anon = format_1930_complaint(resp)
    assert "[FILL IN YOUR FULL NAME]" in complaint_anon
    assert "[FILL IN YOUR MOBILE NUMBER]" in complaint_anon


def test_prd_output_contract_fields(base_request):
    """Verify that ScanResponse complies with PRD v1.0 Section 8 Output Contract."""
    url_r = UrlAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=90.0,
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
        risk_score=80.0,
        detected_intent=DetectedIntentEnum.KYC_VERIFICATION
    )

    resp = compute_score(base_request, url_r, sender_r, intent_r)

    # 1. PRD Verdict Category (SAFE, SUSPICIOUS, LIKELY_SCAM)
    assert resp.verdict_category == PrdVerdictEnum.LIKELY_SCAM
    assert resp.overall_risk_score >= 66

    # 2. Aliases for audit and risk score
    assert resp.audit_id is not None
    assert resp.audit_id == resp.scan_id
    assert resp.risk_score == resp.overall_risk_score

    # 3. Plain language reasons (max 5, ordered by weight)
    assert isinstance(resp.reasons, list)
    assert 1 <= len(resp.reasons) <= 5
    assert all(isinstance(r, str) and len(r) > 0 for r in resp.reasons)

    # 4. Structured evidence list
    assert isinstance(resp.evidence, list)
    assert len(resp.evidence) >= 3
    for ev in resp.evidence:
        assert "tool" in ev
        assert "status" in ev
        assert "finding" in ev
        assert "raw_result" in ev

    # 5. Recommended action citing official helpline
    assert isinstance(resp.recommended_action, str)
    assert "1930" in resp.recommended_action or "cybercrime.gov.in" in resp.recommended_action


def test_benign_trai_otp_override(base_request):
    """Verify genuine bank OTP with official TRAI DLT header scores SAFE (<= 25)."""
    url_r = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=5.0,
        sender_category=SenderCategoryEnum.OFFICIAL_TRAI_HEADER,
        sender_analyzed="VM-HDFCBK"
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=5.0,
        detected_intent=DetectedIntentEnum.BENIGN
    )

    resp = compute_score(base_request, url_r, sender_r, intent_r)
    assert resp.overall_risk_score <= 25
    assert resp.verdict_category == PrdVerdictEnum.SAFE
    assert resp.risk_tier == RiskTierEnum.SAFE
    assert resp.action_required == ActionRequiredEnum.ALLOW


def test_benign_delivery_with_reputable_domain(base_request):
    """Verify legitimate food delivery notification with clean URL scores SAFE."""
    url_r = UrlAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=0.0,
        domain="swiggy.com",
        tld_reputation=TldReputationEnum.REPUTABLE
    )
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=5.0,
        sender_category=SenderCategoryEnum.OFFICIAL_TRAI_HEADER,
        sender_analyzed="AD-SWIGGY"
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=5.0,
        detected_intent=DetectedIntentEnum.BENIGN
    )

    resp = compute_score(base_request, url_r, sender_r, intent_r)
    assert resp.overall_risk_score <= 20
    assert resp.verdict_category == PrdVerdictEnum.SAFE
    assert resp.risk_tier == RiskTierEnum.SAFE


def test_benign_personal_conversation(base_request):
    """Verify casual friend/family message without fraud signals scores SAFE."""
    url_r = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=10.0,
        sender_category=SenderCategoryEnum.PERSONAL_GSM,
        sender_analyzed="+919811223344"
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=0.0,
        detected_intent=DetectedIntentEnum.BENIGN
    )

    resp = compute_score(base_request, url_r, sender_r, intent_r)
    assert resp.overall_risk_score <= 20
    assert resp.verdict_category == PrdVerdictEnum.SAFE
    assert resp.risk_tier == RiskTierEnum.SAFE


# ─── TASK 5.1 & 5.3 SPECIFIC VERIFICATION TESTS ─────────────────────────────


def test_dynamic_weights_with_upi_active():
    """
    Task 5.1: Verify base with UPI assigns URL 30%, Sender 25%, Intent 25%, UPI 20%.
    """
    url_r = UrlAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)
    sender_r = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)
    intent_r = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)
    upi_r = UpiAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0, detected_vpa="user@okhdfcbank")

    weights = _compute_dynamic_weights(url_r, sender_r, intent_r, upi_r)
    assert weights["url_weight"] == 0.30
    assert weights["sender_weight"] == 0.25
    assert weights["intent_weight"] == 0.25
    assert weights["upi_weight"] == 0.20
    assert round(sum(weights.values()), 4) == 1.0


def test_dynamic_weights_without_upi():
    """
    Task 5.1: Verify base without UPI assigns URL 40%, Sender 30%, Intent 30%.
    """
    url_r = UrlAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)
    sender_r = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)
    intent_r = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)

    weights = _compute_dynamic_weights(url_r, sender_r, intent_r, upi_r=None)
    assert weights["url_weight"] == 0.40
    assert weights["sender_weight"] == 0.30
    assert weights["intent_weight"] == 0.30
    assert round(sum(weights.values()), 4) == 1.0


def test_dynamic_weights_with_upi_skipped():
    """
    Task 5.1: If UPI agent is SKIPPED, weights fall back to base 3-vector (URL 40%, Sender 30%, Intent 30%).
    """
    url_r = UrlAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)
    sender_r = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)
    intent_r = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)
    upi_r = UpiAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)

    weights = _compute_dynamic_weights(url_r, sender_r, intent_r, upi_r)
    assert weights["url_weight"] == 0.40
    assert weights["sender_weight"] == 0.30
    assert weights["intent_weight"] == 0.30
    assert weights["upi_weight"] == 0.0
    assert round(weights["url_weight"] + weights["sender_weight"] + weights["intent_weight"], 4) == 1.0


def test_dynamic_weights_with_upi_and_url_skipped():
    """
    Task 5.1: If URL is SKIPPED while UPI is active, the remaining 0.70 total is normalized proportionally.
    Sender: 0.25 / 0.70 = 0.3571
    Intent: 0.25 / 0.70 = 0.3571
    UPI:    0.20 / 0.70 = 0.2857
    """
    url_r = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    sender_r = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)
    intent_r = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0)
    upi_r = UpiAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=50.0, detected_vpa="test@upi")

    weights = _compute_dynamic_weights(url_r, sender_r, intent_r, upi_r)
    assert weights["url_weight"] == 0.0
    assert weights["sender_weight"] == 0.3571
    assert weights["intent_weight"] == 0.3571
    assert weights["upi_weight"] == 0.2857
    assert round(sum(weights.values()), 2) == 1.0


def test_scoring_sla_strictly_under_10ms(base_request):
    """
    Task 5.1: Confirm the scoring engine SLA remains strictly under 10ms across 500 executions.
    """
    url_r = UrlAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=60.0, latency_ms=0.5)
    sender_r = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=70.0, latency_ms=0.5)
    intent_r = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=80.0, latency_ms=0.5)
    upi_r = UpiAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=75.0, latency_ms=0.5, detected_vpa="pay@okhdfc")

    durations = []
    for _ in range(500):
        t0 = time.perf_counter()
        resp = compute_score(base_request, url_r, sender_r, intent_r, upi_r)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        durations.append(elapsed_ms)

    max_latency = max(durations)
    median_latency = sorted(durations)[len(durations) // 2]
    assert max_latency < 10.0, f"Max latency exceeded 10ms SLA: {max_latency:.2f}ms"
    assert median_latency < 2.0, f"Median latency too high: {median_latency:.2f}ms"


def test_hindi_verdict_and_recommendation_polish(base_request):
    """
    Task 5.3: Verify verdict_hi and recommendation_hi generate grammatically sound,
    natural Hindi advisories for elderly citizens, including personal GSM warnings.
    """
    # 1. Personal GSM Caution case
    url_r = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=35.0,
        sender_category=SenderCategoryEnum.PERSONAL_GSM,
        sender_analyzed="+919876543210"
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=35.0,
        detected_intent=DetectedIntentEnum.SUSPICIOUS
    )
    resp = compute_score(base_request, url_r, sender_r, intent_r)

    # Check caution headline contains natural advisory
    assert "सतर्कता आवश्यक" in resp.verdict_hi
    assert "व्यक्तिगत नंबर" in resp.verdict_hi
    assert "1930" in resp.recommendation_hi
    assert any('\u0900' <= c <= '\u097f' for c in resp.verdict_hi)
    assert any('\u0900' <= c <= '\u097f' for c in resp.recommendation_hi)

    # 2. Critical Scam case with Bank Impersonation on Personal GSM
    sender_crit = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=85.0,
        sender_category=SenderCategoryEnum.PERSONAL_GSM,
        brand_claimed="State Bank of India",
        flags=["COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM"]
    )
    intent_crit = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=85.0,
        detected_intent=DetectedIntentEnum.KYC_VERIFICATION
    )
    resp_crit = compute_score(base_request, url_r, sender_crit, intent_crit)
    assert "सावधान" in resp_crit.verdict_hi or "धोखाधड़ी" in resp_crit.verdict_hi
    assert "व्यक्तिगत" in resp_crit.verdict_hi or "फर्जी" in resp_crit.verdict_hi
    assert "1930" in resp_crit.recommendation_hi


