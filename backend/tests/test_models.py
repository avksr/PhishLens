from shared.models import (
    ScanRequest,
    ScanResponse,
    UrlAgentResult,
    SenderAgentResult,
    IntentAgentResult,
    SynthesisBreakdown,
    AuditTrail,
    RiskTierEnum,
    ActionRequiredEnum,
    AgentStatusEnum,
    TldReputationEnum,
    SenderCategoryEnum,
    DetectedIntentEnum
)


def test_scan_request_validation():
    req = ScanRequest(
        content="URGENT: SBI Account blocked. Click https://sbi-kyc.top",
        sender="+919876543210"
    )
    assert req.content.startswith("URGENT")
    assert req.sender == "+919876543210"
    assert req.channel == "sms"


def test_scan_response_serialization():
    url_res = UrlAgentResult(
        status=AgentStatusEnum.SUCCESS,
        url_analyzed="https://sbi-kyc.top",
        risk_score=95.0,
        domain_age_days=2,
        is_typosquatting=True,
        target_brand="SBI",
        tld_reputation=TldReputationEnum.HIGH_RISK,
        flags=["TYPOSQUATTING_DETECTED", "RECENT_DOMAIN"]
    )
    sender_res = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        sender_analyzed="+919876543210",
        risk_score=85.0,
        is_spoofed_header=False,
        sender_category=SenderCategoryEnum.PERSONAL_GSM,
        brand_claimed="SBI",
        flags=["COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM"]
    )
    intent_res = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=90.0,
        detected_intent=DetectedIntentEnum.KYC_VERIFICATION,
        manipulation_tactics=["False Urgency", "Fear Appeal"],
        confidence=0.95,
        flags=["PSYCHOLOGICAL_URGENCY_TRIGGER"]
    )
    audit = AuditTrail(
        url_analysis=url_res,
        sender_analysis=sender_res,
        intent_analysis=intent_res,
        synthesis_breakdown=SynthesisBreakdown(
            heuristics_triggered=["Double Whammy GSM + Fake URL"]
        )
    )
    resp = ScanResponse(
        overall_risk_score=92,
        risk_tier=RiskTierEnum.CRITICAL,
        verdict="Confirmed SBI Impersonation",
        recommendation="Do not share OTP or click links",
        action_required=ActionRequiredEnum.BLOCK_TRANSACTION,
        audit_trail=audit,
        processing_time_ms=450.5
    )
    assert resp.overall_risk_score == 92
    assert resp.risk_tier == RiskTierEnum.CRITICAL
    assert resp.action_required == ActionRequiredEnum.BLOCK_TRANSACTION
    assert resp.audit_trail.url_analysis.risk_score == 95.0
    # Backward compatibility / Auto-derived PRD Output Contract fields
    assert resp.risk_score == 92
    assert resp.verdict_category.value == "LIKELY_SCAM"
    assert resp.recommended_action == "Do not share OTP or click links"
    assert resp.audit_id is not None
    assert isinstance(resp.reasons, list)
    assert isinstance(resp.evidence, list)


def test_prd_output_contract_explicit():
    """Verify that ScanResponse accepts and validates explicit PRD Section 8 contract fields."""
    from shared.models import PrdVerdictEnum, EvidenceItem
    evidence = [
        EvidenceItem(
            tool="url_agent",
            status="SUCCESS",
            finding="Domain sbi-kyc.top typosquats official brand State Bank of India",
            raw_result={"risk_score": 95.0}
        )
    ]
    resp = ScanResponse(
        verdict_category=PrdVerdictEnum.LIKELY_SCAM,
        reasons=["High-risk suspicious domain mimicking SBI."],
        evidence=evidence,
        risk_score=94,
        recommended_action="Do not open any link and report to 1930.",
        audit_id="audit_abc_123"
    )
    assert resp.verdict_category == PrdVerdictEnum.LIKELY_SCAM
    assert resp.risk_score == 94
    assert resp.overall_risk_score == 94
    assert resp.reasons[0].startswith("High-risk")
    assert resp.evidence[0].tool == "url_agent"
    assert resp.audit_id == "audit_abc_123"
    assert resp.recommended_action == "Do not open any link and report to 1930."

