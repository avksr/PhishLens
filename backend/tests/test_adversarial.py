"""
PhishLens - Adversarial Edge Case & Evasion Resistance Tests (Task 2)
Tests adversarial evasion tactics:
- Zero-width space obfuscation (\\u200b, \\u200c)
- Cyrillic homoglyph character spoofing
- Mixed Hindi-English (Hinglish) utility disconnection extortion
- Negative control: Benign messages stay SAFE (0 false positives)
"""

import pytest
from shared.models import (
    ScanRequest,
    UrlAgentResult,
    SenderAgentResult,
    IntentAgentResult,
    AgentStatusEnum,
    SenderCategoryEnum,
    DetectedIntentEnum,
    PrdVerdictEnum,
    RiskTierEnum
)
from core.scoring_engine import compute_score, _detect_adversarial_evasion


def test_zero_width_space_detection():
    """Verify that hidden zero-width characters in content are detected."""
    obfuscated_content = "URGENT:\u200b SBI\u200b KYC suspended. Update now."
    flags = _detect_adversarial_evasion(obfuscated_content)
    assert "ADVERSARIAL_ZERO_WIDTH_DETECTED" in flags


def test_zero_width_space_scoring_escalation():
    """Adversarial zero-width space from unverified sender must trigger CRITICAL escalation."""
    req = ScanRequest(
        content="URGENT:\u200b SBI\u200b KYC will expire tonight. Contact officer.",
        sender="+919876543210"
    )
    url_r = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=50.0,
        sender_category=SenderCategoryEnum.PERSONAL_GSM
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=40.0,
        detected_intent=DetectedIntentEnum.PANIC_URGENCY
    )

    resp = compute_score(req, url_r, sender_r, intent_r)
    assert resp.overall_risk_score >= 80
    assert resp.verdict_category == PrdVerdictEnum.LIKELY_SCAM
    assert any("ADVERSARIAL" in h.upper() for h in resp.audit_trail.synthesis_breakdown.heuristics_triggered)


def test_cyrillic_homoglyph_detection_and_escalation():
    """Mixed Latin and Cyrillic homoglyphs (e.g. Cyrillic 'а', 'о') must be flagged."""
    # Using Cyrillic 'а' (\u0430) and 'о' (\u043e) in word 'bаnk'
    homoglyph_content = "URGENT: Your b\u0430nk \u0430ccount is blocked. Call +919876543210"
    flags = _detect_adversarial_evasion(homoglyph_content)
    assert "ADVERSARIAL_HOMOGLYPH_DETECTED" in flags

    req = ScanRequest(content=homoglyph_content, sender="+919876543210")
    url_r = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=45.0,
        sender_category=SenderCategoryEnum.PERSONAL_GSM
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=35.0,
        detected_intent=DetectedIntentEnum.SUSPICIOUS
    )

    resp = compute_score(req, url_r, sender_r, intent_r)
    assert resp.overall_risk_score >= 80
    assert resp.verdict_category == PrdVerdictEnum.LIKELY_SCAM


def test_hinglish_electricity_disconnection_extortion():
    """Hinglish utility cutoff extortion on personal GSM must escalate to LIKELY_SCAM."""
    req = ScanRequest(
        content="Dear consumer bijli cut ho jayegi tonight at 9.30pm. Please contact electricity officer 8250912345.",
        sender="+918250912345"
    )
    url_r = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=50.0,
        sender_category=SenderCategoryEnum.PERSONAL_GSM
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=45.0,
        detected_intent=DetectedIntentEnum.PANIC_URGENCY
    )

    resp = compute_score(req, url_r, sender_r, intent_r)
    assert resp.overall_risk_score >= 80
    assert resp.verdict_category == PrdVerdictEnum.LIKELY_SCAM
    assert any("utility disconnection" in h.lower() for h in resp.audit_trail.synthesis_breakdown.heuristics_triggered)


def test_official_discom_receipt_remains_safe():
    """Legitimate DISCOM electricity receipts from official TRAI header must remain SAFE."""
    req = ScanRequest(
        content="Dear Consumer, payment of Rs 1,450 for BESCOM electricity bill received with thanks. Receipt #98234.",
        sender="VK-BESCOM"
    )
    url_r = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=5.0,
        sender_category=SenderCategoryEnum.OFFICIAL_TRAI_HEADER
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=5.0,
        detected_intent=DetectedIntentEnum.BENIGN
    )

    resp = compute_score(req, url_r, sender_r, intent_r)
    assert resp.overall_risk_score <= 15
    assert resp.verdict_category == PrdVerdictEnum.SAFE
    assert resp.risk_tier == RiskTierEnum.SAFE


def test_benign_conversational_hinglish_remains_safe():
    """Casual conversational Hindi/English without threats must remain SAFE."""
    req = ScanRequest(
        content="Bhai meeting kab start hogi? Please let me know once you reach office.",
        sender="+919876543210"
    )
    url_r = UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0)
    sender_r = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=5.0,
        sender_category=SenderCategoryEnum.PERSONAL_GSM
    )
    intent_r = IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=5.0,
        detected_intent=DetectedIntentEnum.BENIGN
    )

    resp = compute_score(req, url_r, sender_r, intent_r)
    assert resp.overall_risk_score <= 15
    assert resp.verdict_category == PrdVerdictEnum.SAFE
