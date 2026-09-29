# ============================================================
# OWNER: AVIKA
# FILE: backend/core/scoring_engine.py
# PURPOSE: Risk Scoring & Verdict Engine
#   - Aggregates UrlAgentResult + SenderAgentResult + IntentAgentResult
#   - Applies dynamic weights based on active signals
#   - Runs heuristic escalation rules
#   - Returns final ScanResponse matching schema_mocks.json
# ============================================================

from typing import Dict, List
import time
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
    SenderCategoryEnum,
    DetectedIntentEnum
)
from core.verdict_utils import (
    generate_verdict,
    generate_recommendation,
    build_explanation_summary
)


def _compute_dynamic_weights(
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult
) -> Dict[str, float]:
    """
    Computes normalized weights across the 3 independent vector agents.
    If an agent is SKIPPED or in ERROR, its weight is proportionally
    redistributed to active agents.
    """
    base_weights = {
        "url": 0.40,
        "sender": 0.30,
        "intent": 0.30
    }

    active = {
        "url": url_r.status == AgentStatusEnum.SUCCESS,
        "sender": sender_r.status == AgentStatusEnum.SUCCESS,
        "intent": intent_r.status == AgentStatusEnum.SUCCESS
    }

    # Zero out inactive agents
    filtered_weights = {
        k: (base_weights[k] if active[k] else 0.0)
        for k in base_weights
    }

    total_weight = sum(filtered_weights.values())
    if total_weight > 0:
        normalized = {k: round(v / total_weight, 4) for k, v in filtered_weights.items()}
    else:
        normalized = {"url": 0.0, "sender": 0.0, "intent": 0.0}

    return {
        "url_weight": normalized["url"],
        "sender_weight": normalized["sender"],
        "intent_weight": normalized["intent"]
    }


def compute_score(
    req: ScanRequest,
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult
) -> ScanResponse:
    """
    Avika's Core Risk Scoring Engine:
    1. Dynamic weight redistribution
    2. Weighted base score synthesis
    3. Indian cybersecurity heuristic escalation overrides
    4. Tier determination and actionable verdict generation
    """
    start_time = time.perf_counter()

    # Step 1: Dynamic Weight Calculation
    weights = _compute_dynamic_weights(url_r, sender_r, intent_r)
    w_url = weights["url_weight"]
    w_sender = weights["sender_weight"]
    w_intent = weights["intent_weight"]

    # Step 2: Base Composite Calculation
    base_score = (
        (url_r.risk_score * w_url) +
        (sender_r.risk_score * w_sender) +
        (intent_r.risk_score * w_intent)
    )

    final_score = base_score
    heuristics: List[str] = []

    # Step 3: Heuristic Escalation Rules

    # Rule 1: Double Whammy (High Risk URL + Spoofed / High Risk Sender)
    if url_r.risk_score >= 80 and sender_r.risk_score >= 80:
        final_score = max(final_score, 92.0)
        heuristics.append("CRITICAL_ESCALATION: Phishing URL combined with unauthorized / high-risk sender")

    # Rule 2: Personal GSM Impersonating Commercial Bank or KYC Solicitation
    is_personal_gsm = sender_r.sender_category == SenderCategoryEnum.PERSONAL_GSM
    claims_bank = bool(sender_r.brand_claimed or "COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM" in sender_r.flags)
    is_kyc_or_panic = intent_r.detected_intent in [
        DetectedIntentEnum.KYC_VERIFICATION,
        DetectedIntentEnum.OTP_HARVEST,
        DetectedIntentEnum.PANIC_URGENCY
    ]
    if is_personal_gsm and claims_bank and (is_kyc_or_panic or intent_r.risk_score >= 50):
        final_score = max(final_score, 88.0)
        heuristics.append("CRITICAL_ESCALATION: Personal mobile number impersonating bank with KYC/panic urgency")

    # Rule 3: Active OTP Harvesting Solicitations
    is_otp_harvest = (
        intent_r.detected_intent == DetectedIntentEnum.OTP_HARVEST
        or any("OTP" in t.upper() for t in intent_r.manipulation_tactics)
    )
    if is_otp_harvest and (url_r.risk_score >= 50 or sender_r.risk_score >= 50):
        final_score = max(final_score, 90.0)
        heuristics.append("CRITICAL_ESCALATION: Active OTP harvesting mechanism targeted at victim")

    # Rule 4: Financial Extortion / Digital Arrest Threat
    if intent_r.detected_intent == DetectedIntentEnum.FINANCIAL_EXTORTION:
        final_score = max(final_score, 82.0)
        heuristics.append("HIGH_RISK_ESCALATION: Coercive psychological extortion detected")

    # Rule 5: Certified TRAI DLT Verified Transactional Communication (Safe Override)
    is_official_trai = sender_r.sender_category == SenderCategoryEnum.OFFICIAL_TRAI_HEADER
    if is_official_trai and url_r.status == AgentStatusEnum.SKIPPED and intent_r.risk_score <= 20:
        final_score = min(final_score, 12.0)
        heuristics.append("BENIGN_VERIFICATION: Verified TRAI DLT transactional header with no risk signals")

    # Clamp score to [0, 100] and round to integer
    rounded_score = int(round(max(0.0, min(100.0, final_score))))

    # Step 4: Tier Determination
    # SAFE: 0-24, CAUTION: 25-49, HIGH_RISK: 50-77, CRITICAL: 78-100
    if rounded_score >= 78:
        risk_tier = RiskTierEnum.CRITICAL
        action_required = ActionRequiredEnum.BLOCK_TRANSACTION
    elif rounded_score >= 50:
        risk_tier = RiskTierEnum.HIGH_RISK
        action_required = ActionRequiredEnum.BLOCK_TRANSACTION
    elif rounded_score >= 25:
        risk_tier = RiskTierEnum.CAUTION
        action_required = ActionRequiredEnum.WARN_USER
    else:
        risk_tier = RiskTierEnum.SAFE
        action_required = ActionRequiredEnum.ALLOW

    # Step 5: Explanations & Actionable Advisories
    verdict = generate_verdict(risk_tier, url_r, sender_r, intent_r, heuristics)
    recommendation = generate_recommendation(risk_tier, action_required, url_r, sender_r, intent_r)
    summary_explanation = build_explanation_summary(url_r, sender_r, intent_r, heuristics)

    # Compute execution latency for the scoring engine itself
    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    # Sum total pipeline processing latency including upstream agent latencies
    total_processing_ms = round(
        max(url_r.latency_ms, sender_r.latency_ms, intent_r.latency_ms) + latency_ms,
        2
    )

    synthesis = SynthesisBreakdown(
        weights_applied=weights,
        heuristics_triggered=heuristics,
        summary_explanation=summary_explanation
    )

    audit_trail = AuditTrail(
        url_analysis=url_r,
        sender_analysis=sender_r,
        intent_analysis=intent_r,
        synthesis_breakdown=synthesis
    )

    return ScanResponse(
        overall_risk_score=rounded_score,
        risk_tier=risk_tier,
        verdict=verdict,
        recommendation=recommendation,
        action_required=action_required,
        audit_trail=audit_trail,
        processing_time_ms=total_processing_ms
    )
