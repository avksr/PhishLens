# ============================================================
# OWNER: AVIKA
# FILE: backend/core/scoring_engine.py
# PURPOSE: Risk Scoring & Verdict Engine
#   - Aggregates UrlAgentResult + SenderAgentResult + IntentAgentResult
#   - Applies dynamic weights based on active signals
#   - Runs heuristic escalation rules
#   - Returns final ScanResponse matching schema_mocks.json
# ============================================================

from typing import Dict, List, Optional
import time
from shared.models import (
    ScanRequest,
    ScanResponse,
    UrlAgentResult,
    SenderAgentResult,
    IntentAgentResult,
    UpiAgentResult,
    SynthesisBreakdown,
    AuditTrail,
    RiskTierEnum,
    ActionRequiredEnum,
    AgentStatusEnum,
    SenderCategoryEnum,
    DetectedIntentEnum,
    ConfidenceLevelEnum
)
from core.verdict_utils import (
    generate_verdict,
    generate_verdict_hi,
    generate_recommendation,
    generate_recommendation_hi,
    build_explanation_summary
)


def _compute_dynamic_weights(
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    upi_r: Optional[UpiAgentResult] = None
) -> Dict[str, float]:
    """
    Computes normalized weights across all active independent vector agents.
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

    # Optional 4th Vector: UPI Analysis
    if upi_r and upi_r.status == AgentStatusEnum.SUCCESS:
        base_weights = {
            "url": 0.30,
            "sender": 0.25,
            "intent": 0.25,
            "upi": 0.20
        }
        active["upi"] = True

    # Zero out inactive agents
    filtered_weights = {
        k: (base_weights[k] if active.get(k, False) else 0.0)
        for k in base_weights
    }

    total_weight = sum(filtered_weights.values())
    if total_weight > 0:
        normalized = {k: round(v / total_weight, 4) for k, v in filtered_weights.items()}
    else:
        normalized = {k: 0.0 for k in base_weights}

    result = {
        "url_weight": normalized.get("url", 0.0),
        "sender_weight": normalized.get("sender", 0.0),
        "intent_weight": normalized.get("intent", 0.0)
    }
    if "upi" in normalized:
        result["upi_weight"] = normalized["upi"]
    return result


def _determine_confidence(
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    heuristics: List[str],
    upi_r: Optional[UpiAgentResult] = None
) -> ConfidenceLevelEnum:
    """
    Signal Completeness / Confidence Rating.
    Calculates epistemic certainty based on active vs. skipped/errored vectors.

    Formula (mandatory 3 agents only; UPI is optional and weighted separately):
      active_count      = agents with SUCCESS status
      non_active_count  = agents with ERROR or SKIPPED status

    HIGH   → decisive heuristic fired (CRITICAL_ESCALATION / BENIGN_VERIFICATION)
             OR all 3 mandatory agents returned SUCCESS.
    MEDIUM → exactly 1 mandatory agent was SKIPPED or ERRORed.
    LOW    → 2 or more mandatory agents were SKIPPED or ERRORed.
    """
    has_decisive_escalation = any(
        "CRITICAL_ESCALATION" in h or "BENIGN_VERIFICATION" in h
        for h in heuristics
    )
    if has_decisive_escalation:
        return ConfidenceLevelEnum.HIGH

    # Count inactive (SKIPPED or ERROR) among the 3 mandatory agents only
    mandatory_agents = [url_r, sender_r, intent_r]
    non_active_count = sum(
        1 for a in mandatory_agents
        if a.status in (AgentStatusEnum.ERROR, AgentStatusEnum.SKIPPED)
    )

    if non_active_count >= 2:
        return ConfidenceLevelEnum.LOW
    elif non_active_count == 1:
        return ConfidenceLevelEnum.MEDIUM

    return ConfidenceLevelEnum.HIGH


def _build_fail_secure_response(
    req: ScanRequest,
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    upi_r: Optional[UpiAgentResult],
    latency_ms: float
) -> ScanResponse:
    """
    Fail-Secure Safety Net.
    Returns CAUTION / Score=35 / WARN_USER when all 3 mandatory agents have
    timed out or crashed — prevents a false SAFE verdict on a total pipeline failure.
    """
    synthesis = SynthesisBreakdown(
        weights_applied={"url_weight": 0.0, "sender_weight": 0.0, "intent_weight": 0.0},
        heuristics_triggered=[
            "FAIL_SECURE: All 3 mandatory agents timed out or crashed"
        ],
        summary_explanation=(
            "Pipeline entered fail-secure mode. All three independent analysis agents "
            "(URL, Sender, Intent) returned ERROR or exceeded the 3.5s timeout SLA. "
            "Score defaulted to 35 (CAUTION) to prevent a false-safe classification."
        )
    )
    audit_trail = AuditTrail(
        url_analysis=url_r,
        sender_analysis=sender_r,
        intent_analysis=intent_r,
        upi_analysis=upi_r,
        synthesis_breakdown=synthesis
    )
    return ScanResponse(
        overall_risk_score=35,
        risk_tier=RiskTierEnum.CAUTION,
        confidence=ConfidenceLevelEnum.LOW,
        verdict="Analysis Unavailable — Pipeline Error",
        verdict_hi="विश्लेषण उपलब्ध नहीं — तकनीकी त्रुटि",
        recommendation=(
            "All automated analysis agents failed to respond. Exercise extreme caution. "
            "If uncertain, do NOT proceed with any payment or link click. "
            "Dial 1930 or visit cybercrime.gov.in for assistance."
        ),
        recommendation_hi=(
            "सभी स्वचालित विश्लेषण एजेंट प्रतिक्रिया देने में विफल रहे। अत्यधिक सावधानी बरतें। "
            "किसी भी भुगतान या लिंक पर क्लिक करने से पहले 1930 डायल करें "
            "या cybercrime.gov.in पर जाएं।"
        ),
        action_required=ActionRequiredEnum.WARN_USER,
        audit_trail=audit_trail,
        processing_time_ms=latency_ms
    )


def compute_score(
    req: ScanRequest,
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    upi_r: Optional[UpiAgentResult] = None
) -> ScanResponse:
    """
    Avika's Core Risk Scoring Engine (Day 2 Enhanced):
    1. Dynamic weight redistribution (including optional UPI vector)
    2. Weighted base score synthesis
    3. Indian cybersecurity heuristic escalation overrides (6 rules)
    4. Epistemic confidence rating (HIGH, MEDIUM, LOW)
    5. Dual-language verdict & recommendation synthesis (English + Devanagari Hindi)
    6. Sub-1ms processing latency guarantee
    """
    start_time = time.perf_counter()

    # Step 1: Dynamic Weight Calculation
    weights = _compute_dynamic_weights(url_r, sender_r, intent_r, upi_r)

    # ── Fail-Secure Safety Net ────────────────────────────────────────────────
    # If ALL 3 mandatory agents failed/timed-out, every weight collapses to 0.0
    # and the weighted sum would silently produce score=0 → falsely SAFE.
    # Short-circuit here and return CAUTION/35/WARN_USER instead.
    _all_mandatory_failed = (
        url_r.status == AgentStatusEnum.ERROR
        and sender_r.status == AgentStatusEnum.ERROR
        and intent_r.status == AgentStatusEnum.ERROR
    )
    if _all_mandatory_failed:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return _build_fail_secure_response(req, url_r, sender_r, intent_r, upi_r, latency_ms)
    # ── End Fail-Secure ───────────────────────────────────────────────────────

    w_url = weights.get("url_weight", 0.0)
    w_sender = weights.get("sender_weight", 0.0)
    w_intent = weights.get("intent_weight", 0.0)
    w_upi = weights.get("upi_weight", 0.0)

    # Step 2: Base Composite Calculation
    base_score = (
        (url_r.risk_score * w_url) +
        (sender_r.risk_score * w_sender) +
        (intent_r.risk_score * w_intent)
    )
    if upi_r and w_upi > 0.0:
        base_score += (upi_r.risk_score * w_upi)

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
    is_safe_intent = (
        intent_r.detected_intent == DetectedIntentEnum.BENIGN
        or intent_r.risk_score <= 20
    )
    if is_official_trai and url_r.status == AgentStatusEnum.SKIPPED and is_safe_intent:
        final_score = min(final_score, 12.0)
        heuristics.append("BENIGN_VERIFICATION: Verified TRAI DLT transactional header with no risk signals")

    # Rule 6: Fraudulent UPI / VPA Collect Request Trap (Day 2 Enhancement)
    if upi_r and upi_r.status == AgentStatusEnum.SUCCESS and upi_r.risk_score >= 75:
        final_score = max(final_score, 90.0)
        heuristics.append("CRITICAL_ESCALATION: Fraudulent UPI collect / payment handle trap detected")

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

    # Step 5: Epistemic Confidence Rating
    confidence = _determine_confidence(url_r, sender_r, intent_r, heuristics, upi_r)

    # Step 6: Dual-Language Explanations & Actionable Advisories (English + Hindi)
    verdict = generate_verdict(risk_tier, url_r, sender_r, intent_r, heuristics, upi_r)
    verdict_hi = generate_verdict_hi(risk_tier, url_r, sender_r, intent_r, heuristics, upi_r)
    recommendation = generate_recommendation(risk_tier, action_required, url_r, sender_r, intent_r, upi_r)
    recommendation_hi = generate_recommendation_hi(risk_tier, action_required, url_r, sender_r, intent_r, upi_r)
    summary_explanation = build_explanation_summary(url_r, sender_r, intent_r, heuristics, upi_r)

    # Compute execution latency for the scoring engine itself
    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    # Sum total pipeline processing latency including upstream agent latencies
    upstream_latencies = [url_r.latency_ms, sender_r.latency_ms, intent_r.latency_ms]
    if upi_r:
        upstream_latencies.append(upi_r.latency_ms)
    total_processing_ms = round(max(upstream_latencies) + latency_ms, 2)

    synthesis = SynthesisBreakdown(
        weights_applied=weights,
        heuristics_triggered=heuristics,
        summary_explanation=summary_explanation
    )

    audit_trail = AuditTrail(
        url_analysis=url_r,
        sender_analysis=sender_r,
        intent_analysis=intent_r,
        upi_analysis=upi_r,
        synthesis_breakdown=synthesis
    )

    return ScanResponse(
        overall_risk_score=rounded_score,
        risk_tier=risk_tier,
        confidence=confidence,
        verdict=verdict,
        verdict_hi=verdict_hi,
        recommendation=recommendation,
        recommendation_hi=recommendation_hi,
        action_required=action_required,
        audit_trail=audit_trail,
        processing_time_ms=total_processing_ms
    )
