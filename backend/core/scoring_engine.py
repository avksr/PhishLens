# ============================================================
# OWNER: AVIKA
# FILE: backend/core/scoring_engine.py
# PURPOSE: Risk Scoring & Verdict Engine
#   - Aggregates UrlAgentResult + SenderAgentResult + IntentAgentResult
#   - Applies dynamic weights based on active signals
#   - Runs heuristic escalation rules
#   - Returns final ScanResponse matching schema_mocks.json
# ============================================================

from typing import Dict, List, Optional, Tuple, Set
import time
import re
from datetime import datetime, timezone
from shared.models import (
    ScanRequest,
    ScanResponse,
    UrlAgentResult,
    SenderAgentResult,
    IntentAgentResult,
    UpiAgentResult,
    BankVerificationResult,
    OsintHistoryResult,
    AiTextAgentResult,
    VisionAnalysisResult,
    DocumentFraudResult,
    ModalityEnum,
    SynthesisBreakdown,
    AuditTrail,
    PrdVerdictEnum,
    RiskTierEnum,
    ActionRequiredEnum,
    AgentStatusEnum,
    SenderCategoryEnum,
    ConfidenceLevelEnum,
    ClaimedVsVerifiedMatrix,
    IdentityVerificationItem,
    AgentLatencyBreakdown,
    DetectedIntentEnum,
    TldReputationEnum,
)
from core.verdict_utils import (
    generate_verdict,
    generate_verdict_hi,
    generate_recommendation,
    generate_recommendation_hi,
    build_explanation_summary,
    extract_plain_language_reasons,
    build_evidence_list,
    generate_recommended_action
)


# ── Adversarial Evasion Constants & Helpers (Task 2) ─────────────────────────
_ZERO_WIDTH_CHARS = {'\u200b', '\u200c', '\u200d', '\ufeff', '\u2060', '\u00ad'}
_CYRILLIC_HOMOGLYPH_RE = re.compile(r'[\u0400-\u04FF]')

def _detect_adversarial_evasion(content: str) -> List[str]:
    """Detect deceptive zero-width obfuscation and Cyrillic homoglyphs."""
    flags = []
    if any(c in content for c in _ZERO_WIDTH_CHARS):
        flags.append("ADVERSARIAL_ZERO_WIDTH_DETECTED")
    if _CYRILLIC_HOMOGLYPH_RE.search(content) and any('a' <= c.lower() <= 'z' for c in content):
        flags.append("ADVERSARIAL_HOMOGLYPH_DETECTED")
    return flags


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
    if "upi" in normalized or upi_r is not None:
        result["upi_weight"] = normalized.get("upi", 0.0)
    return result


def _compute_noisy_or_base_score(
    weights: Dict[str, float],
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    upi_r: Optional[UpiAgentResult] = None,
) -> float:
    """
    Computes probabilistic Noisy-OR baseline aggregation across active vectors:
      BaseScore = 100.0 * (1.0 - Π (1.0 - weight_i * (score_i / 100.0) * confidence_i))

    Formula: 1 - Π(1 - weight × score × confidence)
    """
    w_url = weights.get("url_weight", 0.0)
    w_sender = weights.get("sender_weight", 0.0)
    w_intent = weights.get("intent_weight", 0.0)
    w_upi = weights.get("upi_weight", 0.0)

    # Confidences (in [0.0, 1.0])
    c_url = 1.0 if url_r.status == AgentStatusEnum.SUCCESS else 0.0
    c_sender = 1.0 if sender_r.status == AgentStatusEnum.SUCCESS else 0.0
    c_intent = (intent_r.confidence if intent_r.confidence > 0.0 else 1.0) if intent_r.status == AgentStatusEnum.SUCCESS else 0.0
    c_upi = 1.0 if (upi_r and upi_r.status == AgentStatusEnum.SUCCESS) else 0.0

    # Scaled scores (in [0.0, 1.0])
    s_url = max(0.0, min(100.0, url_r.risk_score)) / 100.0
    s_sender = max(0.0, min(100.0, sender_r.risk_score)) / 100.0
    s_intent = max(0.0, min(100.0, intent_r.risk_score)) / 100.0
    s_upi = (max(0.0, min(100.0, upi_r.risk_score)) / 100.0) if upi_r else 0.0

    terms = [
        w_url * s_url * c_url,
        w_sender * s_sender * c_sender,
        w_intent * s_intent * c_intent,
    ]
    if upi_r and w_upi > 0.0:
        terms.append(w_upi * s_upi * c_upi)

    prod = 1.0
    for term in terms:
        clamped_term = max(0.0, min(1.0, term))
        prod *= (1.0 - clamped_term)

    noisy_or_prob = 1.0 - prod
    return max(0.0, min(100.0, round(noisy_or_prob * 100.0, 2)))


def _check_threat_feed_hit(url_r: UrlAgentResult) -> Tuple[bool, bool]:
    """
    Distinguishes authoritative threat feed hits (floor 85) from single reputation flags (weight only).
    Returns: (is_confirmed_feed_hit, is_single_reputation_flag)
    - Confirmed feed hit (OpenPhish, URLhaus, PhishTank): applies floor 85.
    - Single SafeBrowsing / VirusTotal / AlienVault OTX flag: enters via weight only.
    """
    if url_r.status != AgentStatusEnum.SUCCESS:
        return False, False

    flags_upper = [f.upper() for f in url_r.flags]
    details_upper = url_r.details.upper() if url_r.details else ""

    confirmed_keywords = [
        "OPENPHISH", "URLHAUS", "PHISHTANK", "CONFIRMED_FEED_HIT", "THREAT_FEED_HIT", "FEED_HIT"
    ]
    is_confirmed = (
        any(any(k in f for k in confirmed_keywords) for f in flags_upper)
        or any(k in details_upper for k in ["OPENPHISH", "URLHAUS", "PHISHTANK"])
    )

    reputation_keywords = [
        "SAFEBROWSING", "SAFE_BROWSING", "VIRUSTOTAL", "VT_FLAG", "OTX_FLAG", "OTX"
    ]
    is_reputation = (
        any(any(k in f for k in reputation_keywords) for f in flags_upper)
        or any(k in details_upper for k in ["SAFE BROWSING", "VIRUSTOTAL", "OTX"])
    )

    return is_confirmed, is_reputation


def _determine_confidence(
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    heuristics: List[str],
    upi_r: Optional[UpiAgentResult] = None,
    osint_history: Optional[OsintHistoryResult] = None,
) -> ConfidenceLevelEnum:
    """
    Signal Completeness / Confidence Rating.
    Calculates epistemic certainty based on active vs. skipped/errored vectors.
    Note: OSINT SKIPPED lowers confidence rating, not risk score.

    HIGH   → decisive heuristic fired (CRITICAL_ESCALATION / BENIGN_VERIFICATION)
             OR all active mandatory agents returned SUCCESS.
    MEDIUM → exactly 1 agent was SKIPPED or ERRORed (including OSINT skipped).
    LOW    → 2 or more agents were SKIPPED or ERRORed.
    """
    has_decisive_escalation = any(
        "CRITICAL_ESCALATION" in h or "BENIGN_VERIFICATION" in h
        for h in heuristics
    )
    if has_decisive_escalation:
        return ConfidenceLevelEnum.HIGH

    # Count inactive (SKIPPED or ERROR) among the 3 mandatory agents
    mandatory_agents = [url_r, sender_r, intent_r]
    non_active_count = sum(
        1 for a in mandatory_agents
        if a.status in (AgentStatusEnum.ERROR, AgentStatusEnum.SKIPPED)
    )

    # OSINT SKIPPED lowers epistemic confidence without penalizing risk score
    if osint_history and osint_history.status in (AgentStatusEnum.SKIPPED, AgentStatusEnum.ERROR):
        non_active_count += 1

    if non_active_count >= 2:
        return ConfidenceLevelEnum.LOW
    elif non_active_count == 1:
        return ConfidenceLevelEnum.MEDIUM

    return ConfidenceLevelEnum.HIGH


def _build_claimed_vs_verified_matrix(
    req: ScanRequest,
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    upi_r: Optional[UpiAgentResult] = None,
    bank_verification: Optional[BankVerificationResult] = None,
) -> ClaimedVsVerifiedMatrix:
    """
    Point 8 & Point 7: Claimed vs. Verified Identity Matrix with Cross-Agent Contradiction Detection.
    Pillars: Organization, Sender, Website, Payment.
    """
    # 1. Organization Pillar
    claimed_org = sender_r.brand_claimed or url_r.target_brand or "Unknown Entity"
    if claimed_org == "Unknown Entity":
        content_lower = req.content.lower()
        if "sbi" in content_lower:
            claimed_org = "State Bank of India (SBI)"
        elif "hdfc" in content_lower:
            claimed_org = "HDFC Bank"
        elif "icici" in content_lower:
            claimed_org = "ICICI Bank"
        elif any(k in content_lower for k in ["bescom", "electricity", "bijli"]):
            claimed_org = "Electricity Board (DISCOM)"
        elif "olx" in content_lower:
            claimed_org = "OLX India"
        elif "paytm" in content_lower:
            claimed_org = "Paytm"

    if sender_r.sender_category == SenderCategoryEnum.OFFICIAL_TRAI_HEADER:
        org_verified = f"Verified Official TRAI Header ({sender_r.sender_analyzed or 'DLT'})"
        org_match = True
        org_status = "VERIFIED"
    elif claimed_org != "Unknown Entity" and sender_r.sender_category == SenderCategoryEnum.PERSONAL_GSM:
        org_verified = "Not verified — Dispatched from unverified personal mobile"
        org_match = False
        org_status = "MISMATCH"
    else:
        org_verified = "Not verified against official institutional registry"
        org_match = False
        org_status = "UNVERIFIED"

    org_item = IdentityVerificationItem(
        claimed=claimed_org,
        verified=org_verified,
        is_match=org_match,
        status_label=org_status
    )

    # 2. Sender Pillar
    claimed_sender = claimed_org if claimed_org != "Unknown Entity" else "Institutional Service Desk"
    if sender_r.is_spoofed_header:
        sender_verified = f"Spoofed / Lookalike Header ({sender_r.sender_analyzed})"
        sender_match = False
        sender_status = "SPOOFED"
    elif sender_r.sender_category == SenderCategoryEnum.PERSONAL_GSM:
        sender_verified = f"Private Personal GSM ({sender_r.raw_sender or sender_r.sender_analyzed or 'Mobile'})"
        sender_match = False
        sender_status = "MISMATCH" if claimed_org != "Unknown Entity" else "UNVERIFIED"
    elif sender_r.sender_category == SenderCategoryEnum.OFFICIAL_TRAI_HEADER:
        sender_verified = f"Verified TRAI DLT Header ({sender_r.sender_analyzed})"
        sender_match = True
        sender_status = "VERIFIED"
    else:
        sender_verified = sender_r.sender_analyzed or "Unregistered Sender"
        sender_match = False
        sender_status = "UNVERIFIED"

    sender_item = IdentityVerificationItem(
        claimed=claimed_sender,
        verified=sender_verified,
        is_match=sender_match,
        status_label=sender_status
    )

    # 3. Website Pillar
    if url_r.status == AgentStatusEnum.SUCCESS and (url_r.url_analyzed or url_r.domain):
        claimed_web = f"Official {claimed_org} Portal" if claimed_org != "Unknown Entity" else "Secure Official Portal"
        if url_r.is_typosquatting or url_r.risk_score >= 60:
            web_verified = f"Domain Mismatch / Typosquatting ({url_r.domain or url_r.url_analyzed})"
            web_match = False
            web_status = "MISMATCH"
        elif url_r.risk_score >= 35:
            web_verified = f"Suspicious / Untrusted TLD ({url_r.domain or url_r.url_analyzed})"
            web_match = False
            web_status = "SUSPICIOUS"
        else:
            web_verified = f"Legitimate Domain ({url_r.domain})"
            web_match = True
            web_status = "VERIFIED"
    else:
        claimed_web = "None"
        web_verified = "No web link present"
        web_match = True
        web_status = "NOT_APPLICABLE"

    website_item = IdentityVerificationItem(
        claimed=claimed_web,
        verified=web_verified,
        is_match=web_match,
        status_label=web_status
    )

    # 4. Payment Pillar
    vpa = (bank_verification.vpa if bank_verification and bank_verification.vpa 
           else (upi_r.detected_vpa if upi_r and upi_r.detected_vpa else None))
    if vpa:
        claimed_pay = f"Official {claimed_org} Payment Desk" if claimed_org != "Unknown Entity" else "Official Merchant VPA"
        if bank_verification and bank_verification.is_name_mismatch:
            reg_name = bank_verification.registered_bank_name or "Private Individual"
            pay_verified = f"Individual Account: {reg_name} (Mismatch with claimed institution)"
            pay_match = False
            pay_status = "MISMATCH"
        elif upi_r and upi_r.is_spoofed_merchant:
            pay_verified = f"Spoofed Handle ({vpa})"
            pay_match = False
            pay_status = "SPOOFED"
        elif upi_r and upi_r.risk_score >= 50:
            pay_verified = f"Suspicious VPA ({vpa})"
            pay_match = False
            pay_status = "SUSPICIOUS"
        else:
            pay_verified = f"Verified VPA ({vpa})"
            pay_match = True
            pay_status = "VERIFIED"
    else:
        claimed_pay = "None"
        pay_verified = "No UPI handle detected"
        pay_match = True
        pay_status = "NOT_APPLICABLE"

    payment_item = IdentityVerificationItem(
        claimed=claimed_pay,
        verified=pay_verified,
        is_match=pay_match,
        status_label=pay_status
    )

    # Cross-Agent Contradiction Detection (Point 7)
    contradictions = []
    if claimed_org != "Unknown Entity":
        if sender_item.status_label in ("MISMATCH", "SPOOFED"):
            contradictions.append(f"Sender is unverified/personal mobile instead of official {claimed_org}")
        if website_item.status_label in ("MISMATCH", "SPOOFED"):
            contradictions.append(f"Website domain does not belong to {claimed_org}")
        if payment_item.status_label in ("MISMATCH", "SPOOFED"):
            contradictions.append(f"Payment handle is registered to an individual instead of {claimed_org}")

    has_contradiction = len(contradictions) >= 2 or (
        len(contradictions) >= 1 and (
            website_item.status_label in ("MISMATCH", "SPOOFED") or
            payment_item.status_label in ("MISMATCH", "SPOOFED")
        )
    )
    details = "; ".join(contradictions) if contradictions else None

    return ClaimedVsVerifiedMatrix(
        organization=org_item,
        sender=sender_item,
        website=website_item,
        payment=payment_item,
        has_identity_contradiction=has_contradiction,
        contradiction_details=details
    )


def _generate_why_blocked_evidence(
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    upi_r: Optional[UpiAgentResult] = None,
    bank_verification: Optional[BankVerificationResult] = None,
    osint_history: Optional[OsintHistoryResult] = None,
    matrix: Optional[ClaimedVsVerifiedMatrix] = None,
) -> List[str]:
    """Point 9: Evidence-based Explanation Panel."""
    evidence = []
    if sender_r.is_spoofed_header:
        evidence.append("[!] Sender header mimics an authentic institutional sender but lacks DLT authentication")
    elif sender_r.sender_category == SenderCategoryEnum.PERSONAL_GSM and (sender_r.brand_claimed or sender_r.risk_score >= 35):
        evidence.append("[!] Sender identity could not be verified (Personal mobile number used for official alert)")

    if url_r.status == AgentStatusEnum.SUCCESS:
        if url_r.is_typosquatting:
            evidence.append(f"[!] URL domain ({url_r.domain}) is a typosquatted lookalike of {url_r.target_brand or 'trusted brand'}")
        elif url_r.risk_score >= 60:
            evidence.append(f"[!] URL domain ({url_r.domain}) does not match claimed organization")
        elif url_r.risk_score >= 35:
            evidence.append(f"[!] URL uses a suspicious or untrusted top-level domain ({url_r.tld})")

    if intent_r.status == AgentStatusEnum.SUCCESS and intent_r.risk_score >= 30:
        if intent_r.detected_intent in (DetectedIntentEnum.OTP_HARVEST,):
            evidence.append("[!] Active OTP harvesting solicitation detected")
        elif intent_r.detected_intent in (DetectedIntentEnum.KYC_VERIFICATION,):
            evidence.append("[!] Urgency language detected: Threat of imminent account suspension or KYC expiry")
        elif intent_r.detected_intent in (DetectedIntentEnum.PANIC_URGENCY,):
            evidence.append("[!] Psychological urgency / panic manipulation detected")
        elif intent_r.detected_intent in (DetectedIntentEnum.FINANCIAL_EXTORTION,):
            evidence.append("[!] Coercive financial extortion / digital arrest intimidation detected")

    if bank_verification and bank_verification.is_name_mismatch:
        evidence.append(f"[!] Payment identity is suspicious: VPA registered to '{bank_verification.registered_bank_name}' instead of claimed entity")
    elif upi_r and upi_r.risk_score >= 50:
        evidence.append(f"[!] Payment identity is suspicious: High-risk or deceptive VPA handle ({upi_r.detected_vpa})")

    if osint_history and osint_history.total_complaints > 0:
        evidence.append(f"[!] Crowdsourced intelligence: Flagged {osint_history.total_complaints} times in fraud complaints ({osint_history.proof_snippet or 'Community reported'})")

    if matrix and matrix.has_identity_contradiction:
        evidence.append("[!] Cross-agent contradiction: Claimed institutional identity is inconsistent across sender, link, and payment handles")

    if not evidence:
        evidence.append("[✓] No critical threat indicators detected across inspection vectors")

    return evidence


def _generate_actionable_guidance(risk_tier: RiskTierEnum) -> List[str]:
    """Point 18: Actionable Guidance Checklist for Hard Block."""
    if risk_tier in (RiskTierEnum.CRITICAL, RiskTierEnum.HIGH_RISK):
        return [
            "1. Do not enter your UPI PIN, OTP, password, or banking credentials under any circumstances.",
            "2. Do not click, forward, or open any suspicious web links attached to this message.",
            "3. Verify through the organization's official, published customer care number or physical branch.",
            "4. Report this incident immediately to the National Cyber Crime Helpline at 1930 or cybercrime.gov.in."
        ]
    elif risk_tier == RiskTierEnum.CAUTION:
        return [
            "1. Exercise caution — avoid clicking unknown links from personal mobile senders.",
            "2. Verify the sender's identity before making any payment or sharing personal details.",
            "3. If prompted for a UPI PIN to 'receive' money, abort immediately (UPI PIN is ONLY for paying).",
            "4. Call the 1930 cybercrime helpline if you suspect an ongoing fraud attempt."
        ]
    else:
        return [
            "1. Communication exhibits standard transactional patterns.",
            "2. Always verify that payment amounts and recipient names match your intent.",
            "3. Remember that legitimate banks and government bodies NEVER request your UPI PIN or OTP.",
            "4. Keep your banking apps updated and report any unexpected debits immediately."
        ]


def _calculate_confidence_percentage(
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    heuristics: List[str],
    bank_verification: Optional[BankVerificationResult] = None,
    osint_history: Optional[OsintHistoryResult] = None,
    matrix: Optional[ClaimedVsVerifiedMatrix] = None,
) -> float:
    """
    Point 10: Decouple Risk Score (0-100) from Epistemic Confidence (0-100%).
    Risk answers: 'How dangerous does the evidence appear?'
    Confidence answers: 'How strongly does the available evidence support our assessment?'
    """
    confidence = 80.0

    if any("CRITICAL_ESCALATION" in h or "BENIGN_VERIFICATION" in h for h in heuristics):
        confidence += 12.0

    if bank_verification and bank_verification.is_name_mismatch:
        confidence += 5.0

    if osint_history and osint_history.total_complaints > 0:
        confidence += 5.0

    if matrix and matrix.has_identity_contradiction:
        confidence += 4.0

    if url_r.status in (AgentStatusEnum.SKIPPED, AgentStatusEnum.ERROR):
        confidence -= 5.0
    if sender_r.status in (AgentStatusEnum.SKIPPED, AgentStatusEnum.ERROR):
        confidence -= 5.0
    if intent_r.status in (AgentStatusEnum.SKIPPED, AgentStatusEnum.ERROR):
        confidence -= 10.0

    # OSINT SKIPPED lowers confidence rating, not risk score
    if osint_history and osint_history.status in (AgentStatusEnum.SKIPPED, AgentStatusEnum.ERROR):
        confidence -= 5.0

    return round(max(50.0, min(99.0, confidence)), 1)


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
    reasons = [
        "Pipeline entered fail-secure mode due to upstream agent timeout/error",
        "All automated analysis agents (URL, Sender, Intent) failed to respond within 3.5s SLA",
        "Risk score defaulted to 35 (CAUTION) to prevent false-safe classification"
    ]
    evidence = build_evidence_list(url_r, sender_r, intent_r, upi_r)
    action_advisory = (
        "VERIFY & CAUTION: All automated analysis agents failed to respond. "
        "Exercise extreme caution. Do not proceed with any payment or link click. "
        "Dial 1930 or visit cybercrime.gov.in for assistance."
    )
    return ScanResponse(
        overall_risk_score=35,
        risk_score=35,
        verdict_category=PrdVerdictEnum.SUSPICIOUS,
        risk_tier=RiskTierEnum.CAUTION,
        confidence=ConfidenceLevelEnum.LOW,
        reasons=reasons,
        evidence=evidence,
        recommended_action=action_advisory,
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
        processing_time_ms=latency_ms,
        confidence_percentage=50.0,
        claimed_vs_verified=None,
        why_blocked_evidence=["[!] All automated analysis agents failed to respond within 3.5s SLA"],
        actionable_guidance=_generate_actionable_guidance(RiskTierEnum.CAUTION),
        latency_breakdown=AgentLatencyBreakdown(total_ms=latency_ms),
    )


def compute_score(
    req: ScanRequest,
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    upi_r: Optional[UpiAgentResult] = None,
    bank_verification: Optional[BankVerificationResult] = None,
    osint_history: Optional[OsintHistoryResult] = None,
    ai_text: Optional[AiTextAgentResult] = None,
    vision_r: Optional[VisionAnalysisResult] = None,
    doc_r: Optional[DocumentFraudResult] = None,
    modality: ModalityEnum = ModalityEnum.TEXT,
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

    # Step 2: Base Composite Calculation via Probabilistic Noisy-OR
    # Formula: 1 - Π (1 - weight × score × confidence)
    base_score = _compute_noisy_or_base_score(weights, url_r, sender_r, intent_r, upi_r)

    final_score = base_score
    heuristics: List[str] = []
    sanitized_content = "".join(c for c in req.content if c not in _ZERO_WIDTH_CHARS)

    # Pre-build identity matrix for cross-agent inconsistency detection
    matrix = _build_claimed_vs_verified_matrix(
        req, url_r, sender_r, intent_r, upi_r, bank_verification
    )

    # Check threat intelligence feeds (Confirmed OpenPhish/URLhaus hit vs single reputation flag)
    is_feed_hit, is_rep_flag = _check_threat_feed_hit(url_r)

    # Step 3: Heuristic Escalation Rules & Abuse-Proof Threat Floors

    # Rule 0: Adversarial Evasion Tactics (Zero-width obfuscation, Cyrillic homoglyphs)
    adversarial_flags = _detect_adversarial_evasion(req.content)
    if adversarial_flags and sender_r.sender_category != SenderCategoryEnum.OFFICIAL_TRAI_HEADER:
        final_score = max(final_score, 80.0)
        heuristics.append(f"CRITICAL_ESCALATION: Adversarial evasion tactic detected ({', '.join(adversarial_flags)})")

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

    # Rule 2b: Unauthorized Utility / Electricity Disconnection Threat from Personal GSM
    is_discom_threat = bool(re.search(
        r'\b(?:electricity|bijli|power)\s+(?:cut|bill|disconnected|cutoff|band)\b|'
        r'\b(?:disconnected|cut)\s+(?:tonight|today|immediately)\b|'
        r'\b(?:bijli|power)\s+officer\b',
        sanitized_content,
        re.IGNORECASE
    ))
    if is_discom_threat and sender_r.sender_category == SenderCategoryEnum.PERSONAL_GSM:
        final_score = max(final_score, 82.0)
        heuristics.append("CRITICAL_ESCALATION: Unauthorized utility disconnection threat sent from private mobile number")

    # Rule 3: Active OTP Harvesting Solicitations
    is_otp_harvest = (
        intent_r.detected_intent == DetectedIntentEnum.OTP_HARVEST
        or any("OTP" in t.upper() for t in intent_r.manipulation_tactics)
    )
    if is_otp_harvest and (url_r.risk_score >= 50 or sender_r.risk_score >= 50):
        final_score = max(final_score, 90.0)
        heuristics.append("CRITICAL_ESCALATION: Active OTP harvesting mechanism targeted at victim")

    # Rule 3b: Phishing Link Distributed via Personal GSM Number
    if sender_r.sender_category == SenderCategoryEnum.PERSONAL_GSM and url_r.status == AgentStatusEnum.SUCCESS and url_r.risk_score >= 35:
        final_score = max(final_score, 50.0)
        heuristics.append("CAUTION_ESCALATION: High-risk or suspicious web link distributed via personal mobile number")
    elif (
        url_r.status == AgentStatusEnum.SUCCESS
        and url_r.risk_score >= 35
        and (
            url_r.tld_reputation == TldReputationEnum.HIGH_RISK
            or any("TLD" in f.upper() for f in url_r.flags)
        )
    ):
        final_score = max(final_score, 38.0)
        heuristics.append("CAUTION_ESCALATION: Untrusted top-level domain commonly used for phishing")

    # Rule 4: Financial Extortion / Digital Arrest Threat
    if intent_r.detected_intent == DetectedIntentEnum.FINANCIAL_EXTORTION and sender_r.sender_category != SenderCategoryEnum.OFFICIAL_TRAI_HEADER:
        final_score = max(final_score, 82.0)
        heuristics.append("HIGH_RISK_ESCALATION: Coercive psychological extortion detected from unverified sender")

    # Rule 4b: Part-Time Job / Advance Fee / Lottery Scam Solicitation
    is_lottery_or_job = (
        intent_r.detected_intent == DetectedIntentEnum.LOTTERY_REWARD
        or "LOTTERY_JOB_SCAM_FLAG" in intent_r.flags
    )
    if is_lottery_or_job:
        final_score = max(final_score, 45.0)
        heuristics.append("CAUTION_ESCALATION: Advance-fee reward or part-time task solicitation detected")

    # Rule 4c: Psychological Urgency or Manipulation from Personal GSM
    if sender_r.sender_category == SenderCategoryEnum.PERSONAL_GSM and intent_r.risk_score >= 35:
        final_score = max(final_score, 45.0)
        heuristics.append("CAUTION_ESCALATION: Psychological urgency or manipulation sent from private mobile number")

    # Rule 6: Fraudulent UPI / VPA Collect Request Trap (Day 2 Enhancement)
    if upi_r and upi_r.status == AgentStatusEnum.SUCCESS and upi_r.risk_score >= 75:
        final_score = max(final_score, 90.0)
        heuristics.append("CRITICAL_ESCALATION: Fraudulent UPI collect / payment handle trap detected")
    elif upi_r and upi_r.status == AgentStatusEnum.SUCCESS and upi_r.risk_score >= 35 and sender_r.sender_category == SenderCategoryEnum.PERSONAL_GSM:
        final_score = max(final_score, 45.0)
        heuristics.append("CAUTION_ESCALATION: Deceptive payment handle received from unverified personal sender")

    # ── Day 5 / Next-Gen Enhancements: Financial Forensics & Multimodal Routing ──
    active_badges: List[str] = []
    proof_attached: Optional[str] = None

    # Badge & Floor 7: Bank Registered Account Name Mismatch
    has_bank_mismatch = bool(
        bank_verification and bank_verification.status == AgentStatusEnum.SUCCESS and bank_verification.is_name_mismatch
    )
    if has_bank_mismatch:
        active_badges.append("💳 Fake UPI Detected")

    # Badge & Floor 10: Cross-Agent Contradiction Detection
    has_identity_contradiction = bool(matrix and matrix.has_identity_contradiction)
    if has_identity_contradiction:
        active_badges.append("⚠️ Identity Contradiction")

    # Rule 8 Abuse-Proof: OSINT Past History Scam Records
    has_osint_hit = bool(
        osint_history and osint_history.status == AgentStatusEnum.SUCCESS and osint_history.total_complaints > 0
    )
    osint_floor: Optional[float] = None
    is_osint_corroborated = False

    if has_osint_hit:
        active_badges.append(f"⚠️ Flagged {osint_history.total_complaints}x for Scam")
        proof_attached = osint_history.proof_snippet

        # 1. Distinct reporters / sources analysis
        sources: Set[str] = {r.source for r in osint_history.reports if r.source}
        if osint_history.internal_reports_count > 0 and osint_history.external_forum_mentions > 0:
            sources.add("Internal Crowdsource")
            sources.add("External Forums")
        distinct_sources = len(sources)

        # 2. Time decay: reports >180d decay to 0.4x; 90-180d decay to 0.7x; <=90d or no date = 1.0x
        decayed_complaints = 0.0
        now_dt = datetime.now(timezone.utc)
        if osint_history.reports:
            for rep in osint_history.reports:
                freq = rep.frequency_flagged or 1
                decay_factor = 1.0
                if rep.date_reported:
                    try:
                        d_str = rep.date_reported[:10]
                        rep_dt = datetime.fromisoformat(d_str).replace(tzinfo=timezone.utc)
                        age_days = (now_dt - rep_dt).days
                        if age_days > 180:
                            decay_factor = 0.4
                        elif age_days > 90:
                            decay_factor = 0.7
                    except Exception:
                        decay_factor = 1.0
                decayed_complaints += (freq * decay_factor)
        else:
            decayed_complaints = float(osint_history.total_complaints)

        # 3. Independent Corroboration Check
        # Corroborated if multiple distinct sources (>=2) OR decayed complaints >=3 OR another vector shows threat
        has_vector_corroboration = (
            (url_r.status == AgentStatusEnum.SUCCESS and url_r.risk_score >= 35)
            or (sender_r.sender_category == SenderCategoryEnum.PERSONAL_GSM and (claims_bank or sender_r.risk_score >= 35))
            or (intent_r.detected_intent not in [DetectedIntentEnum.BENIGN] and intent_r.risk_score >= 35)
            or (upi_r and upi_r.status == AgentStatusEnum.SUCCESS and upi_r.risk_score >= 40)
            or has_bank_mismatch
            or has_identity_contradiction
            or is_feed_hit
        )
        is_osint_corroborated = (distinct_sources >= 2 or decayed_complaints >= 3 or has_vector_corroboration)

        if is_osint_corroborated:
            if decayed_complaints >= 3 or osint_history.total_complaints >= 3:
                osint_floor = 94.0
            else:
                osint_floor = 86.0
            heuristics.append(
                f"CRITICAL_ESCALATION: Target identified in prior scam reports ({osint_history.proof_snippet or 'Corroborated intelligence'})"
            )
        else:
            # Abuse-Proof: Uncorroborated community complaints are capped at HIGH_RISK (max 75.0)
            osint_floor = 65.0
            heuristics.append(
                f"HIGH_RISK_ESCALATION: Uncorroborated OSINT scam complaint ({osint_history.total_complaints} reports) — capped at HIGH_RISK to prevent reporter abuse"
            )

    # Badge: AI Text Detection
    if ai_text and ai_text.status == AgentStatusEnum.SUCCESS and ai_text.is_ai_generated:
        active_badges.append("🤖 AI Text Detected")

    # Badge: Manipulated Image (ELA)
    if vision_r and vision_r.status == AgentStatusEnum.SUCCESS and vision_r.is_morphed:
        active_badges.append("📸 Manipulated Image")

    # Badge: Document Forgery / Tampered ID
    if doc_r and doc_r.status == AgentStatusEnum.SUCCESS and doc_r.is_forged:
        active_badges.append("❌ Forged ID")

    # Escalation 9: Multimodal Weaponization Multiplier
    is_ai = bool(ai_text and ai_text.is_ai_generated)
    is_visual_forged = bool((vision_r and vision_r.is_morphed) or (doc_r and doc_r.is_forged))
    if is_ai and is_visual_forged:
        final_score = max(final_score, 96.0)
        heuristics.append("CRITICAL_ESCALATION: Multimodal scam weaponization (AI-generated text combined with visual/document tampering)")
    elif is_visual_forged:
        final_score = max(final_score, 85.0)
        heuristics.append("CRITICAL_ESCALATION: Visual tampering or forged credentials detected")

    # ── EXPLICIT PRECEDENCE: Identity/OSINT/Feed Floors Beat Whitelist Cap ──
    has_hard_floor = bool(
        has_bank_mismatch
        or has_identity_contradiction
        or (osint_floor is not None and is_osint_corroborated)
        or is_feed_hit
        or (url_r.risk_score >= 80 and sender_r.risk_score >= 80)
        or (is_personal_gsm and claims_bank and (is_kyc_or_panic or intent_r.risk_score >= 50))
        or (is_otp_harvest and (url_r.risk_score >= 50 or sender_r.risk_score >= 50))
        or (is_discom_threat and is_personal_gsm)
        or (intent_r.detected_intent == DetectedIntentEnum.FINANCIAL_EXTORTION and sender_r.sender_category != SenderCategoryEnum.OFFICIAL_TRAI_HEADER)
    )

    # Rule 5: Certified TRAI DLT Verified Transactional Communication (Safe Override)
    # Whitelist cap applies ONLY if NO hard identity/OSINT/threat floors exist!
    is_official_trai = sender_r.sender_category == SenderCategoryEnum.OFFICIAL_TRAI_HEADER
    is_safe_intent = (
        intent_r.detected_intent in [DetectedIntentEnum.BENIGN, DetectedIntentEnum.FINANCIAL_EXTORTION]
        if is_official_trai else (intent_r.detected_intent == DetectedIntentEnum.BENIGN or intent_r.risk_score <= 20)
    )
    is_safe_or_skipped_url = (
        url_r.status == AgentStatusEnum.SKIPPED
        or (url_r.status == AgentStatusEnum.SUCCESS and url_r.risk_score <= 15 and not url_r.is_typosquatting)
    )

    is_personal_gsm_clean = (
        sender_r.sender_category == SenderCategoryEnum.PERSONAL_GSM
        and not claims_bank
        and sender_r.risk_score <= 15
    )

    if not has_hard_floor:
        if is_official_trai and is_safe_or_skipped_url and is_safe_intent:
            final_score = min(final_score, 12.0)
            heuristics.append("BENIGN_VERIFICATION: Verified TRAI DLT transactional communication with clean signals")
        elif is_personal_gsm_clean and url_r.status == AgentStatusEnum.SKIPPED and intent_r.detected_intent == DetectedIntentEnum.BENIGN:
            final_score = min(final_score, 10.0)
            heuristics.append("BENIGN_VERIFICATION: Standard conversational message without fraud indicators")

    # Enforce Floors with absolute precedence over any caps
    if has_bank_mismatch:
        final_score = max(final_score, 88.0)
        heuristics.append("CRITICAL_ESCALATION: Registered bank account holder name does not match claimed institutional identity")

    if has_identity_contradiction:
        final_score = max(final_score, 92.0)
        heuristics.append(
            f"CRITICAL_ESCALATION: IDENTITY_CONTRADICTION_DETECTED ({matrix.contradiction_details or 'Cross-vector inconsistency'})"
        )

    if osint_floor is not None:
        if is_osint_corroborated:
            final_score = max(final_score, osint_floor)
        else:
            # Abuse-Proof: Uncorroborated community complaint elevated to high-risk but capped below CRITICAL
            final_score = max(final_score, osint_floor)
            final_score = min(final_score, 75.0)

    # Confirmed feed hit = floor 85; single Safe Browsing/VT/OTX flag = weight only
    if is_feed_hit:
        final_score = max(final_score, 85.0)
        heuristics.append("CRITICAL_ESCALATION: Confirmed phishing URL detected in authoritative threat intelligence feed (OpenPhish/URLhaus)")
    elif is_rep_flag:
        heuristics.append("INFO_SIGNAL: External reputation indicator (SafeBrowsing/VT/OTX) incorporated via standard vector weight only")

    # Clamp score to [0, 100] and round to integer
    rounded_score = int(round(max(0.0, min(100.0, final_score))))

    # PRD Verdict Classification (0-30: Safe, 31-65: Suspicious, 66-100: Likely Scam)
    if rounded_score >= 66:
        verdict_category = PrdVerdictEnum.LIKELY_SCAM
    elif rounded_score >= 31:
        verdict_category = PrdVerdictEnum.SUSPICIOUS
    else:
        verdict_category = PrdVerdictEnum.SAFE

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
    confidence = _determine_confidence(url_r, sender_r, intent_r, heuristics, upi_r, osint_history)

    # Step 6: Dual-Language Explanations & Actionable Advisories (English + Hindi)
    verdict = generate_verdict(risk_tier, url_r, sender_r, intent_r, heuristics, upi_r)
    verdict_hi = generate_verdict_hi(risk_tier, url_r, sender_r, intent_r, heuristics, upi_r)
    recommendation = generate_recommendation(risk_tier, action_required, url_r, sender_r, intent_r, upi_r)
    recommendation_hi = generate_recommendation_hi(risk_tier, action_required, url_r, sender_r, intent_r, upi_r)
    summary_explanation = build_explanation_summary(url_r, sender_r, intent_r, heuristics, upi_r)

    # Step 7: Plain-Language Reasons & Auditable Evidence List (PRD FR-8 & FR-9)
    reasons = extract_plain_language_reasons(url_r, sender_r, intent_r, heuristics, upi_r)
    evidence = build_evidence_list(url_r, sender_r, intent_r, upi_r)
    recommended_action = generate_recommended_action(verdict_category, risk_tier, url_r, sender_r, intent_r, upi_r)

    # Points 8, 9, 10, 13, 18: Evidence-based explanation, Actionable Guidance, Decoupled Confidence, Latencies
    why_blocked_evidence = _generate_why_blocked_evidence(
        url_r, sender_r, intent_r, upi_r, bank_verification, osint_history, matrix
    )
    actionable_guidance = _generate_actionable_guidance(risk_tier)
    confidence_percentage = _calculate_confidence_percentage(
        url_r, sender_r, intent_r, heuristics, bank_verification, osint_history, matrix
    )

    # Compute execution latency for the scoring engine itself
    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    # Sum total pipeline processing latency including upstream agent latencies
    upstream_latencies = [url_r.latency_ms, sender_r.latency_ms, intent_r.latency_ms]
    if upi_r:
        upstream_latencies.append(upi_r.latency_ms)
    if bank_verification:
        upstream_latencies.append(bank_verification.latency_ms)
    if osint_history:
        upstream_latencies.append(osint_history.latency_ms)
    if ai_text:
        upstream_latencies.append(ai_text.latency_ms)
    if vision_r:
        upstream_latencies.append(vision_r.latency_ms)
    if doc_r:
        upstream_latencies.append(doc_r.latency_ms)

    total_processing_ms = round(max(upstream_latencies) + latency_ms, 2)

    latency_breakdown = AgentLatencyBreakdown(
        url_ms=url_r.latency_ms,
        sender_ms=sender_r.latency_ms,
        intent_ms=intent_r.latency_ms,
        upi_ms=upi_r.latency_ms if upi_r else 0.0,
        bank_identity_ms=bank_verification.latency_ms if bank_verification else 0.0,
        osint_ms=osint_history.latency_ms if osint_history else 0.0,
        ai_text_ms=ai_text.latency_ms if ai_text else 0.0,
        vision_ms=vision_r.latency_ms if vision_r else 0.0,
        doc_fraud_ms=doc_r.latency_ms if doc_r else 0.0,
        total_ms=total_processing_ms,
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
        upi_analysis=upi_r,
        ai_text_analysis=ai_text,
        bank_verification=bank_verification,
        osint_history=osint_history,
        vision_analysis=vision_r,
        document_fraud=doc_r,
        synthesis_breakdown=synthesis
    )

    return ScanResponse(
        overall_risk_score=rounded_score,
        risk_score=rounded_score,
        verdict_category=verdict_category,
        risk_tier=risk_tier,
        confidence=confidence,
        confidence_percentage=confidence_percentage,
        claimed_vs_verified=matrix,
        why_blocked_evidence=why_blocked_evidence,
        actionable_guidance=actionable_guidance,
        latency_breakdown=latency_breakdown,
        reasons=reasons,
        evidence=evidence,
        recommended_action=recommended_action,
        verdict=verdict,
        verdict_hi=verdict_hi,
        recommendation=recommendation,
        recommendation_hi=recommendation_hi,
        action_required=action_required,
        audit_trail=audit_trail,
        processing_time_ms=total_processing_ms,
        modality=modality,
        active_badges=active_badges,
        proof_attached=proof_attached,
        ai_text_analysis=ai_text,
        bank_verification=bank_verification,
        osint_history=osint_history,
        vision_analysis=vision_r,
        document_fraud=doc_r,
    )
