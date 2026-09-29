"""
PhishLens - Verdict & Recommendation Generator
Owner: AVIKA
Generates human-readable, explainable scam verdicts and actionable intervention advisories.
"""

from typing import List, Optional
from shared.models import (
    RiskTierEnum,
    ActionRequiredEnum,
    UrlAgentResult,
    SenderAgentResult,
    IntentAgentResult
)


def generate_verdict(
    risk_tier: RiskTierEnum,
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    heuristics: List[str]
) -> str:
    """Generates an executive headline summarizing the exact fraud vector detected."""
    brand = sender_r.brand_claimed or url_r.target_brand or "Organization"

    if risk_tier == RiskTierEnum.CRITICAL:
        if sender_r.sender_category == "PERSONAL_GSM" and (sender_r.brand_claimed or url_r.target_brand):
            return f"Confirmed {brand} Impersonation — Urgent Credential / KYC Harvesting Scam"
        if url_r.is_typosquatting:
            return f"High-Confidence Phishing Attack — Typosquatted Domain Mimicking {brand}"
        if intent_r.detected_intent == "OTP_HARVEST":
            return f"Critical Interception: Active OTP / Credential Theft Solicitation"
        return "Critical Scam Threat Detected — Immediate Interception Triggered"

    elif risk_tier == RiskTierEnum.HIGH_RISK:
        if intent_r.detected_intent == "FINANCIAL_EXTORTION":
            return "Extortion / Coercive Threat Scam Detected"
        if intent_r.detected_intent == "LOTTERY_REWARD":
            return "Fraudulent Reward / Part-Time Job Advance-Fee Scam"
        if url_r.tld_reputation == "HIGH_RISK":
            return "Suspicious Message with High-Risk Untrusted Web Link"
        return "High Risk Interaction Detected — Extreme Caution Advised"

    elif risk_tier == RiskTierEnum.CAUTION:
        return "Unverified Digital Interaction — Moderate Risk Signals Present"

    else:
        if sender_r.sender_category == "OFFICIAL_TRAI_HEADER":
            return f"Verified Authentic Transactional Message from {brand or 'Registered Entity'}"
        return "No Malicious Threat Indicators Detected (Benign Interaction)"


def generate_recommendation(
    risk_tier: RiskTierEnum,
    action: ActionRequiredEnum,
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult
) -> str:
    """Generates a concrete, user-facing recommendation before transaction or link click."""
    if action == ActionRequiredEnum.BLOCK_TRANSACTION:
        recs = ["DO NOT proceed with payment or click links."]
        if sender_r.sender_category == "PERSONAL_GSM" and sender_r.brand_claimed:
            recs.append("Legitimate banks NEVER send account alerts from personal 10-digit mobile numbers.")
        if url_r.is_typosquatting or url_r.tld_reputation == "HIGH_RISK":
            recs.append("The attached link directs to an unauthorized external domain.")
        if intent_r.detected_intent in ["KYC_VERIFICATION", "OTP_HARVEST"]:
            recs.append("Never enter Aadhaar, PAN, UPI PIN, or NetBanking passwords on third-party links.")
        return " ".join(recs)

    elif action == ActionRequiredEnum.WARN_USER:
        return "Exercise caution. Confirm the sender's identity through official banking apps before sharing sensitive details or making payments."

    else:
        return "Communication appears legitimate. Standard safety tip: Never share confidential OTPs or UPI PINs with anyone."


def build_explanation_summary(
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    heuristics: List[str]
) -> str:
    """Builds an auditable technical synthesis summary explaining why the score was assigned."""
    parts = []
    if heuristics:
        parts.append(f"Heuristics Triggered: {'; '.join(heuristics)}.")
    
    signals = []
    if url_r.status == "SUCCESS" and url_r.risk_score > 30:
        signals.append(f"URL risk {url_r.risk_score:.0f}/100 ({', '.join(url_r.flags) if url_r.flags else 'elevated risk'})")
    if sender_r.status == "SUCCESS" and sender_r.risk_score > 30:
        signals.append(f"Sender risk {sender_r.risk_score:.0f}/100 ({sender_r.sender_category})")
    if intent_r.status == "SUCCESS" and intent_r.risk_score > 30:
        signals.append(f"Intent risk {intent_r.risk_score:.0f}/100 ({intent_r.detected_intent})")

    if signals:
        parts.append(f"Contributing vector signals: {'; '.join(signals)}.")
    else:
        parts.append("All vector signals evaluate within benign baseline parameters.")

    return " ".join(parts)
