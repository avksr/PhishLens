"""
PhishLens - Verdict & Recommendation Generator
Owner: AVIKA
Generates human-readable, explainable scam verdicts and actionable intervention advisories.
Includes the 1930 Cyber Cell Complaint Generator for cybercrime.gov.in / NCRP portal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional
from datetime import datetime, timezone
from shared.models import (
    RiskTierEnum,
    ActionRequiredEnum,
    UrlAgentResult,
    SenderAgentResult,
    IntentAgentResult,
    UpiAgentResult
)

if TYPE_CHECKING:
    from shared.models import ScanResponse


def generate_verdict(
    risk_tier: RiskTierEnum,
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    heuristics: List[str],
    upi_r: Optional[UpiAgentResult] = None
) -> str:
    """Generates an executive headline summarizing the exact fraud vector detected."""
    brand = sender_r.brand_claimed or url_r.target_brand or (upi_r.target_entity if upi_r else None) or "Organization"

    if risk_tier == RiskTierEnum.CRITICAL:
        if upi_r and upi_r.risk_score >= 80 and upi_r.detected_vpa:
            return f"Fraudulent Payment Interception — Spoofed UPI Handle Claiming {brand}"
        if sender_r.sender_category == "PERSONAL_GSM" and (sender_r.brand_claimed or url_r.target_brand):
            return f"Confirmed {brand} Impersonation — Urgent Credential / KYC Harvesting Scam"
        if url_r.is_typosquatting:
            return f"High-Confidence Phishing Attack — Typosquatted Domain Mimicking {brand}"
        if intent_r.detected_intent == "OTP_HARVEST":
            return "Critical Interception: Active OTP / Credential Theft Solicitation"
        return "Critical Scam Threat Detected — Immediate Interception Triggered"

    elif risk_tier == RiskTierEnum.HIGH_RISK:
        if intent_r.detected_intent == "FINANCIAL_EXTORTION":
            return "Extortion / Coercive Threat Scam Detected"
        if intent_r.detected_intent == "LOTTERY_REWARD":
            return "Fraudulent Reward / Part-Time Job Advance-Fee Scam"
        if upi_r and upi_r.risk_score >= 60:
            return "Suspicious Payment Request from Unverified Virtual Address"
        if url_r.tld_reputation == "HIGH_RISK":
            return "Suspicious Message with High-Risk Untrusted Web Link"
        return "High Risk Interaction Detected — Extreme Caution Advised"

    elif risk_tier == RiskTierEnum.CAUTION:
        return "Unverified Digital Interaction — Moderate Risk Signals Present"

    else:
        if sender_r.sender_category == "OFFICIAL_TRAI_HEADER":
            return f"Verified Authentic Transactional Message from {brand or 'Registered Entity'}"
        return "No Malicious Threat Indicators Detected (Benign Interaction)"


def generate_verdict_hi(
    risk_tier: RiskTierEnum,
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    heuristics: List[str],
    upi_r: Optional[UpiAgentResult] = None
) -> str:
    """
    Generates a localized, citizen-friendly Hindi headline (GIGW 3.0 / Digital India compliant).
    Ensures rural and elderly citizens clearly comprehend the threat without technical jargon.
    """
    brand = sender_r.brand_claimed or url_r.target_brand or (upi_r.target_entity if upi_r else None) or "बैंक/संस्थान"

    if risk_tier == RiskTierEnum.CRITICAL:
        if upi_r and upi_r.risk_score >= 80 and upi_r.detected_vpa:
            return f"धोखाधड़ी — {brand} के नाम पर फर्जी UPI आईडी से अवैध भुगतान का प्रयास।"
        if sender_r.sender_category == "PERSONAL_GSM" and (sender_r.brand_claimed or url_r.target_brand):
            return (
                f"सावधान — 10-अंकीय व्यक्तिगत नंबर से भेजा गया फर्जी {brand} संदेश "
                f"(KYC / पासवर्ड चोरी का प्रयास)।"
            )
        if url_r.is_typosquatting:
            return f"गंभीर फ़िशिंग खतरा — {brand} की हूबहू नकल करने वाली नकली वेबसाइट लिंक पाई गई।"
        if intent_r.detected_intent == "OTP_HARVEST":
            return "गंभीर चेतावनी — संवेदनशील OTP अथवा बैंकिंग पासवर्ड चुराने का सीधा दुर्भावनापूर्ण प्रयास।"
        return "गंभीर साइबर धोखाधड़ी का खतरा — सुरक्षा तंत्र द्वारा तत्काल सुरक्षा अवरोध लागू किया गया।"

    elif risk_tier == RiskTierEnum.HIGH_RISK:
        if intent_r.detected_intent == "FINANCIAL_EXTORTION":
            return "जबरन वसूली / डिजिटल अरेस्ट की फर्जी धमकी — पुलिस या सरकारी एजेंसी कभी ऐसे नोटिस नहीं भेजती।"
        if intent_r.detected_intent == "LOTTERY_REWARD":
            return "फर्जी लॉटरी / पार्ट-टाइम जॉब का प्रलोभन — अग्रिम शुल्क धोखाधड़ी का खतरा।"
        if upi_r and upi_r.risk_score >= 60:
            return "संदिग्ध भुगतान अनुरोध — अपुष्ट यूपीआई पते पर पैसे भेजने से बचें।"
        if url_r.tld_reputation == "HIGH_RISK":
            return "संदिग्ध संदेश — असुरक्षित एवं उच्च जोखिम वाले वेब लिंक से सावधान रहें।"
        return "उच्च जोखिम वाली गतिविधि — अत्यधिक सावधानी और सतर्कता बरतें।"

    elif risk_tier == RiskTierEnum.CAUTION:
        return "अपुष्ट डिजिटल संदेश — मध्यम स्तर के जोखिम संकेत मिले हैं। किसी भी कदम से पहले पुष्टि करें।"

    else:
        if sender_r.sender_category == "OFFICIAL_TRAI_HEADER":
            return f"{brand} से प्राप्त प्रमाणित एवं आधिकारिक बैंकिंग संदेश।"
        return "कोई सुरक्षा जोखिम नहीं मिला — यह एक सुरक्षित और सामान्य संदेश प्रतीत होता है।"


def generate_recommendation(
    risk_tier: RiskTierEnum,
    action: ActionRequiredEnum,
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    upi_r: Optional[UpiAgentResult] = None
) -> str:
    """Generates a concrete, user-facing recommendation before transaction or link click."""
    if action == ActionRequiredEnum.BLOCK_TRANSACTION:
        recs = ["DO NOT proceed with payment or click links."]
        if upi_r and upi_r.risk_score >= 70:
            recs.append("Do NOT authorize UPI collect requests or enter UPI PIN for receiving funds.")
        if sender_r.sender_category == "PERSONAL_GSM" and sender_r.brand_claimed:
            recs.append("Legitimate banks NEVER send account alerts from personal 10-digit mobile numbers.")
        if url_r.is_typosquatting or url_r.tld_reputation == "HIGH_RISK":
            recs.append("The attached link directs to an unauthorized external domain.")
        if intent_r.detected_intent in ["KYC_VERIFICATION", "OTP_HARVEST"]:
            recs.append("Never enter Aadhaar, PAN, UPI PIN, or NetBanking passwords on third-party links.")
        recs.append("Report fraud immediately by dialing 1930 or visiting cybercrime.gov.in.")
        return " ".join(recs)

    elif action == ActionRequiredEnum.WARN_USER:
        return (
            "Exercise caution. Confirm the sender's identity through official banking apps before "
            "sharing sensitive details or making payments."
        )

    else:
        return (
            "Communication appears legitimate. Standard safety tip: "
            "Never share confidential OTPs or UPI PINs with anyone."
        )


def generate_recommendation_hi(
    risk_tier: RiskTierEnum,
    action: ActionRequiredEnum,
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    upi_r: Optional[UpiAgentResult] = None
) -> str:
    """Generates clear, actionable guidance in Hindi for citizens and law enforcement."""
    if action == ActionRequiredEnum.BLOCK_TRANSACTION:
        recs = ["लेन-देन आगे न बढ़ाएं और लिंक पर कभी क्लिक न करें।"]
        if upi_r and upi_r.risk_score >= 70:
            recs.append("पैसे प्राप्त करने के लिए कभी भी UPI पिन दर्ज न करें और न ही कलेक्ट रिक्वेस्ट स्वीकार करें।")
        if sender_r.sender_category == "PERSONAL_GSM" and sender_r.brand_claimed:
            recs.append("वैध बैंक कभी भी व्यक्तिगत 10-अंकीय नंबर से अलर्ट नहीं भेजते।")
        if url_r.is_typosquatting or url_r.tld_reputation == "HIGH_RISK":
            recs.append("संदेश में दिया गया लिंक किसी अनधिकृत बाहरी वेबसाइट पर ले जाता है।")
        if intent_r.detected_intent in ["KYC_VERIFICATION", "OTP_HARVEST"]:
            recs.append("किसी भी अज्ञात लिंक पर अपना आधार, पैन, नेट-बैंकिंग पासवर्ड या OTP दर्ज न करें।")
        recs.append(
            "सहायता एवं शिकायत के लिए तुरंत राष्ट्रीय साइबर हेल्पलाइन 1930 डायल करें या cybercrime.gov.in पर जाएं।"
        )
        return " ".join(recs)

    elif action == ActionRequiredEnum.WARN_USER:
        return (
            "सावधानी बरतें। कोई भी विवरण साझा करने अथवा भुगतान करने से पहले आधिकारिक ऐप या "
            "बैंक शाखा से प्रेषक की पहचान अवश्य सत्यापित करें।"
        )

    else:
        return (
            "संदेश सुरक्षित प्रतीत होता है। सामान्य सुरक्षा नियम: अपना गोपनीय OTP या UPI पिन "
            "किसी के साथ भी साझा न करें।"
        )


def build_explanation_summary(
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    heuristics: List[str],
    upi_r: Optional[UpiAgentResult] = None
) -> str:
    """Builds an auditable technical synthesis summary explaining why the score was assigned."""
    parts = []
    if heuristics:
        parts.append(f"Heuristics Triggered: {'; '.join(heuristics)}.")

    signals = []
    if url_r.status == "SUCCESS" and url_r.risk_score > 30:
        url_flags = ', '.join(url_r.flags) if url_r.flags else 'elevated risk'
        signals.append(f"URL risk {url_r.risk_score:.0f}/100 ({url_flags})")
    if sender_r.status == "SUCCESS" and sender_r.risk_score > 30:
        signals.append(f"Sender risk {sender_r.risk_score:.0f}/100 ({sender_r.sender_category})")
    if intent_r.status == "SUCCESS" and intent_r.risk_score > 30:
        signals.append(f"Intent risk {intent_r.risk_score:.0f}/100 ({intent_r.detected_intent})")
    if upi_r and upi_r.status == "SUCCESS" and upi_r.risk_score > 30:
        signals.append(f"UPI risk {upi_r.risk_score:.0f}/100 ({upi_r.detected_vpa or 'VPA flag'})")

    if signals:
        parts.append(f"Contributing vector signals: {'; '.join(signals)}.")
    else:
        parts.append("All vector signals evaluate within benign baseline parameters.")

    return " ".join(parts)


def format_1930_complaint(
    scan_response: "ScanResponse",
    victim_name: Optional[str] = None,
    victim_phone: Optional[str] = None,
    incident_date: Optional[str] = None,
) -> str:
    """
    1930 Cyber Cell Complaint Generator.

    Formats a copy-ready plain-text complaint block for the National Cyber Crime
    Reporting Portal (NCRP 2.0) at cybercrime.gov.in, aligned with the Ministry
    of Home Affairs / I4C format for online financial fraud complaints.

    Args:
        scan_response:  Completed ScanResponse from PhishLens pipeline.
        victim_name:    Victim's full name (or leave None for a fill-in template).
        victim_phone:   Victim's contact number (or None for template placeholder).
        incident_date:  ISO-format incident date string; defaults to scan timestamp.

    Returns:
        A copy-ready plain-text complaint (English) with Sections A–E.
    """
    DIVIDER = "\u2550" * 64

    # ── Pull audit trail fields ───────────────────────────────────────────────
    at = scan_response.audit_trail
    url_a = at.url_analysis
    snd_a = at.sender_analysis
    int_a = at.intent_analysis
    upi_a = at.upi_analysis
    syn = at.synthesis_breakdown

    # Friendly display values
    url_analyzed = url_a.url_analyzed or "N/A"
    url_score = f"{url_a.risk_score:.0f}"
    url_flags = ", ".join(url_a.flags) if url_a.flags else "None"

    sender_id = snd_a.sender_analyzed or "N/A"
    sender_cat = (
        snd_a.sender_category.value
        if hasattr(snd_a.sender_category, "value")
        else str(snd_a.sender_category)
    )
    sender_flags = ", ".join(snd_a.flags) if snd_a.flags else "None"

    intent_label = (
        int_a.detected_intent.value
        if hasattr(int_a.detected_intent, "value")
        else str(int_a.detected_intent)
    )
    intent_score = f"{int_a.risk_score:.0f}"
    tactics = ", ".join(int_a.manipulation_tactics) if int_a.manipulation_tactics else "None"

    upi_section = ""
    if upi_a and upi_a.detected_vpa:
        upi_vpa = upi_a.detected_vpa
        upi_score = f"{upi_a.risk_score:.0f}"
        upi_flags = ", ".join(upi_a.flags) if upi_a.flags else "None"

        upi_section = (
            f"\nUPI Handle  : {upi_vpa}"
            f"\nUPI Risk    : {upi_score}/100"
            f"\nUPI Flags   : {upi_flags}"
        )

    incident_dt = incident_date or scan_response.timestamp
    risk_tier_val = (
        scan_response.risk_tier.value
        if hasattr(scan_response.risk_tier, "value")
        else str(scan_response.risk_tier)
    )
    action_val = (
        scan_response.action_required.value
        if hasattr(scan_response.action_required, "value")
        else str(scan_response.action_required)
    )
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    complaint = f"""{DIVIDER}
CYBER CRIME COMPLAINT — NATIONAL CYBER CRIME REPORTING PORTAL
Helpline  : 1930 (24\u00d77 National Cyber Crime Helpline)
Portal    : https://cybercrime.gov.in
PhishLens Scan Reference : {scan_response.scan_id}
Generated : {generated_at}
{DIVIDER}

SECTION A — COMPLAINANT DETAILS
Name            : {victim_name or "[FILL IN YOUR FULL NAME]"}
Contact Number  : {victim_phone or "[FILL IN YOUR MOBILE NUMBER]"}
Incident Date   : {incident_dt}

SECTION B — INCIDENT DESCRIPTION
I am writing to report a suspected cybercrime / online financial fraud.
I received a suspicious communication that was automatically flagged as
HIGH RISK by PhishLens real-time scam interception analysis.

Threat Verdict    : {scan_response.verdict}
Risk Score        : {scan_response.overall_risk_score}/100
Threat Category   : {risk_tier_val}
Confidence Level  : {scan_response.confidence}
Recommended Action: {action_val}

SECTION C — TECHNICAL EVIDENCE (PhishLens Audit Trail)
Scan ID       : {scan_response.scan_id}
Scan Time     : {scan_response.timestamp}

URL Analyzed  : {url_analyzed}
URL Risk Score: {url_score}/100
URL Flags     : {url_flags}

Sender ID     : {sender_id}
Sender Type   : {sender_cat}
Sender Flags  : {sender_flags}

Intent        : {intent_label}
Intent Score  : {intent_score}/100
Tactics Used  : {tactics}{upi_section}

SECTION D — AUTOMATED ANALYSIS SUMMARY
{syn.summary_explanation}

Heuristics Triggered:
{chr(10).join(f"  \u2022 {h}" for h in syn.heuristics_triggered) if syn.heuristics_triggered else "  None"}

SECTION E — DECLARATION
I declare that the above information is true and correct to the best of my
knowledge. I request that appropriate legal action be taken against the
perpetrators under the Information Technology Act, 2000 (Section 66C, 66D),
Indian Penal Code Section 420, or any other applicable cybercrime statutes.

For urgent assistance: Dial 1930 (24\u00d77 National Cyber Crime Helpline)
Online complaint    : https://cybercrime.gov.in
{DIVIDER}"""

    return complaint
