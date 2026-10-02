"""
PhishLens - Verdict & Recommendation Generator
Owner: AVIKA
Generates human-readable, explainable scam verdicts and actionable intervention advisories.
Includes the 1930 Cyber Cell Complaint Generator for cybercrime.gov.in / NCRP portal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional, Dict, Any
from datetime import datetime, timezone
from shared.models import (
    PrdVerdictEnum,
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
    is_personal_gsm = (
        sender_r.sender_category == "PERSONAL_GSM"
        or getattr(sender_r.sender_category, "value", None) == "PERSONAL_GSM"
        or str(sender_r.sender_category) == "PERSONAL_GSM"
    )

    if risk_tier == RiskTierEnum.CRITICAL:
        if upi_r and upi_r.risk_score >= 80 and upi_r.detected_vpa:
            return f"Fraudulent Payment Interception — Spoofed UPI Handle Claiming {brand}"
        if is_personal_gsm and (sender_r.brand_claimed or url_r.target_brand):
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
        if is_personal_gsm:
            return f"High Risk: Suspicious Coercion or Transaction Alert from Personal Mobile ({sender_r.sender_analyzed or 'GSM'})"
        return "High Risk Interaction Detected — Extreme Caution Advised"

    elif risk_tier == RiskTierEnum.CAUTION:
        if is_personal_gsm:
            return f"Caution Advised: Unverified message originated from personal mobile number ({sender_r.sender_analyzed or 'GSM'}), not official institution"
        return "Unverified Digital Interaction — Moderate Risk Signals Present"

    else:
        if sender_r.sender_category in ("OFFICIAL_TRAI_HEADER", getattr(sender_r.sender_category, "value", None)):
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
    is_personal_gsm = (
        sender_r.sender_category == "PERSONAL_GSM"
        or getattr(sender_r.sender_category, "value", None) == "PERSONAL_GSM"
        or str(sender_r.sender_category) == "PERSONAL_GSM"
    )

    if risk_tier == RiskTierEnum.CRITICAL:
        if upi_r and upi_r.risk_score >= 80 and upi_r.detected_vpa:
            return f"धोखाधड़ी — {brand} के नाम पर फर्जी UPI आईडी से अवैध भुगतान का प्रयास।"
        if is_personal_gsm and (sender_r.brand_claimed or url_r.target_brand):
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
            return f"संदिग्ध भुगतान अनुरोध — अपुष्ट UPI पते ({upi_r.detected_vpa or 'अनजान आईडी'}) पर पैसे भेजने से बचें।"
        if url_r.tld_reputation == "HIGH_RISK":
            return "संदिग्ध संदेश — असुरक्षित एवं उच्च जोखिम वाले वेब लिंक से सावधान रहें।"
        if is_personal_gsm:
            return f"सतर्कता आवश्यक: यह संदेश किसी व्यक्तिगत नंबर ({sender_r.sender_analyzed or 'मोबाइल'}) से आया है जिसमें संदिग्ध निर्देश दिए गए हैं।"
        return "उच्च जोखिम वाली गतिविधि — अत्यधिक सावधानी और सतर्कता बरतें।"

    elif risk_tier == RiskTierEnum.CAUTION:
        if is_personal_gsm:
            return (
                f"सतर्कता आवश्यक: यह संदेश किसी व्यक्तिगत नंबर ({sender_r.sender_analyzed or 'मोबाइल नंबर'}) से आया है, "
                f"किसी आधिकारिक बैंक या संस्था से नहीं।"
            )
        if url_r.status == "SUCCESS" and (url_r.risk_score >= 35 or url_r.tld_reputation == "HIGH_RISK"):
            return "सतर्कता आवश्यक: संदेश में दिया गया वेब लिंक अपुष्ट है। किसी भी अज्ञात लिंक पर अपनी जानकारी न भरें।"
        return "सतर्कता आवश्यक: अपुष्ट डिजिटल संदेश — मध्यम स्तर के जोखिम संकेत मिले हैं। किसी भी कदम से पहले आधिकारिक स्रोत से पुष्टि करें।"

    else:
        if sender_r.sender_category in ("OFFICIAL_TRAI_HEADER", getattr(sender_r.sender_category, "value", None)):
            return f"{brand} से प्राप्त प्रमाणित एवं आधिकारिक बैंकिंग संदेश।"
        if is_personal_gsm:
            return "सामान्य व्यक्तिगत संदेश — कोई सुरक्षा जोखिम या धोखाधड़ी के संकेत नहीं मिले।"
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
    is_personal_gsm = (
        sender_r.sender_category == "PERSONAL_GSM"
        or getattr(sender_r.sender_category, "value", None) == "PERSONAL_GSM"
        or str(sender_r.sender_category) == "PERSONAL_GSM"
    )

    if action == ActionRequiredEnum.BLOCK_TRANSACTION:
        recs = ["DO NOT proceed with payment or click links."]
        if upi_r and upi_r.risk_score >= 70:
            recs.append("Do NOT authorize UPI collect requests or enter UPI PIN for receiving funds.")
        if is_personal_gsm and sender_r.brand_claimed:
            recs.append("Legitimate banks NEVER send account alerts from personal 10-digit mobile numbers.")
        if url_r.is_typosquatting or url_r.tld_reputation == "HIGH_RISK":
            recs.append("The attached link directs to an unauthorized external domain.")
        if intent_r.detected_intent in ["KYC_VERIFICATION", "OTP_HARVEST"]:
            recs.append("Never enter Aadhaar, PAN, UPI PIN, or NetBanking passwords on third-party links.")
        recs.append("Report fraud immediately by dialing 1930 or visiting cybercrime.gov.in.")
        return " ".join(recs)

    elif action == ActionRequiredEnum.WARN_USER:
        recs = [
            "Exercise caution. Confirm the sender's identity through official banking apps before "
            "sharing sensitive details or making payments."
        ]
        if is_personal_gsm:
            recs.append("Never trust urgency alerts or bank notices originating from personal mobile numbers.")
        if upi_r and upi_r.status == "SUCCESS" and upi_r.detected_vpa:
            recs.append("Remember: UPI PIN is only required to SEND money, never to receive it.")
        recs.append("If in doubt, call the 1930 helpline.")
        return " ".join(recs)

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
    is_personal_gsm = (
        sender_r.sender_category == "PERSONAL_GSM"
        or getattr(sender_r.sender_category, "value", None) == "PERSONAL_GSM"
        or str(sender_r.sender_category) == "PERSONAL_GSM"
    )

    if action == ActionRequiredEnum.BLOCK_TRANSACTION:
        recs = ["लेन-देन आगे न बढ़ाएं और लिंक पर कभी क्लिक न करें।"]
        if upi_r and upi_r.risk_score >= 70:
            recs.append("पैसे प्राप्त करने के लिए कभी भी UPI पिन दर्ज न करें और न ही कलेक्ट रिक्वेस्ट स्वीकार करें।")
        if is_personal_gsm and sender_r.brand_claimed:
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
        recs = [
            "सावधानी बरतें। कोई भी विवरण साझा करने अथवा भुगतान करने से पहले आधिकारिक ऐप या "
            "बैंक शाखा से प्रेषक की पहचान अवश्य सत्यापित करें।"
        ]
        if is_personal_gsm:
            recs.append("व्यक्तिगत 10-अंकीय मोबाइल नंबर से आए संदेशों पर तुरंत विश्वास न करें।")
        if upi_r and upi_r.status == "SUCCESS" and upi_r.detected_vpa:
            recs.append("याद रखें: पैसे प्राप्त करने के लिए UPI पिन की आवश्यकता नहीं होती; पिन केवल भुगतान करने के लिए होता है।")
        recs.append("किसी भी संदेह की स्थिति में राष्ट्रीय साइबर हेल्पलाइन 1930 पर संपर्क करें।")
        return " ".join(recs)

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


def extract_plain_language_reasons(
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    heuristics: List[str],
    upi_r: Optional[UpiAgentResult] = None
) -> List[str]:
    """
    Extracts plain-language reasons (max 5, ordered by weight/severity)
    directly citing evidence from agent findings and heuristic triggers per PRD Section 8.
    """
    candidates = []

    # 1. Critical Heuristic Overrides (Highest Weight)
    for h in heuristics:
        if "Phishing URL combined with unauthorized" in h:
            candidates.append((95, "Phishing link detected originating from an unverified or high-risk sender"))
        elif "Personal mobile number impersonating bank" in h:
            brand = sender_r.brand_claimed or "bank"
            candidates.append((90, f"Private 10-digit mobile number ({sender_r.sender_analyzed or 'personal GSM'}) impersonating {brand}"))
        elif "Active OTP harvesting" in h:
            candidates.append((90, "Active solicitation targeting confidential OTP or online banking credentials"))
        elif "Coercive psychological extortion" in h or "Digital arrest" in h:
            candidates.append((88, "Coercive intimidation threatening immediate police arrest, court summons, or power cutoff"))
        elif "Fraudulent UPI collect" in h:
            vpa = upi_r.detected_vpa if upi_r else "unverified UPI"
            candidates.append((88, f"Fraudulent payment collect request trap from deceptive handle '{vpa}'"))
        elif "BENIGN_VERIFICATION" in h:
            candidates.append((10, "Verified authentic commercial communication matching official TRAI DLT registry"))

    # 2. URL Agent Evidence
    if url_r.status == "SUCCESS" and url_r.risk_score >= 30:
        if url_r.is_typosquatting:
            target = url_r.target_brand or "official entity"
            domain = url_r.domain or "website"
            candidates.append((85, f"Website link mimics official {target} portal but uses unauthorized domain ({domain})"))
        if url_r.domain_age_days is not None and url_r.domain_age_days < 30:
            candidates.append((75, f"Domain was registered only {url_r.domain_age_days} days ago (newly created scam infrastructure)"))
        if getattr(url_r, "tld_reputation", None) == "HIGH_RISK" or "HIGH_RISK_TLD" in url_r.flags:
            candidates.append((70, f"Uses high-risk top-level domain (.{url_r.tld or 'tld'}) commonly favored by ephemeral phishing campaigns"))
        if "HOMOGLYPH_ATTACK_DETECTED" in url_r.flags:
            candidates.append((80, "Contains confusable/homoglyph characters designed to visually deceive the user"))

    # 3. Sender Agent Evidence
    if sender_r.status == "SUCCESS" and sender_r.risk_score >= 30:
        if sender_r.sender_category == "PERSONAL_GSM" and sender_r.brand_claimed:
            candidates.append((82, f"Official alerts from {sender_r.brand_claimed} are never issued from private 10-digit mobile numbers"))
        elif sender_r.sender_category == "LOOKALIKE_HEADER":
            candidates.append((75, f"Sender header '{sender_r.sender_analyzed}' is an unverified lookalike header not registered with TRAI"))
        elif sender_r.is_spoofed_header:
            candidates.append((80, "Header format mimics commercial sender but fails TRAI DLT circle verification"))

    # 4. Intent Agent Evidence
    if intent_r.status == "SUCCESS" and intent_r.risk_score >= 30:
        if intent_r.detected_intent == "PANIC_URGENCY":
            candidates.append((70, "Employs artificial urgency ('disconnected tonight', 'blocked within 2 hours') to trigger panic"))
        elif intent_r.detected_intent == "FINANCIAL_EXTORTION":
            candidates.append((85, "Uses legal or institutional coercion to extort immediate payment without due process"))
        elif intent_r.detected_intent in ["KYC_VERIFICATION", "OTP_HARVEST"]:
            candidates.append((80, "Demands urgent submission of Aadhaar, PAN, NetBanking login, or verification codes"))
        elif intent_r.detected_intent == "LOTTERY_REWARD":
            candidates.append((65, "Promises fraudulent lottery rewards or part-time video-liking income requiring upfront fees"))
        elif intent_r.manipulation_tactics:
            candidates.append((60, f"Psychological manipulation tactics identified: {', '.join(intent_r.manipulation_tactics[:2])}"))

    # 5. UPI Agent Evidence
    if upi_r and upi_r.status == "SUCCESS" and upi_r.risk_score >= 30:
        if upi_r.is_spoofed_merchant:
            candidates.append((82, f"Payment address '{upi_r.detected_vpa}' impersonates an institutional desk on a consumer PSP handle"))
        elif "SUSPICIOUS_VPA_KEYWORD" in upi_r.flags:
            candidates.append((65, "Payment handle contains deceptive keywords associated with scam collections"))

    # Fallback for Benign cases with low/no risk
    if not candidates:
        if sender_r.sender_category == "OFFICIAL_TRAI_HEADER":
            candidates.append((10, f"Verified authentic header ({sender_r.sender_analyzed}) registered on Indian telecom DLT platform"))
        if url_r.status == "SKIPPED":
            candidates.append((5, "No external phishing links or suspicious URLs detected in message"))
        elif url_r.status == "SUCCESS" and url_r.risk_score <= 15:
            candidates.append((5, f"Embedded web link ({url_r.domain or 'URL'}) verified as legitimate and safe"))
        if intent_r.detected_intent == "BENIGN":
            candidates.append((5, "Communication content conforms to standard benign transactional guidelines"))
        if not candidates:
            candidates.append((0, "No malicious indicators detected across all evaluated vector agents"))

    # Sort by weight descending, deduplicate strings, and return top 5
    candidates.sort(key=lambda x: x[0], reverse=True)
    seen = set()
    result = []
    for _, text in candidates:
        if text not in seen:
            seen.add(text)
            result.append(text)
        if len(result) >= 5:
            break

    return result


def build_evidence_list(
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    upi_r: Optional[UpiAgentResult] = None
) -> List[Dict[str, Any]]:
    """
    Builds a structured evidence trail per PRD FR-8 & FR-9.
    Maps every reason and tool directly to an auditable tool result.
    """
    evidence = []

    # URL Agent Tool Result
    if url_r.status == "SKIPPED":
        evidence.append({
            "tool": "url_agent",
            "status": "SKIPPED",
            "finding": "No URL found in message payload to analyze",
            "raw_result": "url_extracted=None, status=SKIPPED"
        })
    elif url_r.status == "ERROR":
        evidence.append({
            "tool": "url_agent",
            "status": "ERROR",
            "finding": "URL analysis tool could not check link (timeout/error)",
            "raw_result": f"error={url_r.details or 'Timeout'}"
        })
    else:
        flags_str = ", ".join(url_r.flags) if url_r.flags else "CLEAN"
        age_str = f", age={url_r.domain_age_days}d" if url_r.domain_age_days is not None else ""
        evidence.append({
            "tool": "url_agent",
            "status": "SUCCESS",
            "finding": f"Domain {url_r.domain or 'unknown'} ({flags_str}){age_str}",
            "raw_result": f"risk={url_r.risk_score:.0f}, domain={url_r.domain}, typosquatting={url_r.is_typosquatting}, tld_rep={url_r.tld_reputation}"
        })

    # Sender Agent Tool Result
    if sender_r.status == "ERROR":
        evidence.append({
            "tool": "sender_agent",
            "status": "ERROR",
            "finding": "Sender verification tool could not verify header (timeout/error)",
            "raw_result": f"error={sender_r.details or 'Timeout'}"
        })
    else:
        cat_str = sender_r.sender_category.value if hasattr(sender_r.sender_category, "value") else str(sender_r.sender_category)
        flags_str = ", ".join(sender_r.flags) if sender_r.flags else "NORMAL"
        evidence.append({
            "tool": "sender_agent",
            "status": "SUCCESS",
            "finding": f"Sender {sender_r.sender_analyzed or 'unspecified'} classified as {cat_str} ({flags_str})",
            "raw_result": f"risk={sender_r.risk_score:.0f}, category={cat_str}, brand_claimed={sender_r.brand_claimed or 'None'}"
        })

    # Intent Agent Tool Result
    if intent_r.status == "ERROR":
        evidence.append({
            "tool": "intent_agent",
            "status": "ERROR",
            "finding": "Psycholinguistic intent tool could not complete analysis",
            "raw_result": f"error={intent_r.details or 'Timeout'}"
        })
    else:
        intent_val = intent_r.detected_intent.value if hasattr(intent_r.detected_intent, "value") else str(intent_r.detected_intent)
        tactics_str = ", ".join(intent_r.manipulation_tactics) if intent_r.manipulation_tactics else "None"
        evidence.append({
            "tool": "intent_agent",
            "status": "SUCCESS",
            "finding": f"Psycholinguistic intent: {intent_val} (tactics: {tactics_str})",
            "raw_result": f"risk={intent_r.risk_score:.0f}, intent={intent_val}, confidence={intent_r.confidence:.2f}"
        })

    # Optional UPI Agent Tool Result
    if upi_r:
        if upi_r.status == "SKIPPED":
            evidence.append({
                "tool": "upi_agent",
                "status": "SKIPPED",
                "finding": "No UPI VPA handle detected in message",
                "raw_result": "vpa=None, status=SKIPPED"
            })
        elif upi_r.status == "ERROR":
            evidence.append({
                "tool": "upi_agent",
                "status": "ERROR",
                "finding": "UPI VPA verification tool could not complete check",
                "raw_result": f"error={upi_r.details or 'Timeout'}"
            })
        else:
            flags_str = ", ".join(upi_r.flags) if upi_r.flags else "VALID_PSP"
            evidence.append({
                "tool": "upi_agent",
                "status": "SUCCESS",
                "finding": f"UPI VPA '{upi_r.detected_vpa}' ({flags_str})",
                "raw_result": f"risk={upi_r.risk_score:.0f}, vpa={upi_r.detected_vpa}, spoofed={upi_r.is_spoofed_merchant}"
            })

    return evidence


def generate_recommended_action(
    verdict_cat: PrdVerdictEnum,
    risk_tier: RiskTierEnum,
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult,
    upi_r: Optional[UpiAgentResult] = None
) -> str:
    """
    Generates action required with official reporting channels per PRD Section 8 Output contract.
    """
    if verdict_cat == PrdVerdictEnum.LIKELY_SCAM or risk_tier in [RiskTierEnum.CRITICAL, RiskTierEnum.HIGH_RISK]:
        actions = ["BLOCK & REPORT: Do not click any links, do not share OTP, and do not make payments."]
        if upi_r and upi_r.risk_score >= 70:
            actions.append("Decline any pending UPI collect requests.")
        actions.append("Report this sender immediately to the National Cyber Crime Helpline (dial 1930 or visit cybercrime.gov.in).")
        return " ".join(actions)

    elif verdict_cat == PrdVerdictEnum.SUSPICIOUS or risk_tier == RiskTierEnum.CAUTION:
        return (
            "VERIFY & CAUTION: Do not click links, share private details, or transfer money. "
            "Verify the authenticity of this message through official customer care or in-branch channels."
        )

    else:
        return "ALLOW: Safe to proceed with normal caution. Never share confidential banking OTPs or UPI PINs."


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
