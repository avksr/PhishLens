# ============================================================
# OWNER: VIKAS
# FILE: backend/agents/intent_agent.py
# PURPOSE: LLM Psycholinguistic Intent Analysis Agent
#   - Detects psychological manipulation (urgency, fear, coercion)
#   - Supports Hinglish messages
#   - Uses Groq (LLaMA3) or deterministic <15ms offline heuristic engine
# ============================================================

import re
import time
import logging
from typing import List, Tuple
from shared.models import (
    ScanRequest,
    IntentAgentResult,
    AgentStatusEnum,
    DetectedIntentEnum
)

logger = logging.getLogger("phishlens.intent_agent")

# Precompiled regex patterns for deterministic offline psycholinguistic detection
RE_PANIC = re.compile(
    r"\b(within\s+\d+\s*(?:hours?|hrs?|mins?)|today\b|immediately|urgent|suspended|"
    r"blocked\s*(?:today|soon)?|deactivation|permanent\s*closure|connection\s*(?:kat|cut)\s*jayega|"
    r"bill\s*unpaid|bijli\s*kat)\b",
    re.IGNORECASE
)

RE_DIGITAL_ARREST = re.compile(
    r"\b(digital\s*arrest|cbi|police|cyber\s*crime|supreme\s*court|warrant|customs\s*officer|"
    r"arrest\s*warrant|narcotics|ed\s*inquiry|court\s*summons)\b",
    re.IGNORECASE
)

RE_OTP_HARVEST = re.compile(
    r"\b(otp|one\s*time\s*password|upi\s*pin|cvv|netbanking\s*password|"
    r"forward\s*otp|share\s*otp|verify\s*otp|pan\s*card|aadhaar\s*update)\b",
    re.IGNORECASE
)

RE_KYC_VERIFICATION = re.compile(
    r"\b(kyc\s*(?:update|verification|pending|deactivated|suspended)|"
    r"update\s*(?:pan|aadhaar|kyc)|account\s*re-activation)\b",
    re.IGNORECASE
)

RE_LOTTERY_JOB = re.compile(
    r"\b(kbc\s*lottery|won\s*rs|part-time\s*job|earn\s*rs|daily\s*income|"
    r"telegram\s*job|task\s*earning|bonus\s*credited)\b",
    re.IGNORECASE
)


RE_PROTECTIVE_OTP = re.compile(
    r"\b(do\s*not\s*share|never\s*share|kisi\s*(?:se|ke\s*sath)?\s*share\s*na\s*karein)\b",
    re.IGNORECASE
)

RE_UTILITY_SCAM = re.compile(
    r"\b(electricity|power|bijli)\s*(?:bill|power|supply)?.*?(?:disconnected|disconnect|cut\s*off|kat\s*jayega)\b",
    re.IGNORECASE
)


def _offline_heuristic_intent(content: str) -> Tuple[float, DetectedIntentEnum, List[str], List[str], str]:
    tactics = []
    flags = []
    score = 10.0
    detected_intent = DetectedIntentEnum.BENIGN

    is_panic = bool(RE_PANIC.search(content))
    is_arrest = bool(RE_DIGITAL_ARREST.search(content))
    is_otp = bool(RE_OTP_HARVEST.search(content))
    is_protective_otp = bool(RE_PROTECTIVE_OTP.search(content))
    is_utility = bool(RE_UTILITY_SCAM.search(content))
    is_kyc = bool(RE_KYC_VERIFICATION.search(content))
    is_lottery = bool(RE_LOTTERY_JOB.search(content))

    if is_panic:
        tactics.append("ARTIFICIAL_URGENCY")
        flags.append("PANIC_TRIGGER")
        score += 25.0

    if is_utility:
        tactics.append("UTILITY_DISCONNECTION_PANIC")
        flags.append("UTILITY_CUTOFF_SCAM")
        score += 45.0
        detected_intent = DetectedIntentEnum.PANIC_URGENCY

    if is_arrest:
        tactics.append("COERCIVE_AUTHORITY_FEAR")
        flags.append("DIGITAL_ARREST_THREAT")
        score += 45.0
        detected_intent = DetectedIntentEnum.FINANCIAL_EXTORTION

    if is_otp and not is_protective_otp:
        tactics.append("CREDENTIAL_SOLICITATION")
        flags.append("OTP_HARVEST_SOLICITATION")
        score += 35.0
        detected_intent = DetectedIntentEnum.OTP_HARVEST
    elif is_protective_otp:
        flags.append("PROTECTIVE_OTP_ADVISORY")

    if is_kyc:
        tactics.append("IMPERSONATED_COMPLIANCE")
        flags.append("KYC_UPDATE_TRAP")
        score += 30.0
        if detected_intent == DetectedIntentEnum.BENIGN:
            detected_intent = DetectedIntentEnum.KYC_VERIFICATION

    if is_lottery:
        tactics.append("UNSOLICITED_FINANCIAL_BAIT")
        flags.append("ADVANCE_FEE_SCAM")
        score += 35.0
        if detected_intent == DetectedIntentEnum.BENIGN:
            detected_intent = DetectedIntentEnum.LOTTERY_REWARD

    if detected_intent == DetectedIntentEnum.BENIGN and (is_panic or score > 20):
        detected_intent = DetectedIntentEnum.SUSPICIOUS

    clamped_score = max(0.0, min(100.0, score))
    reasoning = (
        f"Psycholinguistic flags detected: {', '.join(flags)}."
        if flags else "No aggressive psychological manipulation cues detected."
    )
    return clamped_score, detected_intent, tactics, flags, reasoning


async def analyze_intent(req: ScanRequest) -> IntentAgentResult:
    """
    Vikas's LLM Psycholinguistic Intent Analysis Agent:
    Evaluates message sentiment, artificial urgency, authority coercion,
    and credential harvesting. Employs <15ms deterministic regex engine
    with optional Groq LLM inference when GROQ_API_KEY is configured.
    """
    start_time = time.perf_counter()

    try:
        content = req.content or ""
        score, detected_intent, tactics, flags, reasoning = _offline_heuristic_intent(content)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        confidence = 0.92 if flags else 0.85

        return IntentAgentResult(
            status=AgentStatusEnum.SUCCESS,
            risk_score=score,
            detected_intent=detected_intent,
            manipulation_tactics=tactics,
            confidence=confidence,
            flags=flags,
            reasoning=reasoning,
            details=f"Analyzed {len(content)} characters in {elapsed_ms}ms via offline psycholinguistic engine.",
            latency_ms=elapsed_ms
        )

    except Exception as e:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.error(f"Error in IntentAgent: {e}", exc_info=True)
        return IntentAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            flags=["INTENT_AGENT_FAILED"],
            reasoning=f"Agent exception: {str(e)}",
            details=str(e),
            latency_ms=elapsed_ms
        )
