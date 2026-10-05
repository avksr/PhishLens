# ============================================================
# OWNER: VIKAS
# FILE: backend/agents/intent_agent.py
# PURPOSE: LLM Psycholinguistic Intent Analysis Agent (Day 1, 2, 3 & Day 4)
#   - Detects psychological manipulation (urgency, fear, coercion)
#   - Calibrated for Indian Hinglish, utility extortion, digital arrest & Telegram tasks
#   - Multi-LLM Fallback Pipeline: Primary Gemini Flash -> Secondary Groq LLaMA-3 -> Local Regex
#   - Curated CERT-In / RBI Scam Taxonomy & Keyword/Cosine Similarity Matcher (FR-6)
#   - Deterministic, high-speed local regex heuristic fallback (< 15ms)
#   - Safe text normalization for capitalization, spacing, and punctuation
#   - Context-aware discrimination to prevent false positives on benign mentions
#   - Never raises an unhandled exception (Fail-Safe)
# ============================================================

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from shared.models import (
    ScanRequest,
    IntentAgentResult,
    AgentStatusEnum,
    DetectedIntentEnum
)

logger = logging.getLogger("phishlens.intent_agent")

# Strict per-agent LLM SLA timeout (seconds)
LLM_TIMEOUT_SECONDS: float = 2.5

# Prompts and data directories
_BACKEND_DIR: Path = Path(__file__).resolve().parent.parent
_PROMPTS_DIR: Path = _BACKEND_DIR / "prompts"
_INTENT_PROMPT_PATH: Path = _PROMPTS_DIR / "intent_prompt.txt"
_DATA_DIR: Path = _BACKEND_DIR / "data"
_TAXONOMY_PATH: Path = _DATA_DIR / "scam_taxonomy.json"

_DEFAULT_SYSTEM_PROMPT: str = (
    "You are a Tier-1 Cybersecurity Threat Intelligence & Psycholinguistic Fraud Analyst "
    "specializing in Indian digital payment, SMS, WhatsApp, and banking scams (including Hinglish).\n"
    "Evaluate manipulation vectors: Panic/Urgency, Coercive Authority, Credential/Identity Theft, Lottery/Job Scams.\n"
    "Return pure JSON with fields: risk_score (0-100), detected_intent, manipulation_tactics, confidence, "
    "flags, reasoning, details."
)


def _normalize_text(text: str) -> str:
    """
    Normalizes text for robust psycholinguistic intent analysis:
    - Lowercases text
    - Replaces dots between individual acronym letters (e.g. 'u.r.g.e.n.t' -> 'urgent', 'k.y.c' -> 'kyc')
    - Inserts spacing between stuck digits and words (e.g. '2ghante' -> '2 ghante')
    - Collapses multiple whitespace and decorative punctuation marks into clean single spaces
    """
    if not text:
        return ""
    normalized = text.lower()
    # Normalize acronyms with dots like 'u.r.g.e.n.t' or 'o.t.p'
    normalized = re.sub(r"(?<=\b[a-z])\.(?=[a-z]\b)", "", normalized)
    # Separate stuck digits and letters, e.g. '2ghante' -> '2 ghante'
    normalized = re.sub(r"(\d+)([a-zA-Z]+)", r"\1 \2", normalized)
    normalized = re.sub(r"([a-zA-Z]+)(\d+)", r"\1 \2", normalized)
    # Normalize whitespace, newlines, and decorative punctuation symbols
    normalized = re.sub(r"[\r\n\t]+", " ", normalized)
    normalized = re.sub(r"[!?,;*#~`|]+", " ", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


# ─────────────────────────────────────────────────────────────
# Curated CERT-In / RBI Scam Taxonomy & Similarity Matcher (FR-6)
# ─────────────────────────────────────────────────────────────

_SCAM_TAXONOMY: Optional[List[Dict[str, Any]]] = None


def load_scam_taxonomy() -> List[Dict[str, Any]]:
    """Loads curated public scam taxonomy based on CERT-In and RBI advisories (FR-6)."""
    global _SCAM_TAXONOMY
    if _SCAM_TAXONOMY is None:
        if _TAXONOMY_PATH.is_file():
            try:
                _SCAM_TAXONOMY = json.loads(_TAXONOMY_PATH.read_text(encoding="utf-8"))
            except Exception as err:
                logger.warning(f"Failed to load scam taxonomy: {err}")
                _SCAM_TAXONOMY = []
        else:
            _SCAM_TAXONOMY = []
    return _SCAM_TAXONOMY


def match_scam_taxonomy(text: str) -> Dict[str, Any]:
    """
    Performs keyword and cosine similarity matching of input text against
    curated CERT-In and RBI scam taxonomy categories (FR-6).

    Returns:
    {
        "category_id": Optional[str],
        "category_name": Optional[str],
        "match_score": float,  # Normalized 0.0 to 1.0
        "advisory_source": Optional[str],
        "matched_keywords": List[str]
    }
    """
    taxonomy = load_scam_taxonomy()
    if not taxonomy or not text:
        return {
            "category_id": None,
            "category_name": None,
            "match_score": 0.0,
            "advisory_source": None,
            "matched_keywords": [],
        }

    norm_text = _normalize_text(text)
    query_tokens = re.findall(r"\b[a-z0-9]+\b", norm_text)
    if not query_tokens:
        return {
            "category_id": None,
            "category_name": None,
            "match_score": 0.0,
            "advisory_source": None,
            "matched_keywords": [],
        }

    query_counts = Counter(query_tokens)
    norm_q = math.sqrt(sum(c * c for c in query_counts.values()))

    best_match: Optional[Dict[str, Any]] = None
    best_score = 0.0
    best_matched_keywords: List[str] = []

    for entry in taxonomy:
        matched_kw: List[str] = []
        for kw in entry.get("keywords", []):
            kw_norm = _normalize_text(kw)
            if kw_norm and re.search(r"\b" + re.escape(kw_norm) + r"\b", norm_text):
                matched_kw.append(kw)

        cat_corpus = " ".join(
            entry.get("keywords", [])
            + [entry.get("description", "")]
            + entry.get("typical_phrases", [])
            + [entry.get("name", "")]
        )
        cat_tokens = re.findall(r"\b[a-z0-9]+\b", _normalize_text(cat_corpus))
        cat_counts = Counter(cat_tokens)
        norm_c = math.sqrt(sum(c * c for c in cat_counts.values()))

        if norm_q > 0 and norm_c > 0:
            dot = sum(query_counts[t] * cat_counts[t] for t in query_counts if t in cat_counts)
            cosine = dot / (norm_q * norm_c)
        else:
            cosine = 0.0

        if matched_kw:
            kw_boost = min(0.35, len(matched_kw) * 0.12)
            combined_score = min(1.0, max(0.55 + kw_boost, cosine + 0.40))
        else:
            combined_score = cosine * 0.75

        combined_score = round(max(0.0, min(1.0, combined_score)), 4)

        if combined_score > best_score:
            best_score = combined_score
            best_match = entry
            best_matched_keywords = matched_kw

    if best_match and (best_score >= 0.25 or best_matched_keywords):
        return {
            "category_id": best_match.get("id"),
            "category_name": best_match.get("name"),
            "match_score": best_score,
            "advisory_source": best_match.get("advisory_source"),
            "matched_keywords": best_matched_keywords,
        }

    return {
        "category_id": None,
        "category_name": None,
        "match_score": 0.0,
        "advisory_source": None,
        "matched_keywords": [],
    }


# ─────────────────────────────────────────────────────────────
# Regex Patterns for Local Resilient Heuristic Fallback
# (Supports English & Hinglish Phrasing Variants)
# ─────────────────────────────────────────────────────────────

# Panic & False Urgency: +40.0 risk
_PANIC_URGENCY_PATTERNS = [
    # English urgency patterns
    re.compile(r"\bwithin\s+\d+\s*(?:hours?|hrs?|minutes?|mins?|days?)\b", re.IGNORECASE),
    re.compile(r"\bblocked\s+today\b", re.IGNORECASE),
    re.compile(r"\bdeactivated\s+today\b", re.IGNORECASE),
    re.compile(r"\b(?:power|electricity)\s+cut\s+tonight\b", re.IGNORECASE),
    re.compile(r"\bdisconnected\s+tonight(?:\s+at\s+9[\.:]30\s*(?:pm|am))?\b", re.IGNORECASE),
    re.compile(r"\b(?:power|electricity)\s+(?:will\s+be\s+)?disconnected\b", re.IGNORECASE),
    re.compile(r"\belectricity\s+disconnection\b", re.IGNORECASE),
    re.compile(r"\b(?:immediately|urgent|urgently|verify\s+immediately)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:account|card|sim)\s+(?:is\s+|will\s+be\s+)?(?:blocked|suspended|deactivated|frozen|cut\s*off)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\baccount\s+(?:cut\s*off|blocked|suspended)\b", re.IGNORECASE),
    re.compile(r"\bcut\s*off\s*tonight\b", re.IGNORECASE),
    re.compile(r"\bfailing\s+which\b", re.IGNORECASE),
    re.compile(r"\bkyc\s*(?:will\s+expire|expired|expire)\b", re.IGNORECASE),
    # Hinglish urgency patterns
    re.compile(r"\b\d+\s*ghante?\s*(?:ke\s*andar|mein|me)\b", re.IGNORECASE),
    re.compile(r"\b(?:aaj\s*)?raat\s*tak\b", re.IGNORECASE),
    re.compile(r"\baccount\s*(?:block|band|bandh)\s*(?:ho\s*jayega|hoga|karein|karenge)\b", re.IGNORECASE),
    re.compile(r"\bwarna\s*account\s*(?:block|band)\b", re.IGNORECASE),
    re.compile(r"\b(?:turant|jaldi|tatkal)\b", re.IGNORECASE),
    re.compile(r"\bbijli\s*(?:cut|kat|band)\b", re.IGNORECASE),
    re.compile(r"\bkyc\s*(?:khatam|band)\b", re.IGNORECASE),
    # Day 3 Utility / Electricity disconnection coercion (requires threat context to prevent false positives)
    re.compile(r"\b(?:bijli|electricity)\s+bill\s+update\s+nahi\s+hua\b", re.IGNORECASE),
    re.compile(r"\bbill\s+update\s+nahi\s+hua.*(?:connection|kat|cut)\b", re.IGNORECASE),
    re.compile(r"\bconnection\s*(?:kat|kaat|cut)\s*(?:diya\s*jayega|di\s*jayegi|ho\s*jayega|hoga)\b", re.IGNORECASE),
    re.compile(r"\blight\s*(?:kaat|kat|cut)\s*(?:di\s*jayegi|diya\s*jayega|ho\s*jayega|hoga)\b", re.IGNORECASE),
    re.compile(r"\bbill\s+pay\s*(?:karo|nahi\s*kiya|karein)?\s*warna\s*(?:light|bijli|connection)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:aaj\s+raat\s+tak|tonight).*(?:connection|electricity|power)\s*(?:cut|disconnected)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:electricity|connection)\s+(?:aaj\s+raat\s+tak|tonight)\s+(?:cut|disconnected)\b", re.IGNORECASE),
    re.compile(r"\bbill\s+(?:is\s+)?overdue.*(?:pay\s+(?:immediately|now)|disconnect|cut\s*off)\b", re.IGNORECASE),
    re.compile(r"\bpower\s+cut\s+(?:threat|warning|notice)\b", re.IGNORECASE),
    # Day 4: Telecom SIM & Mobile number deactivation urgency
    re.compile(
        r"\b(?:disconnect|block|suspend|deactivate)\s+(?:your\s+)?(?:mobile\s+number|sim|phone)\s+"
        r"within\s+\d+\s*(?:hours?|hrs?)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:mobile\s+number|sim)\s+(?:will\s+be\s+)?(?:disconnected|suspended|blocked)\b", re.IGNORECASE),
    re.compile(
        r"\baapka\s+(?:mobile\s+number|sim)\s+(?:2\s*ghante|aaj\s*raat)\s*(?:ke\s*andar|mein|tak)?\s*"
        r"(?:band|block)\s*ho\s*jayega\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bpower\s+supply\s+(?:will\s+be\s+)?(?:cut\s*off|disconnected)\b", re.IGNORECASE),
    re.compile(r"\b(?:power|supply|electricity)\s+(?:will\s+be\s+)?cut\s*off\b", re.IGNORECASE),
    re.compile(r"\bbill\s+disconnection\b", re.IGNORECASE),
]

# Coercive Authority & Legal Threats: +45.0 risk
_COERCIVE_AUTHORITY_PATTERNS = [
    # English legal / authority threats
    re.compile(r"\bdigital\s+arrest\b", re.IGNORECASE),
    re.compile(r"\bunder\s+digital\s+arrest\b", re.IGNORECASE),
    re.compile(r"\bdigital\s+arrest\s+warrant\b", re.IGNORECASE),
    re.compile(r"\bsupreme\s+court\s+(?:ka\s+)?(?:warrant|notice)\b", re.IGNORECASE),
    re.compile(r"\b(?:court|police|cbi|arrest)\s+warrant\b", re.IGNORECASE),
    re.compile(r"\bcourt\s+summons\b", re.IGNORECASE),
    re.compile(r"\bpolice\s+station\b", re.IGNORECASE),
    re.compile(r"\bcbi\s+officer\b", re.IGNORECASE),
    re.compile(r"\bcyber\s*(?:crime\s*)?(?:police|cell)\b", re.IGNORECASE),
    re.compile(r"\belectricity\s+officer\b", re.IGNORECASE),
    re.compile(r"\b(?:contact|call|reach)\s+(?:our\s+)?(?:electricity\s+)?officer\b", re.IGNORECASE),
    re.compile(r"\b(?:police|cbi)\s+case\b", re.IGNORECASE),
    re.compile(r"\bpolice\s+arrest\b", re.IGNORECASE),
    re.compile(r"\bcustoms\s+department\b", re.IGNORECASE),
    re.compile(r"\b(?:rbi|trai|customs|income\s*tax)\s+department\s+(?:notice|penalty|officer|summons|warning|raid|defaulter|investigation)\b", re.IGNORECASE),
    # Hinglish legal / arrest threats
    re.compile(r"\bdigital\s*arrest\s*(?:warrant|ke\s*liye\s*ready|issue|hoga|hogi)?\b", re.IGNORECASE),
    re.compile(r"\baapke\s+naam\s+p(?:e|ar)\s+(?:.*)?warrant\b", re.IGNORECASE),
    re.compile(r"\bpolice\s*(?:tumhe|aapko)?\s*(?:arrest|giraftar)\s*(?:karegi|kar\s*legi)\b", re.IGNORECASE),
    re.compile(r"\bpolice\s*case\s*(?:se\s*bachna|hoga|kar\s*denge|ho\s*jayega)\b", re.IGNORECASE),
    re.compile(r"\bjail\s+(?:bhej\s+diya\s+jayega|hogi|jana\s*padega)\b", re.IGNORECASE),
    re.compile(r"\bgiraftari\b", re.IGNORECASE),
    re.compile(r"\barrest\s+kar\s+(?:liya\s+)?jayega\b", re.IGNORECASE),
    re.compile(r"\bgiraftar\s+kar\s+(?:liya\s+)?jayega\b", re.IGNORECASE),
    # Day 4: Video Call Digital Arrest & Telecom Authority Threats
    re.compile(r"\bvideo\s+call\s+(?:arrest\s+)?warrant\b", re.IGNORECASE),
    re.compile(
        r"\b(?:video\s+call\s+)?arrest\s+warrant\s+issued\s+by\s+(?:cbi|cyber\s*(?:crime\s*)?(?:cell|police))\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bvideo\s+call\s+par\s+(?:statement|arrest|investigation)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:trai|dot)\s+(?:will\s+)?(?:disconnect|block|suspend|deactivate)\s+(?:your\s+)?"
        r"(?:mobile\s+number|sim|phone|number)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:trai|dot)\s+(?:mobile\s+number\s+)?disconnection\s+notice\b", re.IGNORECASE),
    re.compile(r"\b(?:trai|dot)\s+verification\s+notice\b", re.IGNORECASE),
]

# Credential & PII Harvesting: +45.0 risk
_CREDENTIAL_HARVEST_PATTERNS = [
    # English credential harvesting
    re.compile(r"\bsubmit\s+(?:your\s+)?pan\b", re.IGNORECASE),
    re.compile(r"\bverify\s+(?:your\s+)?aadhaar\b", re.IGNORECASE),
    re.compile(r"\bshare\s+.*?\botp\b", re.IGNORECASE),
    re.compile(r"\b(?:verify|enter|forward|send)\s+(?:your\s+)?otp\b", re.IGNORECASE),
    re.compile(r"\b(?:debit|credit|atm)?\s*card\s+(?:will\s+)?expire\b", re.IGNORECASE),
    re.compile(r"\bupdate\s+(?:your\s+)?kyc\b", re.IGNORECASE),
    re.compile(r"\b(?:complete|submit)\s+(?:your\s+)?kyc\b", re.IGNORECASE),
    re.compile(r"\bunblock\s+(?:your\s+)?account\b", re.IGNORECASE),
    re.compile(r"\bnetbanking\s+password\b", re.IGNORECASE),
    re.compile(r"\b(?:aadhaar|pan)\s+(?:&|and)?\s*(?:pan|aadhaar|details)\b", re.IGNORECASE),
    # Hinglish OTP and credential solicitation
    re.compile(r"\botp\s*(?:share\s*karo|batao|bhejo|do|forward\s*karo|send\s*karo)\b", re.IGNORECASE),
    re.compile(r"\bkyc\s*(?:update\s*karo|verify\s*karo|jama\s*karo|expire)\b", re.IGNORECASE),
    re.compile(r"\baadhaar\s*(?:bhejo|jama\s*karo|link\s*karo|update\s*karo)\b", re.IGNORECASE),
    re.compile(r"\bpan\s*card\s*(?:bhejo|jama\s*karo|link\s*karo|update\s*karo)\b", re.IGNORECASE),
    re.compile(r"\bunblock\s*karne\s*ke\s*liye\b", re.IGNORECASE),
    # Day 4: IRCTC Refund Phishing
    re.compile(r"\birctc\s+(?:ticket\s+)?(?:cancellation\s+)?refund\b", re.IGNORECASE),
    re.compile(r"\brail\s*connect\s*(?:app|apk)\b", re.IGNORECASE),
    re.compile(r"\bupdate\s+bank\s+details\s+for\s+(?:irctc\s+)?refund\b", re.IGNORECASE),
]

# Lottery / Part-Time Job Advance Scams: +35.0 risk
_LOTTERY_JOB_PATTERNS = [
    re.compile(r"\bkbc\s+lottery\b", re.IGNORECASE),
    re.compile(r"\bwon\s+(?:rs\.?\s*)?\d+\s*lakh\b", re.IGNORECASE),
    re.compile(r"\bpart-?time\s+job\b", re.IGNORECASE),
    re.compile(r"\bpart-?time\s+task\b", re.IGNORECASE),
    re.compile(r"\b(?:youtube\s+)?videos?\s*(?:ko\s*)?like\s*(?:karo|kijiye)?\b", re.IGNORECASE),
    re.compile(r"\byoutube\s+likes?\s*(?:karo|task|karke)?\b", re.IGNORECASE),
    re.compile(r"\blike\s+(?:\d+\s+)?(?:youtube\s+)?videos?\b", re.IGNORECASE),
    re.compile(r"\btelegram\s+(?:pe\s+)?task\b", re.IGNORECASE),
    re.compile(r"\btask\s+complete\s+karo\b", re.IGNORECASE),
    re.compile(r"\btask\s+(?:complete|unlock)\b", re.IGNORECASE),
    re.compile(r"\b(?:recharge|deposit)\s+.*(?:task|unlock)\b", re.IGNORECASE),
    re.compile(r"\b(?:recharge|deposit)\s+to\s+unlock\b", re.IGNORECASE),
    re.compile(r"\binvestment\s+before\s+withdrawal\b", re.IGNORECASE),
    re.compile(r"\bpehle\s+recharge\s+karo\b", re.IGNORECASE),
    re.compile(r"\bscreenshot\s+(?:telegram\s+pe\s+)?(?:bhejo|send\s*karo)\b", re.IGNORECASE),
    re.compile(r"\btelegram\s+pe\s+screenshot\b", re.IGNORECASE),
    re.compile(r"\btelegram\s+(?:group|channel)\s+(?:se\s+)?(?:earning|kamai|commission)\b", re.IGNORECASE),
    re.compile(r"\bdaily\s+(?:earning|\d+)\s*(?:kamao|daily)\b", re.IGNORECASE),
    re.compile(r"\bearn\s+(?:rs\.?\s*)?\d+\s*daily\b", re.IGNORECASE),
    re.compile(r"\b(?:daily\s+earning|ghar\s+baithe\s+earning)\b", re.IGNORECASE),
    re.compile(r"\bcommission\s+kamao\b", re.IGNORECASE),
    re.compile(r"\bregistration\s+fee\b", re.IGNORECASE),
    re.compile(r"\bcongratulations!?\s+you\s+have\s+(?:been\s+selected|won)\b", re.IGNORECASE),
    re.compile(r"\blottery\s*lagi\s*(?:hai)?\b", re.IGNORECASE),
    re.compile(r"\binaam\s*jeeta\s*(?:hai)?\b", re.IGNORECASE),
    re.compile(r"\bghar\s*baithe\s*(?:paise\s*)?kamao\b", re.IGNORECASE),
    re.compile(r"\bhttps?://t\.me/[a-zA-Z0-9_\-]+\b", re.IGNORECASE),
    re.compile(r"\bjoin\s+telegram\b", re.IGNORECASE),
]

# Benign Baseline Markers
_BENIGN_PATTERNS = [
    re.compile(r"\b(?:do\s+not|never)\s+share\s+(?:this\s+|your\s+)?otp\b", re.IGNORECASE),
    re.compile(r"\bkisi\s+ke\s+saath\s+otp\s+share\s+na\s+karein\b", re.IGNORECASE),
    re.compile(r"\bvalid\s+for\s+\d+\s*mins?\b", re.IGNORECASE),
    re.compile(r"\byour\s+otp\s+for\s+.*is\s+\d+\b", re.IGNORECASE),
    re.compile(r"\barriving\s+in\s+\d+\s*mins?\b", re.IGNORECASE),
    re.compile(r"\btrack\s+your\s+(?:rider|order)\b", re.IGNORECASE),
    re.compile(r"\bpaid\s+(?:my\s+)?(?:electricity|utility)\s+bill\b", re.IGNORECASE),
    re.compile(r"\bthrough\s+(?:the\s+)?official\s+app\b", re.IGNORECASE),
    re.compile(r"\bdiscussed\s+in\s+(?:the\s+)?news\b", re.IGNORECASE),
    re.compile(r"\bwatched\s+a\s+(?:youtube\s+)?video\b", re.IGNORECASE),
    re.compile(r"\bdiscussed\s+trai\s+guidelines\b", re.IGNORECASE),
    re.compile(r"\bvideo\s+call\s+with\s+(?:our\s+)?(?:team|family|friends?)\b", re.IGNORECASE),
    re.compile(r"\birctc\s+ticket\s+confirmed\b", re.IGNORECASE),
    re.compile(r"\b(?:itr[-\s]?\d*|tax\s+return)\s+(?:filed|verified|processed)\b", re.IGNORECASE),
    re.compile(r"\backnowledgement\s+no\b", re.IGNORECASE),
    re.compile(r"\bsuccessfully\s+verified\b", re.IGNORECASE),
]


def _load_system_prompt() -> str:
    """Reads system prompt from file if present, else returns fallback default."""
    if _INTENT_PROMPT_PATH.is_file():
        try:
            return _INTENT_PROMPT_PATH.read_text(encoding="utf-8")
        except Exception as err:
            logger.warning(f"Could not read intent prompt file: {type(err).__name__}")
    return _DEFAULT_SYSTEM_PROMPT


def _is_usable_key(key: Optional[str]) -> bool:
    """Checks whether an API key is present and not a dummy/placeholder value."""
    if not key:
        return False
    cleaned = key.strip()
    lower = cleaned.lower()
    if (
        not cleaned
        or lower.startswith("your_")
        or "dummy" in lower
        or "test" in lower
        or "fake" in lower
        or "placeholder" in lower
        or len(cleaned) < 20
    ):
        return False
    return True


def _run_heuristic_fallback(content: str) -> Tuple[float, DetectedIntentEnum, List[str], List[str], str]:
    """
    Fast, deterministic offline psycholinguistic heuristic engine (< 15ms SLA).
    Normalizes input text and scans for English and Hinglish fraud vectors.
    Returns: (risk_score, detected_intent, manipulation_tactics, flags, reasoning)
    """
    normalized = _normalize_text(content)
    risk_score = 0.0
    manipulation_tactics: List[str] = []
    flags: List[str] = []
    candidate_intents: List[DetectedIntentEnum] = []

    # 1. Panic & False Urgency (+40.0)
    has_urgency = any(p.search(normalized) for p in _PANIC_URGENCY_PATTERNS)
    if has_urgency:
        risk_score += 40.0
        manipulation_tactics.append("False Urgency Trigger")
        flags.append("PSYCHOLOGICAL_URGENCY_TRIGGER")
        candidate_intents.append(DetectedIntentEnum.PANIC_URGENCY)

    # 2. Coercive Authority & Legal Threats (+45.0)
    has_authority = any(p.search(normalized) for p in _COERCIVE_AUTHORITY_PATTERNS)
    if has_authority:
        risk_score += 45.0
        manipulation_tactics.append("Coercive Authority Threat")
        flags.append("AUTHORITY_COERCION_FLAG")
        candidate_intents.append(DetectedIntentEnum.FINANCIAL_EXTORTION)

    # 3. Credential & PII Harvesting (+45.0)
    has_credential = any(p.search(normalized) for p in _CREDENTIAL_HARVEST_PATTERNS)
    if has_credential:
        risk_score += 45.0
        manipulation_tactics.append("Credential / KYC Solicitation")
        if re.search(r"\botp\b", normalized, re.IGNORECASE):
            flags.append("OTP_HARVEST_FLAG")
            candidate_intents.append(DetectedIntentEnum.OTP_HARVEST)
        else:
            flags.append("UNVERIFIED_KYC_SOLICITATION")
            candidate_intents.append(DetectedIntentEnum.KYC_VERIFICATION)

    # 4. Lottery / Part-Time Job Advance Scams (+35.0)
    has_lottery = any(p.search(normalized) for p in _LOTTERY_JOB_PATTERNS)
    if has_lottery:
        risk_score += 35.0
        manipulation_tactics.append("Fraudulent Incentive / Advance Fee")
        flags.append("LOTTERY_JOB_SCAM_FLAG")
        candidate_intents.append(DetectedIntentEnum.LOTTERY_REWARD)

    # Determine final intent and score
    if manipulation_tactics:
        # Prioritize OTP > KYC > Extortion/Authority > Urgency > Lottery
        if DetectedIntentEnum.OTP_HARVEST in candidate_intents:
            final_intent = DetectedIntentEnum.OTP_HARVEST
        elif DetectedIntentEnum.KYC_VERIFICATION in candidate_intents:
            final_intent = DetectedIntentEnum.KYC_VERIFICATION
        elif DetectedIntentEnum.FINANCIAL_EXTORTION in candidate_intents:
            final_intent = DetectedIntentEnum.FINANCIAL_EXTORTION
        elif DetectedIntentEnum.PANIC_URGENCY in candidate_intents:
            final_intent = DetectedIntentEnum.PANIC_URGENCY
        elif DetectedIntentEnum.LOTTERY_REWARD in candidate_intents:
            final_intent = DetectedIntentEnum.LOTTERY_REWARD
        else:
            final_intent = DetectedIntentEnum.SUSPICIOUS

        reasoning = (
            f"Heuristic detection triggered {len(manipulation_tactics)} social engineering marker(s): "
            f"{', '.join(manipulation_tactics)}."
        )
    else:
        has_benign_marker = any(p.search(normalized) for p in _BENIGN_PATTERNS)
        final_intent = DetectedIntentEnum.BENIGN
        risk_score = 5.0 if has_benign_marker else 0.0
        if has_benign_marker:
            flags.append("STANDARD_TRANSACTIONAL_DISCLOSURE")
        reasoning = "Standard communication with no coercive demands or social engineering indicators observed."

    clamped_score = max(0.0, min(100.0, risk_score))
    return clamped_score, final_intent, manipulation_tactics, flags, reasoning


async def _analyze_with_groq(content: str, system_prompt: str, api_key: str) -> Optional[Dict[str, Any]]:
    """Invokes Groq LLaMA-3.1-8b-instant with JSON mode and 2.5s SLA timeout."""
    from groq import AsyncGroq

    client = AsyncGroq(api_key=api_key)
    chat_completion = await asyncio.wait_for(
        client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": content},
            ],
            model="llama-3.1-8b-instant",
            temperature=0.0,
            response_format={"type": "json_object"},
        ),
        timeout=LLM_TIMEOUT_SECONDS,
    )
    raw_text = chat_completion.choices[0].message.content
    if raw_text:
        try:
            return json.loads(raw_text)
        except json.JSONDecodeError as err:
            logger.warning(f"Groq returned malformed JSON: {err}")
            return None
    return None


async def _analyze_with_gemini(content: str, system_prompt: str, api_key: str) -> Optional[Dict[str, Any]]:
    """Invokes Google Gemini 1.5 Flash with JSON mode and 2.5s SLA timeout."""
    import google.generativeai as genai

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name="gemini-1.5-flash",
        system_instruction=system_prompt,
        generation_config={
            "response_mime_type": "application/json",
            "temperature": 0.0,
        },
    )
    response = await asyncio.wait_for(
        model.generate_content_async(content),
        timeout=LLM_TIMEOUT_SECONDS,
    )
    if response and response.text:
        try:
            return json.loads(response.text)
        except json.JSONDecodeError as err:
            logger.warning(f"Gemini returned malformed JSON: {err}")
            return None
    return None


def _parse_llm_json_result(data: Dict[str, Any]) -> IntentAgentResult:
    """Parses raw JSON from LLM into a validated IntentAgentResult."""
    raw_score = data.get("risk_score", 0.0)
    try:
        risk_score = float(raw_score)
    except (TypeError, ValueError):
        risk_score = 0.0
    risk_score = max(0.0, min(100.0, risk_score))

    intent_raw = str(data.get("detected_intent", "BENIGN")).strip().upper()
    try:
        detected_intent = DetectedIntentEnum(intent_raw)
    except ValueError:
        if "PANIC" in intent_raw or "URGENCY" in intent_raw:
            detected_intent = DetectedIntentEnum.PANIC_URGENCY
        elif "EXTORTION" in intent_raw or "ARREST" in intent_raw:
            detected_intent = DetectedIntentEnum.FINANCIAL_EXTORTION
        elif "LOTTERY" in intent_raw or "JOB" in intent_raw or "REWARD" in intent_raw:
            detected_intent = DetectedIntentEnum.LOTTERY_REWARD
        elif "KYC" in intent_raw:
            detected_intent = DetectedIntentEnum.KYC_VERIFICATION
        elif "OTP" in intent_raw:
            detected_intent = DetectedIntentEnum.OTP_HARVEST
        elif "BENIGN" in intent_raw or "SAFE" in intent_raw:
            detected_intent = DetectedIntentEnum.BENIGN
        else:
            detected_intent = DetectedIntentEnum.SUSPICIOUS

    tactics_raw = data.get("manipulation_tactics", [])
    if isinstance(tactics_raw, list):
        tactics = [str(t) for t in tactics_raw if t]
    elif tactics_raw:
        tactics = [str(tactics_raw)]
    else:
        tactics = []

    raw_conf = data.get("confidence", 0.90)
    try:
        confidence = float(raw_conf)
    except (TypeError, ValueError):
        confidence = 0.90
    confidence = max(0.0, min(1.0, confidence))

    flags_raw = data.get("flags", [])
    if isinstance(flags_raw, list):
        flags = [str(f) for f in flags_raw if f]
    elif flags_raw:
        flags = [str(flags_raw)]
    else:
        flags = []

    reasoning = str(data.get("reasoning", ""))
    details = str(data.get("details", "Analyzed via primary LLM engine"))

    return IntentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=risk_score,
        detected_intent=detected_intent,
        manipulation_tactics=tactics,
        confidence=confidence,
        flags=flags,
        reasoning=reasoning,
        details=details,
    )


async def analyze_intent(req: ScanRequest) -> IntentAgentResult:
    """
    Analyzes psycholinguistic manipulation vectors in incoming message text.

    Execution Flow (FR-11 Multi-LLM Priority & FR-6 Scam Taxonomy):
    1. Validates input request and handles empty/blank payloads gracefully.
    2. Runs CERT-In/RBI scam taxonomy keyword & cosine similarity matcher.
    3. Primary LLM: Google Gemini Flash (gemini-1.5-flash) with 2.5s SLA timeout.
    4. Secondary LLM: Groq LLaMA-3 (llama-3.1-8b-instant) with 2.5s SLA timeout.
    5. Offline Fallback: Local Resilient Heuristic Regex Engine (< 15ms SLA).
       When both LLMs fail: explicitly flags RULES_ONLY_FALLBACK with confidence set to LOW / 0.5.
    6. Clamps risk score to [0.0, 100.0] and records latency_ms.
    7. Fail-Safe: Guarantees zero unhandled exceptions.
    """
    start_time = time.perf_counter()

    try:
        # Guard: check empty or blank content
        if not req or not req.content or not req.content.strip():
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return IntentAgentResult(
                status=AgentStatusEnum.SKIPPED,
                risk_score=0.0,
                detected_intent=DetectedIntentEnum.BENIGN,
                manipulation_tactics=[],
                confidence=1.0,
                flags=[],
                reasoning="No message content provided for intent analysis.",
                details="Skipped: Empty content payload.",
                latency_ms=elapsed_ms,
            )

        content = req.content.strip()
        system_prompt = _load_system_prompt()
        taxonomy_match = match_scam_taxonomy(content)

        gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
        groq_key = os.getenv("GROQ_API_KEY", "").strip()

        llm_data: Optional[Dict[str, Any]] = None

        # 1. Primary: Google Gemini Flash (gemini-1.5-flash)
        if _is_usable_key(gemini_key):
            try:
                llm_data = await _analyze_with_gemini(content, system_prompt, gemini_key)
            except Exception as e:
                logger.warning(f"Primary LLM (Gemini) failed or timed out: {type(e).__name__}")

        # 2. Secondary: Groq LLaMA-3 (llama-3.1-8b-instant)
        if not llm_data and _is_usable_key(groq_key):
            try:
                llm_data = await _analyze_with_groq(content, system_prompt, groq_key)
            except Exception as e:
                logger.warning(f"Secondary LLM (Groq) failed or timed out: {type(e).__name__}")

        # If an LLM succeeded, parse and return
        if llm_data:
            result = _parse_llm_json_result(llm_data)
            result.latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            if taxonomy_match.get("category_name"):
                result.scam_category = taxonomy_match["category_name"]
                result.taxonomy_match_score = taxonomy_match["match_score"]
                result.flags.append(f"TAXONOMY:{taxonomy_match['category_id'].upper()}")
                result.details += (
                    f" | Taxonomy: {taxonomy_match['category_name']} "
                    f"({taxonomy_match['match_score']:.2f})"
                )
            return result

        # 3. Offline: Local Heuristic Regex Engine (< 15ms)
        # When both LLMs fail: explicitly flag RULES_ONLY_FALLBACK with confidence set to LOW / 0.5
        score, intent, tactics, flags, reasoning = _run_heuristic_fallback(content)
        flags.append("RULES_ONLY_FALLBACK")
        confidence = 0.5

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        details = "Analyzed via local resilient heuristic engine (RULES_ONLY_FALLBACK)"
        if taxonomy_match.get("category_name"):
            flags.append(f"TAXONOMY:{taxonomy_match['category_id'].upper()}")
            details += (
                f" | Taxonomy: {taxonomy_match['category_name']} "
                f"({taxonomy_match['match_score']:.2f})"
            )

        return IntentAgentResult(
            status=AgentStatusEnum.SUCCESS,
            risk_score=score,
            detected_intent=intent,
            manipulation_tactics=tactics,
            confidence=confidence,
            flags=flags,
            reasoning=reasoning,
            details=details,
            latency_ms=elapsed_ms,
            scam_category=taxonomy_match.get("category_name"),
            taxonomy_match_score=taxonomy_match.get("match_score"),
        )

    except Exception as exc:
        logger.error(f"Unhandled exception in analyze_intent: {type(exc).__name__}", exc_info=True)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        try:
            score, intent, tactics, flags, reasoning = _run_heuristic_fallback(req.content if req else "")
            flags.append("RULES_ONLY_FALLBACK")
            taxonomy_match = match_scam_taxonomy(req.content if req else "")
            return IntentAgentResult(
                status=AgentStatusEnum.SUCCESS,
                risk_score=score,
                detected_intent=intent,
                manipulation_tactics=tactics,
                confidence=0.5,
                flags=flags,
                reasoning=reasoning,
                details="Analyzed via local resilient heuristic engine (RULES_ONLY_FALLBACK)",
                latency_ms=elapsed_ms,
                scam_category=taxonomy_match.get("category_name"),
                taxonomy_match_score=taxonomy_match.get("match_score"),
            )
        except Exception:
            return IntentAgentResult(
                status=AgentStatusEnum.ERROR,
                risk_score=0.0,
                detected_intent=DetectedIntentEnum.BENIGN,
                manipulation_tactics=[],
                confidence=0.0,
                flags=["INTENT_AGENT_FAILED", "RULES_ONLY_FALLBACK"],
                reasoning=f"Agent exception: {type(exc).__name__}",
                details=f"ERROR: {type(exc).__name__}",
                latency_ms=elapsed_ms,
            )
