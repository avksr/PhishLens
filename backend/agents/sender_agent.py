"""
backend/agents/sender_agent.py
-------------------------------
Sender Identity & TRAI DLT Verification Agent for PhishLens (ScamShield AI).

Responsibilities
----------------
1. Extract and normalise the sender identifier from a ScanRequest.
2. Validate against the TRAI DLT certified header registry.
3. Detect personal-GSM-number bank impersonation (high-risk scam pattern).
4. Flag lookalike / spoofed alphabetic headers.
5. Return a fully-populated SenderAgentResult, NEVER raise an unhandled
   exception (fail-safe design).

Author  : AVNI — Sender Identity & TRAI DLT Agent
Module  : PhishLens v1.0
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from shared.models import (
    AgentStatusEnum,
    ScanRequest,
    SenderAgentResult,
    SenderCategoryEnum,
)

# ---------------------------------------------------------------------------
# Constants & Pre-compiled Patterns
# ---------------------------------------------------------------------------

# Absolute path to the TRAI DLT registry data file.
_REGISTRY_PATH: Path = Path(__file__).resolve().parents[1] / "data" / "trai_dlt_registry.json"

# Official TRAI DLT header format: <2-letter operator>-<6-letter entity code>
# Examples: VM-SBIINB, AX-HDFCBK, AD-ICICIB, VK-PNBSMS
_TRAI_HEADER_RE = re.compile(r"^([A-Z]{2})-([A-Z]{6})$")

# Lookalike header: alphanumeric string with a hyphen that looks brand-related
# but does NOT match the strict TRAI DLT pattern.
# Examples: SBI-ALERT, HDFC-SEC, KOTAK-KYC, PAYTM-OTP
_LOOKALIKE_HEADER_RE = re.compile(r"^[A-Z0-9]{2,10}-[A-Z0-9]{2,10}$")

# Standard Indian 10-digit personal/commercial GSM mobile number.
_INDIAN_GSM_RE = re.compile(r"^[6-9]\d{9}$")

# Phone number embedded in message body (e.g. "call 9876543210" or "+91 98765 43210")
_EMBEDDED_PHONE_RE = re.compile(
    r"(?:call|contact|helpline|reach|dial|whatsapp)\s*[:\-]?\s*"
    r"(?:\+91[\s-]?)?([6-9]\d{4}[\s-]?\d{5})"
    r"|(?<!\d)(\+91[\s-]?)?([6-9]\d{9})(?!\d)",
    re.IGNORECASE,
)

# Country-code prefixes to strip from phone numbers before classification.
_CC_STRIP_RE = re.compile(r"^(?:\+91|91)(\d{10})$")

# Keywords that indicate a message is claiming official bank / government origin.
_BANKING_KEYWORDS: List[Tuple[str, str]] = [
    ("SBI", "State Bank of India"),
    ("State Bank", "State Bank of India"),
    ("HDFC", "HDFC Bank"),
    ("ICICI", "ICICI Bank"),
    ("Axis Bank", "Axis Bank"),
    ("PNB", "Punjab National Bank"),
    ("Kotak", "Kotak Mahindra Bank"),
    ("Bank of Baroda", "Bank of Baroda"),
    ("Canara Bank", "Canara Bank"),
    ("Yes Bank", "Yes Bank"),
    ("IDBI", "IDBI Bank"),
    ("Union Bank", "Union Bank of India"),
    ("Indian Bank", "Indian Bank"),
    ("UCO Bank", "UCO Bank"),
    ("Paytm", "Paytm Payments Bank"),
    ("PhonePe", "PhonePe"),
]

_GOVT_KEYWORDS: List[Tuple[str, str]] = [
    ("Aadhaar", "UIDAI (Aadhaar Authority)"),
    ("PAN card", "Income Tax / NSDL"),
    ("PAN Card", "Income Tax / NSDL"),
    ("Income Tax", "Income Tax Department"),
    ("Electricity Bill", "Electricity Provider"),
    ("Power cut", "Electricity Provider"),
    ("Challan", "Government / Traffic Authority"),
    ("GSTN", "GSTN (GST Network)"),
    ("EPF", "EPFO"),
    ("EPFO", "EPFO"),
]

_ALL_OFFICIAL_KEYWORDS = _BANKING_KEYWORDS + _GOVT_KEYWORDS


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _load_registry() -> dict:
    """Load and return the TRAI DLT registry JSON.  Raises on I/O failure."""
    with _REGISTRY_PATH.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("registry", {})


def _strip_country_code(phone: str) -> str:
    """Remove leading +91 / 91 to yield a plain 10-digit number."""
    phone = phone.replace(" ", "").replace("-", "")
    match = _CC_STRIP_RE.match(phone)
    return match.group(1) if match else phone


def _sanitise_sender(raw: str) -> str:
    """
    Normalise a raw sender string:
    - Strip leading/trailing whitespace.
    - Remove embedded hyphens for phone-number candidates only (e.g. +91-98765-43210).
    - Strip country-code prefix (+91 / 91) for numeric senders.
    - Uppercase alphabetic sender headers.
    """
    raw = raw.strip()
    # If purely numeric after stripping country code, normalise to 10 digits.
    stripped = _strip_country_code(raw)
    if stripped.isdigit():
        return stripped
    # Alphabetic/alphanumeric header — uppercase and strip whitespace only.
    return raw.upper().strip()


def _extract_phone_from_content(content: str) -> Optional[str]:
    """
    Scan message body for an embedded phone number.
    Returns the first 10-digit candidate found, or None.
    """
    for match in _EMBEDDED_PHONE_RE.finditer(content):
        # Groups: (keyword-prefixed number, cc, bare number)
        candidate = match.group(1) or match.group(3)
        if candidate:
            candidate = candidate.replace(" ", "").replace("-", "")
            candidate = _strip_country_code(candidate)
            if _INDIAN_GSM_RE.match(candidate):
                return candidate
    return None


def _detect_official_keyword(content: str) -> Optional[str]:
    """
    Scan message body for banking / government authority keywords.
    Returns the brand name of the first match, or None.
    """
    for keyword, brand in _ALL_OFFICIAL_KEYWORDS:
        if keyword.lower() in content.lower():
            return brand
    return None


def _clamp_score(score: float) -> float:
    """Ensure risk_score stays within [0.0, 100.0]."""
    return max(0.0, min(100.0, score))


# ---------------------------------------------------------------------------
# Main Agent Function
# ---------------------------------------------------------------------------

async def analyze_sender(req: ScanRequest) -> SenderAgentResult:
    """
    Sender Identity & TRAI DLT Verification Agent entry point.

    Parameters
    ----------
    req : ScanRequest
        The inbound scan request containing the message content and
        optional sender identifier.

    Returns
    -------
    SenderAgentResult
        A fully-populated result object.  This function NEVER raises;
        any unhandled exception is caught and returned as an ERROR status.
    """
    t_start = time.perf_counter()

    try:
        result = await _run_analysis(req, t_start)
    except Exception as exc:  # noqa: BLE001  — intentional fail-safe
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        result = SenderAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=str(exc),
            latency_ms=round(latency_ms, 3),
        )

    return result


async def _run_analysis(req: ScanRequest, t_start: float) -> SenderAgentResult:
    """Core analysis logic — called by analyze_sender inside the try block."""

    flags: List[str] = []

    # ------------------------------------------------------------------
    # Step 1: Sender Extraction & Normalisation
    # ------------------------------------------------------------------
    raw_sender: Optional[str] = req.sender

    if raw_sender:
        normalised = _sanitise_sender(raw_sender)
    else:
        # Attempt to extract a phone number from the message body.
        extracted = _extract_phone_from_content(req.content)
        if extracted:
            raw_sender = extracted
            normalised = extracted
        else:
            # No sender metadata whatsoever — return early.
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.UNKNOWN,
                risk_score=20.0,
                details="No sender metadata provided",
                latency_ms=round(latency_ms, 3),
                raw_sender=None,
                normalised_sender=None,
            )

    # ------------------------------------------------------------------
    # Step 2: TRAI DLT Certified Header Validation
    # ------------------------------------------------------------------
    trai_match = _TRAI_HEADER_RE.match(normalised)
    if trai_match:
        operator_prefix = trai_match.group(1)   # e.g. "VM"
        entity_code = trai_match.group(2)        # e.g. "SBIINB"

        registry = _load_registry()
        entry = registry.get(entity_code)

        if entry and operator_prefix in entry.get("operator_prefixes", []):
            # Fully verified TRAI DLT sender.
            flags.append("VERIFIED_TRAI_DLT_SENDER_HEADER")
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.OFFICIAL_TRAI_HEADER,
                risk_score=_clamp_score(5.0),
                brand_claimed=entry["brand_name"],
                is_spoofed_header=False,
                flags=flags,
                details=(
                    f"Sender '{normalised}' is a verified TRAI DLT certified header "
                    f"for '{entry['brand_name']}' ({entry['category']})."
                ),
                latency_ms=round(latency_ms, 3),
                raw_sender=raw_sender,
                normalised_sender=normalised,
            )

        # Header matches TRAI syntax but entity code not in registry —
        # treat as unverified / potentially spoofed.
        flags.append("UNREGISTERED_TRAI_FORMAT_HEADER")
        # Falls through to lookalike detection below with elevated risk.

    # ------------------------------------------------------------------
    # Step 3: Personal GSM Bank Impersonation Detection
    # ------------------------------------------------------------------
    if _INDIAN_GSM_RE.match(normalised):
        brand = _detect_official_keyword(req.content)
        if brand:
            flags.append("COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM")
            flags.append("MISSING_TRAI_OFFICIAL_HEADER")
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.PERSONAL_GSM,
                risk_score=_clamp_score(85.0),
                brand_claimed=brand,
                is_spoofed_header=False,
                flags=flags,
                details=(
                    "Legitimate financial institutions in India are mandated by TRAI "
                    "to send alerts from certified alphabetic DLT headers, never "
                    "personal 10-digit numbers."
                ),
                latency_ms=round(latency_ms, 3),
                raw_sender=raw_sender,
                normalised_sender=normalised,
            )

        # Plain personal GSM number with no suspicious content.
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        return SenderAgentResult(
            status=AgentStatusEnum.SUCCESS,
            sender_category=SenderCategoryEnum.PERSONAL_GSM,
            risk_score=_clamp_score(40.0),
            flags=flags,
            details="Sender is a personal Indian GSM number with no official brand claims detected.",
            latency_ms=round(latency_ms, 3),
            raw_sender=raw_sender,
            normalised_sender=normalised,
        )

    # ------------------------------------------------------------------
    # Step 4: Lookalike / Spoofed Header Detection
    # ------------------------------------------------------------------
    if _LOOKALIKE_HEADER_RE.match(normalised):
        flags.append("UNVERIFIED_LOOKALIKE_HEADER")
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        return SenderAgentResult(
            status=AgentStatusEnum.SUCCESS,
            sender_category=SenderCategoryEnum.LOOKALIKE_HEADER,
            risk_score=_clamp_score(75.0),
            is_spoofed_header=True,
            flags=flags,
            details=(
                f"Sender header '{normalised}' appears to mimic a brand name but "
                "does not conform to the TRAI DLT certified header syntax "
                "(^[A-Z]{2}-[A-Z]{6}$) and is NOT found in the DLT registry."
            ),
            latency_ms=round(latency_ms, 3),
            raw_sender=raw_sender,
            normalised_sender=normalised,
        )

    # ------------------------------------------------------------------
    # Step 5: Fallback — Unrecognised sender format
    # ------------------------------------------------------------------
    latency_ms = (time.perf_counter() - t_start) * 1000.0
    return SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        sender_category=SenderCategoryEnum.UNKNOWN,
        risk_score=_clamp_score(30.0),
        flags=flags,
        details=f"Sender '{normalised}' does not match any known classification pattern.",
        latency_ms=round(latency_ms, 3),
        raw_sender=raw_sender,
        normalised_sender=normalised,
    )
