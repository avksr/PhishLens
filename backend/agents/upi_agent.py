"""
backend/agents/upi_agent.py
---------------------------
UPI VPA (Virtual Payment Address) Deception Detection Agent for PhishLens.

Responsibilities
----------------
1. Extract UPI VPA handles (user@psp) from message content or direct input.
2. Validate the PSP (Payment Service Provider) handle suffix against the
   official NPCI-registered PSP handle registry.
3. Detect deceptive patterns in the VPA username portion:
   - Brand/institution impersonation in the VPA username
     (e.g. "refund-desk@oksbi", "sbi-refund@okaxis", "hdfc-kyc@ybl").
   - Personal/consumer PSP handles used with commercial/institutional-sounding
     usernames (e.g. an "@ybl" handle — assigned to individual PhonePe users —
     presenting itself as an SBI refund desk).
   - Keyword patterns matching known Indian payment-scam vocabulary
     (refund, helpdesk, support, kyc, prize, lottery, reward, etc.).
4. Cross-validate: if a message claims affiliation with Bank X but the VPA
   resolves to a personal PSP of Bank Y (or a fintech handle), flag as HIGH RISK.
5. Return a fully-populated UpiAgentResult. NEVER raise an unhandled exception.

Author  : AVNI — Sender Identity & UPI Vector Validation
Module  : PhishLens v1.0
"""

from __future__ import annotations

import re
import time
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple

from shared.models import (
    AgentStatusEnum,
    ScanRequest,
    UpiAgentResult,
)

# ---------------------------------------------------------------------------
# UPI VPA Regex
# ---------------------------------------------------------------------------
# Standard UPI VPA format: <localpart>@<psp_handle>
# Local part: alphanumeric, dots, hyphens, underscores (3–256 chars)
# PSP handle: alphanumeric only (2–20 chars), NO dots or hyphens
_UPI_VPA_RE = re.compile(
    r"\b([a-zA-Z0-9.\-_]{1,256})@([a-zA-Z0-9]{2,20})\b"
)

# ---------------------------------------------------------------------------
# UPI Deep Link (Payment URI) Regex
# ---------------------------------------------------------------------------
# Matches the NPCI/BHIM UPI payment deep-link format:
#   upi://pay?pa=<vpa>&pn=<payee_name>&am=<amount>&...
# These appear in QR codes, WhatsApp links, and SMS messages sent by scammers.
# pa  = Payment Address (VPA)          — REQUIRED
# pn  = Payee Name (display name)       — optional but used for impersonation
# am  = Amount (pre-filled rupee value) — optional
_UPI_DEEPLINK_RE = re.compile(
    r"upi://pay\?[^\s\"'<>]{5,500}",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Bank / Utility Keywords for Payee-Name (pn) Impersonation Detection
# ---------------------------------------------------------------------------
# When a UPI deep link's pn parameter claims to be one of these institutions
# but the VPA (pa) is hosted on a consumer-only PSP handle (@ybl, @axl, @ibl)
# or a fintech handle, it is a near-certain merchant-spoofing attempt.
_BANK_UTILITY_KEYWORDS: Dict[str, str] = {
    # Major Indian banks
    "sbi": "State Bank of India",
    "state bank": "State Bank of India",
    "hdfc": "HDFC Bank",
    "icici": "ICICI Bank",
    "axis": "Axis Bank",
    "pnb": "Punjab National Bank",
    "kotak": "Kotak Mahindra Bank",
    "canara": "Canara Bank",
    "union bank": "Union Bank of India",
    "bank of baroda": "Bank of Baroda",
    "bob": "Bank of Baroda",
    "idbi": "IDBI Bank",
    "rbl": "RBL Bank",
    "idfc": "IDFC First Bank",
    "yes bank": "Yes Bank",
    "indian bank": "Indian Bank",
    # Government & fintech brands
    "uidai": "UIDAI (Aadhaar)",
    "aadhaar": "UIDAI (Aadhaar)",
    "epfo": "EPFO",
    "incometax": "Income Tax Department",
    "income tax": "Income Tax Department",
    "irctc": "IRCTC",
    "npci": "NPCI",
    "rbi": "Reserve Bank of India",
    "sebi": "SEBI",
    "government": "Government of India",
    "govt": "Government of India",
    "ministry": "Government of India",
    # Electricity DISCOMs
    "msedcl": "MSEDCL (Maharashtra Electricity)",
    "bescom": "BESCOM (Bangalore Electricity)",
    "tneb": "TNEB (Tamil Nadu Electricity)",
    "uppcl": "UPPCL (UP Electricity)",
    "discom": "Electricity DISCOM",
    "electricity": "Electricity Provider",
    "bijli": "Electricity Provider",
    # Courier / logistics
    "india post": "India Post",
    "bluedart": "BlueDart Express",
    "dtdc": "DTDC Courier",
    "delhivery": "Delhivery Courier",
    # Telecom
    "airtel": "Airtel",
    "jio": "Jio",
    "bsnl": "BSNL",
    # Payments platforms
    "paytm": "Paytm",
    "phonepe": "PhonePe",
    "googlepay": "Google Pay",
    "google pay": "Google Pay",
    "amazon pay": "Amazon Pay",
}

# ---------------------------------------------------------------------------
# NPCI-Registered PSP Handle Registry
# ---------------------------------------------------------------------------
# Maps PSP handle suffix → { psp_name, bank/entity, handle_type }
# handle_type:
#   "BANK"     — issued directly by a scheduled commercial bank to its customers
#   "FINTECH"  — issued by a fintech PSP (PhonePe, Paytm, GPay, etc.)
#   "PERSONAL" — typically consumer/individual accounts (not merchant/business)
#   "MERCHANT" — designated merchant/business PSP handles
#
# NOTE: All handles are lowercase in practice; we normalise to lower before lookup.
_PSP_REGISTRY: Dict[str, dict] = {
    # ── PhonePe (Yes Bank backend) ──
    "ybl": {
        "psp_name": "PhonePe",
        "entity": "PhonePe (Yes Bank backend)",
        "handle_type": "FINTECH",
        "legitimate_owners": ["PhonePe"],
        "note": (
            "@ybl is assigned to individual PhonePe users only; no bank or institution "
            "uses @ybl as their official VPA."
        ),
    },
    "axl": {
        "psp_name": "PhonePe (Axis Bank backend)",
        "entity": "PhonePe (Axis Bank backend)",
        "handle_type": "FINTECH",
        "legitimate_owners": ["PhonePe"],
        "note": "@axl is a PhonePe consumer handle on Axis Bank backend.",
    },
    "ibl": {
        "psp_name": "PhonePe (IndusInd Bank backend)",
        "entity": "PhonePe (IndusInd Bank backend)",
        "handle_type": "FINTECH",
        "legitimate_owners": ["PhonePe"],
    },
    # ── Google Pay (Bank Backends) ──
    "oksbi": {
        "psp_name": "Google Pay / SBI",
        "entity": "Google Pay / State Bank of India",
        "handle_type": "FINTECH",
        "legitimate_owners": ["Google Pay", "State Bank of India"],
    },
    "okhdfc": {
        "psp_name": "Google Pay / HDFC",
        "entity": "Google Pay / HDFC Bank",
        "handle_type": "FINTECH",
        "legitimate_owners": ["Google Pay", "HDFC Bank"],
    },
    "okhdfcbank": {
        "psp_name": "Google Pay / HDFC Bank",
        "entity": "Google Pay / HDFC Bank",
        "handle_type": "FINTECH",
        "legitimate_owners": ["Google Pay", "HDFC Bank"],
    },
    "okaxis": {
        "psp_name": "Google Pay / Axis",
        "entity": "Google Pay / Axis Bank",
        "handle_type": "FINTECH",
        "legitimate_owners": ["Google Pay", "Axis Bank"],
    },
    "okicici": {
        "psp_name": "Google Pay / ICICI",
        "entity": "Google Pay / ICICI Bank",
        "handle_type": "FINTECH",
        "legitimate_owners": ["Google Pay", "ICICI Bank"],
    },
    # ── Paytm ──
    "paytm": {
        "psp_name": "Paytm",
        "entity": "Paytm Payments Bank",
        "handle_type": "FINTECH",
        "legitimate_owners": ["Paytm"],

        "note": "@paytm is used exclusively by Paytm and its registered merchants.",
    },
    # ── Amazon Pay ──
    "apl": {
        "psp_name": "Amazon Pay",
        "entity": "Amazon Pay (Axis Bank backend)",
        "handle_type": "FINTECH",
        "legitimate_owners": ["Amazon Pay"],
    },
    # ── BHIM (NPCI) ──
    "upi": {
        "psp_name": "BHIM UPI / NPCI",
        "entity": "National Payments Corporation of India (NPCI)",
        "handle_type": "BANK",
        "legitimate_owners": ["NPCI", "BHIM"],
    },
    # ── NEFT/IMPS bank-native handles ──
    "sbi": {
        "psp_name": "SBI YONO UPI",
        "entity": "State Bank of India",
        "handle_type": "BANK",
        "legitimate_owners": ["State Bank of India"],
    },
    "hdfcbank": {
        "psp_name": "HDFC Bank UPI (Native)",
        "entity": "HDFC Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["HDFC Bank"],
    },
    "icici": {
        "psp_name": "ICICI Bank UPI (iMobile)",
        "entity": "ICICI Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["ICICI Bank"],
    },
    "axisbank": {
        "psp_name": "Axis Bank UPI (Native)",
        "entity": "Axis Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["Axis Bank"],
    },
    "pnb": {
        "psp_name": "PNB UPI",
        "entity": "Punjab National Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["Punjab National Bank"],
    },
    "kotak": {
        "psp_name": "Kotak UPI",
        "entity": "Kotak Mahindra Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["Kotak Mahindra Bank"],
    },
    "indus": {
        "psp_name": "IndusInd Bank UPI",
        "entity": "IndusInd Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["IndusInd Bank"],
    },
    "idbi": {
        "psp_name": "IDBI Bank UPI",
        "entity": "IDBI Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["IDBI Bank"],
    },
    "boi": {
        "psp_name": "Bank of India UPI",
        "entity": "Bank of India",
        "handle_type": "BANK",
        "legitimate_owners": ["Bank of India"],
    },
    "cnrb": {
        "psp_name": "Canara Bank UPI",
        "entity": "Canara Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["Canara Bank"],
    },
    "unionbank": {
        "psp_name": "Union Bank UPI",
        "entity": "Union Bank of India",
        "handle_type": "BANK",
        "legitimate_owners": ["Union Bank of India"],
    },
    "federal": {
        "psp_name": "Federal Bank UPI",
        "entity": "Federal Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["Federal Bank"],
    },
    "rbl": {
        "psp_name": "RBL Bank UPI",
        "entity": "RBL Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["RBL Bank"],
    },
    "idfcfirst": {
        "psp_name": "IDFC First Bank UPI",
        "entity": "IDFC First Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["IDFC First Bank"],
    },
    "airtel": {
        "psp_name": "Airtel Payments Bank UPI",
        "entity": "Airtel Payments Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["Airtel Payments Bank"],
    },
    "ippb": {
        "psp_name": "India Post Payments Bank UPI",
        "entity": "India Post Payments Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["India Post Payments Bank"],
    },
    "freecharge": {
        "psp_name": "FreeCharge (Axis Bank)",
        "entity": "FreeCharge / Axis Bank",
        "handle_type": "FINTECH",
        "legitimate_owners": ["FreeCharge"],
    },
    "citi": {
        "psp_name": "Citi Bank UPI",
        "entity": "Citibank India",
        "handle_type": "BANK",
        "legitimate_owners": ["Citibank"],
    },
    "hsbc": {
        "psp_name": "HSBC UPI",
        "entity": "HSBC India",
        "handle_type": "BANK",
        "legitimate_owners": ["HSBC"],
    },
    "jio": {
        "psp_name": "JioPay",
        "entity": "Reliance Jio / Jio Financial Services",
        "handle_type": "FINTECH",
        "legitimate_owners": ["Jio Financial Services"],
    },
}

# ---------------------------------------------------------------------------
# Fintech / Consumer-Only PSP Handles
# ---------------------------------------------------------------------------
# These handles are EXCLUSIVELY assigned to individual consumer accounts
# by fintech apps. Legitimate banks and official institutions NEVER use
# these handles as their VPA. Finding an institution-sounding local-part
# (e.g. "sbi-refund") before one of these is a near-certain scam signal.
_CONSUMER_ONLY_HANDLES: Set[str] = {
    "ybl",   # PhonePe (Yes Bank backend) — individual accounts only
    "axl",   # PhonePe (Axis Bank backend) — individual accounts only
    "ibl",   # PhonePe (IndusInd Bank backend) — individual accounts only
}

# ---------------------------------------------------------------------------
# Brand Keywords for Cross-Validation
# ---------------------------------------------------------------------------
# Maps a brand keyword (lowercase) → canonical institution name.
# Used to detect when a VPA local-part claims Brand X but the PSP handle
# belongs to a different bank (e.g. "sbi-refund@okaxis").
_BRAND_KEYWORDS: Dict[str, str] = {
    "sbi": "State Bank of India",
    "statebank": "State Bank of India",
    "hdfc": "HDFC Bank",
    "icici": "ICICI Bank",
    "axis": "Axis Bank",
    "axisbank": "Axis Bank",
    "pnb": "Punjab National Bank",
    "kotak": "Kotak Mahindra Bank",
    "paytm": "Paytm",
    "phonepe": "PhonePe",
    "googlepay": "Google Pay",
    "gpay": "Google Pay",
    "amazon": "Amazon Pay",
    "amzn": "Amazon Pay",
    "uidai": "UIDAI (Aadhaar)",
    "aadhaar": "UIDAI (Aadhaar)",
    "incometax": "Income Tax Department",
    "itdept": "Income Tax Department",
    "epfo": "EPFO",
    "irctc": "IRCTC",
    "npci": "NPCI",
    "bhim": "BHIM / NPCI",
    "rbi": "Reserve Bank of India",
    "sebi": "SEBI",
    "government": "Government",
    "govt": "Government",
    "police": "Police",
    "cbi": "CBI",
    "ippb": "India Post Payments Bank",
    "boi": "Bank of India",
    "bob": "Bank of Baroda",
    "canara": "Canara Bank",
    "union": "Union Bank of India",
    "federal": "Federal Bank",
    "idbi": "IDBI Bank",
    "rbl": "RBL Bank",
    "idfc": "IDFC First Bank",
    "airtel": "Airtel Payments Bank",
    "jio": "Jio Financial Services",
}

# ---------------------------------------------------------------------------
# Scam VPA Local-Part Keyword Patterns
# ---------------------------------------------------------------------------
# These patterns in the local-part (before @) are characteristic of
# Indian UPI payment scams. Scored by severity.
_SCAM_LOCALPART_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    # (compiled_regex, flag_name, risk_score_contribution)
    (re.compile(r"\b(refund|cashback|cash.?back)\b", re.I),
     "SCAM_KEYWORD_REFUND", 35.0),
    (re.compile(r"\b(helpdesk|help.?desk|support|customer.?care|care|assist)\b", re.I),
     "SCAM_KEYWORD_SUPPORT_DESK", 30.0),
    (re.compile(r"\b(kyc|kyc.?update|kyc.?verify)\b", re.I),
     "SCAM_KEYWORD_KYC", 35.0),
    (re.compile(r"\b(prize|reward|lottery|lucky|winner|won|gift)\b", re.I),
     "SCAM_KEYWORD_PRIZE_LOTTERY", 40.0),
    (re.compile(r"\b(verify|verification|authenticate)\b", re.I),
     "SCAM_KEYWORD_VERIFICATION", 20.0),
    (re.compile(r"\b(claim|claims|claimform)\b", re.I),
     "SCAM_KEYWORD_CLAIM", 25.0),
    (re.compile(r"\b(fraud|frauddesk|cyberdesk|cyber)\b", re.I),
     "SCAM_KEYWORD_FRAUD_DESK", 40.0),
    (re.compile(r"\b(govt|gov|government|ministry|minister|collector)\b", re.I),
     "SCAM_KEYWORD_GOVT_IMPERSONATION", 35.0),
    (re.compile(r"\b(police|cbi|ed|enforcement|court|legal)\b", re.I),
     "SCAM_KEYWORD_LAW_ENFORCEMENT", 45.0),
    (re.compile(r"\b(neft|imps|rtgs|transfer|send|receive)\b", re.I),
     "SCAM_KEYWORD_TRANSFER", 15.0),
    (re.compile(r"\b(tax|taxrefund|incometax|gst|duty)\b", re.I),
     "SCAM_KEYWORD_TAX", 30.0),
    (re.compile(r"\b(block|blocked|suspend|suspended|deactivate|deactivated|freeze|frozen)\b", re.I),
     "SCAM_KEYWORD_ACCOUNT_ACTION", 30.0),
    (re.compile(r"\b(otp|pin|password|secret|credential)\b", re.I),
     "SCAM_KEYWORD_CREDENTIAL_HARVEST", 40.0),
]

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _extract_vpas_from_text(text: str) -> List[Tuple[str, str]]:
    """
    Extract all UPI VPA candidates from free-form text.
    Returns a list of (local_part, psp_handle) tuples (both lowercased).
    """
    results: List[Tuple[str, str]] = []
    for m in _UPI_VPA_RE.finditer(text):
        local_part = m.group(1).lower()
        psp_handle = m.group(2).lower()
        results.append((local_part, psp_handle))
    return results


def _parse_upi_deeplink(text: str) -> Optional[Dict[str, str]]:
    """
    Search *text* for a UPI payment deep link (`upi://pay?...`) and parse
    the query parameters.  Returns a dict with keys:
        pa  — UPI VPA / payment address (always present if match found)
        pn  — payee display name (URL-decoded, may be absent)
        am  — pre-filled amount in INR (may be absent)
    Returns None if no deep link is found.

    Examples
    --------
    >>> _parse_upi_deeplink("Pay here: upi://pay?pa=refund-sbi@oksbi&pn=SBI%20Refund&am=1500")
    {'pa': 'refund-sbi@oksbi', 'pn': 'SBI Refund', 'am': '1500'}
    """
    match = _UPI_DEEPLINK_RE.search(text)
    if not match:
        return None
    # Extract the full matched URI and parse its query string.
    uri = match.group(0)
    # urllib.parse.urlparse handles the upi:// scheme.
    parsed = urllib.parse.urlparse(uri)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
    # parse_qs returns lists; take the first value for each key.
    result: Dict[str, str] = {}
    for key in ("pa", "pn", "am", "cu", "tn"):
        values = params.get(key)
        if values:
            result[key] = urllib.parse.unquote_plus(values[0])
    if "pa" not in result:
        return None  # pa (payment address) is mandatory
    return result


def _get_brand_from_payee_name(payee_name: str) -> Optional[str]:
    """
    Check whether a UPI deep-link payee name (pn parameter) claims to
    belong to a known bank, utility, or official institution.
    Returns the canonical institution name if found, else None.
    """
    pn_lower = payee_name.lower()
    for keyword, institution in _BANK_UTILITY_KEYWORDS.items():
        if keyword in pn_lower:
            return institution
    return None


def _get_brand_from_localpart(local_part: str) -> Optional[str]:
    """
    Scan the VPA local-part for any known brand/institution keyword.
    Returns the canonical brand name if found, else None.
    """
    for keyword, brand in _BRAND_KEYWORDS.items():
        if keyword in local_part:
            return brand
    return None


def _score_localpart_scam_keywords(local_part: str) -> Tuple[float, List[str]]:
    """
    Score the VPA local-part against known scam keyword patterns.
    Returns (cumulative_score, [flag_names]).
    """
    score = 0.0
    flags: List[str] = []
    for pattern, flag, contribution in _SCAM_LOCALPART_PATTERNS:
        if pattern.search(local_part):
            score += contribution
            flags.append(flag)
    return min(score, 60.0), flags  # Cap keyword score at 60


def _psp_belongs_to_brand(psp_handle: str, brand: str) -> bool:
    """
    Returns True if the given PSP handle legitimately belongs to the
    claimed brand/institution (per _PSP_REGISTRY).
    """
    entry = _PSP_REGISTRY.get(psp_handle)
    if not entry:
        return False
    owners = entry.get("legitimate_owners", [])
    brand_lower = brand.lower()
    return any(brand_lower in o.lower() or o.lower() in brand_lower for o in owners)


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


# ---------------------------------------------------------------------------
# Main Agent Function
# ---------------------------------------------------------------------------

async def analyze_upi(req: ScanRequest) -> UpiAgentResult:
    """
    UPI VPA Deception Detection Agent entry point.

    Extracts UPI handles from the scan request content/sender and applies
    multi-layer deception checks. Never raises; any unhandled exception
    returns an ERROR-status result.
    """
    t_start = time.perf_counter()
    try:
        result = await _run_upi_analysis(req, t_start)
    except Exception as exc:  # noqa: BLE001 — intentional fail-safe
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        result = UpiAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"UPI agent internal error: {exc}",
            latency_ms=round(latency_ms, 3),
        )
    return result


async def _run_upi_analysis(req: ScanRequest, t_start: float) -> UpiAgentResult:
    """Core UPI analysis pipeline — called inside try block in analyze_upi."""
    # ------------------------------------------------------------------
    # Step 0: UPI Deep Link (QR / Payment URI) Parsing
    # ------------------------------------------------------------------
    # Check for a upi://pay?... deep link FIRST — these appear in QR codes
    # and WhatsApp messages.  If found, we analyse the parsed parameters
    # (especially pn = payee name) before falling through to VPA scoring.
    # ------------------------------------------------------------------
    search_corpus = req.content
    if req.sender:
        search_corpus = req.sender + " " + search_corpus

    deeplink_result = _parse_upi_deeplink(search_corpus)
    if deeplink_result:
        vpa_from_link = deeplink_result["pa"].lower()
        payee_name = deeplink_result.get("pn", "")
        amount = deeplink_result.get("am", "")

        # Split the VPA into local-part and PSP handle for analysis.
        if "@" in vpa_from_link:
            dl_local, dl_psp = vpa_from_link.rsplit("@", 1)
        else:
            dl_local, dl_psp = vpa_from_link, ""

        dl_flags: List[str] = ["UPI_DEEPLINK_DETECTED"]
        dl_risk = 0.0

        # ── Deep-link Check A: Consumer-only handle with bank/utility payee name ──
        # e.g.  pn="SBI Refund" but pa=refund-sbi@ybl
        # Real banks never send payment requests via @ybl, @axl, or @ibl.
        if dl_psp in _CONSUMER_ONLY_HANDLES and payee_name:
            institution = _get_brand_from_payee_name(payee_name)
            if institution:
                dl_flags.append("DEEPLINK_PAYEE_NAME_IMPERSONATION")
                dl_flags.append("CONSUMER_HANDLE_INSTITUTIONAL_LOCALPART")
                dl_flags.append("DECEPTIVE_UPI_VPA_DETECTED")
                dl_risk += 75.0
                amount_note = (
                    f" The payment amount shown is ₹{amount}." if amount else ""
                )
                latency_ms = (time.perf_counter() - t_start) * 1000.0
                return UpiAgentResult(
                    status=AgentStatusEnum.SUCCESS,
                    risk_score=_clamp(dl_risk),
                    detected_vpa=vpa_from_link,
                    is_spoofed_merchant=True,
                    target_entity=institution,
                    flags=dl_flags,
                    details=(
                        f"⚠️ यह UPI लिंक खतरनाक है! / This UPI payment link is dangerous!\n\n"
                        f"इस लिंक में payee का नाम ('{payee_name}') '{institution}' का है, "
                        f"लेकिन असली payment address ('{vpa_from_link}') एक personal PhonePe "
                        f"account का है — जिसे कोई भी बैंक या सरकारी संस्था कभी इस्तेमाल नहीं करती।\n\n"
                        f"In plain English: The payment link shows the name '{payee_name}' "
                        f"(suggesting it belongs to '{institution}'), but the actual UPI address "
                        f"'{vpa_from_link}' belongs to a personal PhonePe account ('{dl_psp}'). "
                        f"No real bank or government body uses a personal PhonePe ID to collect money."
                        + amount_note +
                        " Do NOT pay — this is a common scam technique."
                    ),
                    latency_ms=round(latency_ms, 3),
                )

        # ── Deep-link Check B: Brand cross-validation (local-part vs PSP) ──
        brand_in_dl_local = _get_brand_from_localpart(dl_local)
        psp_entry_dl = _PSP_REGISTRY.get(dl_psp)
        if brand_in_dl_local and psp_entry_dl:
            if not _psp_belongs_to_brand(dl_psp, brand_in_dl_local):
                dl_flags.append("DEEPLINK_BRAND_MISMATCH_PSP_VS_LOCALPART")
                dl_flags.append("DECEPTIVE_UPI_VPA_DETECTED")
                dl_risk += 55.0
                psp_owner = psp_entry_dl.get("entity", dl_psp)
                amount_note = f" Amount shown: ₹{amount}." if amount else ""
                latency_ms = (time.perf_counter() - t_start) * 1000.0
                return UpiAgentResult(
                    status=AgentStatusEnum.SUCCESS,
                    risk_score=_clamp(dl_risk),
                    detected_vpa=vpa_from_link,
                    is_spoofed_merchant=True,
                    target_entity=brand_in_dl_local,
                    flags=dl_flags,
                    details=(
                        f"⚠️ इस UPI link का payment address संदेहास्पद है! / Suspicious UPI deep link detected!\n\n"
                        f"Payment address '{vpa_from_link}' में '{brand_in_dl_local}' का नाम है, "
                        f"लेकिन '@{dl_psp}' वास्तव में '{psp_owner}' से जुड़ा है।\n\n"
                        f"In plain English: The payment address claims to be '{brand_in_dl_local}', "
                        f"but the '@{dl_psp}' part of the address actually belongs to '{psp_owner}', "
                        f"not '{brand_in_dl_local}'. This mismatch is a classic scammer trick."
                        + amount_note
                    ),
                    latency_ms=round(latency_ms, 3),
                )

        # ── Deep-link Check C: Scam keywords in local-part ──
        kw_score_dl, kw_flags_dl = _score_localpart_scam_keywords(dl_local)
        if kw_score_dl >= 30.0:
            dl_flags.extend(kw_flags_dl)
            dl_flags.append("DEEPLINK_SUSPICIOUS_SCAM_PATTERN")
            dl_risk += kw_score_dl
            amount_note = f" Amount shown: ₹{amount}." if amount else ""
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return UpiAgentResult(
                status=AgentStatusEnum.SUCCESS,
                risk_score=_clamp(dl_risk),
                detected_vpa=vpa_from_link,
                is_spoofed_merchant=True,
                target_entity=None,
                flags=dl_flags,
                details=(
                    f"⚠️ यह UPI लिंक संदेहजनक है! / This UPI payment link looks suspicious!\n\n"
                    f"Payment address '{vpa_from_link}' में ऐसे शब्द हैं जो आमतौर पर "
                    f"धोखेबाज़ इस्तेमाल करते हैं (जैसे 'refund', 'helpdesk', 'reward')।\n\n"
                    f"In plain English: The UPI address '{vpa_from_link}' contains keywords "
                    f"commonly used in scams (such as 'refund', 'helpdesk', or 'reward'). "
                    f"Legitimate organisations do not use such words in their payment addresses."
                    + amount_note
                ),
                latency_ms=round(latency_ms, 3),
            )

        # Deep link found but no strong deceptive signal — note it and fall through.
        flags.append("UPI_DEEPLINK_DETECTED")

    # ------------------------------------------------------------------
    # Step 1: Extract VPA candidates from content + sender field
    # ------------------------------------------------------------------
    vpa_candidates = _extract_vpas_from_text(search_corpus)

    if not vpa_candidates:
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        return UpiAgentResult(
            status=AgentStatusEnum.SKIPPED,
            risk_score=0.0,
            details=(
                "इस संदेश में कोई UPI payment address (जैसे someone@bankname) नहीं मिला। / "
                "No UPI payment address was found in this message."
            ),
            latency_ms=round(latency_ms, 3),
        )

    # ------------------------------------------------------------------
    # Step 2: Analyse the highest-risk VPA candidate
    #         (we score all and return the worst-case result)
    # ------------------------------------------------------------------
    best_result: Optional[UpiAgentResult] = None
    best_score = -1.0

    for local_part, psp_handle in vpa_candidates:
        vpa_full = f"{local_part}@{psp_handle}"
        candidate_flags: List[str] = []
        risk_score = 0.0

        psp_entry = _PSP_REGISTRY.get(psp_handle)

        # ── Check 1: Unregistered / Unknown PSP handle ──────────────────
        if psp_entry is None:
            candidate_flags.append("UNREGISTERED_PSP_HANDLE")
            risk_score += 25.0
            psp_label = f"Unknown PSP (@{psp_handle})"
        else:
            psp_label = psp_entry["psp_name"]

        # ── Check 2: Consumer-Only Handle with Institutional-Sounding Local Part ──
        # e.g. "sbi-refund-desk@ybl" — @ybl is ONLY for PhonePe individual users.
        if psp_handle in _CONSUMER_ONLY_HANDLES:
            brand_in_local = _get_brand_from_localpart(local_part)
            if brand_in_local:
                candidate_flags.append("CONSUMER_HANDLE_INSTITUTIONAL_LOCALPART")
                candidate_flags.append("DECEPTIVE_UPI_VPA_DETECTED")
                risk_score += 60.0
                # This is a very high-confidence deceptive signal — short-circuit.
                candidate_score = _clamp(risk_score)
                latency_ms = (time.perf_counter() - t_start) * 1000.0
                return UpiAgentResult(
                    status=AgentStatusEnum.SUCCESS,
                    risk_score=candidate_score,
                    detected_vpa=vpa_full,
                    is_spoofed_merchant=True,
                    target_entity=brand_in_local,
                    flags=candidate_flags,
                    details=(
                        f"⚠️ यह UPI address धोखाधड़ी का संकेत है! / This UPI address is a fraud signal!\n\n"
                        f"'{vpa_full}' में '@' से पहले का हिस्सा '{brand_in_local}' का नाम दर्शाता है, "
                        f"लेकिन '@{psp_handle}' एक personal PhonePe account का address है — "
                        f"जिसे कोई भी बैंक या सरकारी संस्था कभी उपयोग नहीं करती।\n\n"
                        f"In plain English: The UPI address '{vpa_full}' pretends to belong to "
                        f"'{brand_in_local}', but '@{psp_handle}' is exclusively assigned to "
                        f"personal PhonePe user accounts — no real bank or institution ever "
                        f"uses this handle. This is one of the most common tricks used by "
                        f"online fraudsters in India. Do NOT send money to this address."
                    ),
                    latency_ms=round(latency_ms, 3),
                )

        # ── Check 3: Brand cross-validation ─────────────────────────────
        # Does the local-part claim Bank X while the PSP belongs to Bank Y?
        brand_claimed_in_local = _get_brand_from_localpart(local_part)
        if brand_claimed_in_local and psp_entry:
            if not _psp_belongs_to_brand(psp_handle, brand_claimed_in_local):
                candidate_flags.append("BRAND_MISMATCH_PSP_VS_LOCALPART")
                candidate_flags.append("DECEPTIVE_UPI_VPA_DETECTED")
                risk_score += 50.0
                psp_owner = psp_entry.get("entity", psp_handle)
                candidate_score = _clamp(risk_score)
                latency_ms = (time.perf_counter() - t_start) * 1000.0
                return UpiAgentResult(
                    status=AgentStatusEnum.SUCCESS,
                    risk_score=candidate_score,
                    detected_vpa=vpa_full,
                    is_spoofed_merchant=True,
                    target_entity=brand_claimed_in_local,
                    flags=candidate_flags,
                    details=(
                        f"⚠️ इस UPI address में बैंक का नाम गलत तरीके से इस्तेमाल किया गया है! / "
                        f"Misleading UPI address detected!\n\n"
                        f"'{vpa_full}' में '{brand_claimed_in_local}' का नाम है, लेकिन "
                        f"'@{psp_handle}' वास्तव में '{psp_owner}' से संबंधित है, "
                        f"'{brand_claimed_in_local}' से नहीं।\n\n"
                        f"In plain English: The UPI address '{vpa_full}' uses the name of "
                        f"'{brand_claimed_in_local}', but the '@{psp_handle}' part actually "
                        f"belongs to '{psp_owner}'. The real '{brand_claimed_in_local}' would "
                        f"always use their own registered UPI handle — never one from a "
                        f"different bank or service. This is a classic impersonation scam."
                    ),
                    latency_ms=round(latency_ms, 3),
                )

        # ── Check 4: Scam keyword scoring in local-part ──────────────────
        kw_score, kw_flags = _score_localpart_scam_keywords(local_part)
        if kw_score > 0:
            risk_score += kw_score
            candidate_flags.extend(kw_flags)
            if kw_score >= 30.0:
                candidate_flags.append("SUSPICIOUS_SCAM_PATTERN_IN_VPA")

        # ── Check 5: Numeric-heavy local-part (money-mule style handles) ─
        digit_ratio = sum(c.isdigit() for c in local_part) / max(len(local_part), 1)
        if digit_ratio > 0.6:
            candidate_flags.append("NUMERIC_HEAVY_LOCALPART_SUSPICIOUS")
            risk_score += 10.0

        # ── Compute candidate risk score ─────────────────────────────────
        final_score = _clamp(risk_score)

        if final_score > best_score:
            best_score = final_score
            # Build the appropriate details string
            if final_score < 20.0:
                details_str = (
                    f"✅ '{vpa_full}' UPI address '{psp_label}' के साथ registered है "
                    f"और कोई संदेहास्पद pattern नहीं मिला। / "
                    f"The UPI address '{vpa_full}' is registered with '{psp_label}'. "
                    "No suspicious patterns were detected. This address appears safe."
                )
                is_spoofed = False
                target_ent = None
            else:
                # Translate flag names to citizen-friendly phrases
                friendly_reasons = []
                for flag in candidate_flags:
                    if flag == "UNREGISTERED_PSP_HANDLE":
                        friendly_reasons.append("unrecognised payment service provider")
                    elif flag == "SCAM_KEYWORD_REFUND":
                        friendly_reasons.append("'refund' keyword commonly used in fraud")
                    elif flag == "SCAM_KEYWORD_SUPPORT_DESK":
                        friendly_reasons.append("'helpdesk/support' keyword — scammers pose as customer care")
                    elif flag == "SCAM_KEYWORD_KYC":
                        friendly_reasons.append("'KYC' keyword — a top trigger for UPI scams")
                    elif flag == "SCAM_KEYWORD_PRIZE_LOTTERY":
                        friendly_reasons.append("prize/lottery/reward claim — almost always a scam")
                    elif flag == "SCAM_KEYWORD_GOVT_IMPERSONATION":
                        friendly_reasons.append("government name used — verify through official channels only")
                    elif flag == "SCAM_KEYWORD_LAW_ENFORCEMENT":
                        friendly_reasons.append("police/court name used — a pressure tactic by fraudsters")
                    elif flag == "NUMERIC_HEAVY_LOCALPART_SUSPICIOUS":
                        friendly_reasons.append("mostly numbers in the address — typical of temporary mule accounts")
                    elif flag == "SUSPICIOUS_SCAM_PATTERN_IN_VPA":
                        friendly_reasons.append("overall pattern matches known scam UPI addresses")
                    else:
                        friendly_reasons.append(flag.replace("_", " ").lower())
                details_str = (
                    f"⚠️ '{vpa_full}' (payment service: {psp_label}) "
                    f"में कुछ संदेहास्पद संकेत मिले हैं। / "
                    f"The UPI address '{vpa_full}' (via {psp_label}) shows warning signs:\n"
                    + "\n".join(f"  • {r}" for r in friendly_reasons) +
                    "\n\nतुरंत भुगतान न करें — पहले इस address की जाँच करें। / "
                    "Do NOT pay immediately — verify this address before sending any money."
                )
                is_spoofed = bool(candidate_flags)
                target_ent = brand_claimed_in_local

            best_result = UpiAgentResult(
                status=AgentStatusEnum.SUCCESS,
                risk_score=final_score,
                detected_vpa=vpa_full,
                is_spoofed_merchant=is_spoofed,
                target_entity=target_ent,
                flags=candidate_flags,
                details=details_str,
                latency_ms=0.0,  # will be set below
            )

    # ------------------------------------------------------------------
    # Return highest-risk result
    # ------------------------------------------------------------------
    if best_result is None:
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        return UpiAgentResult(
            status=AgentStatusEnum.SKIPPED,
            risk_score=0.0,
            details=(
                "इस संदेश में एक UPI address मिला लेकिन उसे score नहीं किया जा सका। "
                "कृपया manually जाँचें। / "
                "A UPI address was found but could not be fully analysed. "
                "Please verify this address manually before making any payment."
            ),
            latency_ms=round(latency_ms, 3),
        )

    latency_ms = (time.perf_counter() - t_start) * 1000.0
    best_result.latency_ms = round(latency_ms, 3)
    return best_result
