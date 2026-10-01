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
    # ── State Bank of India ──
    "oksbi": {
        "psp_name": "SBI Pay",
        "entity": "State Bank of India",
        "handle_type": "BANK",
        "legitimate_owners": ["State Bank of India"],
    },
    # ── HDFC Bank ──
    "okhdfc": {
        "psp_name": "HDFC Bank UPI",
        "entity": "HDFC Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["HDFC Bank"],
    },
    # ── ICICI Bank ──
    "okicici": {
        "psp_name": "ICICI Bank UPI",
        "entity": "ICICI Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["ICICI Bank"],
    },
    # ── Axis Bank ──
    "okaxis": {
        "psp_name": "Axis Pay",
        "entity": "Axis Bank",
        "handle_type": "BANK",
        "legitimate_owners": ["Axis Bank"],
    },
    # ── PhonePe (Yes Bank backend) ──
    "ybl": {
        "psp_name": "PhonePe",
        "entity": "PhonePe (Yes Bank backend)",
        "handle_type": "FINTECH",
        "legitimate_owners": ["PhonePe"],
        "note": "@ybl is assigned to individual PhonePe users only; no bank or institution uses @ybl as their official VPA.",
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
    # ── Google Pay ──
    "oksbi": {
        "psp_name": "Google Pay / SBI",
        "entity": "Google Pay / State Bank of India",
        "handle_type": "FINTECH",
        "legitimate_owners": ["Google Pay", "State Bank of India"],
    },
    "okhdfcbank": {
        "psp_name": "Google Pay / HDFC",
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

    flags: List[str] = []

    # ------------------------------------------------------------------
    # Step 1: Extract VPA candidates from content + sender field
    # ------------------------------------------------------------------
    search_corpus = req.content
    if req.sender:
        search_corpus = req.sender + " " + search_corpus

    vpa_candidates = _extract_vpas_from_text(search_corpus)

    if not vpa_candidates:
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        return UpiAgentResult(
            status=AgentStatusEnum.SKIPPED,
            risk_score=0.0,
            details="No UPI payment address (like someone@bankname) was found in this message.",
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
                # Build a detailed explanation
                note = (psp_entry or {}).get(
                    "note",
                    f"@{psp_handle} is assigned to individual consumer accounts only — "
                    "official banks and institutions do NOT use this PSP handle."
                )
                explanation = (
                    f"The UPI address '{vpa_full}' is suspicious. "
                    f"The part before '@' suggests it belongs to '{brand_in_local}', "
                    f"but '@{psp_handle}' is a handle assigned exclusively to personal "
                    "PhonePe user accounts — it is never used by any bank or "
                    "official institution. This is a common trick used by scammers."
                )
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
                    details=explanation,
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
                explanation = (
                    f"The UPI address '{vpa_full}' claims to be from '{brand_claimed_in_local}', "
                    f"but the '@{psp_handle}' part of the address actually belongs to "
                    f"'{psp_owner}', not '{brand_claimed_in_local}'. "
                    f"The real {brand_claimed_in_local} would use their own payment address, "
                    f"not one registered to a different bank or service."
                )
                candidate_score = _clamp(risk_score)
                latency_ms = (time.perf_counter() - t_start) * 1000.0
                return UpiAgentResult(
                    status=AgentStatusEnum.SUCCESS,
                    risk_score=candidate_score,
                    detected_vpa=vpa_full,
                    is_spoofed_merchant=True,
                    target_entity=brand_claimed_in_local,
                    flags=candidate_flags,
                    details=explanation,
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
                    f"The UPI address '{vpa_full}' is registered with '{psp_label}'. "
                    "No suspicious patterns were detected."
                )
                is_spoofed = False
                target_ent = None
            else:
                details_str = (
                    f"The UPI address '{vpa_full}' (payment service: {psp_label}) "
                    "shows warning signs that it may be fraudulent. "
                    "Reasons: " + ", ".join(
                        flag.replace("_", " ").lower() for flag in candidate_flags
                    ) + "."
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
            details="A UPI address was found but it could not be scored. Please review manually.",
            latency_ms=round(latency_ms, 3),
        )

    latency_ms = (time.perf_counter() - t_start) * 1000.0
    best_result.latency_ms = round(latency_ms, 3)
    return best_result
