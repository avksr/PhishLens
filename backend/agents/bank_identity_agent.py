"""
backend/agents/bank_identity_agent.py
-------------------------------------
Bank Identity & UPI Name Match Verification Agent for PhishLens (ScamShield AI).

Responsibilities:
1. Cross-validate claimed identity (from message text, Vikas's IntentAgent,
   or UPI payee display name) against the actual bank-registered account name.
2. Utilize `rapidfuzz` (with pure-Python token sort ratio fallback) to compute
   fuzzy name match scores between claimed identity and official registered identity.
3. Query `UpiVerifier` interface (Mock by default, RapidAPI optional via config).
4. Emit evidence carrying `provider: "SANDBOX_MOCK"` (or "RAPIDAPI") for UI
   attribution and simulated badges.
5. Flag impersonation when institutional claims (e.g. "SBI", "HDFC", "Electricity Dept")
   resolve to individual personal or mule bank accounts.

Author  : AVNI — Sender Identity, Email & UPI Intelligence
Module  : PhishLens v1.0
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from agents.upi_verifier import UpiVerificationResult, UpiVerifier, get_upi_verifier
from shared.models import EvidenceItem

# ---------------------------------------------------------------------------
# rapidfuzz Import with Pure-Python Resilient Fallback
# ---------------------------------------------------------------------------
try:
    from rapidfuzz import fuzz
    _HAS_RAPIDFUZZ = True
except ImportError:
    _HAS_RAPIDFUZZ = False


def _token_sort_ratio_fallback(s1: str, s2: str) -> float:
    """
    Pure-Python token sort ratio fallback for environments where rapidfuzz
    is not installed. Guarantees 0-100 score compatibility.
    """
    t1 = sorted(re.findall(r"\w+", s1.lower()))
    t2 = sorted(re.findall(r"\w+", s2.lower()))
    joined1 = " ".join(t1)
    joined2 = " ".join(t2)
    if not joined1 and not joined2:
        return 100.0
    if not joined1 or not joined2:
        return 0.0
    if joined1 == joined2:
        return 100.0

    # Jaccard + Character Overlap heuristic
    set1, set2 = set(t1), set(t2)
    intersection = set1.intersection(set2)
    union = set1.union(set2)
    jaccard = len(intersection) / max(len(union), 1)

    # Bigram similarity
    def get_bigrams(s: str) -> set:
        return set(s[i:i + 2] for i in range(len(s) - 1)) if len(s) > 1 else {s}

    bg1 = get_bigrams(joined1)
    bg2 = get_bigrams(joined2)
    bg_sim = (2.0 * len(bg1.intersection(bg2))) / max(len(bg1) + len(bg2), 1)

    score = (0.5 * jaccard + 0.5 * bg_sim) * 100.0
    return max(0.0, min(100.0, score))


def compute_fuzzy_name_match(claimed: str, registered: str) -> float:
    """
    Calculate fuzzy match score (0.0 to 100.0) between claimed and registered names.
    Uses rapidfuzz.fuzz.token_sort_ratio if available, otherwise resilient fallback.
    """
    c = claimed.strip()
    r = registered.strip()
    if not c or not r:
        return 0.0

    if _HAS_RAPIDFUZZ:
        # Use maximum of token_sort_ratio and token_set_ratio to handle
        # bank account descriptors (e.g., 'STATE BANK OF INDIA - COLLECT').
        return float(max(fuzz.token_sort_ratio(c, r), fuzz.token_set_ratio(c, r)))
    else:
        return _token_sort_ratio_fallback(c, r)


# ---------------------------------------------------------------------------
# Canonical Bank / Institution Alias Mapping
# ---------------------------------------------------------------------------
BANK_EXPANSIONS: Dict[str, List[str]] = {
    "sbi": ["STATE BANK OF INDIA", "SBI", "STATE BANK"],
    "hdfc": ["HDFC BANK", "HDFC BANK LIMITED", "HDFC"],
    "icici": ["ICICI BANK", "ICICI BANK LIMITED", "ICICI"],
    "axis": ["AXIS BANK", "AXIS BANK LIMITED", "AXIS"],
    "pnb": ["PUNJAB NATIONAL BANK", "PNB"],
    "bob": ["BANK OF BARODA", "BOB"],
    "kotak": ["KOTAK MAHINDRA BANK", "KOTAK BANK", "KOTAK"],
    "canara": ["CANARA BANK"],
    "paytm": ["PAYTM PAYMENTS BANK", "ONE97 COMMUNICATIONS", "PAYTM"],
    "phonepe": ["PHONEPE", "PHONEPE PRIVATE LIMITED"],
    "gpay": ["GOOGLE PAY", "GOOGLE INDIA"],
    "electricity": ["ELECTRICITY DISCOM", "POWER DISTRIBUTION", "MSEDCL", "BESCOM", "UPPCL", "TNEB"],
    "uidai": ["UNIQUE IDENTIFICATION AUTHORITY OF INDIA", "AADHAAR", "UIDAI"],
    "incometax": ["INCOME TAX DEPARTMENT", "NSDL", "CBDT"],
    "police": ["POLICE CYBER CELL", "GOVERNMENT OF INDIA", "POLICE"],
}


def _expand_claimed_identity(claimed: str) -> List[str]:
    """Expand claimed name to canonical variations if it represents an organization."""
    c_lower = claimed.lower().strip()
    variants = [claimed.upper()]
    for key, aliases in BANK_EXPANSIONS.items():
        if key in c_lower or any(a.lower() in c_lower for a in aliases):
            variants.extend(aliases)
    return list(dict.fromkeys(variants))


def match_claimed_vs_registered(
    claimed_identity: Optional[str],
    registered_name: Optional[str]
) -> Tuple[float, str, List[str]]:
    """
    Compare claimed identity against registered name from bank record.
    Returns:
        (match_score_0_to_100, verdict_status, list_of_flags)

    verdict_status: "MATCH", "MISMATCH", or "UNVERIFIED"
    """
    if not claimed_identity or not registered_name:
        return 0.0, "UNVERIFIED", []

    claimed_variants = _expand_claimed_identity(claimed_identity)
    registered_clean = registered_name.strip().upper()

    best_score = 0.0
    for variant in claimed_variants:
        score = compute_fuzzy_name_match(variant, registered_clean)
        if score > best_score:
            best_score = score

    # Check if claimed is an institution but registered looks like an individual
    is_claimed_institution = any(
        kw in claimed_identity.lower()
        for kw in ["bank", "sbi", "hdfc", "icici", "axis", "support", "refund", "department", "govt", "police", "tax", "bill"]
    )
    is_registered_individual = not any(
        kw in registered_clean.lower()
        for kw in ["ltd", "limited", "bank", "corporation", "department", "authority", "solutions", "services", "trust", "govt"]
    )

    flags: List[str] = []

    if is_claimed_institution and is_registered_individual and best_score < 70.0:
        flags.append("UPI_BENEFICIARY_IS_INDIVIDUAL_FOR_INSTITUTION")
        flags.append("CRITICAL_BANK_IMPERSONATION_MULE")
        verdict = "MISMATCH"
        # Heavily penalize score when institution is routed to an individual
        effective_score = min(best_score, 15.0)
    elif best_score >= 80.0:
        flags.append("UPI_BENEFICIARY_NAME_VERIFIED")
        verdict = "MATCH"
        effective_score = best_score
    elif best_score < 40.0:
        flags.append("UPI_BENEFICIARY_NAME_MISMATCH")
        flags.append("SUSPECTED_UNAUTHORIZED_RECIPIENT")
        verdict = "MISMATCH"
        effective_score = best_score
    else:
        flags.append("UPI_BENEFICIARY_NAME_PARTIAL_MATCH")
        verdict = "PARTIAL_MATCH"
        effective_score = best_score

    return round(effective_score, 1), verdict, flags


# ---------------------------------------------------------------------------
# Bank Identity Verification Entrypoint
# ---------------------------------------------------------------------------

async def verify_bank_identity(
    vpa: str,
    claimed_identity: Optional[str] = None,
    verifier: Optional[UpiVerifier] = None,
) -> Dict[str, Any]:
    """
    Perform end-to-end bank identity verification for a given VPA.
    Returns structured evidence containing:
    - verification_result: UpiVerificationResult
    - name_match_score: float
    - name_match_status: str
    - flags: List[str]
    - evidence_item: EvidenceItem (with provider="SANDBOX_MOCK")
    """
    if verifier is None:
        verifier = get_upi_verifier()

    verif_res: UpiVerificationResult = await verifier.verify_vpa(vpa)
    score, status, flags = match_claimed_vs_registered(
        claimed_identity,
        verif_res.registered_name
    )

    finding_msg = (
        f"UPI '{vpa}' registered to '{verif_res.registered_name or 'Unknown'}' "
        f"via {verif_res.bank_name or 'Bank'}. Name match: {status} ({score}%)."
    )

    evidence_item = EvidenceItem(
        tool="bank_identity_agent",
        status="FLAGGED" if status == "MISMATCH" else "VERIFIED",
        finding=finding_msg,
        raw_result={
            "vpa": vpa,
            "registered_name": verif_res.registered_name,
            "claimed_identity": claimed_identity,
            "bank_name": verif_res.bank_name,
            "account_type": verif_res.account_type,
            "is_verified_merchant": verif_res.is_verified_merchant,
            "name_match_score": score,
            "name_match_status": status,
            "provider": verif_res.provider,  # "SANDBOX_MOCK" for UI badge
            "flags": flags,
        },
        provider=verif_res.provider,
    )

    return {
        "verification": verif_res,
        "name_match_score": score,
        "name_match_status": status,
        "flags": flags,
        "evidence_item": evidence_item,
        "provider": verif_res.provider,
    }
