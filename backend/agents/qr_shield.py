"""
backend/agents/qr_shield.py
---------------------------
QR Pre-Payment Shield for PhishLens (ScamShield AI).
Owner: AVIKA (Scoring Engine & Vision Lead)

Responsibilities:
1. Parse and validate UPI QR code payment payloads (upi://pay?...).
2. Detect the infamous "Reverse QR / Collect Request Trap":
   - Scammers trick victims by claiming "Scan to receive payment/refund/cashback",
     when scanning any QR code actually debits funds from the victim's account.
3. Validate Merchant Category Codes (MCC) against institutional claims:
   - Commercial / institutional payee claims must possess official merchant MCCs
     and cannot resolve to unverified personal handles.
4. Detect foreign currency anomalies (e.g., non-INR deep links).
5. Detect phishing URLs embedded inside QR codes disguised as payment flows.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse
from pydantic import BaseModel, Field


class QrShieldResult(BaseModel):
    """Structured assessment of a scanned QR payload before transaction execution."""
    is_valid_upi: bool = False
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    payee_vpa: Optional[str] = None
    payee_name: Optional[str] = None
    amount: Optional[float] = None
    currency: str = "INR"
    merchant_code: Optional[str] = None
    transaction_ref: Optional[str] = None
    mode: Optional[str] = None
    is_collect_request_trap: bool = False
    is_unverified_merchant_claim: bool = False
    is_phishing_url: bool = False
    flags: List[str] = Field(default_factory=list)
    advisory: str = ""


# Institutional keywords that require an authentic verified merchant MCC
_INSTITUTIONAL_KEYWORDS = {
    "sbi", "hdfc", "icici", "axis", "pnb", "bob", "kotak", "canara",
    "airtel", "jio", "electricity", "discom", "amazon", "flipkart",
    "paytm", "phonepe", "gpay", "refund", "support", "care", "desk",
    "police", "cyber", "income tax", "customs", "delivery", "olx"
}

# Standard consumer P2P handles typically used by individual bank accounts
_PERSONAL_P2P_HANDLES = {
    "okaxis", "okhdfcbank", "oksbi", "okicici", "ybl", "ibl", "axl", "paytm"
}


def verify_qr_pre_payment(payload: str, user_intent_claim: str = "") -> QrShieldResult:
    """
    Analyzes a raw QR code string before any payment is authorized.
    Evaluates Reverse-QR traps, merchant spoofing, and embedded phishing links.
    """
    if not payload or not isinstance(payload, str):
        return QrShieldResult(
            is_valid_upi=False,
            risk_score=0.0,
            flags=["INVALID_QR_PAYLOAD"],
            advisory="Empty or unreadable QR code payload.",
        )

    clean_payload = payload.strip()
    flags: List[str] = []
    risk_score = 0.0

    # 1. Check if the QR is an HTTP/HTTPS phishing link disguised as a payment QR
    if clean_payload.lower().startswith(("http://", "https://", "ftp://")):
        parsed_url = urlparse(clean_payload)
        domain = parsed_url.netloc.lower()
        flags.append("QR_EMBEDDED_WEB_URL")
        flags.append("QR_NON_UPI_DESTINATION")
        risk_score = 80.0
        return QrShieldResult(
            is_valid_upi=False,
            risk_score=risk_score,
            is_phishing_url=True,
            flags=flags,
            advisory=(
                f"Caution: This QR code directs to a website ({domain}) instead of a secure UPI payment. "
                "Do not open untrusted links or enter payment credentials."
            ),
        )

    # 2. Check if the QR begins with the NPCI UPI URI scheme
    if not clean_payload.lower().startswith("upi://pay"):
        # Check if it is a naked VPA
        if "@" in clean_payload and len(clean_payload.split("@")) == 2 and not clean_payload.startswith("http"):
            return QrShieldResult(
                is_valid_upi=True,
                risk_score=10.0,
                payee_vpa=clean_payload,
                flags=["NAKED_VPA_QR"],
                advisory="Standard P2P handle QR code. Verify payee name before sending money.",
            )
        return QrShieldResult(
            is_valid_upi=False,
            risk_score=50.0,
            flags=["MALFORMED_UPI_URI"],
            advisory="Malformed or unsupported QR code format.",
        )

    # 3. Parse standard upi://pay query parameters
    try:
        parsed = urlparse(clean_payload)
        params = parse_qs(parsed.query)
    except Exception:
        return QrShieldResult(
            is_valid_upi=False,
            risk_score=60.0,
            flags=["UNPARSEABLE_UPI_URI"],
            advisory="Corrupted UPI QR parameters.",
        )

    payee_vpa = params.get("pa", [None])[0]
    payee_name = params.get("pn", [None])[0]
    amount_str = params.get("am", [None])[0]
    currency = params.get("cu", ["INR"])[0]
    mcc = params.get("mc", [None])[0]
    tr = params.get("tr", [None])[0]
    mode = params.get("mode", [None])[0]
    embedded_url = params.get("url", [None])[0]

    amount: Optional[float] = None
    if amount_str:
        try:
            amount = float(amount_str)
        except ValueError:
            flags.append("INVALID_AMOUNT_FIELD")

    # --- Heuristic 1: Reverse QR / Collect Request Trap ---
    # Scammers frequently trick people into scanning a QR to "receive" funds
    is_collect_trap = False
    intent_lower = user_intent_claim.lower()
    is_receiving_intent = any(kw in intent_lower for kw in ["receive", "refund", "cashback", "prize", "lottery", "claim"])

    if is_receiving_intent and amount is not None and amount > 0:
        is_collect_trap = True
        flags.append("REVERSE_QR_TRAP_DETECTED")
        flags.append("QR_COLLECT_DISGUISED_AS_REFUND")
        risk_score = max(risk_score, 95.0)

    if mode in ["01", "02", "04"]:  # NPCI mandate/collect modes
        flags.append("QR_COLLECT_MODE_FLAGGED")
        risk_score = max(risk_score, 85.0)

    # Universal rule: scanning any QR code with a pre-set amount will DEBIT money
    if amount is not None and amount > 10000.0:
        flags.append("HIGH_VALUE_PRESET_AMOUNT")

    # --- Heuristic 2: Institutional Name Impersonation on Personal Handle ---
    is_unverified_merchant = False
    if payee_name:
        pn_lower = payee_name.lower()
        has_institution_keyword = any(kw in pn_lower for kw in _INSTITUTIONAL_KEYWORDS)

        handle_suffix = payee_vpa.split("@")[1].lower() if (payee_vpa and "@" in payee_vpa) else ""
        is_personal_handle = handle_suffix in _PERSONAL_P2P_HANDLES

        # If claiming to be an institution but lacking a valid commercial MCC or using P2P handle
        if has_institution_keyword and (not mcc or mcc in ["0000", ""] or is_personal_handle):
            is_unverified_merchant = True
            flags.append("QR_INSTITUTION_NAME_ON_PERSONAL_HANDLE")
            flags.append("SUSPECTED_SPOOFED_MERCHANT_QR")
            risk_score = max(risk_score, 90.0)

    # --- Heuristic 3: Non-INR Currency Anomaly ---
    if currency and currency.upper() != "INR":
        flags.append("NON_INR_CURRENCY_ANOMALY")
        risk_score = max(risk_score, 85.0)

    # --- Heuristic 4: Embedded Web URL in UPI payload ---
    if embedded_url:
        flags.append("EMBEDDED_URL_IN_QR")
        if not embedded_url.lower().startswith("https://"):
            flags.append("INSECURE_EMBEDDED_HTTP_URL")
            risk_score = max(risk_score, 80.0)

    # Safe baseline score if clean
    if not flags:
        risk_score = 5.0
        flags.append("CLEAN_UPI_QR")

    # Generate Plain-Language Advisory
    if is_collect_trap:
        advisory = (
            f"CRITICAL FRAUD WARNING: This QR code will DEDUCT ₹{amount:,.2f} from your bank account! "
            "In UPI, you NEVER need to scan a QR code or enter your UPI PIN to receive money or refunds."
        )
    elif is_unverified_merchant:
        advisory = (
            f"High Risk Alert: The QR code displays the name '{payee_name}', but is linked to an unverified personal handle "
            f"({payee_vpa}) instead of an official merchant account. Do not pay."
        )
    elif risk_score >= 70.0:
        advisory = f"High Risk: Suspect payment QR detected with anomalies ({', '.join(flags)}). Proceed with caution."
    else:
        amt_disp = f" for ₹{amount:,.2f}" if amount else ""
        advisory = f"Verified UPI QR for {payee_name or payee_vpa}{amt_disp}. Confirm payee details before confirming."

    return QrShieldResult(
        is_valid_upi=True,
        risk_score=round(risk_score, 1),
        payee_vpa=payee_vpa,
        payee_name=payee_name,
        amount=amount,
        currency=currency,
        merchant_code=mcc,
        transaction_ref=tr,
        mode=mode,
        is_collect_request_trap=is_collect_trap,
        is_unverified_merchant_claim=is_unverified_merchant,
        is_phishing_url=False,
        flags=flags,
        advisory=advisory,
    )
