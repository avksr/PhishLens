"""
backend/agents/upi_verifier.py
------------------------------
UPI VPA Verification Interface & Implementations for PhishLens (ScamShield AI).

Provides:
1. `UpiVerifier` (Abstract Base Class / Interface)
2. `MockUpiVerifier` (Default Sandbox Mock, provider: "SANDBOX_MOCK")
3. `RapidApiUpiVerifier` (Optional live verification via RapidAPI / NPCI gateway)
4. `get_upi_verifier()` (Factory returning active verifier according to config)

Evidence items from this module explicitly carry `provider: "SANDBOX_MOCK"`
(or "RAPIDAPI") so the frontend can display appropriate "Simulated" badges.

Author  : AVNI — Sender Identity, Email & UPI Intelligence
Module  : PhishLens v1.0
"""

from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class UpiVerificationResult(BaseModel):
    """Normalized output from any UPI verification provider."""
    vpa: str
    is_valid: bool = True
    account_exists: bool = True
    registered_name: Optional[str] = None
    bank_name: Optional[str] = None
    account_type: str = "SAVINGS"  # SAVINGS, CURRENT, MERCHANT, MULE
    is_verified_merchant: bool = False
    provider: str = "SANDBOX_MOCK"  # SANDBOX_MOCK or RAPIDAPI
    raw_response: Dict[str, Any] = Field(default_factory=dict)


class UpiVerifier(ABC):
    """Abstract interface for UPI VPA bank identity verification."""

    @abstractmethod
    async def verify_vpa(self, vpa: str) -> UpiVerificationResult:
        """Verify the VPA and retrieve bank-registered identity details."""
        pass


class MockUpiVerifier(UpiVerifier):
    """
    Default Sandbox Mock verifier.
    Simulates real-world bank identity registry responses for fraud detection.
    Guarantees zero external network dependencies and sub-millisecond execution.
    """

    # Static registry of simulated test VPAs
    KNOWN_MOCKS: Dict[str, Dict[str, Any]] = {
        # Legitimate corporate / merchant accounts
        "sbicollect@sbi": {
            "registered_name": "STATE BANK OF INDIA - COLLECT",
            "bank_name": "State Bank of India",
            "is_verified_merchant": True,
            "account_type": "MERCHANT",
        },
        "irctc@hdfcbank": {
            "registered_name": "INDIAN RAILWAY CATERING AND TOURISM CORP",
            "bank_name": "HDFC Bank",
            "is_verified_merchant": True,
            "account_type": "MERCHANT",
        },
        "licpremium@icici": {
            "registered_name": "LIFE INSURANCE CORPORATION OF INDIA",
            "bank_name": "ICICI Bank",
            "is_verified_merchant": True,
            "account_type": "MERCHANT",
        },
        # Legitimate benign personal accounts
        "rohan.sharma@okaxis": {
            "registered_name": "ROHAN SHARMA",
            "bank_name": "Axis Bank",
            "is_verified_merchant": False,
            "account_type": "SAVINGS",
        },
        "priya.verma@oksbi": {
            "registered_name": "PRIYA VERMA",
            "bank_name": "State Bank of India",
            "is_verified_merchant": False,
            "account_type": "SAVINGS",
        },
        # Classic Scammer Impersonation targets (Mule accounts mimicking banks)
        "sbi-refund@paytm": {
            "registered_name": "MOHAMMAD SHARIF",
            "bank_name": "Paytm Payments Bank",
            "is_verified_merchant": False,
            "account_type": "SAVINGS",
        },
        "sbi-refund-desk@paytm": {
            "registered_name": "MOHAMMAD SHARIF",
            "bank_name": "Paytm Payments Bank",
            "is_verified_merchant": False,
            "account_type": "SAVINGS",
        },
        "sbi-support@ybl": {
            "registered_name": "SURESH CHANDRA",
            "bank_name": "Yes Bank / PhonePe",
            "is_verified_merchant": False,
            "account_type": "SAVINGS",
        },
        "hdfc-kyc@ybl": {
            "registered_name": "AJAY KUMAR",
            "bank_name": "Yes Bank / PhonePe",
            "is_verified_merchant": False,
            "account_type": "SAVINGS",
        },
        "claim-lottery-prize@oksbi": {
            "registered_name": "RAKESH MULE ACC",
            "bank_name": "State Bank of India",
            "is_verified_merchant": False,
            "account_type": "SAVINGS",
        },
        "customercare@okhdfc": {
            "registered_name": "DINESH VERMA",
            "bank_name": "HDFC Bank",
            "is_verified_merchant": False,
            "account_type": "SAVINGS",
        },
        "refund-support@okaxis": {
            "registered_name": "Mohd Imran",
            "bank_name": "Axis Bank",
            "is_verified_merchant": False,
            "account_type": "SAVINGS",
        },
        "avksr@okaxis": {
            "registered_name": "Avika Sharma",
            "bank_name": "Axis Bank",
            "is_verified_merchant": False,
            "account_type": "SAVINGS",
        },
    }

    async def verify_vpa(self, vpa: str) -> UpiVerificationResult:
        vpa_clean = vpa.strip().lower()

        # 1. Exact match in mock database
        if vpa_clean in self.KNOWN_MOCKS:
            data = self.KNOWN_MOCKS[vpa_clean]
            return UpiVerificationResult(
                vpa=vpa_clean,
                is_valid=True,
                account_exists=True,
                registered_name=data["registered_name"],
                bank_name=data.get("bank_name", "Mock Partner Bank"),
                account_type=data.get("account_type", "SAVINGS"),
                is_verified_merchant=data.get("is_verified_merchant", False),
                provider="SANDBOX_MOCK",
                raw_response={"mock_match": "exact", "source": "sandbox_directory"},
            )

        # 2. Dynamic simulation based on heuristic patterns
        local_part = vpa_clean.split("@")[0] if "@" in vpa_clean else vpa_clean
        handle = vpa_clean.split("@")[1] if "@" in vpa_clean else ""

        # If localpart has bank / authority words, simulate that it resolves to a personal mule name
        institutional_keywords = [
            "sbi", "hdfc", "icici", "axis", "pnb", "bob", "kotak", "canara",
            "refund", "support", "helpdesk", "kyc", "lottery", "reward", "prize",
            "police", "cbi", "tax", "income", "discom", "electricity"
        ]
        has_institution_word = any(kw in local_part for kw in institutional_keywords)

        if has_institution_word:
            # High-fidelity scam simulation: the scammer claimed an institution,
            # but the real bank account name belongs to an unsuspecting or mule individual
            return UpiVerificationResult(
                vpa=vpa_clean,
                is_valid=True,
                account_exists=True,
                registered_name="DINESH KUMAR (INDIVIDUAL MULE)",
                bank_name=f"Partner PSP ({handle.upper() if handle else 'UPI'})",
                account_type="SAVINGS",
                is_verified_merchant=False,
                provider="SANDBOX_MOCK",
                raw_response={"mock_match": "simulated_mule", "trigger": "institutional_keyword_in_localpart"},
            )

        # Standard benign simulation from local-part (e.g. rahul.sharma -> RAHUL SHARMA)
        formatted_name = re.sub(r"[._\-0-9]+", " ", local_part).strip().upper()
        if not formatted_name:
            formatted_name = "BENEFICIARY ACCOUNT"

        return UpiVerificationResult(
            vpa=vpa_clean,
            is_valid=True,
            account_exists=True,
            registered_name=formatted_name,
            bank_name=f"Partner Bank ({handle.upper() if handle else 'UPI'})",
            account_type="SAVINGS",
            is_verified_merchant=False,
            provider="SANDBOX_MOCK",
            raw_response={"mock_match": "derived_name", "derived_from": local_part},
        )


class RapidApiUpiVerifier(UpiVerifier):
    """
    Optional Live UPI Verifier using RapidAPI / NPCI Verification API.
    Activated when config flag `USE_RAPIDAPI_UPI=true` and `RAPIDAPI_KEY` are provided.
    Falls back gracefully to MockUpiVerifier on missing key, timeout, or API failure.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("RAPIDAPI_KEY", "")
        self.endpoint = os.getenv("RAPIDAPI_UPI_ENDPOINT", "https://upi-verification.p.rapidapi.com/verify")
        self.mock_fallback = MockUpiVerifier()

    async def verify_vpa(self, vpa: str) -> UpiVerificationResult:
        if not self.api_key:
            # Fall back to sandbox mock if no key configured
            res = await self.mock_fallback.verify_vpa(vpa)
            res.raw_response["fallback_reason"] = "no_rapidapi_key"
            return res

        try:
            import httpx
            headers = {
                "x-rapidapi-key": self.api_key,
                "x-rapidapi-host": self.endpoint.split("//")[-1].split("/")[0],
                "Content-Type": "application/json",
            }
            async with httpx.AsyncClient(timeout=1.5) as client:
                response = await client.post(
                    self.endpoint,
                    json={"vpa": vpa},
                    headers=headers,
                )
                if response.status_code == 200:
                    data = response.json()
                    return UpiVerificationResult(
                        vpa=vpa,
                        is_valid=data.get("valid", True),
                        account_exists=data.get("account_exists", True),
                        registered_name=data.get("name") or data.get("account_name"),
                        bank_name=data.get("bank_name"),
                        account_type=data.get("account_type", "SAVINGS"),
                        is_verified_merchant=data.get("is_merchant", False),
                        provider="RAPIDAPI",
                        raw_response=data,
                    )
        except Exception as exc:  # noqa: BLE001
            # Seamless fallback to mock on network or timeout failure
            pass

        res = await self.mock_fallback.verify_vpa(vpa)
        res.raw_response["fallback_reason"] = "rapidapi_call_failed"
        return res


def get_upi_verifier() -> UpiVerifier:
    """
    Factory function returning the active UPI Verifier.
    Defaults to MockUpiVerifier ("SANDBOX_MOCK").
    Switches to RapidApiUpiVerifier if `USE_RAPIDAPI_UPI` is enabled.
    """
    use_rapidapi = os.getenv("USE_RAPIDAPI_UPI", "false").lower() in ("true", "1", "yes")
    if use_rapidapi:
        return RapidApiUpiVerifier()
    return MockUpiVerifier()
