"""
backend/tests/test_sender_agent.py
------------------------------------
Pytest test suite for the Sender Identity & TRAI DLT Verification Agent.

Run from the `backend/` directory:
    python -m pytest tests/test_sender_agent.py -v

Requirements:
    pytest, pytest-asyncio, pydantic
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import pytest_asyncio  # noqa: F401 — ensures asyncio plugin is loaded

# ---------------------------------------------------------------------------
# Path Setup — allow imports from `backend/` as root
# ---------------------------------------------------------------------------
# When running from the `backend/` directory the package structure is:
#   backend/
#     agents/sender_agent.py
#     shared/models.py
#     tests/test_sender_agent.py
# We insert the `backend/` directory (parent of `tests/`) into sys.path so
# that `from agents.sender_agent import ...` and `from shared.models import ...`
# resolve correctly regardless of where pytest is invoked.
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from agents.sender_agent import analyze_sender  # noqa: E402
from shared.models import (  # noqa: E402
    AgentStatusEnum,
    ScanRequest,
    SenderAgentResult,
    SenderCategoryEnum,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_request(content: str, sender: str | None = None) -> ScanRequest:
    """Convenience factory for ScanRequest objects."""
    return ScanRequest(content=content, sender=sender)


# ---------------------------------------------------------------------------
# Test 1 — Official TRAI DLT Header (Verified)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_official_trai_header() -> None:
    """
    Certified TRAI DLT header VM-SBIINB must be recognised as
    OFFICIAL_TRAI_HEADER with risk_score <= 10.
    """
    req = _make_request(
        content="Dear Customer, your SBI account balance is Rs. 12,450. "
                "For queries call 1800-11-2211.",
        sender="VM-SBIINB",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS, (
        f"Expected SUCCESS, got {result.status}: {result.details}"
    )
    assert result.sender_category == SenderCategoryEnum.OFFICIAL_TRAI_HEADER, (
        f"Expected OFFICIAL_TRAI_HEADER, got {result.sender_category}"
    )
    assert result.risk_score <= 10.0, (
        f"Expected risk_score <= 10, got {result.risk_score}"
    )
    assert result.is_spoofed_header is False, (
        "Verified TRAI header must NOT be flagged as spoofed."
    )
    assert "VERIFIED_TRAI_DLT_SENDER_HEADER" in result.flags, (
        f"Expected VERIFIED_TRAI_DLT_SENDER_HEADER flag, got {result.flags}"
    )
    assert result.brand_claimed is not None, (
        "brand_claimed must be populated for a verified TRAI header."
    )


# ---------------------------------------------------------------------------
# Test 2 — Personal GSM Number Impersonating SBI (High-Risk Scam)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_personal_gsm_bank_scam() -> None:
    """
    A 10-digit personal GSM number claiming to be SBI must return
    risk_score >= 85 and sender_category == PERSONAL_GSM.
    """
    req = _make_request(
        content="URGENT: Your SBI account has been blocked due to suspicious "
                "activity. Click here to unblock: http://sbi-secure-login.xyz",
        sender="+919876543210",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS, (
        f"Expected SUCCESS, got {result.status}: {result.details}"
    )
    assert result.sender_category == SenderCategoryEnum.PERSONAL_GSM, (
        f"Expected PERSONAL_GSM, got {result.sender_category}"
    )
    assert result.risk_score >= 85.0, (
        f"Expected risk_score >= 85, got {result.risk_score}"
    )
    assert "COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM" in result.flags, (
        f"Missing COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM flag, got {result.flags}"
    )
    assert "MISSING_TRAI_OFFICIAL_HEADER" in result.flags, (
        f"Missing MISSING_TRAI_OFFICIAL_HEADER flag, got {result.flags}"
    )
    assert result.brand_claimed is not None, (
        "brand_claimed must identify the impersonated bank."
    )


# ---------------------------------------------------------------------------
# Test 3 — Lookalike / Spoofed Header (SBI-ALERT)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_lookalike_header() -> None:
    """
    Unregistered alphanumeric header 'SBI-ALERT' must return
    risk_score >= 70 and is_spoofed_header == True.
    """
    req = _make_request(
        content="Alert: Unusual login detected on your SBI Net Banking. "
                "Verify now at http://sbi-netbanking-verify.info",
        sender="SBI-ALERT",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS, (
        f"Expected SUCCESS, got {result.status}: {result.details}"
    )
    assert result.sender_category == SenderCategoryEnum.LOOKALIKE_HEADER, (
        f"Expected LOOKALIKE_HEADER, got {result.sender_category}"
    )
    assert result.risk_score >= 70.0, (
        f"Expected risk_score >= 70, got {result.risk_score}"
    )
    assert result.is_spoofed_header is True, (
        "SBI-ALERT is NOT a registered TRAI DLT header and must be flagged as spoofed."
    )
    assert "UNVERIFIED_LOOKALIKE_HEADER" in result.flags, (
        f"Missing UNVERIFIED_LOOKALIKE_HEADER flag, got {result.flags}"
    )


# ---------------------------------------------------------------------------
# Test 4 — Null Sender Fallback (No Crash, Graceful Handling)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_null_sender_fallback() -> None:
    """
    Null sender with generic content must be handled gracefully
    (no exception, status == SUCCESS, sender_category == UNKNOWN).
    """
    req = _make_request(
        content="Congratulations! You have won a lucky draw prize. "
                "Visit our website to claim your reward.",
        sender=None,
    )
    result: SenderAgentResult = await analyze_sender(req)

    # Must not crash — status must not be ERROR.
    assert result.status != AgentStatusEnum.ERROR, (
        f"Null sender should not trigger an ERROR: {result.details}"
    )
    # Without a sender or recognisable phone number in the content,
    # the fallback category must be UNKNOWN.
    assert result.sender_category == SenderCategoryEnum.UNKNOWN, (
        f"Expected UNKNOWN category for null sender, got {result.sender_category}"
    )
    # Sanity check — risk_score must be in valid range.
    assert 0.0 <= result.risk_score <= 100.0, (
        f"risk_score out of bounds: {result.risk_score}"
    )


# ---------------------------------------------------------------------------
# Test 5 — HDFC DLT Header Verification (Additional Positive Case)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_hdfc_trai_header() -> None:
    """
    Certified TRAI DLT header AX-HDFCBK must resolve to HDFC Bank
    with risk_score <= 10.
    """
    req = _make_request(
        content="Your HDFC Bank OTP is 482910. Do NOT share with anyone.",
        sender="AX-HDFCBK",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.sender_category == SenderCategoryEnum.OFFICIAL_TRAI_HEADER
    assert result.risk_score <= 10.0
    assert result.is_spoofed_header is False
    assert "HDFC" in (result.brand_claimed or ""), (
        f"brand_claimed should reference HDFC, got: {result.brand_claimed}"
    )


# ---------------------------------------------------------------------------
# Test 6 — Null Sender With Embedded Phone Number Claiming Bank
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_null_sender_embedded_gsm_bank_scam() -> None:
    """
    When sender is None but the message body contains a GSM number claiming
    to be a bank, the agent must elevate risk to >= 85.
    """
    req = _make_request(
        content="Your ICICI Bank account is on hold. Call 9123456789 immediately.",
        sender=None,
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.sender_category == SenderCategoryEnum.PERSONAL_GSM
    assert result.risk_score >= 85.0
    assert "COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM" in result.flags


# ---------------------------------------------------------------------------
# Test 7 — Fail-Safe: Agent Never Crashes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_never_raises() -> None:
    """
    The agent must never raise an unhandled exception even under unexpected
    inputs (empty string, special characters, extremely long sender).
    """
    edge_cases = [
        _make_request(content=" ", sender=None),          # near-empty; ScanRequest requires min_length=1
        _make_request(content="Hello", sender=""),
        _make_request(content="Test", sender="!@#$%^&*()_+"),
        _make_request(content="X" * 8_000, sender="A" * 500),  # max allowed length; ScanRequest max_length=8000
    ]
    for req in edge_cases:
        result = await analyze_sender(req)
        # Must always return a SenderAgentResult — never raise.
        assert isinstance(result, SenderAgentResult), (
            f"Expected SenderAgentResult for input {req!r}, got {type(result)}"
        )
        assert 0.0 <= result.risk_score <= 100.0, (
            f"risk_score out of bounds: {result.risk_score}"
        )
