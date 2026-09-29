# ============================================================
# OWNER: VANSH
# FILE: backend/tests/test_pipeline.py
# PURPOSE: End-to-End Integration & Unit Tests for Orchestrator & DB Logger
# ============================================================

import pytest
import asyncio
import time
from unittest.mock import patch

from shared.models import (
    ScanRequest,
    ScanResponse,
    ChannelEnum,
    RiskTierEnum,
    ActionRequiredEnum,
    AgentStatusEnum,
    IntentAgentResult,
    SenderCategoryEnum
)
from core.orchestrator import run_pipeline
from core.db_logger import mask_pii


@pytest.mark.asyncio
async def test_pipeline_e2e_high_risk_scam():
    """Send high-risk SBI KYC message; verify pipeline executes in < 3500ms, returns risk_tier in ['HIGH_RISK', 'CRITICAL']."""
    req = ScanRequest(
        content="Dear Customer, Your SBI account has been suspended due to pending KYC update. Submit PAN and verify OTP at https://sbi-kyc-verify.top within 2 hours.",
        sender="+919823145678",
        extracted_url="https://sbi-kyc-verify.top",
        channel=ChannelEnum.SMS
    )

    t0 = time.perf_counter()
    resp: ScanResponse = await run_pipeline(req)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert elapsed_ms < 3500.0, f"Execution took too long: {elapsed_ms}ms"
    assert resp.risk_tier.value in ["HIGH_RISK", "CRITICAL"], f"Unexpected tier: {resp.risk_tier}"
    assert resp.action_required == ActionRequiredEnum.BLOCK_TRANSACTION
    assert resp.overall_risk_score >= 50
    assert resp.audit_trail is not None


@pytest.mark.asyncio
async def test_pipeline_e2e_benign_otp():
    """Send safe HDFC OTP alert; verify returns risk_tier == 'SAFE'."""
    req = ScanRequest(
        content="784920 is your OTP for HDFC Bank NetBanking transaction at 29-Sep-2026. Do not share OTP with anyone.",
        sender="AD-HDFCBK",
        extracted_url=None,
        channel=ChannelEnum.SMS
    )

    resp: ScanResponse = await run_pipeline(req)
    assert resp.risk_tier == RiskTierEnum.SAFE
    assert resp.action_required == ActionRequiredEnum.ALLOW
    assert resp.overall_risk_score <= 24


@pytest.mark.asyncio
async def test_pipeline_resilience_agent_failure():
    """Mock one agent to raise a TimeoutError; verify orchestrator does NOT crash, recovers gracefully, and returns a valid ScanResponse."""
    async def mock_timeout_agent(req):
        raise asyncio.TimeoutError("Simulated agent timeout")

    req = ScanRequest(
        content="Meeting today at 5 PM for coffee.",
        sender="+919876543210",
        channel=ChannelEnum.SMS
    )

    with patch("core.orchestrator.analyze_intent", side_effect=mock_timeout_agent):
        resp: ScanResponse = await run_pipeline(req)
        assert isinstance(resp, ScanResponse)
        assert resp.audit_trail.intent_analysis.status == AgentStatusEnum.ERROR
        assert "timeout" in resp.audit_trail.intent_analysis.details.lower()
        # Verify pipeline still computed a valid score using dynamic weight redistribution
        assert 0 <= resp.overall_risk_score <= 100


def test_pii_masker():
    """Verify phone numbers, OTPs, and card numbers are redacted properly."""
    # 1. 10-digit Indian phone masking
    phone_raw = "9876543210"
    masked_phone = mask_pii(phone_raw)
    assert masked_phone == "987****210", f"Expected 987****210, got {masked_phone}"

    # 2. OTP masking
    otp_text = "Your OTP 123456 is valid for 10 minutes"
    masked_otp = mask_pii(otp_text)
    assert "OTP ******" in masked_otp
    assert "123456" not in masked_otp

    code_text = "verification code 654321"
    masked_code = mask_pii(code_text)
    assert "code ******" in masked_code
    assert "654321" not in masked_code

    # 3. Card number masking
    card_text = "Payment on card ending 8812 was approved"
    masked_card = mask_pii(card_text)
    assert "ending ****" in masked_card
    assert "8812" not in masked_card
