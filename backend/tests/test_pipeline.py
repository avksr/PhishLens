# ============================================================
# OWNER: VANSH
# FILE: backend/tests/test_pipeline.py
# PURPOSE: Integration & SLA Verification for Orchestrator Pipeline
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
    IntentAgentResult
)
from core.orchestrator import run_pipeline
from core.db_logger import mask_phone_number, mask_pii_content, audit_logger


@pytest.mark.asyncio
async def test_orchestrator_e2e_critical_sbi_scam():
    """Verify that orchestrator executes all agents in parallel within sub-1000ms SLA."""
    req = ScanRequest(
        content=(
            "Dear Customer, Your SBI account is blocked. Verify OTP and submit PAN "
            "at https://sbi-kyc-verify.top within 2 hours."
        ),
        sender="+919823145678",
        extracted_url="https://sbi-kyc-verify.top",
        channel=ChannelEnum.SMS
    )

    t0 = time.perf_counter()
    resp: ScanResponse = await run_pipeline(req)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    # Verification assertions
    assert resp.overall_risk_score >= 80, f"Expected critical score, got {resp.overall_risk_score}"
    assert resp.risk_tier == RiskTierEnum.CRITICAL
    assert resp.action_required == ActionRequiredEnum.BLOCK_TRANSACTION
    assert resp.audit_trail.url_analysis is not None
    assert resp.audit_trail.sender_analysis is not None
    assert resp.audit_trail.intent_analysis is not None
    assert resp.processing_time_ms < 1000.0, f"SLA exceeded: {resp.processing_time_ms}ms"
    assert elapsed_ms < 2000.0


@pytest.mark.asyncio
async def test_orchestrator_agent_timeout_supervisor():
    """Verify that when an agent exceeds 3.5s SLA timeout, fallback is returned without crashing."""
    async def slow_mock_intent(req):
        await asyncio.sleep(4.0)  # Exceeds 3.5s timeout
        return IntentAgentResult()

    req = ScanRequest(
        content="Meeting today at 5 PM",
        sender="+919876543210",
        channel=ChannelEnum.SMS
    )

    with patch("core.orchestrator.AGENT_TIMEOUT_SECONDS", 0.05):  # Use 50ms for fast test execution
        with patch("core.orchestrator.analyze_intent", slow_mock_intent):
            resp: ScanResponse = await run_pipeline(req)
            assert resp.audit_trail.intent_analysis.status == AgentStatusEnum.ERROR
            assert "TIMEOUT_EXCEEDED" in resp.audit_trail.intent_analysis.details
            assert resp.overall_risk_score >= 0


def test_pii_masking_phone_and_otp():
    """Verify GIGW 3.0 zero-trust sanitization rules."""
    phone = "+919876543210"
    masked_phone = mask_phone_number(phone)
    assert masked_phone == "+91-XXXXX-3210"

    raw_text = "Your OTP is 784920. Call officer at 9876543210 immediately."
    masked_text = mask_pii_content(raw_text)
    assert "[REDACTED_CREDENTIAL]" in masked_text
    assert "784920" not in masked_text
    assert "[REDACTED_PHONE]" in masked_text
    assert "9876543210" not in masked_text


@pytest.mark.asyncio
async def test_db_logger_async_write():
    """Verify SQLite async logger records and reads back sanitized scan events."""
    req = ScanRequest(
        content="Test alert with OTP 123456",
        sender="+919876543210",
        channel=ChannelEnum.SMS
    )
    _ = await run_pipeline(req)

    # Allow background log task to commit
    await asyncio.sleep(0.1)

    logs = await audit_logger.get_recent_logs(limit=5)
    assert len(logs) > 0
    latest = logs[0]
    assert "+91-XXXXX-3210" in latest["masked_sender"]
    assert "123456" not in latest["masked_content"]
