"""
backend/tests/test_upi_agent.py
-------------------------------
Unit tests for Avni's UPI VPA Deception Detection Agent.
"""

import pytest
from shared.models import ScanRequest, AgentStatusEnum
from agents.upi_agent import analyze_upi


@pytest.mark.asyncio
async def test_upi_agent_skipped_when_no_vpa():
    """Verify that input without a UPI handle returns SKIPPED."""
    req = ScanRequest(content="Hello please check your email for the receipt", channel="sms")
    res = await analyze_upi(req)
    assert res.status_code if hasattr(res, "status_code") else res.status == AgentStatusEnum.SKIPPED
    assert res.risk_score == 0.0


@pytest.mark.asyncio
async def test_upi_agent_cross_brand_impersonation():
    """Verify cross-brand spoofing like sbi-refund@paytm or sbi-support@ybl."""
    req = ScanRequest(
        content="Pay fee of Rs 500 to sbi-refund-desk@paytm immediately",
        channel="sms"
    )
    res = await analyze_upi(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 50.0
    assert res.is_spoofed_merchant is True
    assert any("BRAND_MISMATCH" in f or "DECEPTIVE" in f or "SPOOF" in f for f in res.flags)


@pytest.mark.asyncio
async def test_upi_agent_scam_keyword_vpa():
    """Verify VPA containing scam keywords (lottery, refund, prize)."""
    req = ScanRequest(
        content="Send payment to claim-lottery-prize@oksbi to receive your reward",
        channel="sms"
    )
    res = await analyze_upi(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 40.0
    assert any("SCAM" in f or "KEYWORD" in f or "SUSPICIOUS" in f for f in res.flags)


@pytest.mark.asyncio
async def test_upi_agent_legitimate_clean_vpa():
    """Verify legitimate benign VPA has low risk score."""
    req = ScanRequest(
        content="Please send payment to rohan.sharma@okaxis for dinner",
        channel="whatsapp"
    )
    res = await analyze_upi(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score <= 20.0
    assert res.is_spoofed_merchant is False


@pytest.mark.asyncio
async def test_upi_agent_fail_safe_shield():
    """Verify that unusual input never causes unhandled exceptions."""
    req = ScanRequest(content="None", channel="sms")
    res = await analyze_upi(req)
    assert res.status in (AgentStatusEnum.SKIPPED, AgentStatusEnum.SUCCESS, AgentStatusEnum.ERROR)
