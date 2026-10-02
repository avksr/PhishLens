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
)
from core.orchestrator import run_pipeline
from core.db_logger import mask_pii


@pytest.mark.asyncio
async def test_pipeline_e2e_high_risk_scam():
    """Send high-risk SBI KYC message; verify pipeline executes in < 3500ms and flags high risk."""
    req = ScanRequest(
        content=(
            "Dear Customer, Your SBI account has been suspended due to pending KYC update. "
            "Submit PAN and verify OTP at https://sbi-kyc-verify.top within 2 hours."
        ),
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
        content="Your OTP for Amazon is 123456. Valid for 5 mins - HDFC Bank",
        sender="VM-HDFCBK",
        extracted_url=None,
        channel=ChannelEnum.SMS
    )

    resp: ScanResponse = await run_pipeline(req)
    assert resp.risk_tier == RiskTierEnum.SAFE
    assert resp.action_required == ActionRequiredEnum.ALLOW
    assert resp.overall_risk_score <= 24


@pytest.mark.asyncio
async def test_pipeline_resilience_agent_failure():
    """Mock agent TimeoutError; verify orchestrator does NOT crash and returns ScanResponse."""
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
    """Verify phone numbers, OTPs, and card numbers are redacted properly per GIGW 3.0."""
    # 1. 10-digit Indian phone masking (+91-987***210)
    phone_raw = "9876543210"
    masked_phone = mask_pii(phone_raw)
    assert masked_phone == "+91-987***210", f"Expected +91-987***210, got {masked_phone}"

    phone_with_cc = "+919876543210"
    masked_phone_cc = mask_pii(phone_with_cc)
    assert masked_phone_cc == "+91-987***210", f"Expected +91-987***210, got {masked_phone_cc}"

    # 2. OTP masking (***)
    otp_text = "Your OTP 123456 is valid for 10 minutes"
    masked_otp = mask_pii(otp_text)
    assert "OTP ***" in masked_otp
    assert "123456" not in masked_otp

    code_text = "verification code 654321"
    masked_code = mask_pii(code_text)
    assert "code ***" in masked_code
    assert "654321" not in masked_code

    # 3. Card number masking (ending ****)
    card_text = "Payment on card ending 8812 was approved"
    masked_card = mask_pii(card_text)
    assert "ending ****" in masked_card
    assert "8812" not in masked_card


def test_input_type_auto_detection_classifier():
    """Verify FR-1 & FR-2: classify_input_type accurately identifies web_url, upi_handle, and text_message."""
    from core.orchestrator import classify_input_type

    # 1. Web URL classifications
    assert classify_input_type("https://sbi-kyc-verify.top") == "web_url"
    assert classify_input_type("http://suspicious-domain.xyz/login?ref=123") == "web_url"
    assert classify_input_type("www.phishingbank.com") == "web_url"
    assert classify_input_type("sbi-kyc-verify.top") == "web_url"
    assert classify_input_type("https://secure.hdfcbank.com/netbanking") == "web_url"

    # 2. UPI Handle classifications
    assert classify_input_type("refund-desk@oksbi") == "upi_handle"
    assert classify_input_type("merchant123@icici") == "upi_handle"
    assert classify_input_type("fraudster.pay@ybl") == "upi_handle"
    assert classify_input_type("upi://pay?pa=fake@okhdfc&pn=HDFC") == "upi_handle"

    # 3. Text Message classifications (including messages with embedded URLs/UPIs)
    assert classify_input_type("Dear customer your electricity bill is unpaid. Pay now.") == "text_message"
    assert classify_input_type("Dear customer, click https://sbi-kyc.top to unblock PAN.") == "text_message"
    assert classify_input_type("Send Rs 500 to merchant@oksbi to claim your prize") == "text_message"
    assert classify_input_type("Your OTP is 482910") == "text_message"
    assert classify_input_type("") == "text_message"


@pytest.mark.asyncio
async def test_pipeline_input_type_auto_classification_wiring():
    """Verify Task 1: run_pipeline auto-classifies free-text inputs and populates detected_input_type."""
    from core.orchestrator import run_pipeline

    # 1. Free-text web URL input
    req_url = ScanRequest(
        content="https://sbi-kyc-verify.top",
        channel=ChannelEnum.UNKNOWN
    )
    resp_url = await run_pipeline(req_url)
    assert req_url.input_type == "web_url"
    assert req_url.metadata.get("input_type") == "web_url"
    assert req_url.extracted_url == "https://sbi-kyc-verify.top"
    assert req_url.channel == ChannelEnum.WEB_URL
    assert resp_url.detected_input_type == "web_url"
    assert resp_url.overall_risk_score > 0

    # 2. Free-text UPI handle input
    req_upi = ScanRequest(
        content="refund-desk@oksbi",
        channel=ChannelEnum.UNKNOWN
    )
    resp_upi = await run_pipeline(req_upi)
    assert req_upi.input_type == "upi_handle"
    assert req_upi.metadata.get("input_type") == "upi_handle"
    assert req_upi.channel == ChannelEnum.UPI_HANDLE
    assert resp_upi.detected_input_type == "upi_handle"
    assert resp_upi.audit_trail.upi_analysis.status == AgentStatusEnum.SUCCESS

    # 3. Plain text message input
    req_txt = ScanRequest(
        content="Meeting at 5 pm for coffee in the office",
        sender="+919876543210",
        channel=ChannelEnum.SMS
    )
    resp_txt = await run_pipeline(req_txt)
    assert req_txt.input_type == "text_message"
    assert resp_txt.detected_input_type == "text_message"


@pytest.mark.asyncio
async def test_audit_privacy_sha256_and_production_mode():
    """Verify Task 2: SHA-256 input_hash computed and content_masked is empty when PRODUCTION_MODE=true."""
    import hashlib
    import os
    from core.db_logger import log_scan_audit, get_scan_by_id, verify_audit_privacy

    raw_text = "SECRET_PAYLOAD: Your account password is 9876543210 and OTP is 112233"
    expected_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

    req = ScanRequest(
        content=raw_text,
        sender="+919876543210",
        channel=ChannelEnum.SMS
    )
    resp = await run_pipeline(req)

    # 1. Dev / Standard mode: input_hash is saved, content is PII-masked
    await log_scan_audit(resp, req)
    record = await get_scan_by_id(resp.scan_id)
    assert record is not None
    assert record["input_hash"] == expected_hash
    assert len(record["input_hash"]) == 64
    assert record["scan_id"] == resp.scan_id
    assert "9876543210" not in record["content_masked"]
    assert "112233" not in record["content_masked"]

    # 2. Production mode (PRODUCTION_MODE=true): content_masked is empty string
    os.environ["PRODUCTION_MODE"] = "true"
    try:
        prod_req = ScanRequest(
            content="TOP_SECRET_ALERT_DO_NOT_STORE_RAW_TEXT",
            sender="+919876543210",
            channel=ChannelEnum.SMS
        )
        prod_resp = await run_pipeline(prod_req)
        await log_scan_audit(prod_resp, prod_req)

        prod_record = await get_scan_by_id(prod_resp.scan_id)
        assert prod_record is not None
        assert prod_record["input_hash"] == hashlib.sha256(prod_req.content.encode("utf-8")).hexdigest()
        assert len(prod_record["input_hash"]) == 64
        # Verify content_masked is empty string
        assert prod_record["content_masked"] == ""
        assert verify_audit_privacy(prod_record, prod_req.content) is True
    finally:
        del os.environ["PRODUCTION_MODE"]


@pytest.mark.asyncio
async def test_audit_inspection_endpoint_us5():
    """Verify US-5: GET /api/v1/audit/{scan_id} returns full execution status for judges/evaluators."""
    import httpx
    from main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        # 1. Perform a scan
        scan_payload = {
            "content": "Verify your identity at https://sbi-kyc-verify.top now",
            "sender": "+919876543210",
            "channel": "sms"
        }
        scan_res = await client.post("/api/v1/scan", json=scan_payload)
        assert scan_res.status_code == 200
        scan_id = scan_res.json()["scan_id"]

        # 2. Query the audit inspection endpoint
        audit_res = await client.get(f"/api/v1/audit/{scan_id}")
        assert audit_res.status_code == 200
        data = audit_res.json()
        assert data["scan_id"] == scan_id
        assert "input_hash" in data
        assert len(data["input_hash"]) == 64  # SHA-256 length
        assert data["status"] == "COMPLETED"
        assert "overall_risk_score" in data
        assert "risk_tier" in data
        assert "action_required" in data

        # 3. Non-existent scan_id returns 404
        not_found_res = await client.get("/api/v1/audit/non-existent-scan-999")
        assert not_found_res.status_code == 404
        assert "not found" in not_found_res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_global_gigw_exception_handler():
    """Verify Task 1.5: Unhandled server errors return sanitized JSON 500 without leaking Python tracebacks."""
    import httpx
    from main import app

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    with patch("api.routes.run_pipeline", side_effect=RuntimeError("Simulated database failure")):
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
            res = await client.post("/api/v1/scan", json={"content": "hello world"})
            assert res.status_code == 500
            data = res.json()
            assert data["error"] == "Internal server error"
            assert data["code"] == "INTERNAL_SERVER_ERROR"
            assert "Traceback" not in res.text
            assert "RuntimeError" not in res.text



