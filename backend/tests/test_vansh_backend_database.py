# ============================================================
# OWNER: VANSH
# FILE: backend/tests/test_vansh_backend_database.py
# PURPOSE: Full Verification Suite for Vansh Backend & Database
#          - Smart Router (Text / Image / PDF)
#          - Timeout -> SKIPPED (No crash)
#          - ProviderBudget rate counters + TTL cache hits
#          - Startup check & Agent Registry
#          - Upload Hardening (magic bytes + size limit)
#          - DB reports table (1 per reporter per target)
#          - OSINT multi-source & DDG flag off by default
#          - /report rate limit tied to reporter
# ============================================================

import os
import pytest
import asyncio
import hashlib
import httpx
from unittest.mock import patch

from shared.models import (
    ScanRequest,
    ScanResponse,
    ChannelEnum,
    ModalityEnum,
    AgentStatusEnum,
)
from core.orchestrator import run_pipeline, safe_url, safe_intent
from core.provider_budget import provider_budget
from core.agent_registry import agent_registry
from core.upload_validator import (
    validate_upload_bytes,
    UploadSizeExceededError,
    InvalidFileSignatureError,
    detect_file_type
)
from core.db_logger import (
    add_crowdsourced_report,
    get_reports_by_target,
    get_scan_by_id,
    log_scan_audit
)
from agents.osint_agent import analyze_osint, is_ddg_scraping_enabled
from main import app


# ─────────────────────────────────────────────────────────────
# 1. Orchestrator + Smart Router & Timeout SLA (Timeout -> SKIPPED)
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_orchestrator_smart_router_text_url_upi():
    """Verify smart routing auto-classifies and extracts vectors for text, URL, and UPI."""
    # 1. URL routing
    req_url = ScanRequest(content="https://sbi-secure-portal.top", channel=ChannelEnum.UNKNOWN)
    resp_url = await run_pipeline(req_url)
    assert resp_url.detected_input_type == "web_url"
    assert resp_url.modality == ModalityEnum.TEXT

    # 2. UPI routing
    req_upi = ScanRequest(content="electricity-desk@oksbi", channel=ChannelEnum.UNKNOWN)
    resp_upi = await run_pipeline(req_upi)
    assert resp_upi.detected_input_type == "upi_handle"
    assert resp_upi.modality == ModalityEnum.TEXT


@pytest.mark.asyncio
async def test_orchestrator_smart_router_pdf_modality():
    """Verify smart router processes PDF input via Document Agent without crash."""
    sample_pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    req_pdf = ScanRequest(
        content="Suspicious invoice attached for KYC",
        modality=ModalityEnum.DOCUMENT,
        file_bytes=sample_pdf_bytes,
        file_name="suspicious_notice.pdf"
    )
    resp = await run_pipeline(req_pdf)
    assert resp.modality == ModalityEnum.DOCUMENT
    assert resp.scan_id is not None
    assert resp.overall_risk_score is not None


@pytest.mark.asyncio
async def test_orchestrator_timeout_yields_skipped_not_crash():
    """Verify that agent TimeoutError (>3.5s) results in AgentStatusEnum.SKIPPED and NEVER crashes."""
    async def mock_hanging_agent(req):
        await asyncio.sleep(5.0)

    req = ScanRequest(content="Meeting at 5 pm", sender="+919876543210")

    with patch("core.orchestrator.analyze_url", side_effect=mock_hanging_agent):
        with patch("core.orchestrator.TIMEOUT_SECONDS", 0.05):
            res_url = await safe_url(req)
            assert res_url.status == AgentStatusEnum.SKIPPED
            assert "skipped" in res_url.details.lower()
            assert "URL_TIMEOUT_SKIPPED" in res_url.flags

    with patch("core.orchestrator.analyze_intent", side_effect=mock_hanging_agent):
        with patch("core.orchestrator.TIMEOUT_SECONDS", 0.05):
            res_intent = await safe_intent(req)
            assert res_intent.status == AgentStatusEnum.SKIPPED
            assert "skipped" in res_intent.details.lower()
            assert "INTENT_TIMEOUT_SKIPPED" in res_intent.flags


# ─────────────────────────────────────────────────────────────
# 2. ProviderBudget: Rate Counters + TTL Cache (Cache hits never use quota)
# ─────────────────────────────────────────────────────────────

def test_provider_budget_sliding_window_and_cache_preserves_quota():
    """Verify ProviderBudget enforces limits and that cache hits NEVER consume quota."""
    provider_budget.reset()

    # Acquire initial quota
    assert provider_budget.acquire("brave_search") is True
    status_initial = provider_budget.get_status()["brave_search"]
    assert status_initial["total_quota_consumed"] == 1
    assert status_initial["cache_hits_saved"] == 0

    # Store response in TTL cache
    provider_budget.set_cached("brave_search", "test_query", ("result_data", 5), ttl=300)

    # 10 repeat calls should all hit cache and NEVER increment total_quota_consumed
    for _ in range(10):
        cached = provider_budget.get_cached("brave_search", "test_query")
        assert cached == ("result_data", 5)

    status_after_cache = provider_budget.get_status()["brave_search"]
    assert status_after_cache["total_quota_consumed"] == 1, "Cache hits must NOT consume quota!"
    assert status_after_cache["cache_hits_saved"] == 10


# ─────────────────────────────────────────────────────────────
# 3. .env Template & Startup Agent Registry
# ─────────────────────────────────────────────────────────────

def test_startup_agent_registry_evaluates_keys():
    """Verify that agent registry flags missing keys and routes to offline fallback."""
    status = agent_registry.get_status()
    assert "intent_llm" in status
    assert "gemini_vision" in status
    assert "brave_osint" in status
    assert "safe_browsing" in status

    # Verify each agent entry has status, fallback mode, and description
    for agent_name, info in status.items():
        assert "status" in info
        assert "fallback_mode" in info
        assert info["status"] in ("ACTIVE", "FALLBACK_OFFLINE")


# ─────────────────────────────────────────────────────────────
# 4. Upload Hardening: Magic Bytes & Size Limits
# ─────────────────────────────────────────────────────────────

def test_upload_validator_magic_bytes_detection():
    """Verify valid PDF, PNG, and JPEG magic bytes are recognized."""
    pdf_bytes = b"%PDF-1.4 test content"
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF"

    assert detect_file_type(pdf_bytes)["file_type"] == "pdf"
    assert detect_file_type(png_bytes)["file_type"] == "image"
    assert detect_file_type(jpeg_bytes)["file_type"] == "image"

    valid_res = validate_upload_bytes(pdf_bytes, "document.pdf")
    assert valid_res["status"] == "VALID"
    assert valid_res["file_type"] == "pdf"


def test_upload_validator_rejects_spoofed_or_invalid_signatures():
    """Verify polyglots and executable/disguised extensions are rejected."""
    fake_exe = b"MZ\x90\x00\x03\x00\x00\x00"
    with pytest.raises(InvalidFileSignatureError):
        validate_upload_bytes(fake_exe, "invoice.pdf")

    fake_text = b"This is just plain text renamed to pdf"
    with pytest.raises(InvalidFileSignatureError):
        validate_upload_bytes(fake_text, "scan.pdf")


def test_upload_validator_enforces_size_limit():
    """Verify oversized payloads exceed limit and raise UploadSizeExceededError."""
    # Temporarily set limit to 1KB for fast test
    with patch("core.upload_validator.get_max_upload_size_bytes", return_value=1024):
        oversized = b"%PDF" + b"A" * 2000
        with pytest.raises(UploadSizeExceededError):
            validate_upload_bytes(oversized, "huge.pdf")


# ─────────────────────────────────────────────────────────────
# 5. Database: Reports Table (One report per reporter per target)
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_reports_table_enforces_one_report_per_reporter_per_target():
    import uuid
    run_id = uuid.uuid4().hex[:8]
    reporter = f"user_{run_id}"
    target = f"sbi-collect-{run_id}@paytm"

    # First report succeeds
    created1, msg1, rec1 = await add_crowdsourced_report(reporter, target, "upi", "Fake customer care")
    assert created1 is True
    assert msg1 == "REPORT_CREATED"

    # Second report for same target by same reporter must be blocked
    created2, msg2, _ = await add_crowdsourced_report(reporter, target, "upi", "Duplicate report")
    assert created2 is False
    assert msg2 == "ALREADY_REPORTED"

    # Different reporter reporting same target succeeds
    created3, msg3, _ = await add_crowdsourced_report("different_user_hash", target, "upi", "Also saw this")
    assert created3 is True
    assert msg3 == "REPORT_CREATED"

    # Check target retrieval
    reports = await get_reports_by_target(target)
    assert len(reports) >= 2


# ─────────────────────────────────────────────────────────────
# 6. OSINT Agent: Multi-Source + DDG Scraping Off by Default
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_osint_agent_ddg_scraping_flag_off_by_default():
    """Verify DuckDuckGo scraping is OFF by default."""
    assert is_ddg_scraping_enabled() is False


@pytest.mark.asyncio
async def test_osint_agent_queries_internal_db_and_crowdsource():
    """Verify OSINT agent queries internal DB and reports table."""
    req = ScanRequest(
        content="Please transfer money to refund-desk@oksbi for refund.",
        channel=ChannelEnum.UNKNOWN
    )
    result = await analyze_osint(req)
    assert result.query_target == "refund-desk@oksbi"
    assert result.total_complaints >= 1
    assert result.status == AgentStatusEnum.SUCCESS
    assert result.risk_score >= 80.0


# ─────────────────────────────────────────────────────────────
# 7. /report Endpoint Rate Limiting Tied to Reporter
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_report_endpoint_duplicate_returns_409_conflict():
    """Verify POST /api/v1/report returns 409 Conflict when reporter submits duplicate."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        unique_target = f"fraud-{os.urandom(4).hex()}.top"
        headers = {"X-Reporter-ID": "reporter_test_runner_99"}

        payload = {
            "target": unique_target,
            "type": "url",
            "details": "Malicious credential phishing portal"
        }

        # First report -> 201 Created
        res1 = await client.post("/api/v1/report", json=payload, headers=headers)
        assert res1.status_code == 201
        assert res1.json()["status"] == "REPORT_RECORDED"

        # Duplicate report -> 409 Conflict
        res2 = await client.post("/api/v1/report", json=payload, headers=headers)
        assert res2.status_code == 409
        assert "already submitted" in res2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_system_status_endpoint():
    """Verify GET /api/v1/system/status returns agent registry and provider budget stats."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        res = await client.get("/api/v1/system/status")
        assert res.status_code == 200
        data = res.json()
        assert "agent_registry" in data
        assert "provider_budgets" in data
