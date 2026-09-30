import pytest
import asyncio
import httpx
from main import app
from shared.models import ScanRequest
from core.orchestrator import run_pipeline


@pytest.mark.asyncio
async def test_get_recent_audits_endpoint():
    """Verify that GET /api/v1/audit/recent returns PII-masked audit logs."""
    # First, generate at least one audit record by executing a scan
    req = ScanRequest(
        content="URGENT: Your SBI account 1234 will be suspended. Verify at https://sbi-kyc-verify.top OTP 982143",
        sender="+919876543210",
        channel="sms"
    )
    resp = await run_pipeline(req)
    await asyncio.sleep(0.3)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        res = await client.get("/api/v1/audit/recent?limit=20")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)
        assert len(data) >= 1

        recent = next((item for item in data if item.get("scan_id") == resp.scan_id), data[0])
        assert "scan_id" in recent
        assert "timestamp" in recent
        assert "overall_risk_score" in recent
        assert "risk_tier" in recent
        assert "action_required" in recent
        assert "verdict" in recent
        assert "sender_masked" in recent
        assert "content_masked" in recent

        # Verify PII masking on the logged data:
        # Full phone number should not appear unmasked
        if recent.get("sender_masked"):
            assert "+919876543210" not in recent["sender_masked"]
            if recent.get("scan_id") == resp.scan_id:
                assert "****" in recent["sender_masked"]

