import pytest
import asyncio
import httpx

from main import app

@pytest.mark.asyncio
async def test_rate_limiting_health_endpoint():
    """Verify that health endpoint works cleanly with rate limiter active."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        res = await client.get("/api/v1/health")
        assert res.status_code == 200
        assert res.json().get("status") == "HEALTHY"

@pytest.mark.asyncio
async def test_rate_limiting_post_scan_returns_429_on_abuse():
    """Verify that POST /api/v1/scan returns HTTP 429 when rate limit of 30 req/min is exceeded."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        payload = {
            "content": "Test rate limit verification message",
            "sender": "+919876543210",
            "channel": "sms"
        }

        # Burst requests beyond 30 requests/minute to trigger HTTP 429
        got_429 = False
        for _ in range(35):
            res = await client.post("/api/v1/scan", json=payload)
            if res.status_code == 429:
                got_429 = True
                break

        assert got_429 is True, "Expected HTTP 429 Too Many Requests when exceeding 30 req/min"
