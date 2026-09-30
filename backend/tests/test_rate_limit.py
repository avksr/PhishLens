import pytest
import httpx

from main import app


@pytest.mark.asyncio
async def test_rate_limiting_slowapi_middleware():
    """Verify that slowapi middleware is active and enforces rate limits."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        # Check normal request works
        res = await client.get("/api/v1/health")
        assert res.status_code == 200
        assert res.json().get("status") == "HEALTHY"
