"""
backend.tests.test_url_agent — Unit tests for the URL & Domain Intelligence Agent.

Run from the project root:
    python -m pytest backend/tests/test_url_agent.py -v

Or from the backend/ directory:
    python -m pytest tests/test_url_agent.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# ── Ensure backend/ and project root are on sys.path so imports resolve ──
_BACKEND_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _BACKEND_DIR.parent
for _p in (str(_BACKEND_DIR), str(_PROJECT_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from agents.url_agent import analyze_url  # noqa: E402
except ImportError:
    from backend.agents.url_agent import analyze_url  # noqa: E402

try:
    from shared.models import (  # noqa: E402
        AgentStatusEnum,
        ScanRequest,
        TldReputationEnum,
        UrlAgentResult,
    )
except ImportError:
    from backend.shared.models import (  # noqa: E402
        AgentStatusEnum,
        ScanRequest,
        TldReputationEnum,
        UrlAgentResult,
    )


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _make_request(
    content: str = "Test message with URL payload",
    extracted_url: str | None = None,
) -> ScanRequest:
    """Shorthand factory for test ScanRequests."""
    return ScanRequest(content=content, extracted_url=extracted_url)


# ──────────────────────────────────────────────
# Test cases
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_url_agent_skipped_when_no_url():
    """
    A payload that contains no URL at all must return:
      - status  = SKIPPED
      - risk_score = 0.0
    """
    req = _make_request(content="Hey, can you send me the report by EOD?")
    result = await analyze_url(req)

    assert isinstance(result, UrlAgentResult)
    assert result.status == AgentStatusEnum.SKIPPED
    assert result.risk_score == 0.0
    assert result.details == "No URL detected in payload"
    assert result.latency_ms >= 0


@pytest.mark.asyncio
async def test_url_agent_legitimate_bank_url():
    """
    An official bank URL (e.g. ``https://www.onlinesbi.sbi/portal``) must:
      - NOT be flagged as typosquatting
      - have a risk score < 15
    """
    req = _make_request(extracted_url="https://www.onlinesbi.sbi/portal")

    # Patch WHOIS so tests don't make real network calls
    with patch(
        "backend.agents.url_agent._check_whois_age",
        return_value=(365, 0.0, []),
    ):
        result = await analyze_url(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.risk_score < 15
    assert result.is_typosquatting is False
    assert "TYPOSQUATTING_DETECTED" not in result.flags


@pytest.mark.asyncio
async def test_url_agent_typosquatting_phishing_url():
    """
    A phishing lookalike URL (e.g. ``https://sbi-kyc-verify.top``) must:
      - risk_score ≥ 80
      - is_typosquatting = True
      - tld_reputation = HIGH_RISK
      - contain both TYPOSQUATTING_DETECTED and HIGH_RISK_TLD flags
    """
    req = _make_request(extracted_url="https://sbi-kyc-verify.top")

    with patch(
        "backend.agents.url_agent._check_whois_age",
        return_value=(5, 40.0, ["NEWLY_REGISTERED_DOMAIN (< 30 days)"]),
    ):
        result = await analyze_url(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.risk_score >= 80
    assert result.is_typosquatting is True
    assert result.tld_reputation == TldReputationEnum.HIGH_RISK
    assert "TYPOSQUATTING_DETECTED" in result.flags
    assert "HIGH_RISK_TLD" in result.flags


@pytest.mark.asyncio
async def test_url_agent_handles_exceptions_gracefully():
    """
    When an unexpected error occurs inside the agent, it must:
      - NOT raise an unhandled exception
      - Return a valid UrlAgentResult with status = ERROR
    """
    # Sabotage _parse_domain to force an exception inside the try block
    with patch(
        f"{analyze_url.__module__}._parse_domain",
        side_effect=RuntimeError("simulated parsing failure"),
    ):
        req = _make_request(extracted_url="https://definitely-broken.example")
        result = await analyze_url(req)

    assert isinstance(result, UrlAgentResult)
    assert result.status == AgentStatusEnum.ERROR
    assert result.risk_score == 0.0
    assert "simulated parsing failure" in (result.details or "")
    assert result.latency_ms >= 0


# ──────────────────────────────────────────────
# Additional edge-case tests
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_url_extracted_from_content_body():
    """
    When ``extracted_url`` is ``None`` but ``content`` contains a URL,
    the agent should extract and analyse it.
    """
    msg = "Dear customer, verify your account at https://hdfc-secure-login.xyz/verify immediately."
    req = _make_request(content=msg)

    with patch(
        "backend.agents.url_agent._check_whois_age",
        return_value=(None, 0.0, []),
    ):
        result = await analyze_url(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.url_analyzed is not None
    assert "hdfc-secure-login.xyz" in (result.url_analyzed or "")
    # Should detect typosquatting on HDFC + high-risk .xyz TLD
    assert result.is_typosquatting is True
    assert result.tld_reputation == TldReputationEnum.HIGH_RISK


@pytest.mark.asyncio
async def test_risk_score_clamped_to_100():
    """
    Even when all signals fire, the final risk_score must not exceed 100.
    """
    req = _make_request(extracted_url="https://sbi-kyc-verify.top")

    # Force WHOIS to also add +40 → total = 35 + 50 + 40 = 125 → clamp to 100
    with patch(
        f"{analyze_url.__module__}._check_whois_age",
        return_value=(2, 40.0, ["NEWLY_REGISTERED_DOMAIN (< 30 days)"]),
    ):
        result = await analyze_url(req)

    assert result.risk_score <= 100.0


@pytest.mark.asyncio
async def test_empty_request_returns_skipped():
    """ScanRequest without URL should be SKIPPED, not crash."""
    req = ScanRequest(content="Message without URL")
    result = await analyze_url(req)

    assert result.status == AgentStatusEnum.SKIPPED
    assert result.risk_score == 0.0
