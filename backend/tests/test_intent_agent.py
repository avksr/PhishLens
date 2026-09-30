# ============================================================
# OWNER: VIKAS
# FILE: backend/tests/test_intent_agent.py
# PURPOSE: Unit Tests for Intent & Psycholinguistic Fraud Agent
# ============================================================

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio  # noqa: F401

_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from agents.intent_agent import analyze_intent  # noqa: E402
from shared.models import (  # noqa: E402
    AgentStatusEnum,
    ChannelEnum,
    DetectedIntentEnum,
    IntentAgentResult,
    ScanRequest,
)


@pytest.mark.asyncio
async def test_intent_agent_high_urgency_scam(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Test 1: High Urgency Scam Verification.
    Payload: "URGENT: SBI account blocked within 2 hours submit PAN"
    Expected: risk_score >= 80, intent KYC_VERIFICATION or PANIC_URGENCY.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="URGENT: SBI account blocked within 2 hours submit PAN",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 80, f"Expected risk_score >= 80, got {res.risk_score}"
    assert res.detected_intent in (
        DetectedIntentEnum.KYC_VERIFICATION,
        DetectedIntentEnum.PANIC_URGENCY,
    ), f"Unexpected intent: {res.detected_intent}"
    assert len(res.manipulation_tactics) >= 1
    assert res.latency_ms >= 0.0


@pytest.mark.asyncio
async def test_intent_agent_benign_otp_notification(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Test 2: Benign OTP Notification Verification.
    Payload: "Your OTP for Amazon is 123456. Valid for 5 mins - HDFC Bank"
    Expected: risk_score <= 15, intent BENIGN.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="Your OTP for Amazon is 123456. Valid for 5 mins - HDFC Bank",
        sender="VM-HDFCBK",
        channel=ChannelEnum.SMS,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score <= 15, f"Expected risk_score <= 15, got {res.risk_score}"
    assert res.detected_intent == DetectedIntentEnum.BENIGN
    assert res.manipulation_tactics == []


@pytest.mark.asyncio
async def test_intent_agent_electricity_extortion_scam(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Test 3: Electricity Power Cut Extortion Scam.
    Payload: "Electricity power disconnected tonight at 9.30 pm contact officer"
    Expected: risk_score >= 70, intent FINANCIAL_EXTORTION or PANIC_URGENCY.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="Electricity power disconnected tonight at 9.30 pm contact officer",
        sender="+918250912345",
        channel=ChannelEnum.SMS,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 70, f"Expected risk_score >= 70, got {res.risk_score}"
    assert res.detected_intent in (
        DetectedIntentEnum.FINANCIAL_EXTORTION,
        DetectedIntentEnum.PANIC_URGENCY,
    ), f"Unexpected intent: {res.detected_intent}"
    assert len(res.manipulation_tactics) >= 1


@pytest.mark.asyncio
async def test_intent_agent_offline_heuristic_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Test 4: Offline Heuristic Fallback SLA & Data Quality.
    Expected: runs in < 50ms, returns valid result, confidence=0.85, correct details.
    """
    monkeypatch.setenv("GROQ_API_KEY", "dummy_groq_api_key_not_real")
    monkeypatch.setenv("GEMINI_API_KEY", "your_gemini_api_key_here")

    req = ScanRequest(
        content="URGENT: Your account is blocked today. Submit PAN immediately.",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
    )
    t0 = time.perf_counter()
    res: IntentAgentResult = await analyze_intent(req)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.confidence == 0.85
    assert res.details == "Analyzed via local resilient heuristic engine"
    assert elapsed_ms < 50.0, f"Heuristic fallback exceeded 50ms SLA: {elapsed_ms}ms"
    assert res.risk_score > 0.0


@pytest.mark.asyncio
async def test_intent_agent_groq_mock_integration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that valid Groq JSON responses are properly parsed into IntentAgentResult."""
    monkeypatch.setenv("GROQ_API_KEY", "gsk_valid_mock_key_1234567890abcdef")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    mock_json = {
        "risk_score": 92.0,
        "detected_intent": "KYC_VERIFICATION",
        "manipulation_tactics": ["False Urgency", "Fear Appeal"],
        "confidence": 0.94,
        "flags": ["PSYCHOLOGICAL_URGENCY_TRIGGER", "UNVERIFIED_KYC_SOLICITATION"],
        "reasoning": "Coercive urgency demanding PAN card submission.",
        "details": "Linguistic markers match high-probability scam corpus."
    }

    mock_chat_completion = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps(mock_json)
    mock_chat_completion.choices = [mock_choice]

    with patch("agents.intent_agent._analyze_with_groq", new_callable=AsyncMock) as mock_groq:
        mock_groq.return_value = mock_json

        req = ScanRequest(content="Update your KYC at https://sbi-fake.top")
        res = await analyze_intent(req)

        assert res.status == AgentStatusEnum.SUCCESS
        assert res.risk_score == 92.0
        assert res.detected_intent == DetectedIntentEnum.KYC_VERIFICATION
        assert res.confidence == 0.94
        assert "False Urgency" in res.manipulation_tactics


@pytest.mark.asyncio
async def test_intent_agent_empty_content() -> None:
    """Verifies that empty/whitespace content gracefully returns SKIPPED status."""
    req = ScanRequest(content="   ")
    res = await analyze_intent(req)
    assert res.status == AgentStatusEnum.SKIPPED
    assert res.risk_score == 0.0
    assert res.detected_intent == DetectedIntentEnum.BENIGN


@pytest.mark.asyncio
async def test_intent_agent_lottery_reward_scam(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies lottery/part-time job fraud patterns."""
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(content="Congratulations! You won Rs 25 Lakh in KBC lottery. Join Telegram to claim.")
    res = await analyze_intent(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 35.0
    assert res.detected_intent == DetectedIntentEnum.LOTTERY_REWARD


@pytest.mark.asyncio
async def test_intent_agent_fail_safe_exception_shield(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that analyze_intent never raises an unhandled exception even if internals fail."""
    with patch("agents.intent_agent._run_heuristic_fallback", side_effect=RuntimeError("Catastrophic error")):
        monkeypatch.setenv("GROQ_API_KEY", "")
        monkeypatch.setenv("GEMINI_API_KEY", "")

        req = ScanRequest(content="Some message")
        res = await analyze_intent(req)
        assert res.status == AgentStatusEnum.ERROR
        assert res.risk_score == 0.0
        assert "INTENT_AGENT_FAILED" in res.flags
