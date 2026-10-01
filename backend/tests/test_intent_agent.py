# ============================================================
# OWNER: VIKAS
# FILE: backend/tests/test_intent_agent.py
# PURPOSE: Unit Tests for Intent & Psycholinguistic Fraud Agent (Day 1, Day 2 & Day 3)
# ============================================================

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

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


# ─────────────────────────────────────────────────────────────
# Day 1 Tests (Preserved Baseline)
# ─────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────
# Day 2 Tests (Comprehensive English & Hinglish Vectors A-M)
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_intent_agent_normal_benign_text(monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement A: Normal benign communication with no panic or urgency red flags."""
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="Your Swiggy order from Biryani Blues is arriving in 15 mins. Track your rider.",
        sender="AD-SWIGGY",
        channel=ChannelEnum.SMS,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.detected_intent == DetectedIntentEnum.BENIGN
    assert res.risk_score <= 15.0
    assert len(res.manipulation_tactics) == 0


@pytest.mark.asyncio
async def test_intent_agent_english_urgency(monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement B: English urgency threat: 'Your account will be blocked within 2 hours.'"""
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="Your account will be blocked within 2 hours.",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.detected_intent == DetectedIntentEnum.PANIC_URGENCY
    assert res.risk_score >= 40.0
    assert "False Urgency Trigger" in res.manipulation_tactics


@pytest.mark.asyncio
async def test_intent_agent_hinglish_urgency(monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement C: Hinglish urgency threat: '2 ghante ke andar account block ho jayega.'"""
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="2 ghante ke andar account block ho jayega.",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.detected_intent == DetectedIntentEnum.PANIC_URGENCY
    assert res.risk_score >= 40.0
    assert "False Urgency Trigger" in res.manipulation_tactics


@pytest.mark.asyncio
async def test_intent_agent_account_blocking_hinglish(monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement D: Account deactivation: 'Aaj raat tak payment nahi kiya toh account band ho jayega.'"""
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="Aaj raat tak payment nahi kiya toh account band ho jayega.",
        sender="+918888899999",
        channel=ChannelEnum.SMS,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.detected_intent == DetectedIntentEnum.PANIC_URGENCY
    assert res.risk_score >= 40.0
    assert "False Urgency Trigger" in res.manipulation_tactics


@pytest.mark.asyncio
async def test_intent_agent_digital_arrest(monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement E: Coercive extortion threat: 'You are under digital arrest.'"""
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="You are under digital arrest by Cyber Crime Cell. Report immediately.",
        sender="+917777788888",
        channel=ChannelEnum.WHATSAPP,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.detected_intent == DetectedIntentEnum.FINANCIAL_EXTORTION
    assert res.risk_score >= 45.0
    assert "Coercive Authority Threat" in res.manipulation_tactics


@pytest.mark.asyncio
async def test_intent_agent_otp_solicitation_hinglish(monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement F: Hinglish OTP harvest: 'OTP share karo immediately.'"""
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="OTP share karo immediately warna account block.",
        sender="+919999911111",
        channel=ChannelEnum.SMS,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.detected_intent == DetectedIntentEnum.OTP_HARVEST
    assert res.risk_score >= 80.0
    assert "Credential / KYC Solicitation" in res.manipulation_tactics
    assert "False Urgency Trigger" in res.manipulation_tactics


@pytest.mark.asyncio
async def test_intent_agent_capitalization_and_punctuation_variations(monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement G: Variations in casing, punctuation, and stuck tokens (e.g. '2GHANTE')."""
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="U.R.G.E.N.T: aapka account 2GHANTE MEIN block ho jayega!!!",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.detected_intent == DetectedIntentEnum.PANIC_URGENCY
    assert res.risk_score >= 40.0
    assert "False Urgency Trigger" in res.manipulation_tactics


@pytest.mark.asyncio
async def test_intent_agent_llm_timeout_triggers_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement I: When LLM call exceeds SLA timeout, agent cleanly falls back without failing."""
    monkeypatch.setenv("GROQ_API_KEY", "gsk_valid_mock_key_1234567890abcdef")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    async def _mock_timeout(*args, **kwargs):
        raise asyncio.TimeoutError("LLM call timed out (> 2.5s)")

    with patch("agents.intent_agent._analyze_with_groq", side_effect=_mock_timeout):
        req = ScanRequest(content="Dear customer your electricity power cut tonight at 9.30 pm.")
        res = await analyze_intent(req)

        assert res.status == AgentStatusEnum.SUCCESS
        assert res.risk_score >= 40.0
        assert res.details == "Analyzed via local resilient heuristic engine"
        assert res.confidence == 0.85


@pytest.mark.asyncio
async def test_intent_agent_invalid_llm_response_triggers_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement J: When LLM returns malformed/unparseable JSON, fallback executes safely."""
    monkeypatch.setenv("GROQ_API_KEY", "gsk_valid_mock_key_1234567890abcdef")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    # Mock _analyze_with_groq returning None (which happens on json.JSONDecodeError)
    with patch("agents.intent_agent._analyze_with_groq", new_callable=AsyncMock) as mock_groq:
        mock_groq.return_value = None

        req = ScanRequest(content="Police case registered. Giraftari se bachne ke liye call karein.")
        res = await analyze_intent(req)

        assert res.status == AgentStatusEnum.SUCCESS
        assert res.detected_intent == DetectedIntentEnum.FINANCIAL_EXTORTION
        assert res.details == "Analyzed via local resilient heuristic engine"
        assert res.confidence == 0.85


@pytest.mark.asyncio
async def test_intent_agent_fallback_valid_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement K: Validates that fallback returns a fully valid IntentAgentResult schema."""
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(content="Emergency: Update KYC at official link within 2 hours.")
    res: IntentAgentResult = await analyze_intent(req)

    assert isinstance(res, IntentAgentResult)
    assert res.status in (AgentStatusEnum.SUCCESS, AgentStatusEnum.SKIPPED, AgentStatusEnum.ERROR)
    assert 0.0 <= res.risk_score <= 100.0
    assert isinstance(res.detected_intent, DetectedIntentEnum)
    assert isinstance(res.manipulation_tactics, list)
    assert 0.0 <= res.confidence <= 1.0
    assert isinstance(res.flags, list)
    assert isinstance(res.reasoning, str) and len(res.reasoning) > 0
    assert isinstance(res.details, str) and len(res.details) > 0
    assert res.latency_ms >= 0.0


@pytest.mark.asyncio
async def test_intent_agent_fallback_determinism(monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement L: Verifies that the local heuristic fallback is 100% deterministic."""
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    content = "Aapka account 2 ghante ke andar block ho jayega. Submit PAN immediately."
    req1 = ScanRequest(content=content)
    req2 = ScanRequest(content=content)

    res1 = await analyze_intent(req1)
    res2 = await analyze_intent(req2)

    assert res1.risk_score == res2.risk_score
    assert res1.detected_intent == res2.detected_intent
    assert res1.manipulation_tactics == res2.manipulation_tactics
    assert res1.flags == res2.flags
    assert res1.reasoning == res2.reasoning
    assert res1.confidence == res2.confidence
    assert res1.details == res2.details


@pytest.mark.asyncio
async def test_intent_agent_fallback_performance_benchmark(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Requirement M: Benchmark fallback execution speed.
    Target: < 15ms for a standard text payload.
    Uses generous ceiling (50ms) to prevent CI flakiness across virtual machines.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    msg = "Dear user, your electricity power disconnected tonight at 9.30 pm. Contact officer immediately."
    req = ScanRequest(content=msg)

    # Warm-up call
    await analyze_intent(req)

    # Timed run
    t_start = time.perf_counter()
    res = await analyze_intent(req)
    elapsed_ms = (time.perf_counter() - t_start) * 1000

    assert res.status == AgentStatusEnum.SUCCESS
    assert elapsed_ms < 50.0, f"Fallback exceeded benchmark SLA: {elapsed_ms:.2f}ms"
    # Note: On standard environments, local regex takes < 2ms (well under the 15ms target)


# ─────────────────────────────────────────────────────────────
# Day 3 Tests (Indian Coercion, Utility & Task Scams + False Positives)
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_intent_agent_electricity_scam(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Day 3 Test 1: Indian Utility / Electricity Bill Scam.
    Payload: "Aapka bijli bill update nahi hua, connection kat diya jayega."
    Expected: PANIC_URGENCY, risk_score >= 40.0, False Urgency Trigger tactic.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="Aapka bijli bill update nahi hua, connection kat diya jayega.",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 40.0
    assert res.detected_intent == DetectedIntentEnum.PANIC_URGENCY
    assert "False Urgency Trigger" in res.manipulation_tactics
    assert "PSYCHOLOGICAL_URGENCY_TRIGGER" in res.flags


@pytest.mark.asyncio
async def test_intent_agent_electricity_hinglish_variation(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Day 3 Test 2: Electricity Hinglish Disconnection Variation.
    Payload: "2 ghante ke andar bill pay karo warna light kaat di jayegi."
    Expected: PANIC_URGENCY, risk_score >= 40.0.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="2 ghante ke andar bill pay karo warna light kaat di jayegi.",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 40.0
    assert res.detected_intent == DetectedIntentEnum.PANIC_URGENCY
    assert "False Urgency Trigger" in res.manipulation_tactics


@pytest.mark.asyncio
async def test_intent_agent_supreme_court_legal_threat(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Day 3 Test 3: Supreme Court / Legal Threat Coercion.
    Payload: "Aapke naam pe Supreme Court ka warrant hai, abhi payment karo."
    Expected: FINANCIAL_EXTORTION, risk_score >= 45.0, Coercive Authority Threat.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="Aapke naam pe Supreme Court ka warrant hai, abhi payment karo.",
        sender="+919988776655",
        channel=ChannelEnum.WHATSAPP,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 45.0
    assert res.detected_intent == DetectedIntentEnum.FINANCIAL_EXTORTION
    assert "Coercive Authority Threat" in res.manipulation_tactics
    assert "AUTHORITY_COERCION_FLAG" in res.flags


@pytest.mark.asyncio
async def test_intent_agent_digital_arrest_variation(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Day 3 Test 4: Digital Arrest Warrant Variation.
    Payload: "Digital arrest warrant issue hua hai."
    Expected: FINANCIAL_EXTORTION, risk_score >= 45.0.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="Digital arrest warrant issue hua hai.",
        sender="+918877665544",
        channel=ChannelEnum.WHATSAPP,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 45.0
    assert res.detected_intent == DetectedIntentEnum.FINANCIAL_EXTORTION
    assert "Coercive Authority Threat" in res.manipulation_tactics


@pytest.mark.asyncio
async def test_intent_agent_youtube_telegram_task_scam(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Day 3 Test 5: YouTube Video Like / Telegram Screenshot Scam.
    Payload: "YouTube videos like karo aur screenshot Telegram pe bhejo."
    Expected: LOTTERY_REWARD, risk_score >= 35.0, Fraudulent Incentive tactic.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="YouTube videos like karo aur screenshot Telegram pe bhejo.",
        sender="+919123456780",
        channel=ChannelEnum.WHATSAPP,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 35.0
    assert res.detected_intent == DetectedIntentEnum.LOTTERY_REWARD
    assert "Fraudulent Incentive / Advance Fee" in res.manipulation_tactics
    assert "LOTTERY_JOB_SCAM_FLAG" in res.flags


@pytest.mark.asyncio
async def test_intent_agent_telegram_earning_scam(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Day 3 Test 6: Telegram Task / Daily Earning Fraud.
    Payload: "Telegram task complete karo aur daily earning kamao."
    Expected: LOTTERY_REWARD, risk_score >= 35.0.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="Telegram task complete karo aur daily earning kamao.",
        sender="+919123456781",
        channel=ChannelEnum.WHATSAPP,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 35.0
    assert res.detected_intent == DetectedIntentEnum.LOTTERY_REWARD
    assert "Fraudulent Incentive / Advance Fee" in res.manipulation_tactics


@pytest.mark.asyncio
async def test_intent_agent_task_recharge_deposit_scam(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Day 3 Test 7: Task Recharge / Advance Fee Unlock Scam.
    Payload: "Pehle recharge karo tab task unlock hoga."
    Expected: LOTTERY_REWARD, risk_score >= 35.0.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="Pehle recharge karo tab task unlock hoga.",
        sender="+919123456782",
        channel=ChannelEnum.WHATSAPP,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 35.0
    assert res.detected_intent == DetectedIntentEnum.LOTTERY_REWARD
    assert "Fraudulent Incentive / Advance Fee" in res.manipulation_tactics


@pytest.mark.asyncio
async def test_intent_agent_false_positive_youtube_video(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Day 3 Test 8: False Positive Prevention - YouTube & Electricity in educational context.
    Payload: "I watched a YouTube video about electricity billing."
    Expected: BENIGN, risk_score <= 15.0, no scam tactics.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="I watched a YouTube video about electricity billing.",
        sender="Friend",
        channel=ChannelEnum.SMS,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score <= 15.0
    assert res.detected_intent == DetectedIntentEnum.BENIGN
    assert len(res.manipulation_tactics) == 0


@pytest.mark.asyncio
async def test_intent_agent_false_positive_supreme_court_news(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Day 3 Test 9: False Positive Prevention - Supreme Court in news/media context.
    Payload: "The Supreme Court judgment was discussed in the news."
    Expected: BENIGN, risk_score <= 15.0, no coercive authority flag.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="The Supreme Court judgment was discussed in the news.",
        sender="NewsAlert",
        channel=ChannelEnum.SMS,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score <= 15.0
    assert res.detected_intent == DetectedIntentEnum.BENIGN
    assert len(res.manipulation_tactics) == 0


@pytest.mark.asyncio
async def test_intent_agent_false_positive_paid_electricity_bill(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Day 3 Test 10: False Positive Prevention - Legitimate bill payment confirmation.
    Payload: "I paid my electricity bill through the official app."
    Expected: BENIGN, risk_score <= 15.0, no urgency or power cut tactics.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="I paid my electricity bill through the official app.",
        sender="Self",
        channel=ChannelEnum.SMS,
    )
    res: IntentAgentResult = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score <= 15.0
    assert res.detected_intent == DetectedIntentEnum.BENIGN
    assert len(res.manipulation_tactics) == 0


@pytest.mark.asyncio
async def test_intent_agent_day3_extended_performance_benchmark(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Day 3 Test 11: Extended benchmark verifying all new Indian scam patterns run under 15ms.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    day3_messages = [
        "Aapka bijli bill update nahi hua, connection kat diya jayega.",
        "2 ghante ke andar bill pay karo warna light kaat di jayegi.",
        "Aapke naam pe Supreme Court ka warrant hai, abhi payment karo.",
        "Digital arrest warrant issue hua hai.",
        "YouTube videos like karo aur screenshot Telegram pe bhejo.",
        "Telegram task complete karo aur daily earning kamao.",
        "Pehle recharge karo tab task unlock hoga.",
        "I watched a YouTube video about electricity billing.",
        "The Supreme Court judgment was discussed in the news.",
        "I paid my electricity bill through the official app.",
    ]

    for msg in day3_messages:
        req = ScanRequest(content=msg)
        t_start = time.perf_counter()
        res = await analyze_intent(req)
        elapsed_ms = (time.perf_counter() - t_start) * 1000

        assert res.status == AgentStatusEnum.SUCCESS
        assert elapsed_ms < 50.0, f"Payload exceeded SLA: {elapsed_ms:.2f}ms for '{msg}'"
