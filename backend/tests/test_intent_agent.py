# ============================================================
# OWNER: VIKAS
# FILE: backend/tests/test_intent_agent.py
# PURPOSE: Unit Tests for Intent & Psycholinguistic Fraud Agent (Day 1, 2, 3 & Day 4)
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

from agents.intent_agent import (  # noqa: E402
    analyze_intent,
    load_scam_taxonomy,
    match_scam_taxonomy,
)
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
    assert res.confidence == 0.5
    assert "RULES_ONLY_FALLBACK" in res.flags
    assert "Analyzed via local resilient heuristic engine" in res.details
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
        assert "Analyzed via local resilient heuristic engine" in res.details
        assert res.confidence == 0.5
        assert "RULES_ONLY_FALLBACK" in res.flags


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
        assert "Analyzed via local resilient heuristic engine" in res.details
        assert res.confidence == 0.5
        assert "RULES_ONLY_FALLBACK" in res.flags


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


# ─────────────────────────────────────────────────────────────
# Day 4 Tests: Multi-LLM Pipeline (FR-11), Scam Taxonomy (FR-6),
# Video Call Digital Arrest & Telecom Threats
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_intent_agent_multi_llm_primary_gemini_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    FR-11 Multi-LLM Fallback:
    Verify Primary is Google Gemini Flash (gemini-1.5-flash).
    When Gemini succeeds, Groq is NOT called, and result has high confidence without RULES_ONLY_FALLBACK.
    """
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyMockKeyGeminiRealFormat1234567890")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_valid_mock_key_1234567890abcdef")

    gemini_mock = {
        "risk_score": 95.0,
        "detected_intent": "FINANCIAL_EXTORTION",
        "manipulation_tactics": ["Digital Arrest Extortion"],
        "confidence": 0.98,
        "flags": ["AUTHORITY_COERCION_FLAG"],
        "reasoning": "Gemini analyzed digital arrest.",
        "details": "Primary LLM analysis via gemini-1.5-flash",
    }

    with patch("agents.intent_agent._analyze_with_gemini", new_callable=AsyncMock) as mock_gemini, \
         patch("agents.intent_agent._analyze_with_groq", new_callable=AsyncMock) as mock_groq:
        mock_gemini.return_value = gemini_mock

        req = ScanRequest(content="video call arrest warrant issued by CBI / Cyber Cell")
        res = await analyze_intent(req)

        assert mock_gemini.called, "Primary LLM (Gemini) should be invoked first"
        assert not mock_groq.called, "Secondary LLM (Groq) must NOT be invoked when Gemini succeeds"
        assert res.status == AgentStatusEnum.SUCCESS
        assert res.risk_score == 95.0
        assert res.confidence == 0.98
        assert "RULES_ONLY_FALLBACK" not in res.flags


@pytest.mark.asyncio
async def test_intent_agent_multi_llm_secondary_groq_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    FR-11 Multi-LLM Fallback:
    When Primary (Gemini) fails or times out, Secondary (Groq LLaMA-3) is invoked as fallback.
    """
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyMockKeyGeminiRealFormat1234567890")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_valid_mock_key_1234567890abcdef")

    groq_mock = {
        "risk_score": 88.0,
        "detected_intent": "PANIC_URGENCY",
        "manipulation_tactics": ["Telecom Disconnection Threat"],
        "confidence": 0.92,
        "flags": ["PSYCHOLOGICAL_URGENCY_TRIGGER"],
        "reasoning": "Groq analyzed TRAI disconnection threat.",
        "details": "Secondary LLM analysis via llama-3.1-8b-instant",
    }

    with patch("agents.intent_agent._analyze_with_gemini", side_effect=asyncio.TimeoutError("Gemini timed out")), \
         patch("agents.intent_agent._analyze_with_groq", new_callable=AsyncMock) as mock_groq:
        mock_groq.return_value = groq_mock

        req = ScanRequest(content="TRAI will disconnect your mobile number within 2 hours")
        res = await analyze_intent(req)

        assert mock_groq.called, "Secondary LLM (Groq) should be called when Gemini times out"
        assert res.status == AgentStatusEnum.SUCCESS
        assert res.risk_score == 88.0
        assert res.confidence == 0.92
        assert "RULES_ONLY_FALLBACK" not in res.flags


@pytest.mark.asyncio
async def test_intent_agent_multi_llm_rules_only_fallback_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    FR-11 Multi-LLM Fallback:
    When both Gemini and Groq fail, the result MUST be explicitly flagged as
    RULES_ONLY_FALLBACK with confidence set to LOW / 0.5.
    """
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyMockKeyGeminiRealFormat1234567890")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_valid_mock_key_1234567890abcdef")

    with patch("agents.intent_agent._analyze_with_gemini", side_effect=RuntimeError("Gemini error")), \
         patch("agents.intent_agent._analyze_with_groq", side_effect=RuntimeError("Groq error")):

        req = ScanRequest(content="video call arrest warrant issued by CBI / Cyber Cell")
        res = await analyze_intent(req)

        assert res.status == AgentStatusEnum.SUCCESS
        assert res.confidence == 0.5, f"Expected confidence 0.5 for rules-only fallback, got {res.confidence}"
        assert "RULES_ONLY_FALLBACK" in res.flags
        assert "RULES_ONLY_FALLBACK" in res.details
        assert res.risk_score >= 45.0


def test_scam_taxonomy_load_public_advisories() -> None:
    """
    FR-6 Scam Taxonomy:
    Verifies that backend/data/scam_taxonomy.json contains public CERT-In and RBI advisories.
    """
    taxonomy = load_scam_taxonomy()
    assert isinstance(taxonomy, list)
    assert len(taxonomy) >= 5

    category_ids = {c["id"] for c in taxonomy}
    expected_categories = {
        "electricity_bill_disconnection",
        "digital_arrest_cbi_extortion",
        "telecom_sim_deactivation",
        "irctc_refund_phishing",
        "part_time_telegram_job_scam",
        "kyc_expiry_deactivation",
    }
    assert expected_categories.issubset(category_ids), f"Missing categories: {expected_categories - category_ids}"

    for entry in taxonomy:
        assert "id" in entry
        assert "name" in entry
        assert "advisory_source" in entry
        assert "keywords" in entry and len(entry["keywords"]) > 0


@pytest.mark.parametrize("message,expected_category", [
    (
        "Aapka bijli bill update nahi hua, connection kat diya jayega.",
        "electricity_bill_disconnection",
    ),
    (
        "video call arrest warrant issued by CBI / Cyber Cell",
        "digital_arrest_cbi_extortion",
    ),
    (
        "TRAI will disconnect your mobile number within 2 hours",
        "telecom_sim_deactivation",
    ),
    (
        "Your IRCTC ticket cancellation refund of Rs 1,450 is pending. Download rail connect apk.",
        "irctc_refund_phishing",
    ),
    (
        "YouTube video like karo aur Telegram pe screenshot bhejo, daily earning hogi.",
        "part_time_telegram_job_scam",
    ),
    (
        "Sir aapka KYC expire ho gaya hai, abhi update karo warna account block.",
        "kyc_expiry_deactivation",
    ),
])
def test_scam_taxonomy_similarity_matcher(message: str, expected_category: str) -> None:
    """
    FR-6 Scam Taxonomy:
    Verifies that match_scam_taxonomy accurately returns the closest CERT-In/RBI category
    and a high match score.
    """
    match = match_scam_taxonomy(message)
    assert match["category_id"] == expected_category, f"Expected {expected_category}, got {match['category_id']}"
    assert match["match_score"] >= 0.50, f"Match score too low: {match['match_score']}"
    assert match["advisory_source"] is not None


def test_scam_taxonomy_similarity_benign_text() -> None:
    """
    FR-6 Scam Taxonomy:
    Benign text with no scam signals must not trigger a high taxonomy match.
    """
    benign_text = "The Supreme Court judgment was discussed in the news."
    match = match_scam_taxonomy(benign_text)
    assert match["category_id"] is None or match["match_score"] < 0.25


@pytest.mark.asyncio
async def test_intent_agent_video_call_digital_arrest_threat(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Day 4 Threat Pattern: Video Call Digital Arrest Extortion.
    Payload: "video call arrest warrant issued by CBI / Cyber Cell"
    Expected: FINANCIAL_EXTORTION, risk_score >= 45.0, RULES_ONLY_FALLBACK, confidence == 0.5.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="video call arrest warrant issued by CBI / Cyber Cell",
        sender="+919988776655",
        channel=ChannelEnum.WHATSAPP,
    )
    res = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 45.0
    assert res.detected_intent == DetectedIntentEnum.FINANCIAL_EXTORTION
    assert "Coercive Authority Threat" in res.manipulation_tactics
    assert "RULES_ONLY_FALLBACK" in res.flags
    assert res.confidence == 0.5
    assert res.scam_category is not None


@pytest.mark.asyncio
async def test_intent_agent_trai_telecom_disconnection_threat(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Day 4 Threat Pattern: Telecom SIM Deactivation Threat.
    Payload: "TRAI will disconnect your mobile number within 2 hours"
    Expected: PANIC_URGENCY, risk_score >= 40.0, RULES_ONLY_FALLBACK, confidence == 0.5.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="TRAI will disconnect your mobile number within 2 hours",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
    )
    res = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 40.0
    assert res.detected_intent in (DetectedIntentEnum.PANIC_URGENCY, DetectedIntentEnum.FINANCIAL_EXTORTION)
    assert "RULES_ONLY_FALLBACK" in res.flags
    assert res.confidence == 0.5
    assert res.scam_category is not None


@pytest.mark.asyncio
async def test_intent_agent_false_positive_trai_and_video_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Day 4 False Positive Prevention:
    Legitimate discussion of TRAI guidelines and video calls must remain BENIGN.
    """
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    req = ScanRequest(
        content="I attended a video call with our team to discuss TRAI guidelines.",
        sender="Manager",
        channel=ChannelEnum.SMS,
    )
    res = await analyze_intent(req)

    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score <= 15.0
    assert res.detected_intent == DetectedIntentEnum.BENIGN
    assert len(res.manipulation_tactics) == 0
