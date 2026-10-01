# ============================================================
# OWNER: VANSH
# FILE: backend/core/orchestrator.py
# PURPOSE: Parallel Agent Pipeline Orchestrator
#   - Step 1: URL Pre-Extraction Fallback
#   - Step 2: Concurrent Agent Execution (3.5s Timeout Supervisor)
#   - Step 3: Synthesis Delegation via Avika's Scoring Engine
#   - Step 4: Non-blocking SQLite Audit Logging
# ============================================================

import re
import asyncio
import logging

from shared.models import (
    ScanRequest,
    ScanResponse,
    UrlAgentResult,
    SenderAgentResult,
    IntentAgentResult,
    UpiAgentResult,
    AgentStatusEnum,
    ChannelEnum
)
from agents.url_agent import analyze_url
from agents.sender_agent import analyze_sender
from agents.intent_agent import analyze_intent
from agents.upi_agent import analyze_upi
from core.scoring_engine import compute_score
from core.db_logger import log_scan_audit

logger = logging.getLogger("phishlens.orchestrator")

TIMEOUT_SECONDS = 3.5
URL_REGEX = re.compile(r'https?://[^\s<>"]+')  # URL extraction
UPI_VPA_REGEX = re.compile(r'\b[a-zA-Z0-9.\-_]{1,256}@[a-zA-Z0-9]{2,20}\b')  # UPI VPA detection

URL_STANDALONE_REGEX = re.compile(
    r'^(?:https?://|www\.)[^\s/$.?#].[^\s]*$',
    re.IGNORECASE
)
DOMAIN_STANDALONE_REGEX = re.compile(
    r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+(?:/[^\s]*)?$',
    re.IGNORECASE
)
UPI_STANDALONE_REGEX = re.compile(
    r'^(?:upi://pay\?[^\s]+|[a-zA-Z0-9.\-_]{1,256}@[a-zA-Z0-9]{2,20})$',
    re.IGNORECASE
)


def classify_input_type(content: str) -> str:
    """
    Auto-classifies free-text input into 'web_url', 'upi_handle', or 'text_message'
    per FR-1 & FR-2 specifications.
    """
    if not content:
        return "text_message"

    text = content.strip()

    # Check standalone UPI VPA or upi:// payment URI
    if UPI_STANDALONE_REGEX.match(text):
        return "upi_handle"

    # Check standalone URL with explicit scheme or www.
    if URL_STANDALONE_REGEX.match(text):
        return "web_url"

    # Check single-token domain format e.g. "sbi-kyc-verify.top" or "google.com/path"
    if " " not in text and "\n" not in text and DOMAIN_STANDALONE_REGEX.match(text):
        if "@" not in text:
            return "web_url"

    return "text_message"


async def safe_url(req: ScanRequest) -> UrlAgentResult:
    """Supervised call for Atharv's URL Agent with 3.5s timeout and error shielding."""
    try:
        return await asyncio.wait_for(analyze_url(req), timeout=TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(f"URL Agent timed out (> {TIMEOUT_SECONDS}s).")
        return UrlAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details="Agent timeout/error",
            flags=["URL_TIMEOUT_EXCEEDED"]
        )
    except Exception as exc:
        logger.error(f"URL Agent error: {exc}", exc_info=True)
        return UrlAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"Agent timeout/error: {str(exc)}",
            flags=["URL_AGENT_ERROR"]
        )


async def safe_sender(req: ScanRequest) -> SenderAgentResult:
    """Supervised call for Avni's Sender Agent with 3.5s timeout and error shielding."""
    try:
        return await asyncio.wait_for(analyze_sender(req), timeout=TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(f"Sender Agent timed out (> {TIMEOUT_SECONDS}s).")
        return SenderAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details="Agent timeout/error",
            flags=["SENDER_TIMEOUT_EXCEEDED"]
        )
    except Exception as exc:
        logger.error(f"Sender Agent error: {exc}", exc_info=True)
        return SenderAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"Agent timeout/error: {str(exc)}",
            flags=["SENDER_AGENT_ERROR"]
        )


async def safe_intent(req: ScanRequest) -> IntentAgentResult:
    """Supervised call for Vikas's Intent Agent with 3.5s timeout and error shielding."""
    try:
        return await asyncio.wait_for(analyze_intent(req), timeout=TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(f"Intent Agent timed out (> {TIMEOUT_SECONDS}s).")
        return IntentAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details="Agent timeout/error",
            reasoning="Agent timeout/error",
            flags=["INTENT_TIMEOUT_EXCEEDED"]
        )
    except Exception as exc:
        logger.error(f"Intent Agent error: {exc}", exc_info=True)
        return IntentAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"Agent timeout/error: {str(exc)}",
            reasoning=f"Agent timeout/error: {str(exc)}",
            flags=["INTENT_AGENT_ERROR"]
        )


async def safe_upi(req: ScanRequest) -> UpiAgentResult:
    """Supervised call for Avni's UPI VPA Agent with 3.5s timeout and error shielding."""
    try:
        return await asyncio.wait_for(analyze_upi(req), timeout=TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(f"UPI Agent timed out (> {TIMEOUT_SECONDS}s).")
        return UpiAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details="Agent timeout/error",
            flags=["UPI_TIMEOUT_EXCEEDED"]
        )
    except Exception as exc:
        logger.error(f"UPI Agent error: {exc}", exc_info=True)
        return UpiAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"Agent timeout/error: {str(exc)}",
            flags=["UPI_AGENT_ERROR"]
        )


async def run_pipeline(req: ScanRequest) -> ScanResponse:
    """
    Vansh's Core Pipeline Orchestrator:
    Executes Atharv (URL), Avni (Sender + UPI), and Vikas (Intent) in parallel
    with 3.5s SLA supervisor, delegates synthesis to Avika's scoring engine,
    and logs to SQLite audit DB.
    """
    # Step 0: Input Type Auto-Detection (FR-1 & FR-2)
    detected_type = classify_input_type(req.content)
    req.input_type = detected_type
    if req.metadata is None:
        req.metadata = {}
    req.metadata["input_type"] = detected_type

    if detected_type == "web_url":
        if req.extracted_url is None:
            stripped = req.content.strip()
            req.extracted_url = stripped if stripped.startswith(("http://", "https://")) else f"https://{stripped}"
        if req.channel in (ChannelEnum.SMS, ChannelEnum.UNKNOWN):
            req.channel = ChannelEnum.WEB_URL
    elif detected_type == "upi_handle":
        if req.channel in (ChannelEnum.SMS, ChannelEnum.UNKNOWN):
            req.channel = ChannelEnum.UPI_HANDLE
    else:
        # Step 1: URL Pre-Extraction Fallback for general text messages
        if req.extracted_url is None:
            url_match = URL_REGEX.search(req.content)
            if url_match:
                req.extracted_url = url_match.group(0)

    # Step 1b: Determine whether to run the UPI agent
    # Activate if classified as upi_handle OR a UPI VPA pattern (@psp) is detected in content/sender.
    has_upi_signal = bool(
        detected_type == "upi_handle"
        or UPI_VPA_REGEX.search(req.content)
        or (req.sender and UPI_VPA_REGEX.search(req.sender))
    )

    # Step 2: Concurrent Agent Execution (3.5s Timeout Supervisor)
    if has_upi_signal:
        url_r, sender_r, intent_r, upi_r = await asyncio.gather(
            safe_url(req),
            safe_sender(req),
            safe_intent(req),
            safe_upi(req),
        )
    else:
        url_r, sender_r, intent_r = await asyncio.gather(
            safe_url(req),
            safe_sender(req),
            safe_intent(req)
        )
        upi_r = UpiAgentResult(
            status=AgentStatusEnum.SKIPPED,
            risk_score=0.0,
            details="No UPI VPA handle detected — agent skipped.",
        )

    # Step 3: Synthesis Delegation
    response: ScanResponse = compute_score(req, url_r, sender_r, intent_r, upi_r)

    # Step 4: Asynchronous Audit Logging (non-blocking)
    try:
        asyncio.create_task(log_scan_audit(response, req))
    except Exception as e:
        logger.warning(f"Could not trigger background audit logging: {e}")

    return response
