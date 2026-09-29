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
    AgentStatusEnum
)
from agents.url_agent import analyze_url
from agents.sender_agent import analyze_sender
from agents.intent_agent import analyze_intent
from core.scoring_engine import compute_score
from core.db_logger import log_scan_audit

logger = logging.getLogger("phishlens.orchestrator")

TIMEOUT_SECONDS = 3.5
URL_REGEX = re.compile(r'https?://[^\s<>"]+')


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


async def run_pipeline(req: ScanRequest) -> ScanResponse:
    """
    Vansh's Core Pipeline Orchestrator:
    Executes Atharv (URL), Avni (Sender), and Vikas (Intent) in parallel with 3.5s SLA supervisor,
    delegates synthesis to Avika's scoring engine, and logs to SQLite audit DB.
    """
    # Step 1: URL Pre-Extraction Fallback
    if req.extracted_url is None:
        url_match = URL_REGEX.search(req.content)
        if url_match:
            req.extracted_url = url_match.group(0)

    # Step 2: Concurrent Agent Execution (3.5s Timeout Supervisor)
    url_r, sender_r, intent_r = await asyncio.gather(
        safe_url(req),
        safe_sender(req),
        safe_intent(req)
    )

    # Step 3: Synthesis Delegation
    response: ScanResponse = compute_score(req, url_r, sender_r, intent_r)

    # Step 4: Asynchronous Audit Logging (non-blocking)
    try:
        asyncio.create_task(log_scan_audit(response, req))
    except Exception as e:
        logger.warning(f"Could not trigger background audit logging: {e}")

    return response
