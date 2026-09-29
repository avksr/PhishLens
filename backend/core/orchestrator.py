# ============================================================
# OWNER: VANSH
# FILE: backend/core/orchestrator.py
# PURPOSE: Parallel Agent Pipeline Orchestrator
#   - Runs all 3 agents simultaneously via asyncio.gather
#   - Enforces 3.5s per-agent timeout supervisor (Strict Hackathon SLA)
#   - Passes results to Avika's scoring engine
#   - Logs sanitized scan to SQLite audit DB
#   - Returns final ScanResponse
# ============================================================

import time
import asyncio
import logging
from typing import Callable, Any

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
from core.db_logger import audit_logger

logger = logging.getLogger("phishlens.orchestrator")

AGENT_TIMEOUT_SECONDS = 3.5


async def _run_agent_with_supervisor(
    agent_coro,
    agent_name: str,
    fallback_factory: Callable[[str, float], Any]
) -> Any:
    """
    Supervises agent execution with strict 3.5s SLA timeout and exception shielding.
    Guarantees the orchestrator pipeline NEVER hangs or crashes.
    """
    t_start = time.perf_counter()
    try:
        res = await asyncio.wait_for(agent_coro, timeout=AGENT_TIMEOUT_SECONDS)
        elapsed = round((time.perf_counter() - t_start) * 1000, 2)
        if hasattr(res, "latency_ms") and getattr(res, "latency_ms", 0.0) == 0.0:
            res.latency_ms = elapsed
        return res
    except asyncio.TimeoutError:
        elapsed = round((time.perf_counter() - t_start) * 1000, 2)
        logger.warning(f"Agent '{agent_name}' timed out after {elapsed}ms (> {AGENT_TIMEOUT_SECONDS}s).")
        return fallback_factory(f"TIMEOUT_EXCEEDED: {agent_name} exceeded {AGENT_TIMEOUT_SECONDS}s SLA", elapsed)
    except Exception as exc:
        elapsed = round((time.perf_counter() - t_start) * 1000, 2)
        logger.error(f"Agent '{agent_name}' raised an unhandled error: {exc}", exc_info=True)
        return fallback_factory(f"AGENT_ERROR: {str(exc)}", elapsed)


def _url_fallback(reason: str, elapsed: float) -> UrlAgentResult:
    return UrlAgentResult(
        status=AgentStatusEnum.ERROR,
        risk_score=0.0,
        flags=["URL_AGENT_FAILED"],
        details=reason,
        latency_ms=elapsed
    )


def _sender_fallback(reason: str, elapsed: float) -> SenderAgentResult:
    return SenderAgentResult(
        status=AgentStatusEnum.ERROR,
        risk_score=0.0,
        flags=["SENDER_AGENT_FAILED"],
        details=reason,
        latency_ms=elapsed
    )


def _intent_fallback(reason: str, elapsed: float) -> IntentAgentResult:
    return IntentAgentResult(
        status=AgentStatusEnum.ERROR,
        risk_score=0.0,
        flags=["INTENT_AGENT_FAILED"],
        reasoning=reason,
        details=reason,
        latency_ms=elapsed
    )


async def run_pipeline(req: ScanRequest) -> ScanResponse:
    """
    Vansh's Core Pipeline Orchestrator:
    1. Launches Atharv (URL), Avni (Sender), and Vikas (Intent) concurrently via asyncio.gather
    2. Enforces 3.5s per-agent supervisor timeout
    3. Invokes Avika's Scoring Engine to synthesize dynamic weights & heuristic escalation rules
    4. Asynchronously commits PII-sanitized audit log to SQLite
    5. Returns unified ScanResponse in sub-1000ms SLA
    """
    pipeline_start = time.perf_counter()

    # Step 1: Parallel Dispatch with Supervisor
    url_coro = _run_agent_with_supervisor(analyze_url(req), "UrlAgent", _url_fallback)
    sender_coro = _run_agent_with_supervisor(analyze_sender(req), "SenderAgent", _sender_fallback)
    intent_coro = _run_agent_with_supervisor(analyze_intent(req), "IntentAgent", _intent_fallback)

    url_result, sender_result, intent_result = await asyncio.gather(
        url_coro, sender_coro, intent_coro
    )

    # Step 2: Synthesis & Scoring via Avika's Engine
    response: ScanResponse = compute_score(req, url_result, sender_result, intent_result)

    # Update end-to-end processing latency
    total_elapsed_ms = round((time.perf_counter() - pipeline_start) * 1000, 2)
    response.processing_time_ms = total_elapsed_ms

    # Step 3: Zero-Trust PII Masked Audit Logging (Non-blocking)
    try:
        asyncio.create_task(audit_logger.log_scan(response, req))
    except Exception as e:
        logger.warning(f"Could not queue audit DB log write: {e}")

    return response
