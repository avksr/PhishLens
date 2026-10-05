# ============================================================
# OWNER: VANSH
# FILE: backend/core/orchestrator.py
# PURPOSE: Parallel Agent Pipeline Orchestrator with Smart Router
#          Supports Text, Image, & PDF Modalities with 3.5s SLA Supervisor
#          Timeout -> SKIPPED (Never crash). GIGW 3.0 Compliant.
# ============================================================

import re
import asyncio
import logging
from typing import Optional

from shared.models import (
    ScanRequest,
    ScanResponse,
    UrlAgentResult,
    SenderAgentResult,
    IntentAgentResult,
    UpiAgentResult,
    OsintHistoryResult,
    DocumentFraudResult,
    AgentStatusEnum,
    ChannelEnum,
    ModalityEnum
)
from agents.url_agent import analyze_url
from agents.sender_agent import analyze_sender
from agents.intent_agent import analyze_intent
from agents.upi_agent import analyze_upi
from agents.osint_agent import analyze_osint
from agents.document_agent import analyze_document
from core.scoring_engine import compute_score
from core.db_logger import log_scan_audit
from core.upload_validator import detect_file_type

logger = logging.getLogger("phishlens.orchestrator")

TIMEOUT_SECONDS = 3.5
URL_REGEX = re.compile(r'https?://[^\s<>"]+')
UPI_VPA_REGEX = re.compile(r'\b[a-zA-Z0-9.\-_]{1,256}@[a-zA-Z0-9]{2,20}\b')

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
    """Supervised call for Atharv's URL Agent with 3.5s timeout. Timeout -> SKIPPED (no crash)."""
    try:
        return await asyncio.wait_for(analyze_url(req), timeout=TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(f"URL Agent timed out (> {TIMEOUT_SECONDS}s). Marking as SKIPPED per SLA.")
        return UrlAgentResult(
            status=AgentStatusEnum.SKIPPED,
            risk_score=0.0,
            details=f"Agent timeout/skipped (> {TIMEOUT_SECONDS}s) — skipped for SLA",
            flags=["URL_TIMEOUT_SKIPPED"]
        )
    except Exception as exc:
        logger.error(f"URL Agent error: {exc}", exc_info=True)
        return UrlAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"Agent error: {str(exc)}",
            flags=["URL_AGENT_ERROR"]
        )


async def safe_sender(req: ScanRequest) -> SenderAgentResult:
    """Supervised call for Avni's Sender Agent with 3.5s timeout. Timeout -> SKIPPED (no crash)."""
    try:
        return await asyncio.wait_for(analyze_sender(req), timeout=TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(f"Sender Agent timed out (> {TIMEOUT_SECONDS}s). Marking as SKIPPED per SLA.")
        return SenderAgentResult(
            status=AgentStatusEnum.SKIPPED,
            risk_score=0.0,
            details=f"Agent timeout/skipped (> {TIMEOUT_SECONDS}s) — skipped for SLA",
            flags=["SENDER_TIMEOUT_SKIPPED"]
        )
    except Exception as exc:
        logger.error(f"Sender Agent error: {exc}", exc_info=True)
        return SenderAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"Agent error: {str(exc)}",
            flags=["SENDER_AGENT_ERROR"]
        )


async def safe_intent(req: ScanRequest) -> IntentAgentResult:
    """Supervised call for Vikas's Intent Agent with 3.5s timeout. Timeout -> SKIPPED (no crash)."""
    try:
        return await asyncio.wait_for(analyze_intent(req), timeout=TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(f"Intent Agent timed out (> {TIMEOUT_SECONDS}s). Marking as SKIPPED per SLA.")
        return IntentAgentResult(
            status=AgentStatusEnum.SKIPPED,
            risk_score=0.0,
            details=f"Agent timeout/skipped (> {TIMEOUT_SECONDS}s) — skipped for SLA",
            reasoning=f"Agent timeout/skipped (> {TIMEOUT_SECONDS}s) — skipped for SLA",
            flags=["INTENT_TIMEOUT_SKIPPED"]
        )
    except Exception as exc:
        logger.error(f"Intent Agent error: {exc}", exc_info=True)
        return IntentAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"Agent error: {str(exc)}",
            reasoning=f"Agent error: {str(exc)}",
            flags=["INTENT_AGENT_ERROR"]
        )


async def safe_upi(req: ScanRequest) -> UpiAgentResult:
    """Supervised call for Avni's UPI VPA Agent with 3.5s timeout. Timeout -> SKIPPED (no crash)."""
    try:
        return await asyncio.wait_for(analyze_upi(req), timeout=TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(f"UPI Agent timed out (> {TIMEOUT_SECONDS}s). Marking as SKIPPED per SLA.")
        return UpiAgentResult(
            status=AgentStatusEnum.SKIPPED,
            risk_score=0.0,
            details=f"Agent timeout/skipped (> {TIMEOUT_SECONDS}s) — skipped for SLA",
            flags=["UPI_TIMEOUT_SKIPPED"]
        )
    except Exception as exc:
        logger.error(f"UPI Agent error: {exc}", exc_info=True)
        return UpiAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"Agent error: {str(exc)}",
            flags=["UPI_AGENT_ERROR"]
        )


async def safe_osint(req: ScanRequest) -> OsintHistoryResult:
    """Supervised call for OSINT Agent with 3.5s timeout. Timeout -> SKIPPED (no crash)."""
    try:
        return await asyncio.wait_for(analyze_osint(req), timeout=TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(f"OSINT Agent timed out (> {TIMEOUT_SECONDS}s). Marking as SKIPPED per SLA.")
        return OsintHistoryResult(
            status=AgentStatusEnum.SKIPPED,
            risk_score=0.0,
            query_target=None,
            total_complaints=0,
            internal_reports_count=0,
            external_forum_mentions=0,
            risk_level="CLEAN",
            details=f"Agent timeout/skipped (> {TIMEOUT_SECONDS}s) — skipped for SLA",
            flags=["OSINT_TIMEOUT_SKIPPED"]
        )
    except Exception as exc:
        logger.debug(f"OSINT Agent error: {exc}")
        return OsintHistoryResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"OSINT lookup error: {str(exc)}",
            flags=["OSINT_AGENT_ERROR"]
        )


async def run_pipeline(req: ScanRequest) -> ScanResponse:
    """
    Vansh's Core Pipeline Orchestrator with Smart Router:
    1. Multi-Modality Smart Router (Text / Image / PDF):
       - PDF: Extracts text, metadata, Aadhaar/PAN, and defanged URLs via Document Agent.
       - Image: Validates magic bytes, extracts visual text/layout.
       - Text: Extracts URL & UPI vectors.
    2. Concurrent Supervised Agent Execution (3.5s Timeout -> SKIPPED, Never Crash)
    3. Multi-Vector Synthesis via Avika's Scoring Engine
    4. Asynchronous PII-Sanitized SQLite / Supabase Audit Logging
    """
    # ── Step 0: Multi-Modality Smart Router (Text / Image / PDF) ──
    doc_fraud_result: Optional[DocumentFraudResult] = None
    target_modality = req.modality or ModalityEnum.TEXT

    # Check if raw binary file was provided or attached
    if req.file_bytes:
        file_info = detect_file_type(req.file_bytes)
        if file_info:
            if file_info["file_type"] == "pdf":
                target_modality = ModalityEnum.DOCUMENT
            elif file_info["file_type"] == "image":
                target_modality = ModalityEnum.IMAGE

    # Smart Router handling for PDF Documents
    if target_modality == ModalityEnum.DOCUMENT or (req.content and req.content.startswith("%PDF-")):
        target_modality = ModalityEnum.DOCUMENT
        try:
            doc_analysis = analyze_document(text=req.content, pdf_bytes=req.file_bytes)
            # Merge extracted URLs from PDF
            if doc_analysis.get("extracted_urls") and not req.extracted_url:
                req.extracted_url = doc_analysis["extracted_urls"][0]

            # Append PDF-extracted text to content for NLP/Intent processing
            pdf_text = doc_analysis.get("pdf_analysis", {}).get("extracted_text", "")
            if pdf_text and pdf_text not in req.content:
                req.content = f"{req.content}\n[PDF Extracted]: {pdf_text}"

            doc_fraud_result = DocumentFraudResult(
                status=AgentStatusEnum.SUCCESS,
                risk_score=doc_analysis.get("risk_score", 0.0),
                flags=doc_analysis.get("flags", []),
                is_forged=doc_analysis.get("risk_score", 0.0) >= 40.0,
                aadhaar_verified=len(doc_analysis.get("aadhaar_numbers", [])) > 0,
                pan_verified=len(doc_analysis.get("pan_numbers", [])) > 0,
                details=f"PDF Document analyzed. Flags: {', '.join(doc_analysis.get('flags', [])) or 'Clean'}",
                latency_ms=doc_analysis.get("latency_ms", 0.0)
            )
        except Exception as e:
            logger.warning(f"Document analysis failed in smart router: {e}")
            doc_fraud_result = DocumentFraudResult(
                status=AgentStatusEnum.ERROR,
                risk_score=0.0,
                details=f"Document analysis error: {e}"
            )

    # ── Step 1: Input Type Auto-Detection (FR-1 & FR-2) ──
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
        # Pre-extract URL if embedded in text message
        if req.extracted_url is None:
            url_match = URL_REGEX.search(req.content)
            if url_match:
                req.extracted_url = url_match.group(0)

    # Determine UPI signal presence
    has_upi_signal = bool(
        detected_type == "upi_handle"
        or UPI_VPA_REGEX.search(req.content)
        or (req.sender and UPI_VPA_REGEX.search(req.sender))
    )

    # ── Step 2: Concurrent Supervised Agent Execution (3.5s Timeout -> SKIPPED) ──
    tasks = [
        safe_url(req),
        safe_sender(req),
        safe_intent(req),
        safe_osint(req),
    ]

    if has_upi_signal:
        tasks.append(safe_upi(req))
        results = await asyncio.gather(*tasks)
        url_r, sender_r, intent_r, osint_r, upi_r = results
    else:
        results = await asyncio.gather(*tasks)
        url_r, sender_r, intent_r, osint_r = results
        upi_r = UpiAgentResult(
            status=AgentStatusEnum.SKIPPED,
            risk_score=0.0,
            details="No UPI VPA handle detected — agent skipped.",
        )

    # ── Step 3: Synthesis via Avika's Scoring Engine ──
    response: ScanResponse = compute_score(
        req=req,
        url_r=url_r,
        sender_r=sender_r,
        intent_r=intent_r,
        upi_r=upi_r,
        osint_history=osint_r,
        doc_r=doc_fraud_result,
        modality=target_modality,
    )
    response.detected_input_type = detected_type
    response.modality = target_modality

    # ── Step 4: Asynchronous Audit Logging (non-blocking) ──
    try:
        asyncio.create_task(log_scan_audit(response, req))
    except Exception as e:
        logger.warning(f"Could not trigger background audit logging: {e}")

    return response
