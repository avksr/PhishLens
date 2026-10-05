# ============================================================
# OWNER: VANSH
# FILE: backend/core/orchestrator.py
# PURPOSE: Parallel Multimodal Agent Pipeline Orchestrator
#          - Phase 1 & 2: Smart Modality Router (Text, Vision, Document)
#          - Phase 2: Concurrent Agent Execution (3.5s Timeout Supervisor)
#            Timeout -> SKIPPED (Never crash). GIGW 3.0 Compliant.
#          - Phase 3: Synthesis Delegation via Avika's Scoring Engine
#          - Phase 4: Non-blocking SQLite / Supabase Audit Logging
# ============================================================

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from agents.ai_text_agent import analyze_ai_text
from agents.bank_identity_agent import verify_bank_identity
from agents.document_agent import analyze_document_fraud, analyze_document
from agents.intent_agent import analyze_intent
from agents.osint_agent import analyze_osint
from agents.sender_agent import analyze_sender
from agents.upi_agent import analyze_upi
from agents.url_agent import analyze_url
from agents.vision_agent import analyze_image_screenshot
from core.db_logger import log_scan_audit
from core.scoring_engine import compute_score
from core.upload_validator import detect_file_type
from shared.models import (
    ActionRequiredEnum,
    AgentStatusEnum,
    AiTextAgentResult,
    BankVerificationResult,
    ChannelEnum,
    DocumentFraudResult,
    IntentAgentResult,
    ModalityEnum,
    OsintHistoryResult,
    PrdVerdictEnum,
    RiskTierEnum,
    ScanRequest,
    ScanResponse,
    SenderAgentResult,
    UpiAgentResult,
    UrlAgentResult,
    VisionAnalysisResult,
)

logger = logging.getLogger("phishlens.orchestrator")

TIMEOUT_SECONDS = 3.5
URL_REGEX = re.compile(r'https?://[^\s<>"]+')
UPI_VPA_REGEX = re.compile(r"\b[a-zA-Z0-9.\-_]{1,256}@[a-zA-Z0-9]{2,20}\b")
PHONE_REGEX = re.compile(r"(?:\+?91[\-\s]?)?[6-9]\d{9}")

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


# ── Supervised Worker Wrappers with SLA Timeouts & Fail-safes ───────────────

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
            flags=["URL_TIMEOUT_SKIPPED"],
        )
    except Exception as exc:
        logger.error(f"URL Agent error: {exc}", exc_info=True)
        return UrlAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"Agent error: {str(exc)}",
            flags=["URL_AGENT_ERROR"],
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
            flags=["SENDER_TIMEOUT_SKIPPED"],
        )
    except Exception as exc:
        logger.error(f"Sender Agent error: {exc}", exc_info=True)
        return SenderAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"Agent error: {str(exc)}",
            flags=["SENDER_AGENT_ERROR"],
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
            flags=["INTENT_TIMEOUT_SKIPPED"],
        )
    except Exception as exc:
        logger.error(f"Intent Agent error: {exc}", exc_info=True)
        return IntentAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"Agent error: {str(exc)}",
            reasoning=f"Agent error: {str(exc)}",
            flags=["INTENT_AGENT_ERROR"],
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
            flags=["UPI_TIMEOUT_SKIPPED"],
        )
    except Exception as exc:
        logger.error(f"UPI Agent error: {exc}", exc_info=True)
        return UpiAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"Agent error: {str(exc)}",
            flags=["UPI_AGENT_ERROR"],
        )


async def safe_bank_identity(req: ScanRequest) -> BankVerificationResult:
    """Supervised call for Bank Identity Verification Agent with 3.5s timeout."""
    try:
        return await asyncio.wait_for(verify_bank_identity(req), timeout=TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(f"Bank Identity Agent timed out (> {TIMEOUT_SECONDS}s). Marking as SKIPPED per SLA.")
        return BankVerificationResult(
            status=AgentStatusEnum.SKIPPED,
            details=f"Bank identity timeout (> {TIMEOUT_SECONDS}s) — skipped for SLA",
        )
    except Exception as exc:
        logger.debug(f"Bank identity agent error: {exc}")
        return BankVerificationResult(
            status=AgentStatusEnum.ERROR,
            details=f"Bank identity error: {exc}",
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
            flags=["OSINT_TIMEOUT_SKIPPED"],
        )
    except Exception as exc:
        logger.debug(f"OSINT Agent error: {exc}")
        return OsintHistoryResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"OSINT lookup error: {str(exc)}",
            flags=["OSINT_AGENT_ERROR"],
        )


async def safe_ai_text(req: ScanRequest) -> AiTextAgentResult:
    """Supervised call for AI Text Detector Agent with 3.5s timeout."""
    try:
        return await asyncio.wait_for(analyze_ai_text(req), timeout=TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(f"AI Text Agent timed out (> {TIMEOUT_SECONDS}s). Marking as SKIPPED per SLA.")
        return AiTextAgentResult(
            status=AgentStatusEnum.SKIPPED,
            details=f"AI text detector timeout (> {TIMEOUT_SECONDS}s) — skipped for SLA",
        )
    except Exception as exc:
        logger.debug(f"AI text agent error: {exc}")
        return AiTextAgentResult(
            status=AgentStatusEnum.ERROR,
            details=f"AI text detector error: {exc}",
        )


async def safe_vision(image_bytes: bytes) -> VisionAnalysisResult:
    """Supervised call for Vision Analysis Agent with 3.5s timeout."""
    try:
        return await asyncio.wait_for(analyze_image_screenshot(image_bytes), timeout=TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(f"Vision agent timed out (> {TIMEOUT_SECONDS}s).")
        return VisionAnalysisResult(
            status=AgentStatusEnum.SKIPPED,
            risk_score=0.0,
            details=f"Vision analysis timed out (> {TIMEOUT_SECONDS}s) — skipped for SLA",
            flags=["VISION_TIMEOUT_SKIPPED"],
        )
    except Exception as exc:
        logger.warning(f"Vision agent error: {exc}")
        return VisionAnalysisResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"Vision analysis error: {exc}",
            flags=["VISION_AGENT_ERROR"],
        )


async def safe_doc_fraud(doc_bytes: bytes) -> DocumentFraudResult:
    """Supervised call for Document Fraud Detection Agent with 3.5s timeout."""
    try:
        return await asyncio.wait_for(analyze_document_fraud(doc_bytes), timeout=TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(f"Document agent timed out (> {TIMEOUT_SECONDS}s).")
        return DocumentFraudResult(
            status=AgentStatusEnum.SKIPPED,
            risk_score=0.0,
            details=f"Document analysis timed out (> {TIMEOUT_SECONDS}s) — skipped for SLA",
            flags=["DOC_TIMEOUT_SKIPPED"],
        )
    except Exception as exc:
        logger.warning(f"Document agent error: {exc}")
        return DocumentFraudResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=f"Document analysis error: {exc}",
            flags=["DOC_AGENT_ERROR"],
        )


# ── Core Text Pipeline Orchestration ───────────────────────────────────────

async def run_pipeline(req: ScanRequest) -> ScanResponse:
    """
    Vansh's Core Pipeline Orchestrator with Multimodal Smart Router:
    Executes Atharv (URL), Avni (Sender, UPI, Bank Match, OSINT), Vikas (Intent, AI Text),
    and Multimodal Vision (ELA & OCR) / Document Fraud in parallel with 3.5s SLA supervisor,
    delegates synthesis to Avika's scoring engine, and logs to SQLite audit DB.
    """
    target_modality = req.modality or ModalityEnum.TEXT
    vision_r: Optional[VisionAnalysisResult] = None
    doc_r: Optional[DocumentFraudResult] = None

    # Step 0a: Multimodal Smart Routing for attached binary uploads
    if req.file_bytes:
        file_info = detect_file_type(req.file_bytes)
        detected_fmt = file_info.get("file_type", "") if isinstance(file_info, dict) else ""
        if detected_fmt in ("image", "IMAGE") or target_modality == ModalityEnum.IMAGE:
            target_modality = ModalityEnum.IMAGE
            vision_r = await safe_vision(req.file_bytes)
            if vision_r.ocr_extracted_text and vision_r.ocr_extracted_text not in req.content:
                req.content = f"{req.content} {vision_r.ocr_extracted_text}".strip()
            for vpa in vision_r.extracted_vpas:
                if vpa not in req.content:
                    req.content += f" {vpa}"
            for ph in vision_r.extracted_phones:
                if not req.sender:
                    req.sender = ph
                elif ph not in req.content:
                    req.content += f" {ph}"
        elif detected_fmt in ("pdf", "PDF", "document", "DOCUMENT") or target_modality == ModalityEnum.DOCUMENT:
            target_modality = ModalityEnum.DOCUMENT
            doc_r = await safe_doc_fraud(req.file_bytes)
            if doc_r.details and doc_r.details not in req.content:
                req.content = f"{req.content} {doc_r.details}".strip()

    # Step 0b: Input Type Auto-Detection (FR-1 & FR-2)
    detected_type = classify_input_type(req.content)
    if detected_type == "web_url":
        if not req.extracted_url:
            cleaned = req.content.strip()
            if not cleaned.lower().startswith(('http://', 'https://')):
                cleaned = f'https://{cleaned}'
            req.extracted_url = cleaned
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

    # Step 1b: Determine whether to run financial & OSINT vectors
    has_upi = bool(
        detected_type == "upi_handle"
        or UPI_VPA_REGEX.search(req.content)
        or (req.sender and UPI_VPA_REGEX.search(req.sender))
    )
    has_phone = bool(PHONE_REGEX.search(req.content) or (req.sender and PHONE_REGEX.search(req.sender)))

    # Step 2: Concurrent Agent Execution (3.5s Timeout Supervisor)
    tasks = [
        safe_url(req),
        safe_sender(req),
        safe_intent(req),
        safe_ai_text(req),
    ]

    if has_upi:
        tasks.append(safe_upi(req))
        tasks.append(safe_bank_identity(req))
    else:
        tasks.append(asyncio.sleep(0, result=UpiAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0, details="No UPI handle")))
        tasks.append(asyncio.sleep(0, result=BankVerificationResult(status=AgentStatusEnum.SKIPPED, details="No UPI handle")))

    if has_upi or has_phone:
        tasks.append(safe_osint(req))
    else:
        tasks.append(asyncio.sleep(0, result=OsintHistoryResult(status=AgentStatusEnum.SKIPPED, details="No target for OSINT")))

    results = await asyncio.gather(*tasks)

    url_r: UrlAgentResult = results[0]
    sender_r: SenderAgentResult = results[1]
    intent_r: IntentAgentResult = results[2]
    ai_text_r: AiTextAgentResult = results[3]
    upi_r: UpiAgentResult = results[4]
    bank_r: BankVerificationResult = results[5]
    osint_r: OsintHistoryResult = results[6]

    # Step 3: Synthesis Delegation via Avika's Scoring Engine
    response: ScanResponse = compute_score(
        req=req,
        url_r=url_r,
        sender_r=sender_r,
        intent_r=intent_r,
        upi_r=upi_r,
        bank_verification=bank_r,
        osint_history=osint_r,
        ai_text=ai_text_r,
        vision_r=vision_r,
        doc_r=doc_r,
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


# ── Multimodal Pipeline Orchestration (Images & Documents) ─────────────────

async def run_multimodal_pipeline(
    file_bytes: Union[bytes, ScanRequest],
    filename: str = "upload.png",
    mime_type: str = "image/png",
    optional_text: str = "",
    sender: Optional[str] = None,
) -> ScanResponse:
    """
    Phase 1 & 2 Multimodal Smart Router:
    Routes image screenshots to Vision AI & OCR, documents to Doc Fraud Engine,
    then combines extracted textual signals with bank & OSINT intelligence.
    """
    if isinstance(file_bytes, ScanRequest):
        req = file_bytes
        actual_bytes = req.file_bytes or b""
        actual_filename = req.file_name or filename
        actual_mime = "application/pdf" if actual_filename.lower().endswith(".pdf") else "image/png"
        actual_text = req.content or ""
        actual_sender = req.sender or sender
    else:
        actual_bytes = file_bytes
        actual_filename = filename
        actual_mime = mime_type
        actual_text = optional_text
        actual_sender = sender

    filename_lower = actual_filename.lower()
    is_image = any(filename_lower.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".webp"]) or "image/" in actual_mime
    is_pdf = filename_lower.endswith(".pdf") or "pdf" in actual_mime

    vision_r: Optional[VisionAnalysisResult] = None
    doc_r: Optional[DocumentFraudResult] = None
    modality = ModalityEnum.TEXT

    extracted_content = actual_text or ""

    if is_image:
        modality = ModalityEnum.IMAGE
        vision_r = await safe_vision(actual_bytes)
        if vision_r.ocr_extracted_text:
            extracted_content = f"{extracted_content} {vision_r.ocr_extracted_text}".strip()
        for vpa in vision_r.extracted_vpas:
            extracted_content += f" {vpa}"
        for ph in vision_r.extracted_phones:
            if not sender:
                sender = ph
            else:
                extracted_content += f" {ph}"

    elif is_pdf:
        modality = ModalityEnum.DOCUMENT
        doc_r = await safe_doc_fraud(actual_bytes)
        if doc_r.details:
            extracted_content = f"{extracted_content} {doc_r.details}".strip()

    if not extracted_content.strip():
        extracted_content = f"Uploaded file: {actual_filename} ({actual_mime})"

    # Construct ScanRequest for standard agent analysis
    req = ScanRequest(
        content=extracted_content,
        sender=actual_sender,
        channel="unknown",
        modality=modality,
        file_bytes=actual_bytes,
        file_name=actual_filename,
    )

    url_match = URL_REGEX.search(req.content)
    if url_match and not req.extracted_url:
        req.extracted_url = url_match.group(0)

    # Execute text, URL, sender, intent, bank, and OSINT vectors on the extracted content
    has_upi = bool(UPI_VPA_REGEX.search(req.content) or (req.sender and UPI_VPA_REGEX.search(req.sender)))
    has_phone = bool(PHONE_REGEX.search(req.content) or (req.sender and PHONE_REGEX.search(req.sender)))

    url_task = safe_url(req)
    sender_task = safe_sender(req)
    intent_task = safe_intent(req)
    ai_text_task = safe_ai_text(req)

    upi_task = safe_upi(req) if has_upi else asyncio.sleep(0, result=UpiAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0, details="No UPI handle"))
    bank_task = safe_bank_identity(req) if has_upi else asyncio.sleep(0, result=BankVerificationResult(status=AgentStatusEnum.SKIPPED, details="No UPI handle"))
    osint_task = safe_osint(req) if (has_upi or has_phone) else asyncio.sleep(0, result=OsintHistoryResult(status=AgentStatusEnum.SKIPPED, details="No target for OSINT"))

    url_r, sender_r, intent_r, ai_text_r, upi_r, bank_r, osint_r = await asyncio.gather(
        url_task, sender_task, intent_task, ai_text_task, upi_task, bank_task, osint_task
    )

    # Avika synthesizes all signals including vision/doc
    response: ScanResponse = compute_score(
        req=req,
        url_r=url_r,
        sender_r=sender_r,
        intent_r=intent_r,
        upi_r=upi_r,
        bank_verification=bank_r,
        osint_history=osint_r,
        ai_text=ai_text_r,
        vision_r=vision_r,
        doc_r=doc_r,
        modality=modality,
    )

    try:
        asyncio.create_task(log_scan_audit(response, req))
    except Exception as e:
        logger.warning(f"Could not trigger background audit logging: {e}")

    return response
