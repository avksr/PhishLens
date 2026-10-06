# ============================================================
# PhishLens API Routes & Controllers
# ============================================================

import hashlib
import json
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, status, Request, UploadFile, File, Form
from pydantic import BaseModel, Field
from slowapi.util import get_remote_address

from shared.models import (
    ScanRequest,
    ScanResponse,
    ChannelEnum,
    ModalityEnum,
    OsintHistoryResult,
)
from core.orchestrator import run_pipeline, run_multimodal_pipeline
from core.limiter import limiter, get_rate_limit
from core.db_logger import (
    get_scan_by_id,
    get_recent_scans,
    add_crowdsourced_report,
    get_recent_reports,
    get_crowdsourced_reports,
)
from core.upload_validator import validate_upload_bytes, UploadValidationError
from core.provider_budget import provider_budget
from core.agent_registry import agent_registry
from agents.osint_agent import analyze_osint
from agents.qr_shield import verify_qr_pre_payment, QrShieldResult

router = APIRouter(prefix="/api/v1", tags=["Scan & Interception"])


def get_reporter_rate_limit_key(request: Request) -> str:
    """
    Extracts reporter identifier for rate limiting.
    Tied to reporter (X-Reporter-ID / X-User-ID / Authorization) and falls back to IP.
    """
    reporter_id = (
        request.headers.get("X-Reporter-ID")
        or request.headers.get("X-User-ID")
        or request.query_params.get("reporter_id")
    )
    if reporter_id:
        return f"reporter:{reporter_id.strip()}"
    return f"ip:{get_remote_address(request)}"


class ReportCreateRequest(BaseModel):
    target: Optional[str] = Field(None, min_length=2, max_length=500, description="URL, UPI ID, Phone Number, or scam payload")
    type: Optional[str] = Field(None, description="url, upi, phone, or content")
    reporter_id: Optional[str] = Field(None, description="Client or user identifier")
    details: Optional[str] = Field(None, max_length=1000, description="Context or proof details")
    # Legacy / alias support
    target_handle: Optional[str] = None
    target_type: Optional[str] = None
    scam_category: Optional[str] = None
    claimed_name: Optional[str] = None
    reported_by: Optional[str] = None


class ReportScamPayload(ReportCreateRequest):
    """Backward compatibility alias for ReportCreateRequest."""
    pass


# ─────────────────────────────────────────────────────────────
# Scan & Upload Endpoints
# ─────────────────────────────────────────────────────────────

@router.post("/scan", response_model=ScanResponse, status_code=status.HTTP_200_OK)
@limiter.limit(get_rate_limit)
async def scan_payload(req: ScanRequest, request: Request) -> ScanResponse:
    """
    Real-time multi-agent scan endpoint.
    Protected by GIGW 3.0 / DDoS rate limiter configured via RATE_LIMIT_PER_MINUTE.
    Executes Atharv (URL), Avni (Sender+UPI), Vikas (Intent), Bank Identity, and OSINT in parallel,
    then computes unified risk score via Avika's Scoring Engine.
    """
    return await run_pipeline(req)


@router.post("/scan/upload", response_model=ScanResponse, status_code=status.HTTP_200_OK)
@limiter.limit(get_rate_limit)
async def scan_upload_file(
    request: Request,
    file: UploadFile = File(..., description="Uploaded screenshot or PDF document"),
    content: Optional[str] = Form(None, description="Optional accompanying text"),
    sender: Optional[str] = Form(None, description="Optional sender identifier"),
    channel: Optional[str] = Form("unknown", description="Communication channel"),
) -> ScanResponse:
    """
    Upload hardening: magic-byte check + size limit before OCR/PDF parsing.
    Validates file signatures (PDF, PNG, JPEG, WebP) and enforces MAX_UPLOAD_SIZE_MB (<5MB).
    Auto-routes to Document Agent or Multimodal Vision pipeline.
    """
    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        validation = validate_upload_bytes(file_bytes, filename=file.filename)
    except UploadValidationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)

    modality = ModalityEnum.DOCUMENT if validation["file_type"] == "pdf" else ModalityEnum.IMAGE

    # Build ScanRequest with binary file bytes
    req = ScanRequest(
        content=content or f"[Uploaded {validation['file_type'].upper()}: {file.filename or 'file'}]",
        sender=sender,
        channel=ChannelEnum(channel) if channel in [c.value for c in ChannelEnum] else ChannelEnum.UNKNOWN,
        modality=modality,
        file_bytes=file_bytes,
        file_name=file.filename,
    )

    return await run_pipeline(req)


# Alias for backward compatibility
scan_uploaded_file = scan_upload_file


# ─────────────────────────────────────────────────────────────
# Crowdsourced Reporting (One report per reporter per target)
# ─────────────────────────────────────────────────────────────

@router.post("/report", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute", key_func=get_reporter_rate_limit_key)
async def submit_scam_report(payload: ReportCreateRequest, request: Request):
    """
    Crowdsourced Scam Report Endpoint:
    - Rate limit tied to reporter identity (not just IP).
    - Enforces database constraint: strictly ONE report per reporter per target.
    - Duplicate reports return HTTP 409 Conflict.
    """
    target = payload.target or payload.target_handle
    if not target:
        raise HTTPException(status_code=400, detail="Missing required 'target' or 'target_handle'.")

    report_type = payload.type or payload.target_type or payload.scam_category or "scam"

    effective_reporter = (
        payload.reporter_id
        or payload.reported_by
        or request.headers.get("X-Reporter-ID")
        or request.headers.get("X-User-ID")
        or get_remote_address(request)
    )
    reporter_hash = hashlib.sha256(effective_reporter.encode("utf-8")).hexdigest()

    details = payload.details or ""
    if payload.claimed_name:
        details = f"[Claimed: {payload.claimed_name}] {details}".strip()

    is_created, msg, record = await add_crowdsourced_report(
        reporter_hash=reporter_hash,
        target=target,
        report_type=report_type,
        details=details,
    )

    if not is_created:
        if msg == "ALREADY_REPORTED":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"You have already submitted a report for '{target}'. Thank you for your contribution.",
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register report due to an internal database error.",
        )

    return {
        "status": "REPORT_RECORDED",
        "message": "Report registered in PhishLens crowdsourced database.",
        "report_id": record["id"],
        "target": record["target"],
        "timestamp": record["timestamp"],
    }


# Alias for backward compatibility
report_scam_entity = submit_scam_report


@router.get("/reports/recent", status_code=status.HTTP_200_OK)
async def get_recent_community_reports(limit: int = 20):
    """Retrieve the most recent crowdsourced scam reports."""
    return await get_recent_reports(limit=min(limit, 50))


@router.get("/osint/lookup", response_model=OsintHistoryResult, status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")
async def osint_lookup(query: str, request: Request) -> OsintHistoryResult:
    """
    Standalone OSINT investigation lookup for a specific UPI ID or phone number.
    Queries both Internal Crowdsourced DB (Path A) and External Forum Scraping (Path B).
    """
    req = ScanRequest(content=query, sender=query)
    return await analyze_osint(req)


# ─────────────────────────────────────────────────────────────
# Audit & Observability Endpoints
# ─────────────────────────────────────────────────────────────

@router.get("/audit/recent", status_code=status.HTTP_200_OK)
async def get_recent_audits(limit: int = 10):
    """
    Retrieve the most recent scan audits with PII masked (GIGW 3.0 compliant)
    for evaluator and administrative verification.
    """
    return await get_recent_scans(limit=min(limit, 50))


@router.get("/audit/{scan_id}", status_code=status.HTTP_200_OK)
async def get_audit(scan_id: str):
    """
    Audit Log Inspection Endpoint (US-5):
    Returns full audit record for a given scan_id for judges/evaluators.
    Returns 404 if scan_id not found.
    """
    record = await get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit record not found for scan_id: {scan_id}",
        )
    return record


@router.get("/audit/{scan_id}/explainability", status_code=status.HTTP_200_OK)
async def get_audit_explainability(scan_id: str):
    """
    Explainability JSON Export Endpoint:
    Returns full Noisy-OR breakdown, formula steps, and vector contribution matrix.
    """
    record = await get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    response_payload = record.get("response_payload", {})
    if isinstance(response_payload, str):
        try:
            response_payload = json.loads(response_payload)
        except Exception:
            pass
    if isinstance(response_payload, dict) and "explainability" in response_payload:
        return response_payload["explainability"]

    return {
        "scan_id": record.get("scan_id"),
        "timestamp": record.get("timestamp"),
        "overall_risk_score": record.get("overall_risk_score"),
        "risk_tier": record.get("risk_tier"),
        "verdict": record.get("verdict"),
        "action_required": record.get("action_required"),
        "latency_ms": record.get("latency_ms"),
        "noisy_or": {
            "formula": "100.0 * (1.0 - Π (1.0 - weight_i * (score_i / 100.0) * confidence_i))",
            "base_score": record.get("overall_risk_score"),
        },
    }


class QrCheckRequest(BaseModel):
    payload: str = Field(..., description="Raw QR code payload or upi://pay URI")
    user_intent: Optional[str] = Field(default="", description="User claim (e.g. 'refund', 'receive money')")


@router.post("/qr/check", response_model=QrShieldResult, status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")
async def check_qr_code(body: QrCheckRequest, request: Request) -> QrShieldResult:
    """
    Standalone QR Pre-Payment Shield Endpoint for Frontend QR scanner:
    Validates QR before payment authorization. Catches Reverse-QR traps and merchant spoofing.
    """
    return verify_qr_pre_payment(body.payload, user_intent_claim=body.user_intent or "")


@router.get("/system/status", status_code=status.HTTP_200_OK)
async def get_system_status():
    """
    System Diagnostic Status:
    Returns Agent Registry (enabled vs fallback) and Provider Budget quotas.
    """
    return {
        "agent_registry": agent_registry.get_status(),
        "provider_budgets": provider_budget.get_status(),
    }


@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    return {
        "status": "HEALTHY",
        "service": "PhishLens ScamShield API",
        "version": "2.0.0",
        "capabilities": [
            "URL Typosquatting & Threat Intel",
            "TRAI DLT & Sender Verification",
            "Psycholinguistic Intent & Coercion",
            "AI Text & Synthetic Copy Detection",
            "UPI Identity & Bank Name Cross-Verification",
            "Parallel OSINT Forum Scraping & Community DB",
            "Vision AI Error Level Analysis (ELA)",
            "Perceptual Hashing (pHash) Receipt Tampering",
            "QR Pre-Payment Shield & Reverse-QR Trap Detection",
            "Document Tampering & MRZ Checksum Validation",
        ],
    }
