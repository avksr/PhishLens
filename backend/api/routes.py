from typing import Optional
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from pydantic import BaseModel, Field

from core.db_logger import (
    add_crowdsourced_report,
    get_crowdsourced_reports,
    get_recent_scans,
    get_scan_by_id,
)
from core.limiter import limiter, get_rate_limit
from core.orchestrator import run_multimodal_pipeline, run_pipeline
from agents.osint_agent import analyze_osint
from agents.qr_shield import verify_qr_pre_payment, QrShieldResult
from shared.models import ScanRequest, ScanResponse, OsintHistoryResult

router = APIRouter(prefix="/api/v1", tags=["Scan & Interception"])


class ReportScamPayload(BaseModel):
    target_handle: str = Field(..., description="UPI ID or Phone number to report")
    target_type: str = Field(default="UPI", description="'UPI' or 'PHONE'")
    scam_category: str = Field(default="GENERAL_FRAUD", description="e.g. OLX_BUYER_FRAUD, UTILITY_ELECTRICITY")
    claimed_name: Optional[str] = Field(None, description="Claimed identity (e.g. BSES Support, SBI Desk)")
    details: Optional[str] = Field(None, description="Details of the scam attempt")
    reported_by: Optional[str] = Field(default="COMMUNITY_USER")


@router.post("/scan", response_model=ScanResponse, status_code=status.HTTP_200_OK)
@limiter.limit(get_rate_limit)
async def scan_payload(req: ScanRequest, request: Request) -> ScanResponse:
    """
    Real-time multi-agent scan endpoint.
    Protected by GIGW 3.0 / DDoS rate limiter configured via RATE_LIMIT_PER_MINUTE.
    Executes Atharv (URL), Avni (Sender), Vikas (Intent), UPI, Bank Identity, and OSINT in parallel,
    then computes unified risk score via Avika's Scoring Engine.
    """
    return await run_pipeline(req)


@router.post("/scan/upload", response_model=ScanResponse, status_code=status.HTTP_200_OK)
@limiter.limit("20/minute")
async def scan_uploaded_file(
    request: Request,
    file: UploadFile = File(..., description="Uploaded screenshot or PDF document"),
    content: Optional[str] = Form(None, description="Optional accompanying text"),
    sender: Optional[str] = Form(None, description="Optional sender identifier"),
) -> ScanResponse:
    """
    Multimodal Smart Router endpoint:
    Accepts screenshot images (PNG, JPG, WEBP) or documents (PDF),
    runs Error Level Analysis (ELA) / Document Fraud checks, extracts text via OCR,
    and runs full financial identity and OSINT verification.
    """
    try:
        file_bytes = await file.read()
        if len(file_bytes) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        filename = file.filename or "upload"
        mime_type = file.content_type or "application/octet-stream"

        return await run_multimodal_pipeline(
            file_bytes=file_bytes,
            filename=filename,
            mime_type=mime_type,
            optional_text=content or "",
            sender=sender,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Multimodal scan processing error: {str(e)}",
        )


@router.post("/report", status_code=status.HTTP_201_CREATED)
@limiter.limit("15/minute")
async def report_scam_entity(payload: ReportScamPayload, request: Request):
    """
    Community Crowdsourcing Endpoint:
    Allows victims and community evaluators to report fraudulent UPI handles or phone numbers.
    Logged to PhishLens's crowdsourced threat registry.
    """
    success = await add_crowdsourced_report(
        target_handle=payload.target_handle,
        target_type=payload.target_type,
        scam_category=payload.scam_category,
        claimed_name=payload.claimed_name,
        details=payload.details,
        reported_by=payload.reported_by or "COMMUNITY_USER",
    )
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save scam report.")

    return {
        "status": "RECORDED",
        "target": payload.target_handle,
        "message": "Incident logged to PhishLens Crowdsourced Scam Registry.",
    }


@router.get("/osint/lookup", response_model=OsintHistoryResult, status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")
async def osint_lookup(query: str, request: Request) -> OsintHistoryResult:
    """
    Standalone OSINT investigation lookup for a specific UPI ID or phone number.
    Queries both Internal Crowdsourced DB (Path A) and External Forum Scraping (Path B).
    """
    req = ScanRequest(content=query, sender=query)
    return await analyze_osint(req)


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
        import json
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
