from fastapi import APIRouter, HTTPException, status, Request
from shared.models import ScanRequest, ScanResponse
from core.orchestrator import run_pipeline
from core.limiter import limiter, get_rate_limit
from core.db_logger import get_scan_by_id, get_recent_scans

router = APIRouter(prefix="/api/v1", tags=["Scan & Interception"])


@router.post("/scan", response_model=ScanResponse, status_code=status.HTTP_200_OK)
@limiter.limit(get_rate_limit)
async def scan_payload(req: ScanRequest, request: Request) -> ScanResponse:
    """
    Real-time multi-agent scan endpoint.
    Protected by GIGW 3.0 / DDoS rate limiter configured via RATE_LIMIT_PER_MINUTE.
    Executes Atharv (URL), Avni (Sender), and Vikas (Intent) in parallel,
    then computes unified risk score via Avika's Scoring Engine.
    """
    return await run_pipeline(req)


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
            detail=f"Audit record not found for scan_id: {scan_id}"
        )
    return record


@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    return {
        "status": "HEALTHY",
        "service": "PhishLens ScamShield API",
        "version": "1.0.0"
    }
