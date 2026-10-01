from fastapi import APIRouter, HTTPException, status, Request
from shared.models import ScanRequest, ScanResponse
from core.orchestrator import run_pipeline
from core.db_logger import get_recent_scans
from core.limiter import limiter

router = APIRouter(prefix="/api/v1", tags=["Scan & Interception"])


@router.post("/scan", response_model=ScanResponse, status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")
async def scan_payload(req: ScanRequest, request: Request) -> ScanResponse:
    """
    Real-time multi-agent scan endpoint.
    Protected by GIGW 3.0 / DDoS rate limiter (30 req/min per IP, returns HTTP 429 on abuse).
    Executes Atharv (URL), Avni (Sender), and Vikas (Intent) in parallel,
    then computes unified risk score via Avika's Scoring Engine.
    """
    try:
        return await run_pipeline(req)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan pipeline execution error: {str(e)}"
        )


@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    return {
        "status": "HEALTHY",
        "service": "PhishLens ScamShield API",
        "version": "1.0.0"
    }


@router.get("/audit/recent", status_code=status.HTTP_200_OK)
async def get_recent_audits(limit: int = 10):
    """
    Retrieve the most recent scan audits with PII masked (GIGW 3.0 compliant)
    for evaluator and administrative verification.
    """
    return await get_recent_scans(limit=min(limit, 50))
