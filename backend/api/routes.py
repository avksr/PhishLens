from fastapi import APIRouter, HTTPException, status
from shared.models import ScanRequest, ScanResponse
from core.orchestrator import run_pipeline

router = APIRouter(prefix="/api/v1", tags=["Scan & Interception"])


@router.post("/scan", response_model=ScanResponse, status_code=status.HTTP_200_OK)
async def scan_payload(req: ScanRequest) -> ScanResponse:
    """
    Real-time multi-agent scan endpoint.
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
