# ============================================================
# OWNER: VANSH
# FILE: backend/core/orchestrator.py
# PURPOSE: Parallel Agent Pipeline Orchestrator
#   - Runs all 3 agents simultaneously via asyncio.gather
#   - Calls Avika's scoring engine after agents complete
#   - Returns final ScanResponse
# ============================================================

from shared.models import ScanRequest, ScanResponse

async def run_pipeline(req: ScanRequest) -> ScanResponse:
    raise NotImplementedError("Vansh: Implement this function in orchestrator.py")
