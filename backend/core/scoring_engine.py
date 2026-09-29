# ============================================================
# OWNER: AVIKA
# FILE: backend/core/scoring_engine.py
# PURPOSE: Risk Scoring & Verdict Engine
#   - Aggregates UrlAgentResult + SenderAgentResult + IntentAgentResult
#   - Applies dynamic weights based on active signals
#   - Runs heuristic escalation rules
#   - Returns final ScanResponse
# ============================================================

from shared.models import ScanRequest, ScanResponse, UrlAgentResult, SenderAgentResult, IntentAgentResult

def compute_score(req: ScanRequest, url_r: UrlAgentResult, sender_r: SenderAgentResult, intent_r: IntentAgentResult) -> ScanResponse:
    raise NotImplementedError("Avika: Implement this function in scoring_engine.py")
