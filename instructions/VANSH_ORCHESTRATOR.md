# 🤖 AI Agent Directive — VANSH (Backend Orchestrator & Database Logger)

> **Instructions for Vansh:** Upload or paste this file directly into your AI coding assistant (Cursor, Antigravity, Copilot, ChatGPT, or Claude). Your agent will read this and immediately build your module with zero guesswork.

---

```markdown
You are an expert FastAPI & Distributed Systems Python Engineer pair programming with VANSH on the "PhishLens" (ScamShield AI) team.

## YOUR MISSION TODAY:
Build the asynchronous multi-agent orchestrator pipeline, timeout supervisor, and PII-masked SQLite database audit logger for PhishLens.

## YOUR ASSIGNED ENVIRONMENT & FILES:
1. Branch: `feature/vansh-orchestrator`
   Command to create: `git checkout -b feature/vansh-orchestrator`
2. Target Files to Code:
   - `backend/core/orchestrator.py` (parallel execution pipeline)
   - `backend/core/db_logger.py` (async SQLite database logger with PII masking)
   - `backend/api/routes.py` (FastAPI route controller)
   - `backend/main.py` (FastAPI application entrypoint)
3. Test File to Create:
   - `backend/tests/test_pipeline.py` (end-to-end integration tests)

## STRICT DATA CONTRACT (MANDATORY):
You MUST import shared models from `shared.models`. DO NOT define local Pydantic models.
```python
from shared.models import (
    ScanRequest,
    ScanResponse,
    UrlAgentResult,
    SenderAgentResult,
    IntentAgentResult,
    AgentStatusEnum
)
```

## IMPLEMENTATION SPECIFICATIONS:

### 1. `backend/core/orchestrator.py`:
Implement:
```python
async def run_pipeline(req: ScanRequest) -> ScanResponse:
```
- **Step 1: URL Pre-Extraction Fallback:**
  If `req.extracted_url` is None, inspect `req.content` using regex `r'https?://[^\s]+'` and populate `req.extracted_url` if a URL is found.
- **Step 2: Concurrent Agent Execution (3.5s Timeout Supervisor):**
  - Import the 3 agent functions:
    ```python
    from agents.url_agent import analyze_url
    from agents.sender_agent import analyze_sender
    from agents.intent_agent import analyze_intent
    from core.scoring_engine import compute_score
    ```
  - Wrap each agent call in an async task with an enforced `asyncio.wait_for(..., timeout=3.5)` and exception handler:
    - If `analyze_url(req)` times out or raises an error, catch it and return `UrlAgentResult(status=AgentStatusEnum.ERROR, risk_score=0.0, details="Agent timeout/error")`.
    - If `analyze_sender(req)` times out or raises an error, return `SenderAgentResult(status=AgentStatusEnum.ERROR, risk_score=0.0, details="Agent timeout/error")`.
    - If `analyze_intent(req)` times out or raises an error, return `IntentAgentResult(status=AgentStatusEnum.ERROR, risk_score=0.0, details="Agent timeout/error")`.
  - Execute all 3 in parallel:
    ```python
    url_r, sender_r, intent_r = await asyncio.gather(
        safe_url(req),
        safe_sender(req),
        safe_intent(req)
    )
    ```
- **Step 3: Synthesis Delegation:**
  - Call Avika's scoring engine:
    ```python
    response = compute_score(req, url_r, sender_r, intent_r)
    ```
- **Step 4: Asynchronous Audit Logging:**
  - Fire a background task to log the scan without blocking the response:
    ```python
    asyncio.create_task(log_scan_audit(response, req))
    ```
  - Return `response`.

### 2. `backend/core/db_logger.py`:
- Use `aiosqlite` for non-blocking database I/O.
- Database file: `backend/phishlens_audit.db`.
- Initialize table schema:
  ```sql
  CREATE TABLE IF NOT EXISTS scan_audit (
      scan_id TEXT PRIMARY KEY,
      timestamp TEXT,
      sender_masked TEXT,
      content_masked TEXT,
      overall_risk_score INTEGER,
      risk_tier TEXT,
      action_required TEXT,
      verdict TEXT,
      latency_ms REAL
  )
  ```
- **GIGW 3.0 Zero PII Leakage Function:**
  Implement `mask_pii(text: str) -> str`:
  - Mask 10-digit Indian mobile numbers (`9876543210` -> `987****210`).
  - Mask OTP numbers (`OTP 123456` or `code 654321` -> `OTP ******`).
  - Mask credit/debit card numbers (`ending 8812` -> `ending ****`).
- `async def log_scan_audit(resp: ScanResponse, req: ScanRequest)`:
  - Mask PII in `req.content` and `req.sender`.
  - Write record to `scan_audit` table.

### 3. `backend/api/routes.py` & `backend/main.py`:
- `POST /api/v1/scan`: Call `run_pipeline(req)` and return `ScanResponse`.
- `GET /api/v1/health`: Return service health and version.
- Enable CORS middleware for frontend communication (`http://localhost:5173`).

## UNIT TESTS TO WRITE (`backend/tests/test_pipeline.py`):
Write pytest test cases using `@pytest.mark.asyncio`:
1. `test_pipeline_e2e_high_risk_scam()`: Send high-risk SBI KYC message; verify pipeline executes in < 3500ms, returns `risk_tier in ["HIGH_RISK", "CRITICAL"]`.
2. `test_pipeline_e2e_benign_otp()`: Send safe HDFC OTP alert; verify returns `risk_tier == "SAFE"`.
3. `test_pipeline_resilience_agent_failure()`: Mock one agent to raise a TimeoutError; verify orchestrator does NOT crash, recovers gracefully, and returns a valid `ScanResponse`.
4. `test_pii_masker()`: Verify phone numbers and OTPs are redacted properly.

## HOW TO VERIFY YOUR CODE:
Run from `backend/` directory:
```bash
python -m pytest tests/test_pipeline.py -v
uvicorn main:app --reload --port 8000
```

Now, write the code for `backend/core/orchestrator.py`, `backend/core/db_logger.py`, `backend/api/routes.py`, `backend/main.py`, and `backend/tests/test_pipeline.py`.
```
