# 🤖 AI Agent Directive — AVIKA (Risk Scoring Engine & Synthesis Lead)

> **Instructions for Avika:** Upload or paste this file directly into your AI coding assistant (Cursor, Antigravity, Copilot, ChatGPT, or Claude). Your agent will read this and immediately build or extend your module with zero guesswork.

---

```markdown
You are an expert Cybersecurity Scoring Architect pair programming with AVIKA on the "PhishLens" (ScamShield AI) team.

## YOUR MISSION TODAY:
Build and maintain the core Multi-Vector Risk Scoring & Verdict Engine for PhishLens.

## YOUR ASSIGNED ENVIRONMENT & FILES:
1. Branch: `feature/avika-scoring-engine`
   Command to create: `git checkout -b feature/avika-scoring-engine`
2. Target Files to Code:
   - `backend/core/scoring_engine.py` (Dynamic weights & escalation synthesis)
   - `backend/core/verdict_utils.py` (Explainable verdicts & recommendations)
3. Test File to Create:
   - `backend/tests/test_scoring.py` (Standalone scoring test suite)

## STRICT DATA CONTRACT (MANDATORY):
You MUST import shared models from `shared.models`. DO NOT define local Pydantic models.
```python
from shared.models import (
    ScanRequest,
    ScanResponse,
    UrlAgentResult,
    SenderAgentResult,
    IntentAgentResult,
    SynthesisBreakdown,
    AuditTrail,
    RiskTierEnum,
    ActionRequiredEnum,
    AgentStatusEnum,
    SenderCategoryEnum,
    DetectedIntentEnum
)
```

## FUNCTION SPECIFICATION:
Implement:
```python
def compute_score(
    req: ScanRequest,
    url_r: UrlAgentResult,
    sender_r: SenderAgentResult,
    intent_r: IntentAgentResult
) -> ScanResponse:
```

### LOGIC & ALGORITHMIC REQUIREMENTS:
1. **Dynamic Weight Normalization (`_compute_dynamic_weights`):**
   - Base weights: URL 40%, Sender 30%, Intent 30%.
   - If an agent is SKIPPED or in ERROR, its weight becomes 0.0.
   - Proportionally renormalize active agents so sum of weights always equals 1.0.
2. **Indian Scam Heuristic Overrides (Critical Escalations):**
   - **Double Whammy:** High risk URL (>=80) + high risk Sender (>=80) -> Force composite score >= 92 and tier `CRITICAL`.
   - **GSM Bank KYC Spoofing:** Personal GSM sender + bank claim + KYC urgency -> Force composite score >= 88 and tier `CRITICAL`.
   - **Active OTP Harvesting:** Intent detects OTP harvesting + elevated risk in URL or Sender -> Force score >= 90 and tier `CRITICAL`.
   - **Financial Extortion:** Intent detects extortion/digital arrest -> Force score >= 82 and tier `HIGH_RISK`.
   - **TRAI Certified Whitelist Override:** Certified DLT header + URL skipped + benign intent (<=20) -> Cap composite score <= 12 and tier `SAFE`.
3. **Tier Mapping:**
   - 0 – 24: `SAFE`, action `ALLOW`
   - 25 – 49: `CAUTION`, action `WARN_USER`
   - 50 – 77: `HIGH_RISK`, action `BLOCK_TRANSACTION`
   - 78 – 100: `CRITICAL`, action `BLOCK_TRANSACTION`
4. **Explainable Rationale & Actionable Recommendations:**
   - Implement `generate_verdict()`, `generate_recommendation()`, and `build_explanation_summary()` in `backend/core/verdict_utils.py`.
   - Ensure the final `ScanResponse` conforms to `schema_mocks.json`.

## HOW TO VERIFY YOUR CODE:
Run from `backend/` directory:
```bash
python -m pytest tests/test_scoring.py -v
```
```
