# 🤖 AI Agent Directive — VIKAS (LLM Intent & Psycholinguistic Agent)

> **Instructions for Vikas:** Upload or paste this file directly into your AI coding assistant (Cursor, Antigravity, Copilot, ChatGPT, or Claude). Your agent will read this and immediately build your module with zero guesswork.

---

```markdown
You are an expert Cybersecurity & NLP Engineer pair programming with VIKAS on the "PhishLens" (ScamShield AI) team.

## YOUR MISSION TODAY:
Build the complete, production-grade LLM Intent & Psycholinguistic Fraud Agent for PhishLens.

## YOUR ASSIGNED ENVIRONMENT & FILES:
1. Branch: `feature/vikas-intent-agent`
   Command to create: `git checkout -b feature/vikas-intent-agent`
2. Target File to Code: `backend/agents/intent_agent.py`
3. Test File to Create: `backend/tests/test_intent_agent.py`
4. Reference Prompt File:
   - `backend/prompts/intent_prompt.txt` (Structured psycholinguistic analysis system prompt)

## STRICT DATA CONTRACT (MANDATORY):
You MUST import shared models from `shared.models`. DO NOT define local Pydantic models.
```python
from shared.models import (
    ScanRequest,
    IntentAgentResult,
    AgentStatusEnum,
    DetectedIntentEnum
)
```

## FUNCTION SPECIFICATION:
Implement:
```python
async def analyze_intent(req: ScanRequest) -> IntentAgentResult:
```

### LOGIC & ALGORITHMIC REQUIREMENTS:
1. **Primary LLM Engine (Groq / Gemini):**
   - Check environment variables for `GROQ_API_KEY` or `GEMINI_API_KEY`.
   - If `GROQ_API_KEY` is present:
     - Use `groq.AsyncGroq` client with model `llama-3.1-8b-instant`.
     - Set `temperature=0.0` (deterministic output).
     - Set `response_format={"type": "json_object"}`.
   - If `GEMINI_API_KEY` is present and Groq is absent:
     - Use `google.generativeai` with `gemini-1.5-flash` in JSON mode.
   - Load the system prompt from `backend/prompts/intent_prompt.txt`.
   - Pass `req.content` as the user message.
   - Parse the JSON response into `IntentAgentResult`.
2. **Resilient Local Heuristic Fallback Engine (CRITICAL):**
   - If API keys are missing, network times out (enforce a 2.5s timeout on LLM calls), or API rate limits trigger:
   - **DO NOT CRASH.** Fall back seamlessly to a local regex keyword heuristic engine scanning for Indian fraud tactics:
     - **Panic & False Urgency:**
       - Patterns: `within \d+ hours`, `blocked today`, `deactivated today`, `power cut tonight`, `disconnected tonight at 9.30 pm`, `immediately`
       - Action: set intent `PANIC_URGENCY`, add `+40.0` risk, add manipulation tactic `"False Urgency Trigger"`.
     - **Coercive Authority & Legal Threats:**
       - Patterns: `arrest warrant`, `police station`, `cbi officer`, `court summons`, `cyber crime cell`, `electricity officer`
       - Action: set intent `FINANCIAL_EXTORTION`, add `+45.0` risk, add tactic `"Coercive Authority Threat"`.
     - **Credential & PII Harvesting:**
       - Patterns: `submit pan`, `verify aadhaar`, `share otp`, `update kyc`, `unblock account`, `netbanking password`
       - Action: set intent `KYC_VERIFICATION` or `OTP_HARVEST`, add `+45.0` risk, add tactic `"Credential / KYC Solicitation"`.
     - **Lottery / Part-Time Job Advance Scams:**
       - Patterns: `kbc lottery`, `won \d+ lakh`, `part-time job`, `like youtube videos`, `earn \d+ daily`, `telegram`
       - Action: set intent `LOTTERY_REWARD`, add `+35.0` risk.
     - **Benign Baseline:**
       - If standard notification with no threat patterns (e.g. "OTP for Amazon is 654321. Do not share"):
       - Set intent `BENIGN`, risk = `5.0`.
   - The fallback must return a complete `IntentAgentResult` with `confidence=0.85` and `details="Analyzed via local resilient heuristic engine"`.
3. **Score Normalization & Latency:**
   - Clamp final `risk_score` to `[0.0, 100.0]`.
   - Measure execution latency and populate `latency_ms`.
4. **CRITICAL FAIL-SAFE RULE:**
   - This function must **NEVER** raise an unhandled exception.
   - Wrap in `try...except Exception as e:`. On error, run the heuristic fallback or return `IntentAgentResult(status=AgentStatusEnum.ERROR, risk_score=0.0, details=str(e), latency_ms=...)`.

## UNIT TESTS TO WRITE (`backend/tests/test_intent_agent.py`):
Write pytest test cases using `@pytest.mark.asyncio`:
1. `test_intent_agent_high_urgency_scam()`: "URGENT: SBI account blocked within 2 hours submit PAN" returns `risk_score >= 80`, intent `KYC_VERIFICATION` or `PANIC_URGENCY`.
2. `test_intent_agent_benign_otp_notification()`: "Your OTP for Amazon is 123456. Valid for 5 mins - HDFC Bank" returns `risk_score <= 15`, intent `BENIGN`.
3. `test_intent_agent_electricity_extortion_scam()`: "Electricity power disconnected tonight at 9.30 pm contact officer" returns `risk_score >= 70`, intent `FINANCIAL_EXTORTION` or `PANIC_URGENCY`.
4. `test_intent_agent_offline_heuristic_fallback()`: Test with empty/dummy API key; verify heuristic fallback runs in < 50ms and returns valid result.

## HOW TO VERIFY YOUR CODE:
Run from `backend/` directory:
```bash
python -m pytest tests/test_intent_agent.py -v
flake8 agents/intent_agent.py --max-line-length=120
```

Now, write the code for `backend/agents/intent_agent.py` and `backend/tests/test_intent_agent.py`.
```
