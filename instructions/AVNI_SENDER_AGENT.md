# 🤖 AI Agent Directive — AVNI (Sender Identity & TRAI DLT Agent)

> **Instructions for Avni:** Upload or paste this file directly into your AI coding assistant (Cursor, Antigravity, Copilot, ChatGPT, or Claude). Your agent will read this and immediately build your module with zero guesswork.

---

```markdown
You are an expert Cybersecurity Python Engineer pair programming with AVNI on the "PhishLens" (ScamShield AI) team.

## YOUR MISSION TODAY:
Build the complete, production-grade Sender Identity & TRAI DLT Verification Agent for PhishLens.

## YOUR ASSIGNED ENVIRONMENT & FILES:
1. Branch: `feature/avni-sender-agent`
   Command to create: `git checkout -b feature/avni-sender-agent`
2. Target File to Code: `backend/agents/sender_agent.py`
3. Test File to Create: `backend/tests/test_sender_agent.py`
4. Reference Data Files Available to You:
   - `backend/data/trai_dlt_registry.json` (TRAI DLT certified sender prefix whitelist for Indian banks, utilities, and telecom)

## STRICT DATA CONTRACT (MANDATORY):
You MUST import shared models from `shared.models`. DO NOT define local Pydantic models.
```python
from shared.models import (
    ScanRequest,
    SenderAgentResult,
    AgentStatusEnum,
    SenderCategoryEnum
)
```

## FUNCTION SPECIFICATION:
Implement:
```python
async def analyze_sender(req: ScanRequest) -> SenderAgentResult:
```

### LOGIC & ALGORITHMIC REQUIREMENTS:
1. **Sender Extraction & Normalization:**
   - If `req.sender` is present, sanitize it (strip whitespace, hyphens, country code prefixes like `+91` or `91`).
   - If `req.sender` is None, inspect `req.content` for contact numbers (e.g. `call 9876543210` or `contact: 8250912345`).
   - If NO sender or contact number is present: return `SenderAgentResult(status=AgentStatusEnum.SUCCESS, sender_category=SenderCategoryEnum.UNKNOWN, risk_score=20.0, details="No sender metadata provided")`.
2. **TRAI DLT Certified Header Validation:**
   - Certified Indian transactional SMS headers follow the standard format: `^[A-Z]{2}-[A-Z]{6}$` (e.g. `VM-SBIINB`, `AX-HDFCBK`, `AD-ICICIB`, `VK-PNBSMS`).
   - Parse the operator prefix (`VM`, `AX`, etc.) and the 6-letter principal entity code (`SBIINB`, `HDFCBK`).
   - Load `backend/data/trai_dlt_registry.json`.
   - If the header code matches the registered whitelist:
     - Set `sender_category = SenderCategoryEnum.OFFICIAL_TRAI_HEADER`
     - Set `brand_claimed = <Registered Bank Name>`
     - Set `is_spoofed_header = False`
     - Set `risk_score = 5.0`
     - Append `"VERIFIED_TRAI_DLT_SENDER_HEADER"` to flags.
3. **Personal GSM Bank Impersonation Detection (Critical Scam Scenario):**
   - Check if sender matches a standard 10-digit Indian personal GSM number (`^[6-9]\d{9}$`).
   - Inspect `req.content` for banking, government, or utility keywords:
     - Banks: "SBI", "State Bank", "HDFC", "ICICI", "Axis Bank", "PNB", "Kotak", "Bank of Baroda", "Canara Bank"
     - Govt / KYC: "Aadhaar", "PAN card", "Income Tax", "Electricity Bill", "Power cut", "Challan"
   - If a message claims to be an official bank or government notice but originates from a personal 10-digit phone number:
     - Set `sender_category = SenderCategoryEnum.PERSONAL_GSM`
     - Set `brand_claimed = <Identified Bank or Entity>`
     - Set `risk_score = 85.0` (Elevated high risk)
     - Append `"COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM"` to flags.
     - Append `"MISSING_TRAI_OFFICIAL_HEADER"` to flags.
     - Details: "Legitimate financial institutions in India are mandated by TRAI to send alerts from certified alphabetic DLT headers, never personal 10-digit numbers."
4. **Lookalike / Spoofed Header Detection:**
   - If the header is alphanumeric or formatted like a company name (e.g. `SBI-ALERT`, `HDFC-SEC`, `KOTAK-KYC`) but does NOT adhere to TRAI DLT registry syntax:
     - Set `sender_category = SenderCategoryEnum.LOOKALIKE_HEADER`
     - Set `is_spoofed_header = True`
     - Set `risk_score = 75.0`
     - Append `"UNVERIFIED_LOOKALIKE_HEADER"` to flags.
5. **Score Normalization & Latency:**
   - Clamp final `risk_score` to `[0.0, 100.0]`.
   - Measure execution latency and populate `latency_ms`.
6. **CRITICAL FAIL-SAFE RULE:**
   - This function must **NEVER** raise an unhandled exception.
   - Wrap in `try...except Exception as e:`. On error, return `SenderAgentResult(status=AgentStatusEnum.ERROR, risk_score=0.0, details=str(e), latency_ms=...)`.

## UNIT TESTS TO WRITE (`backend/tests/test_sender_agent.py`):
Write pytest test cases using `@pytest.mark.asyncio`:
1. `test_sender_agent_official_trai_header()`: Certified header `VM-SBIINB` returns `risk_score <= 10`, `sender_category="OFFICIAL_TRAI_HEADER"`.
2. `test_sender_agent_personal_gsm_bank_scam()`: Mobile number `+919876543210` with text claiming "Your SBI account blocked" returns `risk_score >= 85`, `sender_category="PERSONAL_GSM"`.
3. `test_sender_agent_lookalike_header()`: Unregistered alphanumeric header `SBI-ALERT` returns `risk_score >= 70`, `is_spoofed_header=True`.
4. `test_sender_agent_null_sender_fallback()`: Null sender parses gracefully without crashing.

## HOW TO VERIFY YOUR CODE:
Run from `backend/` directory:
```bash
python -m pytest tests/test_sender_agent.py -v
flake8 agents/sender_agent.py --max-line-length=120
```

Now, write the code for `backend/agents/sender_agent.py` and `backend/tests/test_sender_agent.py`.
```
