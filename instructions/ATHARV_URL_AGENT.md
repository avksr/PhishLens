# 🤖 AI Agent Directive — ATHARV (URL & Domain Agent)

> **Instructions for Atharv:** Upload or paste this file directly into your AI coding assistant (Cursor, Antigravity, Copilot, ChatGPT, or Claude). Your agent will read this and immediately build your module with zero guesswork.

---

```markdown
You are an expert Cybersecurity Python Engineer pair programming with ATHARV on the "PhishLens" (ScamShield AI) team.

## YOUR MISSION TODAY:
Build the complete, production-grade URL & Domain Intelligence Agent for PhishLens.

## YOUR ASSIGNED ENVIRONMENT & FILES:
1. Branch: `feature/atharv-url-agent`
   Command to create: `git checkout -b feature/atharv-url-agent`
2. Target File to Code: `backend/agents/url_agent.py`
3. Test File to Create: `backend/tests/test_url_agent.py`
4. Reference Data Files Available to You:
   - `backend/data/brand_domains.json` (canonical domain list for Indian banks and brands)
   - `backend/data/high_risk_tlds.txt` (list of high-risk top-level domains)

## STRICT DATA CONTRACT (MANDATORY):
You MUST import shared models from `shared.models`. DO NOT define local Pydantic models.
```python
from shared.models import (
    ScanRequest,
    UrlAgentResult,
    AgentStatusEnum,
    TldReputationEnum
)
```

## FUNCTION SPECIFICATION:
Implement:
```python
async def analyze_url(req: ScanRequest) -> UrlAgentResult:
```

### LOGIC & ALGORITHMIC REQUIREMENTS:
1. **URL Extraction Fallback:**
   - If `req.extracted_url` is present, use it.
   - If `req.extracted_url` is None, inspect `req.content` using regex `r'https?://[^\s]+'`.
   - If NO URL is found: return `UrlAgentResult(status=AgentStatusEnum.SKIPPED, risk_score=0.0, details="No URL detected in payload", latency_ms=...)`.
2. **Domain & TLD Parsing:**
   - Use `tldextract` or `urllib.parse` to extract the subdomain, domain, and suffix (e.g. `sbi-kyc-verify.top` -> domain: `sbi-kyc-verify`, suffix: `top`).
3. **High-Risk TLD Reputation Check:**
   - Load `backend/data/high_risk_tlds.txt`.
   - If the domain's suffix/TLD is in the high-risk list (e.g. `.top`, `.xyz`, `.club`, `.cfd`, `.icu`):
     - Set `tld_reputation = TldReputationEnum.HIGH_RISK`
     - Add `+35.0` to risk score
     - Append `"HIGH_RISK_TLD"` to flags.
4. **Typosquatting & Lookalike Detection:**
   - Load `backend/data/brand_domains.json`.
   - Check if any brand keyword (e.g., "sbi", "hdfc", "icici", "axis", "amazon") appears in the extracted domain while the domain is NOT in the official domains list for that brand.
   - Alternatively, compute Levenshtein / normalized similarity against official domains (e.g. `sbi-kyc-verify.top` vs `onlinesbi.sbi`).
   - If typosquatting is detected:
     - Set `is_typosquatting = True`
     - Set `target_brand = <Brand Name>`
     - Add `+50.0` to risk score
     - Append `"TYPOSQUATTING_DETECTED"` to flags.
5. **WHOIS Domain Age Check:**
   - Use `python-whois` (wrapped in a try/except with a 1.5s timeout or RDAP lookup).
   - If domain age is less than 30 days:
     - Add `+40.0` to risk score
     - Append `"NEWLY_REGISTERED_DOMAIN (< 30 days)"` to flags.
   - If WHOIS query fails or times out, degrade gracefully without crashing.
6. **Score Normalization & Latency:**
   - Clamp final `risk_score` to `[0.0, 100.0]`.
   - Measure execution time and set `latency_ms`.
7. **CRITICAL FAIL-SAFE RULE:**
   - This function must **NEVER** raise an unhandled exception.
   - Wrap the entire body in a `try...except Exception as e:` block. On error, return `UrlAgentResult(status=AgentStatusEnum.ERROR, risk_score=0.0, details=str(e), latency_ms=...)`.

## UNIT TESTS TO WRITE (`backend/tests/test_url_agent.py`):
Write pytest test cases using `@pytest.mark.asyncio`:
1. `test_url_agent_skipped_when_no_url()`: Payload without URL returns `status="SKIPPED"` and `risk_score=0.0`.
2. `test_url_agent_legitimate_bank_url()`: Official bank URL (e.g. `https://www.onlinesbi.sbi/portal`) returns `risk_score < 15` and `is_typosquatting=False`.
3. `test_url_agent_typosquatting_phishing_url()`: Lookalike URL (e.g. `https://sbi-kyc-verify.top`) returns `risk_score >= 80`, `is_typosquatting=True`, and `tld_reputation="HIGH_RISK"`.
4. `test_url_agent_handles_exceptions_gracefully()`: Malformed URL does not crash and returns valid result.

## HOW TO VERIFY YOUR CODE:
Run from `backend/` directory:
```bash
python -m pytest tests/test_url_agent.py -v
flake8 agents/url_agent.py --max-line-length=120
```

Now, write the code for `backend/agents/url_agent.py` and `backend/tests/test_url_agent.py`.
```
