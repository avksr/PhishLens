## 📋 PR Checklist

**Fill this out before requesting review. Incomplete PRs will not be merged.**

### What does this PR do?
<!-- One sentence description of the change -->

### Type of Change
- [ ] `feat` — New feature
- [ ] `fix` — Bug fix
- [ ] `docs` — Documentation update
- [ ] `test` — Adding or updating tests
- [ ] `refactor` — Code cleanup (no functionality change)

### My Component Checklist
- [ ] My code imports `shared/models.py` — I have NOT redefined any Pydantic models locally
- [ ] My agent function never raises an unhandled exception (returns `status="ERROR"` on failure)
- [ ] I have NOT committed `.env`, `venv/`, `node_modules/`, or `__pycache__/`
- [ ] I tested my component standalone before raising this PR

### Agent-Specific Checks (backend only)
- [ ] (Atharv) `analyze_url()` returns `SKIPPED` when no URL is present
- [ ] (Avni) `analyze_sender()` returns `OFFICIAL_TRAI_HEADER` for `VM-HDFCBK`
- [ ] (Vikas) `analyze_intent()` returns valid JSON from LLM in < 700ms
- [ ] (Avika) `compute_score()` returns `CRITICAL` for Personal GSM + Bank claim + risky URL
- [ ] (Vansh) `POST /api/v1/scan` returns valid `ScanResponse` end-to-end
- [ ] (Yuvraj) UI renders all 4 risk tiers correctly with correct color/modal behavior

### Latency (backend PRs)
- [ ] My component's `latency_ms` is under **600ms** in standalone testing

### Screenshots (frontend PRs — required)
<!-- Paste screenshots of the UI component you built -->

### Reviewer
@avksr
