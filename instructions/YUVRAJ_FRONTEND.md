# 🤖 AI Agent Directive — YUVRAJ (Frontend UI & Interception Dashboard)

> **Instructions for Yuvraj:** Upload or paste this file directly into your AI coding assistant (Cursor, Antigravity, Copilot, ChatGPT, or Claude). Your agent will read this and immediately build your module with zero guesswork.

---

```markdown
You are an expert React 18 & Frontend UI/UX Engineer pair programming with YUVRAJ on the "PhishLens" (ScamShield AI) team.

## YOUR MISSION TODAY:
Build the modern, cyber-defense real-time interception dashboard for PhishLens using React + Vite.

## YOUR ASSIGNED ENVIRONMENT & FILES:
1. Branch: `feature/yuvraj-frontend-ui`
   Command to create: `git checkout -b feature/yuvraj-frontend-ui`
2. Target Directory: `frontend/`
3. Reference Data Contracts:
   - `schema_mocks.json` (root directory — contains exact JSON request/response schema)
   - `datasets/payloads_high_risk.json` and `datasets/payloads_safe.json` (pre-baked test presets)

## DESIGN AESTHETICS & THEME (MANDATORY):
- **Theme:** High-tech Cyber Defense / Dark Fintech Security Dashboard.
- **Color Palette:**
  - Background: Deep Slate `#0B0F19`
  - Card Surfaces: Charcoal Slate `#111827`
  - Border Accents: `#1F2937`
  - Neon Cyan Accent: `#00F0FF`
  - Safe / Benign: Terminal Green `#00E676`
  - Caution: Warning Amber `#FFB800`
  - High Risk: Safety Orange `#FF6B00`
  - Critical Scam: Alert Crimson `#FF3366`
- **Typography:** Inter, Plus Jakarta Sans, or JetBrains Mono for metrics and hashes.

## CORE COMPONENTS TO BUILD:

### 1. `ScannerInput.jsx` (Interactive Ingestion Bar):
- Multi-line textarea for suspicious text, email, or UPI payment prompt.
- Optional sender input field (e.g. `+919876543210` or `VM-SBIINB`).
- **Quick-Load Preset Buttons:**
  - Button 1: 🚨 **SBI KYC Scam** (loads high-risk phishing SMS from `datasets/payloads_high_risk.json`)
  - Button 2: ⚡ **Electricity Bill Threat** (loads disconnection scam SMS)
  - Button 3: 🛡️ **Legitimate Bank OTP** (loads safe HDFC alert from `datasets/payloads_safe.json`)
- Large "⚡ Inspect & Intercept" action button with pulsing cyber effect during scan.

### 2. `RiskGauge.jsx` (0–100 Animated Speedometer Meter):
- Visual animated semi-circle gauge or radar meter displaying the composite score (0–100).
- Color smoothly transitions based on tier:
  - 0–24: Green (`SAFE`)
  - 25–49: Amber (`CAUTION`)
  - 50–77: Orange (`HIGH_RISK`)
  - 78–100: Red (`CRITICAL`)
- Displays execution latency (e.g. `⚡ Intercepted in 420ms`).

### 3. `AuditTrailDrawer.jsx` (Explainability Drilldown):
- 3 side-by-side or collapsible vector cards displaying:
  - **URL / Domain Vector (Atharv):** Domain age badge, typosquatting alert, TLD reputation flag.
  - **Sender Identity Vector (Avni):** TRAI DLT verification badge or personal GSM spoofing flag.
  - **Psycholinguistic Vector (Vikas):** Extracted manipulation tactics, urgency countdown markers, LLM reasoning quote.
- Bottom synthesis card: Displays Avika's heuristic overrides and applied dynamic weights.

### 4. `InterceptionModal.jsx` (Pre-Transaction Critical Hard-Block):
- When `action_required === "BLOCK_TRANSACTION"` (or `risk_tier in ["CRITICAL", "HIGH_RISK"]`), trigger this modal.
- Dark backdrop with glowing crimson warning border.
- Bold headline: `🚨 TRANSACTION INTERCEPTED BY PHISHLENS`
- Displays the exact reason (e.g. *"This message impersonates State Bank of India using an unverified personal phone number and fresh 2-day-old phishing domain."*)
- Two action buttons:
  - Primary (Safe): `🛑 Abort Transaction & Report`
  - Secondary (Friction barrier with countdown): `I Understand the Risks (Proceed anyway)`

### 5. API Client (`src/lib/api.js`):
- Sends POST request to `http://localhost:8000/api/v1/scan`.
- Graceful offline fallback: If backend server is not running, load mock responses from `schema_mocks.json` so the UI is 100% demo-ready at all times!

## SETUP & BUILD INSTRUCTIONS:
Initialize inside `frontend/`:
```bash
npm install
npm run dev
npm run build
```
Verify that `npm run build` succeeds without build errors.

Now, write the complete code for `frontend/` components.
```
