<div align="center">

# 🔍 PhishLens

### Real-Time Explainable Multi-Vector Scam Interception Engine

[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react)](https://reactjs.org)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python)](https://python.org)
[![Groq](https://img.shields.io/badge/Groq-LLaMA3-F55036?style=for-the-badge)](https://groq.com)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

> **Stop scams before they strike.** PhishLens is an autonomous, explainable AI agent that performs real-time multi-signal analysis of suspicious messages, URLs, and payment requests to detect and intercept digital fraud — in under 1 second.

[🚀 Live Demo](#) · [📖 Docs](#architecture) · [🐛 Report Bug](https://github.com/avksr/PhishLens/issues) · [💡 Request Feature](https://github.com/avksr/PhishLens/issues)

</div>

---

## 📌 The Problem

Over **₹1,750 Crore** is lost annually to cyber fraud in India. Attackers exploit three parallel vulnerabilities:

| Vector | How Attackers Exploit It |
|:---|:---|
| 🔗 **URL / Domain** | Register fresh phishing domains (< 7 days old) mimicking SBI, HDFC, Amazon — bypassing blacklists that update in 24–72 hours |
| 👤 **Sender Identity** | Use personal GSM numbers (`+91-XXXXXXXXXX`) to impersonate TRAI-registered bank headers, bypassing SMS carrier filters |
| 🧠 **Psychological Manipulation** | Craft fear-based urgency ("blocked in 2 hours", "digital arrest") to bypass rational decision-making |

Existing solutions fail because they are **single-vector, reactive, and unexplainable**.

---

## ✨ How PhishLens Works

PhishLens runs **three independent AI agents in parallel**, then synthesizes their findings into a unified, explainable verdict in **< 1000ms**.

```
User Input (SMS / WhatsApp / Email / UPI)
         │
         ▼
┌─────────────────────────────────────────┐
│         FastAPI Orchestrator (Vansh)    │
│         asyncio.gather → parallel run   │
└──────────┬──────────────┬──────────┬───┘
           │              │          │
     ┌─────▼─────┐  ┌─────▼───┐  ┌──▼──────────┐
     │ URL Agent │  │ Sender  │  │ Intent Agent│
     │ (Atharv) │  │ (Avni)  │  │  (Vikas)   │
     │           │  │         │  │  Groq LLM  │
     └─────┬─────┘  └─────┬───┘  └──┬──────────┘
           └──────────────┴──────────┘
                          │
                ┌─────────▼─────────┐
                │  Risk Scoring     │
                │  Engine (Avika)   │
                │  Dynamic Weights  │
                │  + Heuristics     │
                └─────────┬─────────┘
                          │
                ┌─────────▼─────────┐
                │  ScanResponse     │
                │  SAFE / CAUTION   │
                │  HIGH_RISK /      │
                │  CRITICAL         │
                └─────────┬─────────┘
                          │
                ┌─────────▼─────────┐
                │  React Dashboard  │
                │  (Yuvraj)         │
                │  Radar + Meter +  │
                │  Interception UI  │
                └───────────────────┘
```

---

## 🚦 Risk Tiers

| Tier | Score | Frontend Behavior | Action |
|:---|:---|:---|:---|
| ✅ **SAFE** | 0–24 | Green confirmation banner | `ALLOW` |
| ⚠️ **CAUTION** | 25–49 | Amber inline warning | `WARN_USER` |
| 🚫 **HIGH_RISK** | 50–77 | Orange persistent alert card | `BLOCK_TRANSACTION` |
| 🛑 **CRITICAL** | 78–100 | **Full-screen interception modal** | `BLOCK_TRANSACTION` |

---

## 🏗️ Project Structure

```
PhishLens/
├── backend/                    # FastAPI Python backend
│   ├── main.py                 # App entry point
│   ├── shared/
│   │   └── models.py           # 🔑 Shared Pydantic models — EVERYONE imports from here
│   ├── api/
│   │   └── routes.py           # POST /api/v1/scan endpoint
│   ├── agents/
│   │   ├── url_agent.py        # Atharv — Domain age, typosquatting, TLD reputation
│   │   ├── sender_agent.py     # Avni  — TRAI DLT verification, GSM spoofing
│   │   └── intent_agent.py     # Vikas — Groq/Gemini LLM psycholinguistic analysis
│   ├── core/
│   │   ├── orchestrator.py     # Vansh — asyncio.gather parallel pipeline
│   │   ├── scoring_engine.py   # Avika — Dynamic weighting + heuristic escalation
│   │   ├── verdict_utils.py    # Avika — Human-readable verdicts
│   │   └── db_logger.py        # Vansh — SQLite scan logging
│   ├── data/
│   │   ├── trai_dlt_registry.json   # Avni  — TRAI DLT sender prefix database
│   │   ├── brand_domains.json       # Atharv — Official brand domain mappings
│   │   └── high_risk_tlds.txt       # Atharv — Malicious TLD list
│   ├── prompts/
│   │   └── intent_prompt.txt        # Vikas — LLM system prompt
│   ├── tests/
│   │   └── test_pipeline.py         # Integration tests
│   └── requirements.txt
│
├── frontend/                   # React frontend (Yuvraj)
│   ├── src/
│   │   ├── components/         # UI components
│   │   ├── lib/
│   │   │   └── api.ts          # API client
│   │   └── App.tsx
│   └── package.json
│
├── datasets/                   # Test payloads (PM)
│   ├── payloads_high_risk.json
│   ├── payloads_safe.json
│   └── payloads_edge_cases.json
│
├── schema_mocks.json           # 🔑 Master data contract & mock responses
├── .github/
│   ├── workflows/
│   │   └── ci.yml              # GitHub Actions CI pipeline
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── pull_request_template.md
├── CONTRIBUTING.md
└── README.md
```

---

## ⚡ Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- A free [Groq API Key](https://console.groq.com) **or** [Gemini API Key](https://aistudio.google.com/app/apikey)

### 1. Clone the repo
```bash
git clone https://github.com/avksr/PhishLens.git
cd PhishLens
```

### 2. Backend Setup
```bash
cd backend
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt

# Create your .env file
echo "GROQ_API_KEY=your_key_here" > .env

# Start the server
uvicorn main:app --reload --port 8000
```

API will be live at: `http://localhost:8000`
Swagger docs: `http://localhost:8000/docs`

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

Frontend will be live at: `http://localhost:5173`

---

## 📡 API Reference

### `POST /api/v1/scan`

**Request:**
```json
{
  "content": "URGENT: Your SBI account is blocked. Submit PAN at https://sbi-kyc-verify.top",
  "sender": "+919876543210",
  "extracted_url": "https://sbi-kyc-verify.top",
  "channel": "sms"
}
```

**Response:**
```json
{
  "scan_id": "c7a8b3e1-9524-4f0e-b7d6-ec2d79d501b4",
  "overall_risk_score": 92,
  "risk_tier": "CRITICAL",
  "verdict": "Confirmed SBI Impersonation — KYC / Credential Harvesting Attack",
  "recommendation": "STOP — Legitimate banks NEVER send alerts from personal mobile numbers.",
  "action_required": "BLOCK_TRANSACTION",
  "processing_time_ms": 820.5,
  "audit_trail": { ... }
}
```

See [`schema_mocks.json`](schema_mocks.json) for complete request/response schemas and mock examples.

---

## 🛡️ Branch Strategy

```
main          ← Production-ready code only (protected, PR required)
  └── dev     ← Integration branch (all features merge here first)
        ├── feature/atharv-url-agent
        ├── feature/avni-sender-agent
        ├── feature/vikas-intent-agent
        ├── feature/avika-scoring-engine
        ├── feature/yuvraj-frontend-ui
        └── feature/vansh-orchestrator
```

**Rules:**
- ❌ Never push directly to `main`
- ❌ Never push directly to `dev`
- ✅ Always open a PR from your feature branch → `dev`
- ✅ At least 1 review required before merging to `dev`
- ✅ Only the PM/Team Lead merges `dev` → `main`

---

## 👥 Team

| Name | Role | Branch |
|:---|:---|:---|
| **Avksr** (You) | Project Manager & Team Lead | `main` owner |
| **Vansh** | Backend Orchestrator (FastAPI) | `feature/vansh-orchestrator` |
| **Atharv** | URL & Domain Agent | `feature/atharv-url-agent` |
| **Avni** | Sender & TRAI Agent | `feature/avni-sender-agent` |
| **Vikas** | LLM Intent Agent (Groq) | `feature/vikas-intent-agent` |
| **Avika** | Risk Scoring Engine | `feature/avika-scoring-engine` |
| **Yuvraj** | Frontend UI (React) | `feature/yuvraj-frontend-ui` |

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more information.

---

<div align="center">
Built with ❤️ for hackathon competition · <a href="https://github.com/avksr/PhishLens">github.com/avksr/PhishLens</a>
</div>
