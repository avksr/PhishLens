<div align="center">

# ⚡ PhishLens

### Real-Time Explainable Multi-Vector Scam Interception Engine

[![Hackathon Project](https://img.shields.io/badge/Hackathon-Ready-FF0055?style=for-the-badge&logo=target)](docs/TEAM_IMPLEMENTATION_PLAN.md)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react)](https://reactjs.org)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python)](https://python.org)
[![Groq LLaMA-3](https://img.shields.io/badge/Groq-LLaMA3-F55036?style=for-the-badge)](https://groq.com)
[![Compliance](https://img.shields.io/badge/Compliance-GIGW%203.0%20Cybersecurity-00F0FF?style=for-the-badge)](docs/TEAM_IMPLEMENTATION_PLAN.md)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

> 🛑 **Stop scams BEFORE they strike.** Unlike reactive portals where victims report after losing their life savings, **PhishLens** is an active, pre-transaction interception layer. It evaluates messages, links, and payment requests across 3 parallel AI vectors in **under 1000ms** to block fraud before an irreversible OTP or payment is submitted.

[🚀 Quick Start](#-quick-start) · [🎯 Problem & Solution](#-the-problem--hackathon-mission) · [🧠 Architecture](#-how-phishlens-works) · [👥 Team Members](#-team-members)

</div>

---

## 🎯 The Problem & Hackathon Mission

Over **₹1,750 Crore** is stolen annually in India through sophisticated digital scams. Current government and telecom defenses (such as Chakshu) are **post-hoc registries** — victims only report after money is gone.

### The 3 Fatal Attack Vectors

| Attack Vector | How Cybercriminals Exploit It | PhishLens Interception Defense |
|:---|:---|:---|
| 🔗 **Domain Spoofing** | Register fresh lookalike domains (< 7 days old) mimicking SBI, HDFC, or ITR, bypassing 48-hour blacklists | Levenshtein typosquatting detection + high-risk TLD filtering (`.top`, `.xyz`, `.club`, `.cfd`) + WHOIS domain age checks |
| 👤 **Identity Impersonation** | Use personal 10-digit GSM numbers (`+91-XXXXXXXXXX`) to send fake bank KYC alerts, bypassing carrier rules | TRAI DLT header regex validation (`^[A-Z]{2}-[A-Z]{6}$`) + certified entity cross-checks + GSM bank spoofing escalation |
| 🧠 **Psychological Coercion** | Create extreme panic ("power cut tonight", "digital arrest by CBI", "account suspended in 2h") | Dual-mode intent engine (Groq LLaMA-3 + <15ms offline regex heuristics) detecting urgency, intimidation, and harvesting |

---

## 🏆 Why PhishLens Wins

1. ⚡ **Sub-1000ms Interception SLA**: Runs 3 specialized agents concurrently via `asyncio.gather` with a strict `3.5s` supervisor timeout.
2. 🛡️ **Pre-Transaction Hard Block**: Triggers a full-screen interception modal in the user payment flow before an OTP or UPI PIN is entered.
3. ⚖️ **Dynamic Weight Redistribution**: Normalizes agent weights (URL 40%, Sender 30%, Intent 30%) on the fly if an agent is skipped or errors.
4. 🚨 **Non-Linear Escalation Overrides**: Catches deceptive multi-vector combos that trick traditional linear weighted averages (e.g. Double Whammy, GSM Bank Spoofing).
5. 🔒 **GIGW 3.0 & Zero-Trust Privacy**: Redacts 10-digit phones and OTPs before persisting to the immutable SQLite audit database.

---

## 🧠 How PhishLens Works

<div align="center">

![PhishLens Architecture Flowchart](docs/PhishLens_Architecture_Flowchart.png)

</div>

```
User Input (SMS / WhatsApp / Email / UPI)
         │
         ▼
┌─────────────────────────────────────────┐
│         FastAPI Orchestrator (Vansh)    │
│    asyncio.gather (3.5s SLA Timeout)    │
└──────────┬──────────────┬──────────┬───┘
           │              │          │
     ┌─────▼─────┐  ┌─────▼───┐  ┌──▼──────────┐
     │ URL Agent │  │ Sender  │  │ Intent Agent│
     │ (Atharv)  │  │ (Avni)   │  │  (Vikas)    │
     │ Typosquat │  │ TRAI DLT│  │  LLM / Fast │
     │ TLD check │  │ GSM Rule│  │  Heuristics │
     └─────┬─────┘  └─────┬───┘  └──┬──────────┘
           └──────────────┴──────────┘
                          │
                ┌─────────▼─────────┐
                │  Risk Scoring     │
                │  Engine (Avika)   │
                │  Dynamic Weights  │
                │  + Escalations    │
                └─────────┬─────────┘
                          │
          ┌───────────────┴───────────────┐
          ▼                               ▼
  ScanResponse JSON             SQLite Audit DB (Vansh)
  SAFE / CAUTION /              (Async, Zero-Trust PII Masked:
  HIGH_RISK / CRITICAL           10-digit phone & OTP redacted)
          │
          ▼
   React Dashboard (Yuvraj)
   Speedometer Gauge + Audit Drawer
   + Pre-Transaction Interception Modal
```

---

## 🚦 The 4-Tier Decision Matrix

| Tier | Score Range | Frontend UI Behavior | Action Required | Interception Mode |
|:---|:---|:---|:---|:---|
| ✅ **SAFE** | 0–24 | Green confirmation banner | `ALLOW` | Frictionless pass-through |
| ⚠️ **CAUTION** | 25–49 | Amber inline warning advisory | `WARN_USER` | Advises manual sender verification |
| 🚫 **HIGH_RISK** | 50–77 | Orange persistent alert card | `BLOCK_TRANSACTION` | Explicit user confirmation required |
| 🛑 **CRITICAL** | 78–100 | **Full-Screen Hard Block Interception Modal** | `BLOCK_TRANSACTION` | Actively prevents payment or OTP submission |

---

## 🚨 Critical Escalation Overrides

1. **Double Whammy (High-Risk URL + Spoofed / High-Risk Sender)**:
   - Condition: $S_{url} \ge 80$ AND $S_{sender} \ge 80$
   - Override: $\text{Score} \leftarrow \max(\text{Score}, 92.0)$ $\to$ `CRITICAL` / `BLOCK_TRANSACTION`
2. **Personal GSM Bank Impersonation**:
   - Condition: Sender is a 10-digit GSM number claiming bank identity with KYC/panic urgency
   - Override: $\text{Score} \leftarrow \max(\text{Score}, 88.0)$ $\to$ `CRITICAL` / `BLOCK_TRANSACTION`
3. **Active OTP / Credential Harvesting**:
   - Condition: Demands OTP, UPI PIN, or NetBanking password under urgency or suspicious sender/URL
   - Override: $\text{Score} \leftarrow \max(\text{Score}, 90.0)$ $\to$ `CRITICAL` / `BLOCK_TRANSACTION`
4. **Digital Arrest & Coercive Psychological Extortion**:
   - Condition: Threatens police arrest, CBI inquiry, or legal prosecution to induce panic
   - Override: $\text{Score} \leftarrow \max(\text{Score}, 82.0)$ $\to$ `HIGH_RISK` / `BLOCK_TRANSACTION`
5. **Certified TRAI DLT Exemption (Safe Override)**:
   - Condition: Verified official TRAI DLT header with no high-risk URL or coercion markers
   - Override: $\text{Score} \leftarrow \min(\text{Score}, 12.0)$ $\to$ `SAFE` / `ALLOW`

---

## 🏗️ Project Structure

```
PhishLens/
├── backend/
│   ├── main.py
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py
│   ├── shared/
│   │   ├── __init__.py
│   │   └── models.py
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── url_agent.py
│   │   ├── sender_agent.py
│   │   └── intent_agent.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── orchestrator.py
│   │   ├── scoring_engine.py
│   │   ├── verdict_utils.py
│   │   └── db_logger.py
│   ├── data/
│   │   ├── brand_domains.json
│   │   ├── high_risk_tlds.txt
│   │   └── trai_dlt_registry.json
│   ├── prompts/
│   │   └── intent_prompt.txt
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── test_models.py
│   │   ├── test_scoring.py
│   │   └── test_pipeline.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── lib/
│   │   │   └── api.ts
│   │   ├── App.tsx
│   │   └── index.css
│   └── package.json
├── datasets/
│   ├── payloads_high_risk.json
│   ├── payloads_safe.json
│   └── payloads_edge_cases.json
├── docs/
│   ├── TEAM_IMPLEMENTATION_PLAN.md
│   └── PhishLens_Architecture_Flowchart.png
├── schema_mocks.json
├── .github/
│   ├── workflows/
│   │   └── ci.yml
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   └── feature_request.md
│   └── pull_request_template.md
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

---

## ⚡ Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/avksr/PhishLens.git
cd PhishLens
```

### 2. Backend Setup
```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env

# Launch FastAPI Orchestrator
uvicorn main:app --reload --port 8000
```
- API Docs: `http://localhost:8000/docs`

### 3. Run Test Suite
```bash
# Run tests with pytest
pytest tests/ -v
```

### 4. Frontend Setup
```bash
cd ../frontend
npm install
npm run dev
```
- Live UI: `http://localhost:5173`

---

## 📡 API Reference

### `POST /api/v1/scan`

**Sample Attack Request:**
```json
{
  "content": "Dear Customer, Your SBI account has been suspended due to pending KYC update. Please verify OTP and submit PAN immediately within 2 hours at https://sbi-kyc-verify.top to avoid permanent deactivation.",
  "sender": "+919823145678",
  "extracted_url": "https://sbi-kyc-verify.top",
  "channel": "sms"
}
```

**Real-Time Interception Response (`ScanResponse`):**
```json
{
  "scan_id": "c7a8b3e1-9524-4f0e-b7d6-ec2d79d501b4",
  "timestamp": "2026-09-29T16:15:30Z",
  "overall_risk_score": 92,
  "risk_tier": "CRITICAL",
  "action_required": "BLOCK_TRANSACTION",
  "verdict": "Confirmed SBI Impersonation — KYC / Credential Harvesting Attack",
  "recommendation": "STOP — Legitimate banks NEVER send alerts from personal mobile numbers. Do NOT click external links or share OTP.",
  "processing_time_ms": 1.25,
  "audit_trail": {
    "url_analysis": {
      "status": "SUCCESS",
      "risk_score": 85.0,
      "is_typosquatting": true,
      "target_brand": "SBI",
      "tld_reputation": "HIGH_RISK",
      "flags": ["HIGH_RISK_TLD:.top", "BRAND_NAME_SPOOFING:SBI"],
      "latency_ms": 0.45
    },
    "sender_analysis": {
      "status": "SUCCESS",
      "risk_score": 85.0,
      "sender_category": "PERSONAL_GSM",
      "is_spoofed_header": true,
      "brand_claimed": "SBI",
      "flags": ["COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM"],
      "latency_ms": 0.32
    },
    "intent_analysis": {
      "status": "SUCCESS",
      "risk_score": 70.0,
      "detected_intent": "KYC_VERIFICATION",
      "manipulation_tactics": ["PANIC_URGENCY", "OTP_HARVEST", "PAN_HARVEST"],
      "confidence": 0.95,
      "latency_ms": 0.48
    },
    "synthesis_breakdown": {
      "weights_applied": {
        "url_weight": 0.40,
        "sender_weight": 0.30,
        "intent_weight": 0.30
      },
      "heuristics_triggered": [
        "CRITICAL_ESCALATION: Phishing URL combined with unauthorized / high-risk sender",
        "CRITICAL_ESCALATION: Personal mobile number impersonating bank with KYC/panic urgency"
      ],
      "summary_explanation": "Critical multi-vector attack detected: typosquatted domain hosted on high-risk TLD combined with personal GSM bank impersonation soliciting credentials."
    }
  }
}
```

---

## 👥 Team Members

| Name | Role |
| :--- | :--- |
| **Vansh** | Backend / Orchestrator & DB Logging |
| **Atharv** | URL & Domain Intelligence Agent |
| **Avni** | Sender Identity & TRAI DLT Agent |
| **Vikas** | LLM Psycholinguistic Intent Agent |
| **Avika** | Risk Scoring Engine & Synthesis |
| **Yuvraj** | Frontend Dashboard & UI |

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.

---

<div align="center">
Built with ⚡ for real-time cyber defense · <a href="https://github.com/avksr/PhishLens">github.com/avksr/PhishLens</a>
</div>
