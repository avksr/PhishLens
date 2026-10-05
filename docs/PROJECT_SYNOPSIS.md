# Project Synopsis

---

## Project Title
**PhishLens (ScamShield AI)**  
*Real-Time Explainable Multi-Vector Scam Interception Engine*

---

## Team Members

| Name | Role & Responsibility |
|:---|:---|
| **Vansh** | Backend Orchestrator, FastAPI Pipeline & Audit Database |
| **Atharv** | URL & Domain Intelligence Agent |
| **Avni** | Sender Identity & TRAI DLT Verification Agent |
| **Vikas** | LLM Psycholinguistic Intent Analysis Agent |
| **Avika** | Risk Scoring Engine & Explainable Verdict Synthesis |
| **Yuvraj** | Frontend Dashboard & Pre-Transaction Interception UI |

---

## 1. Abstract

India loses over **₹1,750 Crore annually** to digital financial fraud through SMS phishing, fake KYC extortion, electricity disconnection threats, and "digital arrest" coercion scams. Existing government countermeasures like Chakshu and the 1930 National Cyber Crime Portal operate as **post-incident reporting registries** — victims can only file complaints *after* irreversible financial damage has occurred.

**PhishLens** addresses this fundamental gap by introducing a **real-time, pre-transaction interception layer** that evaluates suspicious digital communications (SMS, WhatsApp, Email, UPI payment prompts) across three independent AI-driven analysis vectors — **Domain Intelligence**, **Sender Identity Verification**, and **Psycholinguistic Intent Analysis** — concurrently, before a user submits an OTP, enters a UPI PIN, or clicks a phishing link.

The system synthesizes signals from all three vectors using a **dynamic weighted scoring engine** with India-specific heuristic escalation overrides, produces an **Explainable AI (XAI) verdict** with bilingual (English & Hindi) citizen-safe advisories, and renders a **tiered intervention** (Allow / Warn / Hard Block) in **under 1 second** — all while maintaining compliance with **GIGW 3.0 Cybersecurity Standards** including zero-trust input sanitization, rate limiting, and PII redaction in audit trails.

---

## 2. Problem Statement

Digital financial fraud in India has evolved into a sophisticated, multi-vector social engineering ecosystem that exploits three simultaneous weaknesses:

1. **Domain Spoofing:** Attackers register fresh lookalike domains (e.g., `sbi-kyc-update.top`, `hdfc-refund.xyz`) on high-risk TLDs, often less than 48 hours old, which bypass traditional static URL blacklists. By the time these domains are flagged in public registries, thousands of victims have already been defrauded.

2. **Sender Identity Impersonation:** Fraudsters use personal 10-digit GSM mobile numbers (`+91-98XXXXXXXX`) to send messages that impersonate Tier-1 Indian banks (SBI, HDFC, ICICI, PNB), government agencies (Income Tax, UIDAI), or utility providers (DISCOM). Legitimate commercial communications in India are mandated by TRAI to use registered DLT alphabetic sender headers (e.g., `VM-SBIINB`), but most citizens are unaware of this distinction.

3. **Psychological Manipulation:** Scam messages employ aggressive fear-based language ("account blocked within 2 hours", "electricity disconnected tonight", "arrest warrant issued by CBI") to create artificial panic that overrides rational judgment, coercing victims into immediate action without verification.

**No existing system simultaneously analyzes all three vectors in parallel, synthesizes them into a unified risk assessment, and intervenes *before* the victim completes an irreversible financial transaction.**

---

## 3. Objectives

1. **Pre-Transaction Interception:** Design and implement an active intervention system that evaluates suspicious digital messages *before* a user submits an OTP, UPI PIN, or credential — unlike post-hoc reporting systems.

2. **Multi-Vector Parallel Analysis:** Execute three independent, specialized AI agents concurrently — URL/Domain Intelligence, Sender Identity Verification, and LLM-powered Intent Analysis — with a strict 3.5-second per-agent timeout to guarantee sub-5-second end-to-end latency.

3. **Explainable Risk Scoring:** Synthesize agent outputs through a dynamic weighted scoring engine (URL 40%, Sender 30%, Intent 30%) with non-linear heuristic escalation overrides for India-specific attack patterns (e.g., personal GSM bank impersonation, fake electricity disconnection threats).

4. **Bilingual Citizen Advisories:** Generate human-understandable verdicts and actionable safety recommendations in both English and Hindi to serve India's diverse linguistic demographic, including elderly and first-time digital banking users.

5. **GIGW 3.0 Compliance:** Adhere to Government of India Guidelines for Websites (GIGW) 3.0 cybersecurity principles — enforcing rate limiting (30 req/min), zero-trust input validation, and PII masking (phone numbers, OTPs) in all persistent audit records.

---

## 4. System Architecture

### 4.1 High-Level Pipeline

```
User Input (SMS / WhatsApp / Email / UPI Payment)
         │
         ▼
┌─────────────────────────────────────────┐
│     React Frontend (Yuvraj)             │
│     ScannerInput + InterceptionModal    │
└──────────┬──────────────────────────────┘
           │  POST /api/v1/scan
           ▼
┌─────────────────────────────────────────┐
│     FastAPI Orchestrator (Vansh)        │
│     GIGW 3.0 Rate Limiting + Sanitize  │
│     asyncio.gather (timeout=3.5s)      │
└──────┬──────────┬──────────┬────────────┘
       │          │          │
 ┌─────▼─────┐ ┌──▼──────┐ ┌─▼────────────┐
 │ URL Agent │ │ Sender  │ │ Intent Agent │
 │ (Atharv)  │ │ (Avni)  │ │ (Vikas)      │
 │ WHOIS +   │ │ TRAI    │ │ Groq LLaMA-3 │
 │ Typosquat │ │ DLT +   │ │ + Offline    │
 │ + TLD Rep │ │ GSM Det │ │ Regex Fback  │
 └─────┬─────┘ └──┬──────┘ └─┬────────────┘
       └──────────┴──────────┘
                  │
        ┌─────────▼──────────┐
        │ Risk Scoring Engine│
        │ (Avika)            │
        │ Dynamic Weights +  │
        │ Heuristic Escala-  │
        │ tions + Bilingual  │
        │ XAI Synthesis      │
        └─────────┬──────────┘
                  │
     ┌────────────┴────────────┐
     ▼                         ▼
  ScanResponse           SQLite Audit DB
  (JSON: Score,          (PII-Masked,
   Tier, Verdict,         Async Logging)
   Recommendation,
   Audit Trail)
     │
     ▼
  React Dashboard
  4-Tier Interception
  (SAFE / CAUTION /
   HIGH_RISK / CRITICAL)
```

### 4.2 Parallel Agent Architecture

All three analysis agents execute concurrently via Python's `asyncio.gather()` with an enforced `asyncio.wait_for(timeout=3.5)` per agent. If any agent exceeds the timeout or encounters an API failure, the orchestrator marks it as `ERROR`, and Avika's scoring engine dynamically redistributes the failed agent's weight proportionally among the surviving active agents — guaranteeing that the pipeline never crashes and always returns an actionable verdict.

### 4.3 Dynamic Weight Normalization

$$\text{RiskScore}_{\text{composite}} = \sum_{i \in \{url, sender, intent\}} w_i \times S_i$$

Where $w_i$ is the dynamically normalized weight for agent $i$, and $S_i$ is the agent's risk score (0–100). Base weights are URL: 0.40, Sender: 0.30, Intent: 0.30. If an agent is skipped or errors, its weight is zeroed and the remaining weights are re-normalized to sum to 1.0.

---

## 5. Methodology

### 5.1 URL & Domain Intelligence (Atharv)
- **URL Extraction:** Regex-based extraction of embedded URLs from raw message text.
- **Domain Age Check:** WHOIS/RDAP lookup to flag domains registered within the last 30 days (with in-memory LRU cache for repeat queries).
- **Typosquatting Detection:** Levenshtein distance computation against top 50 Indian banking and government domains (`onlinesbi.sbi`, `hdfcbank.com`, `incometax.gov.in`).
- **TLD Reputation:** Flagging high-risk TLDs (`.top`, `.xyz`, `.club`, `.work`, `.icu`, `.buzz`, `.cc`, `.cfd`) commonly used in ephemeral phishing campaigns.

### 5.2 Sender Identity & TRAI DLT Verification (Avni)
- **TRAI Header Regex:** Matching against the mandated commercial SMS header format `^[A-Z]{2}-[A-Z]{6}$` (e.g., `VM-SBIINB`, `AX-HDFCBK`).
- **DLT Registry Cross-Check:** Validating headers against a curated registry of verified TRAI-registered banking and government sender IDs.
- **GSM Bank Spoofing Detection:** Flagging personal 10-digit mobile numbers that claim bank identity in their message content (`COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM`).
- **UPI VPA Fraud Detection:** Identifying deceptive UPI payment handles (e.g., `refund-desk@oksbi`).

### 5.3 LLM Psycholinguistic Intent Analysis (Vikas)
- **Primary Engine:** Groq LLaMA-3 8B (or Google Gemini Flash) with deterministic JSON output mode (`temperature=0.0`) and a structured few-shot threat analysis prompt.
- **Offline Fallback:** A comprehensive regex keyword heuristic engine covering urgency triggers ("within 2 hours", "blocked today"), coercion patterns ("arrest warrant", "CBI inquiry"), and credential solicitation ("submit OTP", "share PAN").
- **Hinglish Support:** Few-shot examples calibrated for colloquial Indian fraud patterns ("*Aapka bijli bill update nahi hua, connection kat diya jayega*").

### 5.4 Risk Scoring & Verdict Synthesis (Avika)
- **Dynamic Weight Redistribution:** Proportional re-normalization when agents are skipped or errored.
- **Fail-Secure Default:** If all agents fail, the system returns CAUTION (score 35) with "Analysis Unavailable" — never falsely returning SAFE.
- **Critical Heuristic Overrides:**
  - **TRAI Whitelist Override:** Caps risk ≤ 12 for verified official headers with clean URLs.
  - **Double Whammy Escalation:** Forces score ≥ 92 when both URL and Intent risks ≥ 70.
  - **GSM Bank Impersonation:** Forces score ≥ 88 for personal numbers claiming bank identity.
  - **Active OTP Harvesting:** Forces score ≥ 90 for credential theft solicitation.
  - **Digital Arrest Coercion:** Forces score ≥ 94 for fake police/legal threats.
- **Bilingual Explainability:** Dual English + Hindi verdict headlines and citizen-safe recommendations.
- **1930 Report Generator:** Auto-formatted incident draft for immediate submission to the National Cyber Crime Portal.

### 5.5 Frontend Interception UI (Yuvraj)
- **4-Tier Visual Feedback:** SAFE (green banner), CAUTION (amber advisory), HIGH_RISK (orange alert), CRITICAL (full-screen hard-block modal).
- **Pre-Transaction Interception Modal:** Actively prevents OTP/UPI PIN submission with a visual countdown timer.
- **Audit Trail Inspection Drawer:** Side-by-side breakdown of URL, Sender, and Intent agent findings with latency metrics.
- **1-Click Demo Presets:** Quick-load scenarios for live evaluation demonstrations.

---

## 6. Technology Stack

| Layer | Technology | Purpose |
|:---|:---|:---|
| **Backend Framework** | FastAPI (Python 3.11+) | Async REST API with Pydantic v2 validation |
| **Parallel Execution** | `asyncio.gather` + `wait_for` | Concurrent agent dispatch with 3.5s timeout |
| **LLM Inference** | Groq LLaMA-3 8B / Google Gemini Flash | Psycholinguistic intent classification |
| **Domain Intelligence** | WHOIS/RDAP + `tldextract` + Levenshtein | Domain age, TLD reputation, typosquatting |
| **Data Validation** | Pydantic v2 BaseModel | Zero-trust input/output schema enforcement |
| **Rate Limiting** | `slowapi` (GIGW 3.0) | 30 req/min per client IP |
| **Audit Database** | SQLite (async) | PII-masked immutable scan records |
| **Frontend** | React 18 + Vite | Cyber-defense themed dashboard |
| **Testing** | pytest | Unit tests + latency benchmarks |
| **CI/CD** | GitHub Actions | Automated lint, test, and build pipeline |
| **Version Control** | Git (feature branch workflow) | Isolated developer branches with PR to `dev` |

---

## 7. The 4-Tier Decision Matrix

| Score Range | Risk Tier | Frontend Behavior | Action | Interception Mode |
|:---:|:---|:---|:---|:---|
| **0 – 24** | SAFE | Green confirmation banner | `ALLOW` | Frictionless pass-through |
| **25 – 49** | CAUTION | Amber inline warning | `WARN_USER` | Advisory to verify sender manually |
| **50 – 77** | HIGH_RISK | Orange persistent alert | `BLOCK_TRANSACTION` | Explicit user confirmation required |
| **78 – 100** | CRITICAL | Full-screen hard-block modal | `BLOCK_TRANSACTION` | Actively prevents OTP/payment submission |

---

## 8. Expected Outcomes

1. **Detection Accuracy:** ≥ 85% true positive rate on curated Indian scam payloads (SBI KYC fraud, electricity cut-off threats, digital arrest coercion, work-from-home scams).
2. **False-Positive Rate:** ≤ 10% on legitimate transactional bank OTPs and government notifications from verified TRAI DLT headers.
3. **Latency Performance:** Median end-to-end pipeline execution < 1000ms; scoring engine execution < 10ms.
4. **Offline Resilience:** Full functionality maintained via local regex heuristic fallback when LLM APIs or WHOIS services are unavailable.
5. **GIGW 3.0 Compliance:** Zero PII exposure in persistent audit records; enforced rate limiting; dependency audit with zero high-severity CVEs.
6. **Citizen Safety Impact:** Bilingual (English + Hindi) actionable advisories accessible to elderly and first-time digital banking users.

---

## 9. Modules & Individual Contributions

### Module 1: FastAPI Orchestrator & Audit Database (Vansh)
- Parallel agent dispatch via `asyncio.gather` with enforced 3.5s timeout.
- `POST /api/v1/scan` and `GET /api/v1/health` endpoints.
- Async SQLite audit logger with PII scrubbing (phone numbers → `987****210`, OTPs → `******`).
- `slowapi` rate limiting middleware (30 req/min).

### Module 2: URL & Domain Intelligence Agent (Atharv)
- URL extraction regex from arbitrary message text.
- WHOIS domain age lookup with in-memory LRU cache.
- Levenshtein typosquatting detection against top Indian banking domains.
- High-risk TLD reputation scoring (`.top`, `.xyz`, `.club`).

### Module 3: Sender Identity & TRAI DLT Agent (Avni)
- TRAI DLT commercial header regex validation (`^[A-Z]{2}-[A-Z]{6}$`).
- Verified sender cross-check against curated TRAI registry.
- Personal GSM bank spoofing detection (`COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM`).
- UPI VPA spoofing identification.

### Module 4: LLM Psycholinguistic Intent Agent (Vikas)
- Groq / Gemini API integration with structured JSON output and few-shot threat prompts.
- Detection taxonomy: Panic Urgency, Financial Extortion, KYC Verification, OTP Harvesting, Digital Arrest.
- Offline regex fallback engine for zero-downtime resilience.
- Hinglish language support.

### Module 5: Risk Scoring & Verdict Synthesis Engine (Avika)
- Dynamic weight normalization with proportional redistribution on agent failure.
- 6 critical heuristic escalation overrides (TRAI whitelist, Double Whammy, GSM spoof, OTP harvest, Digital Arrest, DISCOM threat).
- Fail-secure safety net (never defaults to SAFE on total agent failure).
- Bilingual English + Hindi verdict and recommendation generation.
- Signal confidence rating (HIGH / MEDIUM / LOW).
- Automated 1930 / cybercrime.gov.in complaint draft generator.

### Module 6: Frontend Interception Dashboard (Yuvraj)
- React/Vite cyber-defense themed dashboard (dark slate background `#0B0F19`, neon cyan `#00F0FF`, crimson alerts `#FF3366`).
- Animated 0–100 risk gauge with tier badge visualization.
- Pre-transaction hard-block interception modal.
- Collapsible audit trail inspection drawer.
- 1-click judge demo presets and 1930 report copy button.

---

## 10. Future Scope

1. **Chakshu & NCRP Gateway Integration:** Direct API-level integration with the Telecom Regulatory Authority of India's Chakshu portal and the National Cyber Crime Reporting Portal (1930) for automated one-click incident filing.
2. **Cross-Report Graph Intelligence:** A Neo4j-backed knowledge graph linking shared scam phone numbers, UPI VPAs, and hosting IP addresses across victim reports to identify coordinated fraud networks.
3. **Multimodal Analysis Engine:** Extension to inspect QR code images (via OCR) and fake payment receipt screenshots for visual phishing indicators.
4. **Browser Extension & Mobile SDK:** Lightweight client-side plugins for Chrome, WhatsApp Web, and Android/iOS payment apps that invoke PhishLens scanning before any transaction is executed.
5. **Federated Threat Intelligence:** Anonymized cross-institutional threat sharing across banks, telecoms, and law enforcement agencies using privacy-preserving federated learning.

---

## 11. References

1. TRAI — Telecom Commercial Communications Customer Preference Regulations (TCCCPR), 2018.
2. Ministry of Home Affairs — National Cyber Crime Reporting Portal (https://cybercrime.gov.in).
3. CERT-In — Indian Computer Emergency Response Team Advisories on SMS Phishing.
4. NIC — Guidelines for Indian Government Websites (GIGW) 3.0 — Cybersecurity Standards.
5. RBI — Master Direction on Digital Payment Security Controls, 2024.
6. Groq — LLaMA-3 8B Inference API Documentation (https://groq.com).
7. IETF RFC 9083 — Registration Data Access Protocol (RDAP) for WHOIS Queries.

---

> **Repository:** [github.com/avksr/PhishLens](https://github.com/avksr/PhishLens)  
> **License:** MIT
