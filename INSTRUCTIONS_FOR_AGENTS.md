# 🤖 PhishLens — AI Coding Agent Master Directives

Welcome to **PhishLens (ScamShield AI)**!

If you are using an AI coding assistant (like **Cursor**, **Antigravity**, **GitHub Copilot**, **Windsurf**, **Claude**, or **ChatGPT**), you don't need to manually explain the project context or type long instructions.

Simply give your AI agent your dedicated prompt file from the `instructions/` folder below. Your agent will read the data contract, architectural rules, imports, and algorithms, and immediately build your module with zero errors.

---

## 📂 Quick Links: Select Your Role & Copy Your Agent Prompt

| Team Member | Module & Responsibility | Dedicated AI Prompt File | One-Click Command for Your Agent |
|:---|:---|:---|:---|
| **Vansh** | Backend / Parallel Orchestrator & SQLite DB | [`instructions/VANSH_ORCHESTRATOR.md`](instructions/VANSH_ORCHESTRATOR.md) | `@instructions/VANSH_ORCHESTRATOR.md Build my module now.` |
| **Atharv** | URL & Domain Intelligence Agent | [`instructions/ATHARV_URL_AGENT.md`](instructions/ATHARV_URL_AGENT.md) | `@instructions/ATHARV_URL_AGENT.md Build my module now.` |
| **Avni** | Sender Identity & TRAI DLT Agent | [`instructions/AVNI_SENDER_AGENT.md`](instructions/AVNI_SENDER_AGENT.md) | `@instructions/AVNI_SENDER_AGENT.md Build my module now.` |
| **Vikas** | LLM Psycholinguistic Intent Agent | [`instructions/VIKAS_INTENT_AGENT.md`](instructions/VIKAS_INTENT_AGENT.md) | `@instructions/VIKAS_INTENT_AGENT.md Build my module now.` |
| **Avika** | Risk Scoring Engine & Synthesis Lead | [`instructions/AVIKA_SCORING_ENGINE.md`](instructions/AVIKA_SCORING_ENGINE.md) | `@instructions/AVIKA_SCORING_ENGINE.md Build my module now.` |
| **Yuvraj** | Frontend UI & Interception Dashboard | [`instructions/YUVRAJ_FRONTEND.md`](instructions/YUVRAJ_FRONTEND.md) | `@instructions/YUVRAJ_FRONTEND.md Build my module now.` |

---

## ⚡ How to Use with Any AI Assistant

### Method 1: In Cursor or Windsurf
1. Open the Chat / Composer (`Ctrl + L` or `Ctrl + I`).
2. Type `@instructions/YOUR_FILE.md` (e.g. `@instructions/ATHARV_URL_AGENT.md`).
3. Press **Enter**. Your AI will inspect the schema, read the reference files, and generate your code and tests.

### Method 2: In ChatGPT, Claude, or Web AI
1. Open your assigned file from `instructions/` (e.g. `instructions/AVNI_SENDER_AGENT.md`).
2. Copy the entire markdown text.
3. Paste it into the prompt box and press **Enter**.

---

## 🛡️ Core Rules All Agents Follow
1. **Single Source of Truth:** All agents import from `shared.models`. Never redefine Pydantic models.
2. **Never Crash:** All agent functions must catch errors and return `status="ERROR"` rather than throwing unhandled exceptions.
3. **Execution Latency:** Target $< 600\text{ms}$ per component so the total pipeline finishes in $< 1000\text{ms}$.
