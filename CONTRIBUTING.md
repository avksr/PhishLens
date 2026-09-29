# Contributing to PhishLens

Welcome to the team! This guide tells you everything you need to know to contribute without breaking things for others.

---

## 🌿 Branch Workflow

### Your branch name (use EXACTLY this format):
| Team Member | Branch Name |
|:---|:---|
| Vansh | `feature/vansh-orchestrator` |
| Atharv | `feature/atharv-url-agent` |
| Avni | `feature/avni-sender-agent` |
| Vikas | `feature/vikas-intent-agent` |
| Avika | `feature/avika-scoring-engine` |
| Yuvraj | `feature/yuvraj-frontend-ui` |

### Setup your branch (do this once at the start):
```bash
# 1. Clone the repo
git clone https://github.com/avksr/PhishLens.git
cd PhishLens

# 2. Create your feature branch from main
git checkout -b feature/your-branch-name

# 3. Verify you are on your branch
git branch
```

### Daily workflow:
```bash
# Start of day: pull latest changes
git pull origin main

# Do your work, then stage and commit
git add .
git commit -m "feat(agent): add typosquatting detection logic"

# Push your work
git push origin feature/your-branch-name
```

### When your feature is ready to integrate:
1. Go to https://github.com/avksr/PhishLens
2. Click **"Compare & pull request"**
3. Set **base: `dev`** ← **compare: `feature/your-branch-name`**
4. Fill in the PR template (auto-loaded)
5. Tag **@avksr** (Team Lead) as reviewer
6. Wait for approval before merging

---

## 📝 Commit Message Format

Use this format for ALL commits:

```
<type>(<scope>): <short description>

Examples:
feat(url-agent): add domain age WHOIS lookup
fix(sender-agent): handle null sender without crashing
feat(frontend): add animated risk meter component
docs(readme): update API reference section
test(scoring): add edge case for SKIPPED url agent
```

**Types:** `feat` | `fix` | `docs` | `test` | `refactor` | `style` | `chore`  
**Scopes:** `url-agent` | `sender-agent` | `intent-agent` | `scoring` | `orchestrator` | `frontend` | `readme` | `ci`

---

## 🚫 Rules (MUST Follow)

- ❌ **Never push to `main` directly** — PRs only
- ❌ **Never push to `dev` directly** — PRs only  
- ❌ **Never commit your `.env` file** — it has secret API keys
- ❌ **Never commit `node_modules/` or `venv/`**
- ✅ **Always import models from `backend/shared/models.py`** — do NOT redefine them in your own file
- ✅ **Your agent function must NEVER raise an exception** — always return a result with `status="ERROR"` on failure
- ✅ **Test your agent standalone** before sending a PR

---

## 🔑 Environment Variables

Create a `.env` file inside `backend/` (this file is git-ignored, never commit it):

```env
GROQ_API_KEY=your_groq_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here
```

Get your free Groq key: https://console.groq.com  
Get your free Gemini key: https://aistudio.google.com/app/apikey

---

## 🧪 Testing Your Code

Before raising a PR, make sure your component passes its standalone test:

```bash
# From the backend/ directory, with venv activated:

# Test URL Agent (Atharv)
python -m pytest tests/test_url_agent.py -v

# Test Sender Agent (Avni)
python -m pytest tests/test_sender_agent.py -v

# Test Intent Agent (Vikas)
python -m pytest tests/test_intent_agent.py -v

# Test Scoring Engine (Avika)
python -m pytest tests/test_scoring.py -v

# Full pipeline integration test (Vansh runs this last)
python -m pytest tests/test_pipeline.py -v
```

---

## ❓ Getting Help

If you are stuck:
1. Check the `schema_mocks.json` in the root — it has examples for all inputs and outputs
2. Tag **@avksr** in a GitHub Issue or message the PM
3. The PM will escalate to the Tech Lead for unblocking
