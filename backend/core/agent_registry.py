# ============================================================
# OWNER: VANSH
# FILE: backend/core/agent_registry.py
# PURPOSE: Environment Key Checker & Agent Registry
#          Disables agents or flags fallback mode when keys are missing (PRD §8)
# ============================================================

import os
import logging
from typing import Dict, Any

logger = logging.getLogger("phishlens.agent_registry")

# Map of agents to required environment variables and descriptions
AGENT_KEY_REQUIREMENTS: Dict[str, Dict[str, Any]] = {
    "intent_llm": {
        "keys": ["GROQ_API_KEY"],
        "fallback_mode": "Regex & Keyword Heuristics",
        "optional": True,
        "description": "Groq LLaMA 3.1 LLM Intent Analysis"
    },
    "gemini_vision": {
        "keys": ["GEMINI_API_KEY"],
        "fallback_mode": "Local OCR & Layout Heuristics",
        "optional": True,
        "description": "Google Gemini Multimodal Vision Analysis"
    },
    "brave_osint": {
        "keys": ["BRAVE_API_KEY", "BRAVE_SEARCH_API_KEY"],
        "fallback_mode": "Internal Crowdsourced DB",
        "optional": True,
        "description": "Brave Search Web Intelligence for Complaints"
    },
    "reddit_osint": {
        "keys": ["REDDIT_CLIENT_ID"],
        "fallback_mode": "Public Reddit Search API",
        "optional": True,
        "description": "Reddit API Forum Scam Intelligence"
    },
    "safe_browsing": {
        "keys": ["GOOGLE_SAFE_BROWSING_API_KEY"],
        "fallback_mode": "Tier 1 Local Feeds & Offline Heuristics",
        "optional": True,
        "description": "Google Safe Browsing v4 Threat Intelligence"
    },
    "virustotal": {
        "keys": ["VIRUSTOTAL_API_KEY"],
        "fallback_mode": "Offline Heuristics & Brand Watchlist",
        "optional": True,
        "description": "VirusTotal v3 URL Malware Scanner"
    },
    "database": {
        "keys": ["DATABASE_URL", "SUPABASE_DB_URL", "SUPABASE_URL"],
        "fallback_mode": "Async Local SQLite Engine (phishlens_audit.db)",
        "optional": True,
        "description": "Supabase Postgres Production Persistence"
    }
}


class AgentRegistry:
    """Tracks enabled state and fallback mode of each multi-agent subsystem."""

    def __init__(self):
        self._status: Dict[str, Dict[str, Any]] = {}
        self.evaluate_environment()

    def evaluate_environment(self) -> Dict[str, Dict[str, Any]]:
        """Inspect environment keys and determine agent activation status."""
        self._status.clear()
        logger.info("── PhishLens Multi-Agent Startup Registry Check ──")

        for agent, spec in AGENT_KEY_REQUIREMENTS.items():
            keys = spec["keys"]
            found_key = any(bool(os.getenv(k, "").strip()) for k in keys)
            fallback = spec["fallback_mode"]
            desc = spec["description"]

            if found_key:
                status = "ACTIVE"
                detail = f"Enabled with API key ({', '.join(k for k in keys if os.getenv(k))})"
                logger.info(f"  [OK] {desc}: ACTIVE")
            else:
                status = "FALLBACK_OFFLINE"
                detail = f"Missing key ({'/'.join(keys)}) -> Routed to {fallback}"
                logger.warning(f"  [WARN] {desc}: Keys missing ({'/'.join(keys)}). Auto-switching to: {fallback}")

            self._status[agent] = {
                "status": status,
                "description": desc,
                "has_api_key": found_key,
                "fallback_mode": fallback,
                "detail": detail
            }

        return self._status

    def is_live_api_ready(self, agent_name: str) -> bool:
        """Check if an agent has valid live API keys."""
        item = self._status.get(agent_name)
        if not item:
            return False
        return item["has_api_key"]

    def get_status(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._status)


# Global Singleton
agent_registry = AgentRegistry()
