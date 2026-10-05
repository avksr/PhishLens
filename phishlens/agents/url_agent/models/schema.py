"""
phishlens.agents.url_agent.models.schema — Data models for URL Agent.

Standardizes input configurations, granular risk signals, and final outputs
for deep URL inspection.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class URLAgentInput(BaseModel):
    """Input payload for advanced URL inspection."""
    url: str
    deep_scan: bool = True
    user_agent_override: Optional[str] = None


class RiskSignal(BaseModel):
    """Individual security signal detected during URL analysis."""
    category: str  # e.g., "HOMOGRAPH", "REDIRECT", "SSL", "DOM", "CLOAKING"
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    description: str


class URLAgentOutput(BaseModel):
    """Standardized output returned by the URL Agent."""
    input_url: str
    final_destination_url: str
    risk_score: int = Field(ge=0, le=100)  # 0 = Safe, 100 = Malicious
    threat_level: str  # "SAFE", "SUSPICIOUS", "MALICIOUS"
    redirect_chain: List[str]
    signals: List[RiskSignal]
    metadata: Dict[str, Any]
    explanation: str
