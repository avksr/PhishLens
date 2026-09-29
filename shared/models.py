"""
shared.models — Canonical Pydantic data models for PhishLens multi-agent pipeline.

Every agent MUST import its request/result types from here.
DO NOT define local Pydantic models inside agent files.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────
# Enumerations
# ──────────────────────────────────────────────

class AgentStatusEnum(str, enum.Enum):
    """Lifecycle status reported by every agent."""
    SUCCESS = "SUCCESS"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class TldReputationEnum(str, enum.Enum):
    """Reputation classification of a top-level domain."""
    TRUSTED = "TRUSTED"
    NEUTRAL = "NEUTRAL"
    HIGH_RISK = "HIGH_RISK"


# ──────────────────────────────────────────────
# Shared request model
# ──────────────────────────────────────────────

class ScanRequest(BaseModel):
    """
    Unified inbound payload consumed by every agent.

    Fields
    ------
    content : str
        The raw message body (SMS / email / chat text).
    extracted_url : Optional[str]
        A URL that the orchestrator or an upstream agent has already
        extracted from `content`.  May be ``None``.
    sender : Optional[str]
        The sender identifier (phone number, email, handle).
    timestamp : Optional[datetime]
        When the message was received.
    metadata : dict
        Arbitrary key/value bag for orchestrator-level context.
    """
    content: str = ""
    extracted_url: Optional[str] = None
    sender: Optional[str] = None
    timestamp: Optional[datetime] = None
    metadata: dict = Field(default_factory=dict)


# ──────────────────────────────────────────────
# URL Agent result model
# ──────────────────────────────────────────────

class UrlAgentResult(BaseModel):
    """
    Structured output of the URL & Domain Intelligence Agent.

    All numeric scores are in the range [0.0, 100.0].
    """
    status: AgentStatusEnum = AgentStatusEnum.SUCCESS
    risk_score: float = 0.0
    url_analyzed: Optional[str] = None
    domain: Optional[str] = None
    tld: Optional[str] = None
    tld_reputation: TldReputationEnum = TldReputationEnum.NEUTRAL
    is_typosquatting: bool = False
    target_brand: Optional[str] = None
    domain_age_days: Optional[int] = None
    flags: List[str] = Field(default_factory=list)
    details: Optional[str] = None
    latency_ms: float = 0.0
