"""
PhishLens - Shared Data Models (Single Source of Truth)
Every agent and pipeline component MUST import types from this module.
Ref: schema_mocks.json
"""

from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid


class ChannelEnum(str, Enum):
    SMS = "sms"
    WHATSAPP = "whatsapp"
    EMAIL = "email"
    QR_PAYMENT = "qr_payment"
    WEB_URL = "web_url"
    UNKNOWN = "unknown"


class AgentStatusEnum(str, Enum):
    SUCCESS = "SUCCESS"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class RiskTierEnum(str, Enum):
    SAFE = "SAFE"                # 0-24
    CAUTION = "CAUTION"          # 25-49
    HIGH_RISK = "HIGH_RISK"      # 50-77
    CRITICAL = "CRITICAL"        # 78-100


class ActionRequiredEnum(str, Enum):
    ALLOW = "ALLOW"
    WARN_USER = "WARN_USER"
    BLOCK_TRANSACTION = "BLOCK_TRANSACTION"


class TldReputationEnum(str, Enum):
    HIGH_RISK = "HIGH_RISK"
    NEUTRAL = "NEUTRAL"
    REPUTABLE = "REPUTABLE"


class SenderCategoryEnum(str, Enum):
    OFFICIAL_TRAI_HEADER = "OFFICIAL_TRAI_HEADER"
    PERSONAL_GSM = "PERSONAL_GSM"
    INTERNATIONAL = "INTERNATIONAL"
    LOOKALIKE_HEADER = "LOOKALIKE_HEADER"
    UNKNOWN = "UNKNOWN"


class DetectedIntentEnum(str, Enum):
    PANIC_URGENCY = "PANIC_URGENCY"
    FINANCIAL_EXTORTION = "FINANCIAL_EXTORTION"
    LOTTERY_REWARD = "LOTTERY_REWARD"
    KYC_VERIFICATION = "KYC_VERIFICATION"
    OTP_HARVEST = "OTP_HARVEST"
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"


# --- Request Payload ---
class ScanRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=8000, description="Raw message, email, or payment prompt text")
    sender: Optional[str] = Field(
        None, description="Sender phone number or TRAI DLT header (e.g. +919876543210, VM-SBIINB)"
    )
    extracted_url: Optional[str] = Field(None, description="Pre-extracted or user-provided URL to inspect")
    channel: ChannelEnum = Field(default=ChannelEnum.SMS, description="Ingestion channel")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Client metadata")


# --- Individual Agent Result Models ---
class UrlAgentResult(BaseModel):
    status: AgentStatusEnum = AgentStatusEnum.SUCCESS
    url_analyzed: Optional[str] = None
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    domain: Optional[str] = None
    tld: Optional[str] = None
    domain_age_days: Optional[int] = None
    is_typosquatting: bool = False
    target_brand: Optional[str] = None
    tld_reputation: TldReputationEnum = TldReputationEnum.NEUTRAL
    flags: List[str] = Field(default_factory=list)
    details: str = ""
    latency_ms: float = 0.0


class SenderAgentResult(BaseModel):
    status: AgentStatusEnum = AgentStatusEnum.SUCCESS
    sender_analyzed: Optional[str] = None
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    is_spoofed_header: bool = False
    sender_category: SenderCategoryEnum = SenderCategoryEnum.UNKNOWN
    brand_claimed: Optional[str] = None
    flags: List[str] = Field(default_factory=list)
    details: str = ""
    latency_ms: float = 0.0
    # Added by Avni — sender_agent.py audit fields (optional, backward-compatible)
    raw_sender: Optional[str] = None
    normalised_sender: Optional[str] = None


class IntentAgentResult(BaseModel):
    status: AgentStatusEnum = AgentStatusEnum.SUCCESS
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    detected_intent: DetectedIntentEnum = DetectedIntentEnum.BENIGN
    manipulation_tactics: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    flags: List[str] = Field(default_factory=list)
    reasoning: str = ""
    details: str = ""
    latency_ms: float = 0.0


# --- Composite Output Models ---
class SynthesisBreakdown(BaseModel):
    weights_applied: Dict[str, float] = Field(default_factory=lambda: {
        "url_weight": 0.40,
        "sender_weight": 0.30,
        "intent_weight": 0.30
    })
    heuristics_triggered: List[str] = Field(default_factory=list)
    summary_explanation: str = ""


class AuditTrail(BaseModel):
    url_analysis: UrlAgentResult
    sender_analysis: SenderAgentResult
    intent_analysis: IntentAgentResult
    synthesis_breakdown: SynthesisBreakdown


class ScanResponse(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    overall_risk_score: int = Field(..., ge=0, le=100)
    risk_tier: RiskTierEnum
    verdict: str
    recommendation: str
    action_required: ActionRequiredEnum
    audit_trail: AuditTrail
    processing_time_ms: float
