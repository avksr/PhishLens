"""
PhishLens - Shared Data Models (Single Source of Truth)
Every agent and pipeline component MUST import types from this module.
Ref: schema_mocks.json
"""

from typing import List, Optional, Dict, Any, Union
from enum import Enum
from pydantic import BaseModel, Field, model_validator
from datetime import datetime, timezone
import uuid


class EvidenceItem(BaseModel):
    tool: str
    status: str
    finding: str
    raw_result: Optional[Dict[str, Any]] = None
    provider: Optional[str] = Field(default=None, description="Source provider or SANDBOX_MOCK for simulated checks")



class PrdVerdictEnum(str, Enum):
    SAFE = "SAFE"                # 0-30 Safe
    SUSPICIOUS = "SUSPICIOUS"    # 31-65 Suspicious
    LIKELY_SCAM = "LIKELY_SCAM"  # 66-100 Likely Scam



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


class ConfidenceLevelEnum(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


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
    phone_type: Optional[str] = Field(default=None, description="e.g. MOBILE, PROMOTIONAL_140, SERVICE_160, TOLL_FREE, LANDLINE, INVALID")
    email_analysis: Optional[Dict[str, Any]] = Field(default=None, description="Detailed email header and pattern checks")
    provider: Optional[str] = Field(default="TRAI_DLT_REGISTRY", description="Provider attribution or SANDBOX_MOCK")


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


class UpiAgentResult(BaseModel):
    status: AgentStatusEnum = AgentStatusEnum.SUCCESS
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    detected_vpa: Optional[str] = None
    is_spoofed_merchant: bool = False
    target_entity: Optional[str] = None
    flags: List[str] = Field(default_factory=list)
    details: str = ""
    latency_ms: float = 0.0
    # Added by Avni — Bank Identity & Sandbox verification fields
    registered_name: Optional[str] = Field(default=None, description="Official bank-registered name for VPA")
    claimed_name: Optional[str] = Field(default=None, description="Claimed identity in message or payee name")
    name_match_score: Optional[float] = Field(default=None, ge=0.0, le=100.0, description="Fuzzy name match score (0-100)")
    name_match_status: Optional[str] = Field(default=None, description="MATCH, MISMATCH, or UNVERIFIED")
    provider: Optional[str] = Field(default="SANDBOX_MOCK", description="Verification provider tag, e.g. SANDBOX_MOCK")



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
    upi_analysis: Optional[UpiAgentResult] = None
    synthesis_breakdown: SynthesisBreakdown


class ScanResponse(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    audit_id: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    overall_risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    risk_score: Optional[int] = None
    verdict_category: Optional[PrdVerdictEnum] = None
    risk_tier: Optional[RiskTierEnum] = None
    confidence: ConfidenceLevelEnum = ConfidenceLevelEnum.HIGH
    reasons: List[str] = Field(default_factory=list, description="Plain-language, max 5, ordered by weight")
    evidence: List[Union[EvidenceItem, Dict[str, Any]]] = Field(default_factory=list, description="tool name, finding, raw result summary, status")
    recommended_action: Optional[str] = None
    verdict: Optional[str] = None
    verdict_hi: Optional[str] = None
    recommendation: Optional[str] = None
    recommendation_hi: Optional[str] = None
    action_required: Optional[ActionRequiredEnum] = None
    audit_trail: Optional[AuditTrail] = None
    processing_time_ms: float = 0.0
    detected_input_type: Optional[str] = Field(
        None, description="Auto-detected input type: web_url, upi_handle, or text_message"
    )

    @model_validator(mode="after")
    def populate_prd_aliases(self) -> "ScanResponse":
        # Synchronize risk_score and overall_risk_score
        if self.risk_score is None and self.overall_risk_score is not None:
            self.risk_score = self.overall_risk_score
        elif self.overall_risk_score is None and self.risk_score is not None:
            self.overall_risk_score = self.risk_score
        elif self.overall_risk_score is None and self.risk_score is None:
            self.overall_risk_score = 0
            self.risk_score = 0

        # Synchronize audit_id and scan_id
        if not self.audit_id:
            self.audit_id = self.scan_id
        elif not self.scan_id:
            self.scan_id = self.audit_id

        # Determine verdict_category if not explicitly provided
        score = self.risk_score if self.risk_score is not None else 0
        if self.verdict_category is None:
            if score <= 30:
                self.verdict_category = PrdVerdictEnum.SAFE
            elif score <= 65:
                self.verdict_category = PrdVerdictEnum.SUSPICIOUS
            else:
                self.verdict_category = PrdVerdictEnum.LIKELY_SCAM

        # Synchronize legacy risk_tier if not provided
        if self.risk_tier is None:
            if score < 25:
                self.risk_tier = RiskTierEnum.SAFE
            elif score < 50:
                self.risk_tier = RiskTierEnum.CAUTION
            elif score < 78:
                self.risk_tier = RiskTierEnum.HIGH_RISK
            else:
                self.risk_tier = RiskTierEnum.CRITICAL

        # Synchronize recommendations
        if not self.recommended_action and self.recommendation:
            self.recommended_action = self.recommendation
        elif not self.recommendation and self.recommended_action:
            self.recommendation = self.recommended_action
        elif not self.recommended_action and not self.recommendation:
            self.recommended_action = "No action required." if score <= 30 else "Exercise caution and do not share OTP or sensitive data."
            self.recommendation = self.recommended_action

        # Synchronize verdict
        if not self.verdict:
            self.verdict = f"Scan completed: {self.verdict_category.value}"

        # Synchronize action_required
        if self.action_required is None:
            if self.verdict_category == PrdVerdictEnum.SAFE:
                self.action_required = ActionRequiredEnum.ALLOW
            elif self.verdict_category == PrdVerdictEnum.SUSPICIOUS:
                self.action_required = ActionRequiredEnum.WARN_USER
            else:
                self.action_required = ActionRequiredEnum.BLOCK_TRANSACTION

        return self


