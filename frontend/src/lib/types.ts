// ────────────────────────────────────────────────────────────
//  PhishLens  ·  Frontend Type Definitions
//  Mirrors backend/shared/models.py  ·  Source: schema_mocks.json
// ────────────────────────────────────────────────────────────

export type Channel = 'sms' | 'whatsapp' | 'email' | 'qr_payment' | 'web_url' | 'unknown';

export type RiskTier = 'SAFE' | 'CAUTION' | 'HIGH_RISK' | 'CRITICAL';

export type ActionRequired = 'ALLOW' | 'WARN_USER' | 'BLOCK_TRANSACTION';

export type AgentStatus = 'SUCCESS' | 'SKIPPED' | 'ERROR';

export type TldReputation = 'HIGH_RISK' | 'NEUTRAL' | 'REPUTABLE';

export type SenderCategory =
  | 'OFFICIAL_TRAI_HEADER'
  | 'PERSONAL_GSM'
  | 'INTERNATIONAL'
  | 'LOOKALIKE_HEADER'
  | 'UNKNOWN';

export type DetectedIntent =
  | 'PANIC_URGENCY'
  | 'FINANCIAL_EXTORTION'
  | 'LOTTERY_REWARD'
  | 'KYC_VERIFICATION'
  | 'OTP_HARVEST'
  | 'BENIGN'
  | 'SUSPICIOUS';

// ── Day 4: Bilingual ─────────────────────────────────────────

export type Language = 'en' | 'hi';

// ── Day 4: Auto-Detection Badge ──────────────────────────────

export type DetectedInputType = 'url' | 'upi' | 'sms';

// ── Request ──────────────────────────────────────────────────

export interface ScanRequest {
  content: string;
  sender?: string;
  extracted_url?: string | null;
  channel?: Channel;
  metadata?: {
    client_timestamp?: string;
    device_platform?: string;
  };
}

// ── Agent Results ─────────────────────────────────────────────

export interface UrlAgentResult {
  status: AgentStatus;
  url_analyzed: string | null;
  risk_score: number;
  domain_age_days: number | null;
  is_typosquatting: boolean;
  target_brand: string | null;
  tld_reputation: TldReputation;
  flags: string[];
  details: string;
  latency_ms: number;
}

export interface SenderAgentResult {
  status: AgentStatus;
  sender_analyzed: string | null;
  risk_score: number;
  is_spoofed_header: boolean;
  sender_category: SenderCategory;
  brand_claimed: string | null;
  flags: string[];
  details: string;
  latency_ms: number;
}

export interface IntentAgentResult {
  status: AgentStatus;
  risk_score: number;
  detected_intent: DetectedIntent;
  manipulation_tactics: string[];
  confidence: number;
  flags: string[];
  reasoning: string;
  details: string;
  latency_ms: number;
}

export interface SynthesisBreakdown {
  weights_applied: {
    url_weight: number;
    sender_weight: number;
    intent_weight: number;
  };
  heuristics_triggered: string[];
  summary_explanation: string;
}

export interface AuditTrail {
  url_analysis: UrlAgentResult;
  sender_analysis: SenderAgentResult;
  intent_analysis: IntentAgentResult;
  synthesis_breakdown: SynthesisBreakdown;
}

// ── Response ──────────────────────────────────────────────────

export interface ScanResponse {
  scan_id: string;
  timestamp: string;
  overall_risk_score: number;
  risk_tier: RiskTier;
  verdict: string;
  recommendation: string;
  action_required: ActionRequired;
  audit_trail: AuditTrail;
  processing_time_ms: number;
  /** Hindi verdict from Avika's scoring engine (optional, bilingual support) */
  verdict_hi?: string;
  /** Hindi recommendation from Avika's scoring engine (optional, bilingual support) */
  recommendation_hi?: string;
}

// ── UI Helpers ────────────────────────────────────────────────

export interface UiTreatment {
  /** Whether to show the full-screen InterceptionModal */
  showModal: boolean;
  /** Accent color hex for gauges, badges, borders */
  accentColor: string;
  /** Human-readable label */
  label: string;
}

// ── Day 4: Live Audit Feed ────────────────────────────────────

export interface AuditLogEntry {
  scan_id: string;
  timestamp: string;
  risk_tier: RiskTier;
  overall_risk_score: number;
  verdict: string;
  verdict_hi?: string;
  channel: Channel;
  processing_time_ms: number;
}
