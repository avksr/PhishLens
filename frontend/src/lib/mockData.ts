// ────────────────────────────────────────────────────────────
//  PhishLens  ·  Master Mock Data (Offline Demo)
//  Comprehensive mock JSON for scan results, threat flags,
//  agent statuses, source attribution, and scan history.
// ────────────────────────────────────────────────────────────

import type { RiskTier, Channel } from './types';

// ── Detected Threat Flag Types ────────────────────────────────

export type ThreatFlag =
  | 'fake_upi'
  | 'flagged_nx'
  | 'ai_text'
  | 'manipulated_photo'
  | 'forged_doc';

// ── Agent Status in Mock ──────────────────────────────────────

export interface MockAgent {
  name: string;
  role: string;
  status: 'SUCCESS' | 'SKIPPED' | 'ERROR';
  latency_ms: number;
}

// ── Scan History Entry ────────────────────────────────────────

export interface ScanHistoryEntry {
  scan_id: string;
  timestamp: string;
  target: string;
  channel: Channel;
  risk_tier: RiskTier;
  threat_score: number;
  detectedFlags: ThreatFlag[];
  verdict: string;
  verdict_hi?: string;
  processing_time_ms: number;
}

// ── Master Mock Scan Result ───────────────────────────────────

export interface MockScanResult {
  /** Indicates this result is a simulated/demo scan */
  isSimulated: boolean;

  /** Threat flags detected by multi-agent pipeline */
  detectedFlags: ThreatFlag[];

  /** Agent statuses — includes one SKIPPED agent */
  agents: MockAgent[];

  /** Source of the threat intelligence */
  sourceAttribution: string;

  /** UPI ID / target being analyzed */
  targetIdentifier: string;

  /** Overall risk score */
  overallRiskScore: number;

  /** Risk classification tier */
  riskTier: RiskTier;

  /** Human-readable verdict */
  verdict: string;

  /** Bilingual verdict */
  verdict_hi: string;
}

// ── Master Mock Result Instance ───────────────────────────────

export const mockScanResult: MockScanResult = {
  isSimulated: true,

  detectedFlags: [
    'fake_upi',
    'flagged_nx',
    'ai_text',
    'manipulated_photo',
    'forged_doc',
  ],

  agents: [
    {
      name: 'Atharv',
      role: 'URL / Domain Analyzer',
      status: 'SUCCESS',
      latency_ms: 320,
    },
    {
      name: 'Avni',
      role: 'Sender Identity Verifier',
      status: 'SKIPPED',
      latency_ms: 3,
    },
    {
      name: 'Vikas',
      role: 'Psycholinguistic Intent Detector',
      status: 'SUCCESS',
      latency_ms: 680,
    },
    {
      name: 'Avika',
      role: 'Synthesis & Scoring Engine',
      status: 'SUCCESS',
      latency_ms: 45,
    },
  ],

  sourceAttribution: 'Flagged by OpenPhish',

  targetIdentifier: 'scammer@fakebank',

  overallRiskScore: 87,

  riskTier: 'CRITICAL',

  verdict:
    'Multi-vector phishing attack: Fake UPI address combined with AI-generated text and manipulated evidence documents.',

  verdict_hi:
    'मल्टी-वेक्टर फ़िशिंग हमला: नकली UPI पता, AI-जनित टेक्स्ट, और हेरफेर किए गए साक्ष्य दस्तावेज़ों का संयोजन।',
};

// ── Scan History for /audit/recent ────────────────────────────

export const mockScanHistory: ScanHistoryEntry[] = [
  {
    scan_id: 'sc-001-a7b3c9e2',
    timestamp: new Date(Date.now() - 120_000).toISOString(),
    target: 'scammer@fakebank',
    channel: 'qr_payment',
    risk_tier: 'CRITICAL',
    threat_score: 92,
    detectedFlags: ['fake_upi', 'ai_text', 'forged_doc'],
    verdict: 'Confirmed phishing — Fake UPI with forged KYC',
    verdict_hi: 'फ़िशिंग की पुष्टि — नकली UPI और जाली KYC',
    processing_time_ms: 820,
  },
  {
    scan_id: 'sc-002-d4e5f6a1',
    timestamp: new Date(Date.now() - 480_000).toISOString(),
    target: 'https://sbi-kyc-verify.top/login',
    channel: 'sms',
    risk_tier: 'HIGH_RISK',
    threat_score: 78,
    detectedFlags: ['flagged_nx', 'ai_text'],
    verdict: 'High-risk domain with AI-generated lure text',
    verdict_hi: 'उच्च जोखिम डोमेन — AI-निर्मित प्रलोभन टेक्स्ट',
    processing_time_ms: 640,
  },
  {
    scan_id: 'sc-003-b8c9d0e3',
    timestamp: new Date(Date.now() - 1_200_000).toISOString(),
    target: '+919876543210',
    channel: 'sms',
    risk_tier: 'HIGH_RISK',
    threat_score: 74,
    detectedFlags: ['manipulated_photo'],
    verdict: 'Manipulated screenshot used as social proof',
    verdict_hi: 'सोशल प्रूफ के रूप में हेरफेर किया गया स्क्रीनशॉट',
    processing_time_ms: 560,
  },
  {
    scan_id: 'sc-004-f1a2b3c4',
    timestamp: new Date(Date.now() - 2_400_000).toISOString(),
    target: 'VM-HDFCBK',
    channel: 'sms',
    risk_tier: 'SAFE',
    threat_score: 8,
    detectedFlags: [],
    verdict: 'Legitimate bank OTP transaction notification',
    verdict_hi: 'वैध बैंक OTP लेनदेन अधिसूचना',
    processing_time_ms: 535,
  },
  {
    scan_id: 'sc-005-e5f6a7b8',
    timestamp: new Date(Date.now() - 3_600_000).toISOString(),
    target: 'support@amazzon-refund.click',
    channel: 'email',
    risk_tier: 'CRITICAL',
    threat_score: 95,
    detectedFlags: ['fake_upi', 'flagged_nx', 'ai_text', 'forged_doc'],
    verdict: 'Full-spectrum phishing — typosquatting + forged refund docs',
    verdict_hi: 'फुल-स्पेक्ट्रम फ़िशिंग — टाइपोस्क्वाटिंग + जाली रिफंड दस्तावेज़',
    processing_time_ms: 910,
  },
  {
    scan_id: 'sc-006-c9d0e1f2',
    timestamp: new Date(Date.now() - 5_400_000).toISOString(),
    target: 'https://paytm-cashback.in/win',
    channel: 'whatsapp',
    risk_tier: 'CAUTION',
    threat_score: 42,
    detectedFlags: ['ai_text'],
    verdict: 'Suspicious lottery/cashback lure — exercise caution',
    verdict_hi: 'संदिग्ध लॉटरी/कैशबैक प्रलोभन — सावधानी बरतें',
    processing_time_ms: 380,
  },
  {
    scan_id: 'sc-007-a3b4c5d6',
    timestamp: new Date(Date.now() - 7_200_000).toISOString(),
    target: 'merchant@verified.upi',
    channel: 'qr_payment',
    risk_tier: 'SAFE',
    threat_score: 5,
    detectedFlags: [],
    verdict: 'Verified merchant UPI — no threats detected',
    verdict_hi: 'सत्यापित मर्चेंट UPI — कोई खतरा नहीं',
    processing_time_ms: 290,
  },
  {
    scan_id: 'sc-008-d7e8f9a0',
    timestamp: new Date(Date.now() - 10_800_000).toISOString(),
    target: 'https://icici-update.top/verify',
    channel: 'email',
    risk_tier: 'CRITICAL',
    threat_score: 89,
    detectedFlags: ['flagged_nx', 'forged_doc', 'manipulated_photo'],
    verdict: 'Credential harvesting via forged bank portal',
    verdict_hi: 'जाली बैंक पोर्टल द्वारा क्रेडेंशियल हार्वेस्टिंग',
    processing_time_ms: 770,
  },
];
