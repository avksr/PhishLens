// ────────────────────────────────────────────────────────────
//  PhishLens  ·  API Client  (with offline mock fallback)
//  POST /api/v1/scan  →  ScanResponse
// ────────────────────────────────────────────────────────────

import type { ScanRequest, ScanResponse, RiskTier, UiTreatment, AuditLogEntry } from './types';

// ── Runtime datasets (bundled at build time) ──────────────────
import highRiskPayloads from '../../../datasets/payloads_high_risk.json';
import safePayloads     from '../../../datasets/payloads_safe.json';

export { highRiskPayloads, safePayloads };

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';

// ── Offline mock database (keyed by keyword match) ────────────

const MOCK_RESPONSES: ScanResponse[] = [
  // CRITICAL — SBI KYC
  {
    scan_id: 'c7a8b3e1-9524-4f0e-b7d6-ec2d79d501b4',
    timestamp: new Date().toISOString(),
    overall_risk_score: 92, 
    risk_tier: 'CRITICAL',
    verdict: 'Confirmed Impersonation & Credential Harvesting Attack',
    verdict_hi: 'पुष्टि: प्रतिरूपण एवं क्रेडेंशियल हार्वेस्टिंग हमला',
    recommendation:
      'BLOCK IMMEDIATE ACTION. This message impersonates State Bank of India using an unverified personal mobile number and a fresh phishing domain (.top). Never enter OTP or KYC credentials on third-party domains.',
    recommendation_hi:
      'तुरंत ब्लॉक करें। यह संदेश एक असत्यापित व्यक्तिगत मोबाइल नंबर और नई फ़िशिंग डोमेन (.top) से भारतीय स्टेट बैंक की नकल कर रहा है। कभी भी तृतीय-पक्ष डोमेन पर OTP या KYC क्रेडेंशियल दर्ज न करें।',
    action_required: 'BLOCK_TRANSACTION',
    audit_trail: {
      url_analysis: {
        status: 'SUCCESS',
        url_analyzed: 'https://sbi-kyc-verify.top',
        risk_score: 95,
        domain_age_days: 2,
        is_typosquatting: true,
        target_brand: 'State Bank of India (SBI)',
        tld_reputation: 'HIGH_RISK',
        flags: [
          'DOMAIN_REGISTERED_RECENTLY (< 7 days)',
          'TYPOSQUATTING_DETECTED (sbi-kyc-verify mimicking onlinesbi.sbi)',
          'HIGH_RISK_TLD (.top)',
        ],
        details:
          'Domain registered 48 hours ago via privacy proxy. Mimics official SBI domain structure.',
        latency_ms: 320,
      },
      sender_analysis: {
        status: 'SUCCESS',
        sender_analyzed: '+919876543210',
        risk_score: 88,
        is_spoofed_header: false,
        sender_category: 'PERSONAL_GSM',
        brand_claimed: 'State Bank of India (SBI)',
        flags: [
          'COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM',
          'MISSING_TRAI_OFFICIAL_HEADER (Expected format like VM-SBIINB or AX-SBIINB)',
        ],
        details:
          'Legitimate banking alerts in India are mandated by TRAI to originate from DLT registered alphabetic sender IDs (e.g. SBIBNK), never personal 10-digit mobile numbers.',
        latency_ms: 110,
      },
      intent_analysis: {
        status: 'SUCCESS',
        risk_score: 90,
        detected_intent: 'KYC_VERIFICATION',
        manipulation_tactics: [
          'False Urgency (2-hour account deactivation ultimatum)',
          'Fear Appeals (Account blocked/frozen)',
          'Credential & PII Harvesting (Aadhaar, PAN)',
        ],
        confidence: 0.94,
        flags: ['PSYCHOLOGICAL_URGENCY_TRIGGER', 'UNVERIFIED_KYC_SOLICITATION'],
        reasoning:
          'The message creates artificial panic by claiming immediate account deactivation within 2 hours, coercing the recipient into submitting sensitive KYC identity documents via an insecure unverified link.',
        details: 'Linguistic markers match high-probability social engineering scam corpus.',
        latency_ms: 680,
      },
      synthesis_breakdown: {
        weights_applied: { url_weight: 0.4, sender_weight: 0.3, intent_weight: 0.3 },
        heuristics_triggered: [
          'CRITICAL_ESCALATION: High risk URL combined with Personal GSM sender claiming Tier-1 Indian Bank',
          'Active credential harvesting pattern detected across all 3 independent vectors',
        ],
        summary_explanation:
          'All three autonomous agents independently flagged severe anomalies: Domain age (2 days), unauthorized personal sender ID, and coercive fear-based KYC extortion.',
      },
    },
    processing_time_ms: 820.5,
  },

  // HIGH_RISK — Electricity
  {
    scan_id: 'a1b2c3d4-1111-2222-3333-444455556666',
    timestamp: new Date().toISOString(),
    overall_risk_score: 74,
    risk_tier: 'HIGH_RISK',
    verdict: 'Social Engineering — Utility Service Impersonation',
    verdict_hi: 'सोशल इंजीनियरिंग — बिजली सेवा प्रतिरूपण',
    recommendation:
      "Do NOT call the number. Legitimate electricity boards never threaten disconnection via SMS from personal numbers. Verify directly via official BESCOM/MSEDCL app or website.",
    recommendation_hi:
      'इस नंबर पर कॉल न करें। असली बिजली बोर्ड कभी भी व्यक्तिगत नंबर से SMS द्वारा कनेक्शन काटने की धमकी नहीं देते। सीधे BESCOM/MSEDCL की आधिकारिक ऐप या वेबसाइट से सत्यापित करें।',
    action_required: 'WARN_USER',
    audit_trail: {
      url_analysis: {
        status: 'SKIPPED',
        url_analyzed: null,
        risk_score: 0,
        domain_age_days: null,
        is_typosquatting: false,
        target_brand: null,
        tld_reputation: 'NEUTRAL',
        flags: [],
        details: 'No URL found in message body.',
        latency_ms: 3,
      },
      sender_analysis: {
        status: 'SUCCESS',
        sender_analyzed: '+919812345678',
        risk_score: 82,
        is_spoofed_header: false,
        sender_category: 'PERSONAL_GSM',
        brand_claimed: 'State Electricity Board',
        flags: [
          'UTILITY_PROVIDER_CLAIMED_ON_PERSONAL_GSM',
          'MISSING_TRAI_OFFICIAL_HEADER',
          'UNVERIFIED_CALLBACK_NUMBER',
        ],
        details:
          'Government utility boards are DLT-registered. No legitimate electricity board contacts via personal mobile numbers.',
        latency_ms: 95,
      },
      intent_analysis: {
        status: 'SUCCESS',
        risk_score: 76,
        detected_intent: 'PANIC_URGENCY',
        manipulation_tactics: [
          'Imminent Service Threat (Disconnection tonight at 9:30 PM)',
          'Time Pressure (Immediate contact demanded)',
          'Impersonation of Official Authority',
        ],
        confidence: 0.88,
        flags: ['PSYCHOLOGICAL_URGENCY_TRIGGER', 'UTILITY_IMPERSONATION_PATTERN'],
        reasoning:
          'Classic utility disconnection scam pattern. Uses time-pressure ("tonight at 9:30 PM") and authority impersonation to coerce victim into calling a scammer-controlled number.',
        details:
          'Matches known BESCOM/utility impersonation scam corpus with 88% confidence.',
        latency_ms: 540,
      },
      synthesis_breakdown: {
        weights_applied: { url_weight: 0.0, sender_weight: 0.5, intent_weight: 0.5 },
        heuristics_triggered: [
          'Personal GSM sender claiming utility authority',
          'Urgency-based social engineering without digital link (phone-redirect scam)',
        ],
        summary_explanation:
          'No URL present — attack vector is phone call redirection. Personal GSM sender combined with high-urgency utility impersonation pattern.',
      },
    },
    processing_time_ms: 638,
  },

  // SAFE — HDFC OTP
  {
    scan_id: 'f290d4a9-8351-499b-98df-5847eec659a8',
    timestamp: new Date().toISOString(),
    overall_risk_score: 8,
    risk_tier: 'SAFE',
    verdict: 'Legitimate Bank OTP Transaction Notification',
    verdict_hi: 'वैध बैंक OTP लेनदेन सूचना',
    recommendation:
      'Normal verified communication. Remember to never share this OTP with any caller or in third-party forms.',
    recommendation_hi:
      'सामान्य सत्यापित संचार। याद रखें कि यह OTP किसी भी कॉलर या तृतीय-पक्ष फॉर्म में साझा न करें।',
    action_required: 'ALLOW',
    audit_trail: {
      url_analysis: {
        status: 'SKIPPED',
        url_analyzed: null,
        risk_score: 0,
        domain_age_days: null,
        is_typosquatting: false,
        target_brand: null,
        tld_reputation: 'NEUTRAL',
        flags: [],
        details: 'No URL found in message body.',
        latency_ms: 2,
      },
      sender_analysis: {
        status: 'SUCCESS',
        sender_analyzed: 'VM-HDFCBK',
        risk_score: 5,
        is_spoofed_header: false,
        sender_category: 'OFFICIAL_TRAI_HEADER',
        brand_claimed: 'HDFC Bank',
        flags: ['VERIFIED_TRAI_DLT_SENDER_HEADER'],
        details:
          'Sender matches certified TRAI transactional sender prefix assigned to HDFC Bank Ltd.',
        latency_ms: 85,
      },
      intent_analysis: {
        status: 'SUCCESS',
        risk_score: 10,
        detected_intent: 'BENIGN',
        manipulation_tactics: [],
        confidence: 0.98,
        flags: ['STANDARD_TRANSACTIONAL_DISCLOSURE'],
        reasoning:
          "Standard bank transaction notification with explicit cautionary advice ('Do not share OTP with anyone'). No credential solicitation links or coercive demands.",
        details: 'Legitimate transactional OTP delivery pattern.',
        latency_ms: 520,
      },
      synthesis_breakdown: {
        weights_applied: { url_weight: 0.0, sender_weight: 0.5, intent_weight: 0.5 },
        heuristics_triggered: [
          'Verified sender DLT registry match',
          'Explicit anti-phishing advisory present in payload',
        ],
        summary_explanation:
          'Communication matches verified banking gateway protocols with zero malicious indicators.',
      },
    },
    processing_time_ms: 535.2,
  },
];

/** Pick the best offline mock for a given request */
function pickMockResponse(req: ScanRequest): ScanResponse {
  const text = (req.content + (req.sender ?? '')).toLowerCase();
  if (text.includes('sbi') || text.includes('kyc') || text.includes('.top')) {
    return { ...MOCK_RESPONSES[0], timestamp: new Date().toISOString() };
  }
  if (text.includes('electricity') || text.includes('power') || text.includes('disconnected')) {
    return { ...MOCK_RESPONSES[1], timestamp: new Date().toISOString() };
  }
  if (
    text.includes('otp') ||
    text.includes('hdfc') ||
    text.includes('vm-') ||
    text.includes('transaction')
  ) {
    return { ...MOCK_RESPONSES[2], timestamp: new Date().toISOString() };
  }
  // Generic fallback — CAUTION tier
  return {
    ...MOCK_RESPONSES[1],
    scan_id: crypto.randomUUID(),
    overall_risk_score: 42,
    risk_tier: 'CAUTION',
    verdict: 'Unverified Communication — Exercise Caution',
    verdict_hi: 'असत्यापित संचार — सावधानी बरतें',
    recommendation: 'Could not definitively classify. Treat with caution.',
    recommendation_hi: 'निश्चित रूप से वर्गीकृत नहीं किया जा सका। सावधानी से व्यवहार करें।',
    action_required: 'WARN_USER',
    timestamp: new Date().toISOString(),
    processing_time_ms: 250,
  };
}

// ── Core API Call ─────────────────────────────────────────────

/**
 * Sends a message to the PhishLens multi-agent scan pipeline.
 * If the backend is offline, returns a realistic mock response (demo-safe).
 */
export async function scanMessage(req: ScanRequest): Promise<ScanResponse> {
  const body: ScanRequest = {
    ...req,
    channel: req.channel ?? 'sms',
    metadata: {
      client_timestamp: new Date().toISOString(),
      device_platform: 'web',
      ...req.metadata,
    },
  };

  try {
    const response = await fetch(`${BASE_URL}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      const errorBody = await response.text().catch(() => 'Unknown error');
      throw new Error(`PhishLens API ${response.status}: ${errorBody}`);
    }

    return response.json() as Promise<ScanResponse>;
  } catch {
    // Backend offline → graceful demo fallback
    console.warn('[PhishLens] Backend unreachable — using offline mock response');
    // Simulate network latency
    await new Promise((r) => setTimeout(r, 600 + Math.random() * 400));
    return pickMockResponse(req);
  }
}

// ── UI Treatment Helper ───────────────────────────────────────

/**
 * Maps risk_tier + action_required → UI rendering decisions.
 * The full-screen InterceptionModal triggers ONLY when
 * action_required === 'BLOCK_TRANSACTION'.
 */
export function getUiTreatment(tier: RiskTier, action_required?: string): UiTreatment {
  const showModal = action_required === 'BLOCK_TRANSACTION';
  switch (tier) {
    case 'SAFE':
      return { showModal: false, accentColor: '#00E676', label: 'SAFE' };
    case 'CAUTION':
      return { showModal: false, accentColor: '#FFB800', label: 'CAUTION' };
    case 'HIGH_RISK':
      return { showModal, accentColor: '#FF6B00', label: 'HIGH RISK' };
    case 'CRITICAL':
      return { showModal, accentColor: '#FF3366', label: 'CRITICAL' };
  }
}

// ── Day 4: Live Audit Feed ────────────────────────────────────

const MOCK_AUDIT_LOGS: AuditLogEntry[] = [
  {
    scan_id: 'c7a8b3e1-9524-4f0e-b7d6-ec2d79d501b4',
    timestamp: new Date(Date.now() - 120_000).toISOString(),
    risk_tier: 'CRITICAL',
    overall_risk_score: 92,
    verdict: 'Confirmed Impersonation & Credential Harvesting Attack',
    verdict_hi: 'पुष्टि: प्रतिरूपण एवं क्रेडेंशियल हार्वेस्टिंग हमला',
    channel: 'sms',
    processing_time_ms: 820.5,
  },
  {
    scan_id: 'a1b2c3d4-1111-2222-3333-444455556666',
    timestamp: new Date(Date.now() - 480_000).toISOString(),
    risk_tier: 'HIGH_RISK',
    overall_risk_score: 74,
    verdict: 'Social Engineering — Utility Service Impersonation',
    verdict_hi: 'सोशल इंजीनियरिंग — बिजली सेवा प्रतिरूपण',
    channel: 'sms',
    processing_time_ms: 638,
  },
  {
    scan_id: 'f290d4a9-8351-499b-98df-5847eec659a8',
    timestamp: new Date(Date.now() - 900_000).toISOString(),
    risk_tier: 'SAFE',
    overall_risk_score: 8,
    verdict: 'Legitimate Bank OTP Transaction Notification',
    verdict_hi: 'वैध बैंक ओटीपी लेनदेन अधिसूचना',
    channel: 'sms',
    processing_time_ms: 535.2,
  },
  {
    scan_id: 'b5e9d002-77a4-42ff-9afc-3c118e5a12d1',
    timestamp: new Date(Date.now() - 1_800_000).toISOString(),
    risk_tier: 'CAUTION',
    overall_risk_score: 42,
    verdict: 'Unverified Communication — Exercise Caution',
    verdict_hi: 'असत्यापित संचार — सावधानी बरतें',
    channel: 'whatsapp',
    processing_time_ms: 250,
  },
  {
    scan_id: 'e7f3a014-2c55-4b8d-a923-7d66cc4f0011',
    timestamp: new Date(Date.now() - 3_600_000).toISOString(),
    risk_tier: 'SAFE',
    overall_risk_score: 12,
    verdict: 'Verified e-commerce order confirmation',
    verdict_hi: 'सत्यापित ई-कॉमर्स ऑर्डर पुष्टि',
    channel: 'email',
    processing_time_ms: 412.3,
  },
];

/**
 * Fetches recent audit logs from `GET /api/v1/audit/recent?limit=10`.
 * Falls back to offline mock data when the backend is unreachable.
 */
export async function fetchRecentAuditLogs(limit: number = 10): Promise<AuditLogEntry[]> {
  try {
    const response = await fetch(`${BASE_URL}/api/v1/audit/recent?limit=${limit}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error(`${response.status}`);
    return response.json() as Promise<AuditLogEntry[]>;
  } catch {
    // Backend offline → demo fallback
    console.warn('[PhishLens] Audit API unreachable — using mock audit logs');
    await new Promise((r) => setTimeout(r, 300 + Math.random() * 200));
    return MOCK_AUDIT_LOGS.slice(0, limit);
  }
}
