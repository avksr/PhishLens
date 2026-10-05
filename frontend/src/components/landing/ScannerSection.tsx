// ─────────────────────────────────────────────────────────────
//  PhishLens Enterprise Landing · Embedded Scanner Console & Radar
//  Strictly matched to Stitch screen projects/1873559564137532359
//  Dark Theme block (#0B1120) with 2-col Split: Scanner + Live Radar
// ─────────────────────────────────────────────────────────────
import { useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Terminal,
  ScanLine,
  Lock,
  AlertTriangle,
  AlertOctagon,
  CheckCircle,
  ExternalLink,
  Radio,
  Loader2,
  ChevronDown,
  Flag,
  X,
  Send,
} from 'lucide-react';

export interface ThreatAnalysis {
  riskScore: number;
  status: 'Safe' | 'Suspicious' | 'Critical';
  verdictTitle: string;
  flags: string[];
  remediation: string;
  col1Title: string;
  col1Value: string;
  col1Note: string;
  col1Dot: string;
  col2Title: string;
  col2Value: string;
  col2Note: string;
  col2Dot: string;
  col3Title: string;
  col3Value: string;
  col3Note: string;
  col3Dot: string;
}

export function analyzeThreat(text: string): ThreatAnalysis {
  const lower = text.toLowerCase();
  let score = 0;
  const flags: string[] = [];
  const heuristics: string[] = [];

  // 1. Keyword check (+30 to risk score)
  const keywordList = ['urgent', 'kyc', 'verify', 'suspended', 'win', 'lottery'];
  const matchedKeywords = keywordList.filter(kw => lower.includes(kw));
  if (matchedKeywords.length > 0) {
    score += 30;
    flags.push('Urgency / Pressure');
    heuristics.push(`Keywords matched: [${matchedKeywords.join(', ')}]`);
  }

  // 2. Malicious link check (+45 to risk score)
  const linkList = ['.xyz', '.top', 'bit.ly', 'tinyurl.com'];
  const matchedLinks = linkList.filter(ext => lower.includes(ext));
  if (matchedLinks.length > 0) {
    score += 45;
    flags.push('High-Risk Domain');
    heuristics.push(`Rogue domain indicators: [${matchedLinks.join(', ')}]`);
  }

  // 3. UPI Scams check (+40 to risk score, Flag as "Fake UPI")
  const upiList = ['@ybl', '@okicici', 'cashback'];
  const matchedUpi = upiList.filter(upi => lower.includes(upi));
  if (matchedUpi.length > 0) {
    score += 40;
    flags.push('Fake UPI');
    heuristics.push(`Payment redirect / VPA: [${matchedUpi.join(', ')}]`);
  }

  // 4. Safe default: If none of these trigger, return a SAFE result (Score < 20)
  if (flags.length === 0) {
    const isDomain =
      lower.startsWith('http://') ||
      lower.startsWith('https://') ||
      (lower.includes('.') && !lower.includes(' '));
    const safeScore = isDomain ? 0.1 : 4.5;

    return {
      riskScore: safeScore,
      status: 'Safe',
      verdictTitle: 'VERDICT: BENIGN VERIFIED INFRASTRUCTURE',
      flags: ['Clean Baseline', 'Zero Deceptive Markers'],
      remediation: 'Automated Routing: Direct SSL termination approved with zero friction.',
      col1Title: 'Domain & EV SSL',
      col1Value: isDomain ? 'Allowlisted Host / CDN' : 'Standard Text Payload',
      col1Note: 'TLS 1.3 · HSTS Enforced',
      col1Dot: 'bg-emerald-400',
      col2Title: 'Reputation History',
      col2Value: 'Clean 14+ Years',
      col2Note: 'Zero deceptive reports',
      col2Dot: 'bg-emerald-400',
      col3Title: 'Safety Classification',
      col3Value: 'Allowlisted Enterprise',
      col3Note: 'Direct bypass approved',
      col3Dot: 'bg-emerald-400',
    };
  }

  // Cap score at 99.8 max
  if (score > 99.8) score = 99.8;

  const status: 'Critical' | 'Suspicious' = score >= 60 ? 'Critical' : 'Suspicious';

  if (flags.includes('Fake UPI')) {
    return {
      riskScore: score,
      status,
      verdictTitle:
        status === 'Critical'
          ? 'CRITICAL: FRAUDULENT UPI PAYMENT SCAM'
          : 'WARNING: SUSPICIOUS PAYMENT IDENTIFIER',
      flags,
      remediation: 'Automated Remediation: Carrier SMS filter deployed + VPA blacklisted in registry.',
      col1Title: 'Payment Signal',
      col1Value: 'Unregistered Merchant VPA',
      col1Note: heuristics[0] ?? 'Fake UPI handle detected',
      col1Dot: 'bg-rose-400',
      col2Title: 'Redirect Destination',
      col2Value: 'Out-of-band Payment Lock',
      col2Note: heuristics[1] ?? 'NPCI unverified entity',
      col2Dot: 'bg-amber-400',
      col3Title: 'Payload Extracted',
      col3Value: 'Financial Coercion Script',
      col3Note: 'Attempts unauthorized debit / QR',
      col3Dot: 'bg-rose-400',
    };
  }

  if (flags.includes('High-Risk Domain')) {
    return {
      riskScore: score,
      status,
      verdictTitle:
        status === 'Critical'
          ? 'CRITICAL VERDICT: MALICIOUS PHISHING ATTEMPT'
          : 'WARNING: SUSPICIOUS DOMAIN OBSERVED',
      flags,
      remediation: 'Automated Remediation: DNS sinkhole broadcasted to 14 SOC tenants.',
      col1Title: 'Target Mimicry',
      col1Value: 'Telegram Desktop SSO',
      col1Note: 'Homoglyph attack detected',
      col1Dot: 'bg-rose-400',
      col2Title: 'Domain Age & ASN',
      col2Value: '38 Hours (Bulletproof ASN)',
      col2Note: heuristics[0] ?? 'Cloudflare proxy bypass attempt',
      col2Dot: 'bg-amber-400',
      col3Title: 'Payload Intention',
      col3Value: '2FA / Session Hijacking',
      col3Note: 'Embedded reverse proxy script',
      col3Dot: 'bg-rose-400',
    };
  }

  // Keywords only triggered
  return {
    riskScore: score,
    status,
    verdictTitle:
      status === 'Critical'
        ? 'CRITICAL: HIGH-PRESSURE SOCIAL ENGINEERING'
        : 'WARNING: DECEPTIVE LINGUISTIC PATTERNS',
    flags,
    remediation: 'Automated Advisory: Message quarantined in queue. Interception warning dispatched.',
    col1Title: 'Linguistic Classifier',
    col1Value: 'Urgency & Pressure Coercion',
    col1Note: heuristics[0] ?? 'Psychological coercion detected',
    col1Dot: 'bg-rose-400',
    col2Title: 'Channel Origin',
    col2Value: 'Unverified External Source',
    col2Note: 'Direct message payload flagged',
    col2Dot: 'bg-amber-400',
    col3Title: 'Payload Assessment',
    col3Value: 'Account Diversion / Extortion',
    col3Note: 'Potential executive / VIP mimicry',
    col3Dot: 'bg-rose-400',
  };
}

const SAMPLES = [
  {
    label: 'Telegram Credential Harvester',
    payload: 'https://support-telegram-verify-auth.xyz/recovery?id=829012',
    dotClr: 'bg-rose-500',
  },
  {
    label: 'SMS Smishing (Bank Alert)',
    payload: 'URGENT: Your Wells Fargo account has been locked. Verify at bit.ly/wf-sec-9921',
    dotClr: 'bg-amber-500',
  },
  {
    label: 'Benign (Stripe.com)',
    payload: 'https://stripe.com/docs/security',
    dotClr: 'bg-emerald-500',
  },
];

// ─── Mock Raw Technical Evidence ────────────────────────────────────────────
const MOCK_EVIDENCE = {
  rawHeaders: {
    'X-Forwarded-For': '185.220.101.47',
    'X-Real-IP': '185.220.101.47',
    'Server': 'nginx/1.18.0 (Ubuntu)',
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store, no-cache',
    'Strict-Transport-Security': 'MISSING',
    'X-Frame-Options': 'MISSING',
    'X-Content-Type-Options': 'MISSING',
  },
  pHash: '8f9a2b4c1d7e3f06a5b8c9d2e4f1a703',
  originASN: 'AS209588 — Flyservers S.A. (Bulletproof Hosting)',
  dkimStatus: 'FAIL — No DKIM record found. SPF: ~all (SoftFail)',
};

const EVIDENCE_JSON = JSON.stringify(
  {
    raw_headers: MOCK_EVIDENCE.rawHeaders,
    perceptual_hash: {
      matched_phash: MOCK_EVIDENCE.pHash,
      similarity_score: '97.4% match to known phishing kit #TG-4829',
    },
    network: {
      origin_asn: MOCK_EVIDENCE.originASN,
      ip_reputation: 'BLACKLISTED — Tor exit node (Ahmia index)',
      geo: 'NL → proxy chain → US-VA',
    },
    email_auth: {
      dkim_status: MOCK_EVIDENCE.dkimStatus,
      dmarc: 'p=none — No enforcement policy',
    },
  },
  null,
  2
);

// ─── Tech Evidence Panel Component ───────────────────────────────────────────
function TechEvidencePanel() {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="mt-3 rounded-lg border border-slate-800 overflow-hidden">
      <button
        type="button"
        onClick={() => setIsOpen(prev => !prev)}
        className="w-full flex items-center justify-between px-3 py-2.5 bg-slate-900/70 hover:bg-slate-800/80 transition-colors text-[11px] font-mono-code text-slate-400 hover:text-slate-300 group cursor-pointer"
        aria-expanded={isOpen}
        id="tech-evidence-toggle"
      >
        <span className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
          <span>View Raw Technical Evidence (Headers, pHash, IP)</span>
        </span>
        <motion.span
          animate={{ rotate: isOpen ? 180 : 0 }}
          transition={{ duration: 0.25, ease: 'easeInOut' }}
        >
          <ChevronDown className="w-3.5 h-3.5 text-slate-500 group-hover:text-slate-400" />
        </motion.span>
      </button>

      <AnimatePresence initial={false}>
        {isOpen && (
          <motion.div
            key="evidence-panel"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] }}
            style={{ overflow: 'hidden' }}
          >
            <div className="bg-[#050B14] p-4 font-mono text-xs text-slate-400 rounded-b-md border-t border-slate-800">
              <div className="flex items-center gap-1.5 mb-3 pb-2 border-b border-slate-800/80">
                <span className="w-2 h-2 rounded-full bg-rose-500/80" />
                <span className="w-2 h-2 rounded-full bg-amber-500/80" />
                <span className="w-2 h-2 rounded-full bg-emerald-500/80" />
                <span className="ml-2 text-[10px] text-slate-600 tracking-wider uppercase">
                  phishlens-engine // raw-dump v4.2 // output: forensic_trace.json
                </span>
              </div>
              <pre className="whitespace-pre-wrap break-all leading-relaxed text-[11px]">
                <span className="text-slate-500">{'// FORENSIC TRACE — DO NOT SHARE\n'}</span>
                {EVIDENCE_JSON.split('\n').map((line, i) => {
                  const keyMatch = line.match(/^(\s*)("[\w_-]+")(: )(.*)/);
                  if (keyMatch) {
                    const [, indent, key, colon, val] = keyMatch;
                    const isStr = val.startsWith('"');
                    const vc =
                      val.includes('MISSING') || val.includes('FAIL') || val.includes('BLACKLISTED')
                        ? 'text-rose-400'
                        : val.includes('97.4%') || val.includes('AS209')
                        ? 'text-amber-400'
                        : isStr
                        ? 'text-emerald-300'
                        : 'text-blue-300';
                    return (
                      <span key={i}>
                        {indent}
                        <span className="text-blue-400">{key}</span>
                        <span className="text-slate-500">{colon}</span>
                        <span className={vc}>{val}</span>
                        {'\n'}
                      </span>
                    );
                  }
                  return (
                    <span key={i} className="text-slate-600">
                      {line}
                      {'\n'}
                    </span>
                  );
                })}
              </pre>
              <div className="mt-3 pt-2.5 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-600">
                <span>Generated: {new Date().toISOString()} · Session ephemeral</span>
                <span className="text-blue-500/70 hover:text-blue-400 cursor-pointer transition-colors">
                  Export JSON ↗
                </span>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─── Report Scammer Modal ─────────────────────────────────────────────────────
const THREAT_TYPES = ['URL / Website', 'Phone / WhatsApp', 'Fake UPI / QR Code', 'Email / Phishing Mail'];

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
}

function ReportScammerModal({ isOpen, onClose }: ReportModalProps) {
  const [threatType, setThreatType] = useState(THREAT_TYPES[0]);
  const [indicator, setIndicator] = useState('');
  const [details, setDetails] = useState('');
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!indicator.trim()) return;
    setSubmitted(true);
    setTimeout(() => {
      setSubmitted(false);
      setIndicator('');
      setDetails('');
      setThreatType(THREAT_TYPES[0]);
      onClose();
    }, 2000);
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div
            key="modal-backdrop"
            className="fixed inset-0 z-50 backdrop-blur-sm bg-slate-950/80"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            onClick={onClose}
            aria-hidden="true"
          />
          <motion.div
            key="modal-card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="report-modal-title"
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            initial={{ opacity: 0, scale: 0.92, y: 16 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.94, y: 10 }}
            transition={{ duration: 0.28, ease: [0.34, 1.26, 0.64, 1] }}
          >
            <div
              className="relative w-full max-w-lg bg-[#0B1120] border border-slate-800 rounded-2xl shadow-2xl shadow-black/60 overflow-hidden"
              onClick={e => e.stopPropagation()}
            >
              <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-rose-500/60 to-transparent" />
              <div className="flex items-start justify-between p-6 pb-4 border-b border-slate-800/80">
                <div>
                  <div className="flex items-center gap-2.5 mb-1">
                    <div className="p-1.5 rounded-lg bg-rose-500/10 border border-rose-500/20">
                      <Flag className="w-4 h-4 text-rose-400" />
                    </div>
                    <h2
                      id="report-modal-title"
                      className="text-base font-semibold text-white tracking-tight"
                    >
                      Report Phishing Threat
                    </h2>
                  </div>
                  <p className="text-xs text-slate-500 font-mono-code leading-relaxed">
                    Submit to PhishLens threat intelligence registry. Reviewed by our SOC within 4h.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={onClose}
                  id="report-modal-close"
                  className="p-1.5 rounded-lg text-slate-500 hover:text-white hover:bg-slate-800 transition-all cursor-pointer"
                  aria-label="Close modal"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-6">
                <AnimatePresence mode="wait">
                  {submitted ? (
                    <motion.div
                      key="success"
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      exit={{ opacity: 0 }}
                      className="flex flex-col items-center justify-center py-10 gap-4 text-center"
                    >
                      <div className="w-12 h-12 rounded-full bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center">
                        <CheckCircle className="w-6 h-6 text-emerald-400" />
                      </div>
                      <div>
                        <p className="text-white font-semibold mb-1">Report Submitted</p>
                        <p className="text-xs text-slate-500 font-mono-code">
                          Threat logged to intelligence registry. TID:{' '}
                          <span className="text-blue-400">
                            PLR-{Math.floor(Math.random() * 90000) + 10000}
                          </span>
                        </p>
                      </div>
                    </motion.div>
                  ) : (
                    <motion.form
                      key="form"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      onSubmit={handleSubmit}
                      className="space-y-4"
                    >
                      <div>
                        <label
                          htmlFor="threat-type-select"
                          className="block text-[11px] font-mono-code uppercase tracking-wider text-slate-400 mb-1.5"
                        >
                          Type of Threat
                        </label>
                        <select
                          id="threat-type-select"
                          value={threatType}
                          onChange={e => setThreatType(e.target.value)}
                          className="w-full bg-slate-900/80 border border-slate-700/80 rounded-lg px-3 py-2.5 text-sm text-slate-200 font-mono-code focus:outline-none focus:ring-1 focus:ring-rose-500/50 focus:border-rose-500/50 transition-all cursor-pointer"
                        >
                          {THREAT_TYPES.map(t => (
                            <option key={t} value={t} className="bg-slate-900">
                              {t}
                            </option>
                          ))}
                        </select>
                      </div>

                      <div>
                        <label
                          htmlFor="threat-indicator-input"
                          className="block text-[11px] font-mono-code uppercase tracking-wider text-slate-400 mb-1.5"
                        >
                          Threat Indicator
                        </label>
                        <input
                          id="threat-indicator-input"
                          type="text"
                          value={indicator}
                          onChange={e => setIndicator(e.target.value)}
                          placeholder="e.g. https://evil-phish.xyz or +91-9876543210"
                          required
                          className="w-full bg-slate-900/80 border border-slate-700/80 rounded-lg px-3 py-2.5 text-sm text-slate-200 font-mono-code placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-rose-500/50 focus:border-rose-500/50 transition-all"
                        />
                      </div>

                      <div>
                        <label
                          htmlFor="threat-details-textarea"
                          className="block text-[11px] font-mono-code uppercase tracking-wider text-slate-400 mb-1.5"
                        >
                          Additional Details
                        </label>
                        <textarea
                          id="threat-details-textarea"
                          value={details}
                          onChange={e => setDetails(e.target.value)}
                          placeholder="Describe the scam — how you received it, what it claimed, any lured action..."
                          rows={4}
                          className="w-full bg-slate-900/80 border border-slate-700/80 rounded-lg px-3 py-2.5 text-sm text-slate-200 font-mono-code placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-rose-500/50 focus:border-rose-500/50 transition-all resize-none leading-relaxed"
                        />
                      </div>

                      <div className="flex items-center gap-3 pt-1">
                        <button
                          type="button"
                          onClick={onClose}
                          id="report-modal-cancel-btn"
                          className="flex-1 px-4 py-2.5 rounded-lg border border-slate-700 text-slate-400 hover:text-white hover:border-slate-600 hover:bg-slate-800/60 text-sm font-medium transition-all cursor-pointer"
                        >
                          Cancel
                        </button>
                        <button
                          type="submit"
                          id="report-modal-submit-btn"
                          disabled={!indicator.trim()}
                          className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold transition-all shadow-lg shadow-rose-900/40 active:scale-95 cursor-pointer"
                        >
                          <Send className="w-4 h-4" />
                          Submit Report to Database
                        </button>
                      </div>

                      <p className="text-[10px] text-slate-600 font-mono-code text-center leading-relaxed">
                        Reports are anonymized. By submitting you agree to our{' '}
                        <span className="text-slate-500 hover:text-slate-400 cursor-pointer transition-colors underline underline-offset-2">
                          Threat Data Policy
                        </span>
                        .
                      </p>
                    </motion.form>
                  )}
                </AnimatePresence>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}

// ─── Main ScannerSection ──────────────────────────────────────────────────────
export function ScannerSection() {
  // 1. State Management (existing — preserved)
  const [inputText, setInputText] = useState(
    'https://support-telegram-verify-auth.xyz/recovery?id=829012'
  );
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ThreatAnalysis | null>(() =>
    analyzeThreat('https://support-telegram-verify-auth.xyz/recovery?id=829012')
  );

  // 2. Report Modal state
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);

  // 2. The handleScan Function
  const handleScan = (customText?: string) => {
    const textToAnalyze = customText !== undefined ? customText : inputText;
    if (!textToAnalyze.trim()) return;

    setIsScanning(true);

    // Simulate network call / API latency (1.6s)
    setTimeout(() => {
      const result = analyzeThreat(textToAnalyze);
      setScanResult(result);
      setIsScanning(false);
    }, 1600);
  };

  const handleSampleClick = (samplePayload: string) => {
    setInputText(samplePayload);
    handleScan(samplePayload);
  };

  return (
    <>
      {/* Report Scammer Modal */}
      <ReportScammerModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
      />

      <section
        id="scanner"
        className="relative bg-[#0B1120] text-white py-14 sm:py-20 overflow-hidden border-y border-slate-800"
    >
      {/* Subtle background grid + animated scanline overlay inside terminal container */}
      <div
        className="absolute inset-0 bg-[linear-gradient(to_right,#ffffff05_1px,transparent_1px),linear-gradient(to_bottom,#ffffff05_1px,transparent_1px)] bg-[size:32px_32px] pointer-events-none opacity-40"
        aria-hidden="true"
      />
      <div className="absolute inset-0 pointer-events-none overflow-hidden" aria-hidden="true">
        <div className="w-full h-36 bg-gradient-to-b from-transparent via-blue-500/15 to-transparent animate-scanline" />
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6">
        
        {/* Terminal Header Metadata */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
          <div className="flex items-center gap-2.5">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-80" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
            </span>
            <span className="font-mono-code text-xs uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <span>ENGINE ONLINE</span>
              <span className="text-slate-600">//</span>
              <span className="text-slate-400">NEURAL HEURISTIC v4.2</span>
            </span>
          </div>

          <div className="flex items-center gap-3 text-xs text-slate-400 font-mono-code">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700/60 text-slate-300">
              <Lock className="w-3 h-3 text-blue-400" />
              <span>256-bit Ephemeral Tunnel</span>
            </span>
            <span className="hidden sm:inline text-slate-500">Node: us-east-ciso</span>

            {/* Report Phishing button — top-right header */}
            <button
              type="button"
              id="open-report-modal-btn"
              onClick={() => setIsReportModalOpen(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 hover:bg-rose-500/20 hover:border-rose-500/50 hover:text-rose-300 transition-all text-[11px] font-medium cursor-pointer active:scale-95"
            >
              <Flag className="w-3 h-3" />
              <span>Report Phishing</span>
            </button>
          </div>
        </div>

        {/* 2-COLUMN BALANCED SPLIT LAYOUT: SCANNER CONSOLE (LEFT) + LIVE THREAT RADAR HUD (RIGHT) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          
          {/* LEFT COLUMN (cols 1-7): INTERACTIVE SCANNER CONSOLE */}
          <div className="lg:col-span-7 flex flex-col justify-start">
            <div className="scanner-glow relative rounded-2xl p-1 bg-gradient-to-b from-slate-700/50 via-slate-800/20 to-slate-900/60 shadow-2xl transition-all">
              <div className="rounded-[14px] bg-slate-950/95 border border-slate-700/70 p-4 sm:p-6 backdrop-blur-md relative overflow-hidden">
                
                <label
                  htmlFor="payload-input"
                  className="block text-xs font-mono-code uppercase text-slate-400 mb-2 flex items-center justify-between"
                >
                  <span>Inspect suspicious URI, webhook, raw headers or message:</span>
                  <span className="text-blue-400 text-[11px] lowercase tracking-normal flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
                    autodetect encoding
                  </span>
                </label>

                {/* Pill Input Box */}
                <div className="scan-pill rounded-xl p-2 sm:p-2.5 flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
                  <div className="flex items-center pl-2 text-slate-400">
                    <Terminal className="w-5 h-5 text-blue-400" />
                  </div>
                  <input
                    id="payload-input"
                    type="text"
                    value={inputText}
                    onChange={e => setInputText(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        handleScan();
                      }
                    }}
                    placeholder="Paste suspicious link, SMS payload, or email body..."
                    className="w-full bg-transparent text-slate-100 placeholder-slate-500 font-mono-code text-xs sm:text-sm px-2 py-1.5 focus:outline-none selection:bg-blue-600"
                  />
                  <button
                    id="scan-trigger-btn"
                    type="button"
                    onClick={() => handleScan()}
                    disabled={isScanning || !inputText.trim()}
                    className={`btn-lift relative overflow-hidden inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs sm:text-sm transition-all shadow-md active:scale-95 focus:outline-none focus:ring-2 focus:ring-blue-400 shrink-0 cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed ${
                      isScanning ? 'opacity-75 cursor-wait' : ''
                    }`}
                  >
                    {isScanning ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <ScanLine className="w-4 h-4" />
                    )}
                    <span id="scan-btn-text">{isScanning ? 'Scanning...' : 'Scan Now'}</span>
                  </button>
                </div>

                {/* Pre-populated Quick Samples for One-click Test */}
                <div className="mt-3.5 flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
                  <span className="text-slate-500 font-mono-code">Try sample:</span>
                  {SAMPLES.map(sample => (
                    <button
                      key={sample.label}
                      type="button"
                      onClick={() => handleSampleClick(sample.payload)}
                      disabled={isScanning}
                      className="sample-chip group px-2.5 py-1 rounded bg-slate-900/90 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white transition-all duration-150 flex items-center gap-1.5 active:scale-95 cursor-pointer disabled:opacity-50"
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${sample.dotClr} group-hover:scale-125 transition-transform`} />
                      <span>{sample.label}</span>
                    </button>
                  ))}

                  {/* Inline Report Scammer CTA */}
                  <button
                    type="button"
                    id="report-cta-inline-btn"
                    onClick={() => setIsReportModalOpen(true)}
                    className="ml-auto group px-2.5 py-1 rounded bg-rose-500/8 hover:bg-rose-500/15 border border-rose-500/25 hover:border-rose-500/40 text-rose-400 hover:text-rose-300 transition-all duration-150 flex items-center gap-1.5 active:scale-95 cursor-pointer"
                  >
                    <Flag className="w-3 h-3" />
                    <span>Report Phishing Link / Number</span>
                  </button>
                </div>

                {/* Scanning Progress Bar Animation (Shown while isScanning) */}
                {isScanning && (
                  <div className="mt-5 pt-4 border-t border-slate-800/80 font-mono-code text-xs animate-in fade-in duration-200">
                    <div className="flex items-center justify-between text-blue-400 mb-2">
                      <span className="flex items-center gap-2">
                        <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
                        <span>Decompiling payload &amp; executing Chromium sandbox...</span>
                      </span>
                      <span className="text-[11px] text-slate-400">14ms</span>
                    </div>
                    <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden border border-slate-800">
                      <div className="h-full bg-gradient-to-r from-blue-600 via-indigo-500 to-blue-400 rounded-full w-4/5 animate-pulse" />
                    </div>
                    <div className="mt-2.5 text-[11px] text-slate-500 flex justify-between">
                      <span>DOM snapshot · Perceptual hash · TLS verify</span>
                      <span className="text-blue-500">Heuristic Neural Sweep Active</span>
                    </div>
                  </div>
                )}

                {/* LIVE DIAGNOSTIC OUTPUT CARD (Dynamically reads from scanResult) */}
                {!isScanning && scanResult && (
                  <div
                    id="scan-result-panel"
                    className="mt-5 pt-4 border-t border-slate-800/80 font-mono-code text-xs transition-all duration-300"
                  >
                    <div className="flex items-center justify-between text-slate-400 mb-2.5">
                      <span
                        className={`flex items-center gap-1.5 font-semibold tracking-wide ${
                          scanResult.status === 'Safe'
                            ? 'text-emerald-400'
                            : scanResult.status === 'Critical'
                            ? 'text-rose-400'
                            : 'text-amber-400'
                        }`}
                      >
                        {scanResult.status === 'Safe' ? (
                          <CheckCircle className="w-4 h-4 text-emerald-400" />
                        ) : scanResult.status === 'Critical' ? (
                          <AlertOctagon className="w-4 h-4 text-rose-500" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-amber-500" />
                        )}
                        <span>{scanResult.verdictTitle}</span>
                      </span>
                      <span
                        className={`text-[11px] px-2 py-0.5 rounded font-semibold border ${
                          scanResult.status === 'Safe'
                            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-300'
                            : scanResult.status === 'Critical'
                            ? 'bg-rose-500/10 border-rose-500/20 text-rose-300'
                            : 'bg-amber-500/10 border-amber-500/20 text-amber-300'
                        }`}
                      >
                        Risk Score: {scanResult.riskScore.toFixed(1)} / 100
                      </span>
                    </div>

                    {/* Flags Chip Row */}
                    {scanResult.flags.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1.5 mb-3">
                        <span className="text-[10px] text-slate-500 uppercase">Flags:</span>
                        {scanResult.flags.map(flag => (
                          <span
                            key={flag}
                            className={`text-[10px] px-1.5 py-0.5 rounded font-mono-code ${
                              scanResult.status === 'Safe'
                                ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                                : scanResult.status === 'Critical'
                                ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                                : 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                            }`}
                          >
                            {flag}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Breakdown grid */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 mt-3 text-[11px]">
                      <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-colors">
                        <div className="text-slate-400 mb-1">{scanResult.col1Title}</div>
                        <div className="text-slate-200 font-medium flex items-center gap-1.5">
                          <span className={`w-1.5 h-1.5 rounded-full ${scanResult.col1Dot} animate-pulse`} />
                          <span className="truncate">{scanResult.col1Value}</span>
                        </div>
                        <div className="text-slate-400 text-[10px] mt-0.5 truncate">
                          {scanResult.col1Note}
                        </div>
                      </div>

                      <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-colors">
                        <div className="text-slate-400 mb-1">{scanResult.col2Title}</div>
                        <div className="text-slate-200 font-medium flex items-center gap-1.5">
                          <span className={`w-1.5 h-1.5 rounded-full ${scanResult.col2Dot}`} />
                          <span className="truncate">{scanResult.col2Value}</span>
                        </div>
                        <div className="text-slate-400 text-[10px] mt-0.5 truncate">
                          {scanResult.col2Note}
                        </div>
                      </div>

                      <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-colors">
                        <div className="text-slate-400 mb-1">{scanResult.col3Title}</div>
                        <div className="text-slate-200 font-medium flex items-center gap-1.5">
                          <span className={`w-1.5 h-1.5 rounded-full ${scanResult.col3Dot}`} />
                          <span className="truncate">{scanResult.col3Value}</span>
                        </div>
                        <div className="text-slate-400 text-[10px] mt-0.5 truncate">
                          {scanResult.col3Note}
                        </div>
                      </div>
                    </div>

                    {/* Expandable Tech Evidence Panel (Suspicious / Critical only) */}
                    {(scanResult.status === 'Suspicious' || scanResult.status === 'Critical') && (
                      <TechEvidencePanel key={scanResult.verdictTitle} />
                    )}

                    {/* Remediation line */}
                    <div className="mt-3.5 flex items-center justify-between text-[11px] text-slate-400 bg-slate-900/50 px-3 py-2 rounded border border-slate-800/80">
                      <span className="truncate flex items-center gap-2">
                        <span className="relative flex h-2 w-2 shrink-0">
                          <span
                            className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                              scanResult.status === 'Safe' ? 'bg-emerald-400' : 'bg-rose-400'
                            }`}
                          />
                          <span
                            className={`relative inline-flex rounded-full h-2 w-2 ${
                              scanResult.status === 'Safe' ? 'bg-emerald-500' : 'bg-rose-500'
                            }`}
                          />
                        </span>
                        {scanResult.remediation}
                      </span>
                      <span className="text-blue-400 hover:text-blue-300 hover:underline cursor-pointer flex items-center gap-1 shrink-0 ml-2">
                        <span>Export IOC</span>
                        <ExternalLink className="w-3 h-3" />
                      </span>
                    </div>
                  </div>
                )}

              </div>
            </div>

            <div className="mt-3 text-center sm:text-left">
              <p className="text-[11px] text-slate-500 font-mono-code">
                Zero payload telemetry is stored. Full RFC 8805 compliant ephemeral processing.
              </p>
            </div>
          </div>

          {/* RIGHT COLUMN (cols 8-12): LIVE ATMOSPHERIC THREAT RADAR HUD */}
          <div className="lg:col-span-5 flex flex-col items-center justify-center">
            <div className="relative w-full max-w-[420px] rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950/95 border border-slate-800/90 p-5 shadow-2xl backdrop-blur-md overflow-hidden group">
              
              {/* HUD Top Header */}
              <div className="flex items-center justify-between text-xs font-mono-code mb-3 border-b border-slate-800/80 pb-2.5">
                <div className="flex items-center gap-2">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-80" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500" />
                  </span>
                  <span className="text-blue-300 font-medium tracking-wider">LIVE TELEMETRY RADAR</span>
                </div>
                <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-blue-950/60 border border-blue-800/40 text-[10px] text-blue-300">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
                  <span>360° SWEEP</span>
                </div>
              </div>

              {/* Atmospheric Fade Form Radar Display Container */}
              <div className="relative w-full aspect-square max-w-[340px] mx-auto flex items-center justify-center my-2">
                {/* Atmospheric Radial Vignette / Fade Mask */}
                <div className="absolute inset-0 rounded-full radar-fade-stage pointer-events-none flex items-center justify-center overflow-hidden">
                  {/* Ambient background grid texture */}
                  <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:16px_16px] opacity-60" />
                  
                  {/* Concentric Radar Range Rings */}
                  <div className="absolute w-[94%] h-[94%] rounded-full border border-blue-500/15" />
                  <div className="absolute w-[72%] h-[72%] rounded-full border border-blue-500/25 border-dashed" />
                  <div className="absolute w-[48%] h-[48%] rounded-full border border-blue-500/35" />
                  <div className="absolute w-[24%] h-[24%] rounded-full border border-blue-500/45" />

                  {/* Radar Crosshairs & Diagonals */}
                  <div className="absolute w-full h-[1px] bg-gradient-to-r from-transparent via-blue-500/30 to-transparent" />
                  <div className="absolute h-full w-[1px] bg-gradient-to-b from-transparent via-blue-500/30 to-transparent" />
                  <div className="absolute w-full h-[1px] rotate-45 bg-gradient-to-r from-transparent via-blue-500/15 to-transparent" />
                  <div className="absolute w-full h-[1px] -rotate-45 bg-gradient-to-r from-transparent via-blue-500/15 to-transparent" />

                  {/* Continuous Ambient Radar Pulse Ring */}
                  <div className="absolute w-[60%] h-[60%] rounded-full border border-blue-400/40 animate-radar-pulse pointer-events-none" />

                  {/* Rotating 360-degree Conic Radar Sweep Beam */}
                  <div
                    className="absolute inset-0 rounded-full animate-radar-sweep pointer-events-none"
                    style={{
                      background:
                        'conic-gradient(from 0deg, rgba(37, 99, 235, 0.42) 0deg, rgba(37, 99, 235, 0.08) 45deg, transparent 90deg, transparent 360deg)',
                    }}
                  />

                  {/* Center Radar Sensor Hub */}
                  <div className="absolute z-10 w-4 h-4 rounded-full bg-blue-600 border-2 border-white shadow-lg shadow-blue-500/60 flex items-center justify-center">
                    <div className="w-1.5 h-1.5 rounded-full bg-white animate-ping" />
                  </div>

                  {/* Live Radar Nodes */}
                  <div className="absolute inset-0 pointer-events-none">
                    {/* Safe Node */}
                    <div className="absolute flex items-center gap-1.5" style={{ top: '28%', left: '66%' }}>
                      <div className="relative flex items-center justify-center">
                        <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-sm shadow-emerald-400" />
                        <span className="absolute w-5 h-5 rounded-full bg-emerald-400/30 animate-ping" />
                      </div>
                      <span className="px-1.5 py-0.5 rounded bg-slate-900/90 border border-emerald-500/40 text-[9px] font-mono-code text-emerald-300 shadow">
                        Verified TLS
                      </span>
                    </div>

                    {/* Threat Node */}
                    <div className="absolute flex items-center gap-1.5" style={{ top: '64%', left: '24%' }}>
                      <div className="relative flex items-center justify-center">
                        <span className="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-sm shadow-rose-500" />
                        <span className="absolute w-6 h-6 rounded-full border border-rose-500/70 threat-ripple" />
                      </div>
                      <span className="px-1.5 py-0.5 rounded bg-rose-950/90 border border-rose-500/50 text-[9px] font-mono-code text-rose-300 shadow">
                        Threat Blocked
                      </span>
                    </div>

                    {/* Benign Node */}
                    <div className="absolute flex items-center gap-1.5" style={{ top: '76%', left: '70%' }}>
                      <div className="relative flex items-center justify-center">
                        <span className="w-2 h-2 rounded-full bg-blue-400 shadow-sm shadow-blue-400" />
                      </div>
                      <span className="px-1.5 py-0.5 rounded bg-slate-900/90 border border-blue-500/40 text-[9px] font-mono-code text-blue-300 shadow">
                        Clean Mail
                      </span>
                    </div>
                  </div>

                </div>
              </div>

              {/* HUD Live Counter & Ticker Footer */}
              <div className="mt-2 pt-3 border-t border-slate-800/80 flex items-center justify-between font-mono-code text-[11px]">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Threats Neutralized:</span>
                  <span className="text-rose-400 font-bold tracking-tight bg-rose-950/60 border border-rose-800/40 px-2 py-0.5 rounded">
                    1,842
                  </span>
                </div>
                <div className="flex items-center gap-1.5 text-slate-400 text-[10px]">
                  <Radio className="w-3 h-3 text-emerald-400" />
                  <span>Grid Synchronized</span>
                </div>
              </div>

              {/* Geographic Nodes Status Strip */}
              <div className="mt-2 text-center">
                <span className="text-[10px] text-slate-500 font-mono-code">
                  Live Heuristic Telemetry: Telegram · WhatsApp · M365 · Slack
                </span>
              </div>

            </div>
          </div>

        </div>

      </div>
    </section>
    </>
  );
}
