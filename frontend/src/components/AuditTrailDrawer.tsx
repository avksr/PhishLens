// ────────────────────────────────────────────────────────────
//  PhishLens  ·  AuditTrailDrawer Component  (Day 4 Revision)
//  3 vector cards + synthesis + Live Audit Feed drawer
// ────────────────────────────────────────────────────────────

import { useState, useEffect } from 'react';
import type { AuditTrail, UrlAgentResult, SenderAgentResult, IntentAgentResult, SynthesisBreakdown, AuditLogEntry, RiskTier, Language } from '../lib/types';
import { fetchRecentAuditLogs } from '../lib/api';

// ── Helpers ───────────────────────────────────────────────────

function scoreColor(n: number): string {
  if (n <= 24) return '#00E676';
  if (n <= 49) return '#FFB800';
  if (n <= 77) return '#FF6B00';
  return '#FF3366';
}

function tierColor(tier: RiskTier): string {
  switch (tier) {
    case 'SAFE':      return '#00E676';
    case 'CAUTION':   return '#FFB800';
    case 'HIGH_RISK': return '#FF6B00';
    case 'CRITICAL':  return '#FF3366';
  }
}

function StatusBadge({ status }: { status: 'SUCCESS' | 'SKIPPED' | 'ERROR' }) {
  const cfg = {
    SUCCESS: { bg: 'rgba(0,230,118,0.1)', border: 'rgba(0,230,118,0.3)', color: '#00E676', icon: '✓' },
    SKIPPED: { bg: 'rgba(75,85,104,0.15)', border: '#374151', color: '#94A3B8', icon: '–' },
    ERROR:   { bg: 'rgba(255,51,102,0.1)', border: 'rgba(255,51,102,0.3)', color: '#FF3366', icon: '!' },
  }[status];
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '4px',
      padding: '2px 9px', borderRadius: '12px', fontSize: '10.5px', fontWeight: 700,
      fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.5px',
      background: cfg.bg, border: `1px solid ${cfg.border}`, color: cfg.color,
    }}>
      {cfg.icon} {status}
    </span>
  );
}

function ScorePill({ score }: { score: number }) {
  const c = scoreColor(score);
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '4px',
      padding: '3px 10px', borderRadius: '12px', fontSize: '13px', fontWeight: 700,
      fontFamily: 'JetBrains Mono, monospace',
      color: c, background: `${c}14`, border: `1px solid ${c}35`,
    }}>
      {score}
      <span style={{ fontSize: '10px', fontWeight: 400, opacity: 0.7 }}>/100</span>
    </span>
  );
}

function FlagList({ flags }: { flags: string[] }) {
  if (!flags.length) return (
    <span style={{ fontSize: '12px', color: '#94A3B8', fontFamily: 'Inter, sans-serif', fontStyle: 'italic' }}>No flags raised</span>
  );
  return (
    <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '5px' }}>
      {flags.map((f, i) => (
        <li key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '7px' }}>
          <span aria-hidden style={{ color: '#FF6B00', fontSize: '12px', marginTop: '1px', flexShrink: 0 }}>⚑</span>
          <span style={{ fontSize: '12px', color: '#CBD5E1', fontFamily: 'JetBrains Mono, monospace', lineHeight: '1.5', wordBreak: 'break-word' }}>{f}</span>
        </li>
      ))}
    </ul>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p style={{
      margin: '14px 0 6px', fontSize: '10px', fontWeight: 700, letterSpacing: '0.9px',
      textTransform: 'uppercase', color: '#94A3B8', fontFamily: 'Inter, sans-serif',
    }}>{children}</p>
  );
}

function AgentCard({ icon, title, agentName, children, accentColor = '#00F0FF', expanded, onToggle }: {
  icon: string; title: string; agentName: string; children: React.ReactNode;
  accentColor?: string; expanded: boolean; onToggle: () => void;
}) {
  return (
    <div style={{
      background: '#0D1623', border: `1px solid ${expanded ? accentColor + '35' : '#1F2937'}`,
      borderRadius: '12px', overflow: 'hidden', transition: 'border-color 0.25s ease',
      boxShadow: expanded ? `0 0 20px ${accentColor}10` : 'none',
    }}>
      {/* Card header — clickable */}
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        className="w-full flex items-center justify-between gap-3 px-3 sm:px-4 py-2.5 sm:py-3.5 mobile-card-padding"
        style={{ background: 'transparent', border: 'none', cursor: 'pointer' }}
      >
        <div className="flex items-center gap-2.5">
          <div style={{
            width: 34, height: 34, borderRadius: '8px', fontSize: '17px',
            background: `${accentColor}12`, border: `1px solid ${accentColor}28`,
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
          }} aria-hidden>{icon}</div>
          <div style={{ textAlign: 'left' }}>
            <p className="text-[13px] sm:text-[13.5px]" style={{ margin: 0, fontWeight: 700, color: '#F1F5F9', fontFamily: 'Plus Jakarta Sans, Inter, sans-serif' }}>
              {title}
            </p>
            <p style={{ margin: 0, fontSize: '10.5px', color: '#94A3B8', fontFamily: 'JetBrains Mono, monospace' }}>
              Agent: {agentName}
            </p>
          </div>
        </div>
        <svg aria-hidden width="16" height="16" viewBox="0 0 16 16"
          style={{ transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.25s ease', flexShrink: 0 }}>
          <path d="M3 6l5 5 5-5" stroke="#94A3B8" strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      </button>

      {/* Collapsible body */}
      <div style={{
        maxHeight: expanded ? '800px' : '0',
        overflow: 'hidden',
        transition: 'max-height 0.35s ease',
      }}>
        <div className="px-3 sm:px-4 pb-3.5 sm:pb-4 mobile-card-padding" style={{ borderTop: '1px solid #1F2937' }}>
          {children}
        </div>
      </div>
    </div>
  );
}

// ── URL Vector Card ───────────────────────────────────────────

function UrlCard({ data, expanded, onToggle }: { data: UrlAgentResult; expanded: boolean; onToggle: () => void }) {
  const c = scoreColor(data.risk_score);
  return (
    <AgentCard icon="🔗" title="URL / Domain Vector" agentName="Atharv" accentColor={c} expanded={expanded} onToggle={onToggle}>
      <div className="flex items-center gap-2.5 mt-3.5 flex-wrap">
        <StatusBadge status={data.status} />
        <ScorePill score={data.risk_score} />
        {data.url_analyzed && (
          <code className="text-[11px] px-2 py-0.5 rounded-md break-all max-w-full" style={{
            background: '#111827', color: '#CBD5E1', fontFamily: 'JetBrains Mono, monospace',
            border: '1px solid #1F2937',
          }}>{data.url_analyzed}</code>
        )}
      </div>

      {data.status !== 'SKIPPED' && (
        <>
          <div className="flex gap-2 mt-3 flex-wrap">
            {data.domain_age_days !== null && (
              <span style={{
                padding: '4px 10px', borderRadius: '8px', fontSize: '11.5px', fontWeight: 600,
                fontFamily: 'JetBrains Mono, monospace',
                background: data.domain_age_days < 30 ? 'rgba(255,107,0,0.12)' : 'rgba(0,230,118,0.1)',
                color: data.domain_age_days < 30 ? '#FF6B00' : '#00E676',
                border: `1px solid ${data.domain_age_days < 30 ? 'rgba(255,107,0,0.3)' : 'rgba(0,230,118,0.25)'}`,
              }}>
                🕒 Domain age: {data.domain_age_days}d
              </span>
            )}
            {data.is_typosquatting && (
              <span style={{
                padding: '4px 10px', borderRadius: '8px', fontSize: '11.5px', fontWeight: 600,
                fontFamily: 'JetBrains Mono, monospace',
                background: 'rgba(255,51,102,0.12)', color: '#FF3366',
                border: '1px solid rgba(255,51,102,0.3)',
              }}>⚠ Typosquatting</span>
            )}
            <span style={{
              padding: '4px 10px', borderRadius: '8px', fontSize: '11.5px', fontWeight: 600,
              fontFamily: 'JetBrains Mono, monospace',
              background: data.tld_reputation === 'HIGH_RISK' ? 'rgba(255,51,102,0.12)' : 'rgba(0,230,118,0.1)',
              color: data.tld_reputation === 'HIGH_RISK' ? '#FF3366' : '#00E676',
              border: `1px solid ${data.tld_reputation === 'HIGH_RISK' ? 'rgba(255,51,102,0.3)' : 'rgba(0,230,118,0.25)'}`,
            }}>TLD: {data.tld_reputation}</span>
          </div>

          {data.target_brand && (
            <><SectionLabel>Impersonated Brand</SectionLabel>
            <p style={{ margin: 0, fontSize: '12.5px', color: '#F1F5F9', fontFamily: 'Inter, sans-serif', fontWeight: 600 }}>{data.target_brand}</p></>
          )}
        </>
      )}

      <SectionLabel>Flags</SectionLabel>
      <FlagList flags={data.flags} />

      <SectionLabel>Agent Analysis</SectionLabel>
      <p style={{ margin: 0, fontSize: '12.5px', color: '#CBD5E1', fontFamily: 'Inter, sans-serif', lineHeight: '1.6' }}>
        {data.details}
      </p>

      <p style={{ margin: '10px 0 0', fontSize: '10px', color: '#94A3B8', fontFamily: 'JetBrains Mono, monospace' }}>
        ⚡ {data.latency_ms}ms
      </p>
    </AgentCard>
  );
}

// ── Sender Vector Card ────────────────────────────────────────

function SenderCard({ data, expanded, onToggle }: { data: SenderAgentResult; expanded: boolean; onToggle: () => void }) {
  const c = scoreColor(data.risk_score);
  const catColor: Record<string, string> = {
    OFFICIAL_TRAI_HEADER: '#00E676', PERSONAL_GSM: '#FF3366',
    INTERNATIONAL: '#FFB800', LOOKALIKE_HEADER: '#FF6B00', UNKNOWN: '#94A3B8',
  };
  return (
    <AgentCard icon="📡" title="Sender Identity Vector" agentName="Avni" accentColor={c} expanded={expanded} onToggle={onToggle}>
      <div className="flex items-center gap-2.5 mt-3.5 flex-wrap">
        <StatusBadge status={data.status} />
        <ScorePill score={data.risk_score} />
        {data.sender_analyzed && (
          <code className="text-[11.5px] px-2 py-0.5 rounded-md" style={{
            background: '#111827', color: '#CBD5E1', fontFamily: 'JetBrains Mono, monospace',
            border: '1px solid #1F2937',
          }}>{data.sender_analyzed}</code>
        )}
      </div>

      {data.status !== 'SKIPPED' && (
        <div className="flex gap-2 mt-3 flex-wrap">
          <span style={{
            padding: '4px 10px', borderRadius: '8px', fontSize: '11px', fontWeight: 700,
            fontFamily: 'JetBrains Mono, monospace',
            color: catColor[data.sender_category] ?? '#CBD5E1',
            background: `${catColor[data.sender_category] ?? '#CBD5E1'}14`,
            border: `1px solid ${catColor[data.sender_category] ?? '#CBD5E1'}35`,
          }}>{data.sender_category.replace(/_/g, ' ')}</span>

          {data.is_spoofed_header && (
            <span style={{
              padding: '4px 10px', borderRadius: '8px', fontSize: '11px', fontWeight: 700,
              fontFamily: 'JetBrains Mono, monospace', color: '#FF3366',
              background: 'rgba(255,51,102,0.12)', border: '1px solid rgba(255,51,102,0.3)',
            }}>⚠ SPOOFED HEADER</span>
          )}

          {data.brand_claimed && (
            <span style={{
              padding: '4px 10px', borderRadius: '8px', fontSize: '11px', fontWeight: 600,
              fontFamily: 'Inter, sans-serif', color: '#CBD5E1',
              background: 'rgba(148,163,184,0.08)', border: '1px solid #1F2937',
            }}>Claims: {data.brand_claimed}</span>
          )}
        </div>
      )}

      <SectionLabel>Flags</SectionLabel>
      <FlagList flags={data.flags} />
      <SectionLabel>Agent Analysis</SectionLabel>
      <p style={{ margin: 0, fontSize: '12.5px', color: '#CBD5E1', fontFamily: 'Inter, sans-serif', lineHeight: '1.6' }}>
        {data.details}
      </p>
      <p style={{ margin: '10px 0 0', fontSize: '10px', color: '#94A3B8', fontFamily: 'JetBrains Mono, monospace' }}>
        ⚡ {data.latency_ms}ms
      </p>
    </AgentCard>
  );
}

// ── Intent Vector Card ────────────────────────────────────────

function IntentCard({ data, expanded, onToggle }: { data: IntentAgentResult; expanded: boolean; onToggle: () => void }) {
  const c = scoreColor(data.risk_score);
  const intentColors: Record<string, string> = {
    BENIGN: '#00E676', SUSPICIOUS: '#FFB800', PANIC_URGENCY: '#FF6B00',
    FINANCIAL_EXTORTION: '#FF3366', LOTTERY_REWARD: '#FF6B00',
    KYC_VERIFICATION: '#FF3366', OTP_HARVEST: '#FF3366',
  };
  const ic = intentColors[data.detected_intent] ?? '#CBD5E1';

  return (
    <AgentCard icon="🧠" title="Psycholinguistic Vector" agentName="Vikas" accentColor={c} expanded={expanded} onToggle={onToggle}>
      <div className="flex items-center gap-2.5 mt-3.5 flex-wrap">
        <StatusBadge status={data.status} />
        <ScorePill score={data.risk_score} />
        <span style={{
          padding: '4px 11px', borderRadius: '8px', fontSize: '11px', fontWeight: 700,
          fontFamily: 'JetBrains Mono, monospace',
          color: ic, background: `${ic}14`, border: `1px solid ${ic}35`,
        }}>{data.detected_intent.replace(/_/g, ' ')}</span>
        <span style={{
          padding: '4px 11px', borderRadius: '8px', fontSize: '11px', fontWeight: 600,
          fontFamily: 'JetBrains Mono, monospace', color: '#CBD5E1',
          background: 'rgba(148,163,184,0.08)', border: '1px solid #1F2937',
        }}>Confidence: {(data.confidence * 100).toFixed(0)}%</span>
      </div>

      {data.manipulation_tactics.length > 0 && (
        <>
          <SectionLabel>Manipulation Tactics</SectionLabel>
          <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '5px' }}>
            {data.manipulation_tactics.map((t, i) => (
              <li key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '7px' }}>
                <span aria-hidden style={{ color: '#FF6B00', fontSize: '13px', flexShrink: 0, marginTop: '1px' }}>◈</span>
                <span style={{ fontSize: '12.5px', color: '#CBD5E1', fontFamily: 'Inter, sans-serif', lineHeight: '1.5' }}>{t}</span>
              </li>
            ))}
          </ul>
        </>
      )}

      <SectionLabel>LLM Reasoning</SectionLabel>
      <blockquote style={{
        margin: 0, padding: '10px 14px', borderLeft: '3px solid #00F0FF',
        borderRadius: '0 8px 8px 0', background: 'rgba(0,240,255,0.04)',
        fontSize: '12.5px', color: '#CBD5E1', fontFamily: 'Inter, sans-serif',
        lineHeight: '1.65', fontStyle: 'italic',
      }}>
        {data.reasoning}
      </blockquote>

      <SectionLabel>Flags</SectionLabel>
      <FlagList flags={data.flags} />
      <p style={{ margin: '10px 0 0', fontSize: '10px', color: '#94A3B8', fontFamily: 'JetBrains Mono, monospace' }}>
        ⚡ {data.latency_ms}ms
      </p>
    </AgentCard>
  );
}

// ── Synthesis Card ────────────────────────────────────────────

function SynthesisCard({ data }: { data: SynthesisBreakdown }) {
  const weights = [
    { label: 'URL', value: data.weights_applied.url_weight, color: '#00F0FF' },
    { label: 'Sender', value: data.weights_applied.sender_weight, color: '#A78BFA' },
    { label: 'Intent', value: data.weights_applied.intent_weight, color: '#34D399' },
  ];

  return (
    <div className="p-4 sm:p-[18px] rounded-xl" style={{
      background: 'linear-gradient(135deg, #0D1623 0%, #111827 100%)',
      border: '1px solid rgba(0,240,255,0.18)',
      boxShadow: '0 0 24px rgba(0,240,255,0.05)',
    }}>
      <div className="flex items-center gap-2.5 mb-4">
        <div style={{
          width: 34, height: 34, borderRadius: '8px', fontSize: '17px',
          background: 'rgba(0,240,255,0.1)', border: '1px solid rgba(0,240,255,0.25)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }} aria-hidden>⚖️</div>
        <div>
          <p style={{ margin: 0, fontSize: '13.5px', fontWeight: 700, color: '#F1F5F9', fontFamily: 'Plus Jakarta Sans, Inter, sans-serif' }}>
            Avika · Synthesis Engine
          </p>
          <p style={{ margin: 0, fontSize: '10.5px', color: '#94A3B8', fontFamily: 'JetBrains Mono, monospace' }}>
            Dynamic weight orchestration
          </p>
        </div>
      </div>

      {/* Weight bars */}
      <div className="flex flex-col sm:flex-row gap-3 mb-4">
        {weights.map(w => (
          <div key={w.label} className="flex-1 min-w-[80px]">
            <div className="flex justify-between mb-1">
              <span style={{ fontSize: '10.5px', color: '#94A3B8', fontFamily: 'JetBrains Mono, monospace' }}>{w.label}</span>
              <span style={{ fontSize: '10.5px', color: w.color, fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>
                {(w.value * 100).toFixed(0)}%
              </span>
            </div>
            <div className="h-[5px] rounded-sm overflow-hidden" style={{ background: '#1F2937' }}>
              <div style={{
                height: '100%', borderRadius: '3px',
                width: `${w.value * 100}%`,
                background: w.color,
                boxShadow: `0 0 8px ${w.color}60`,
                transition: 'width 0.8s ease',
              }} />
            </div>
          </div>
        ))}
      </div>

      {/* Heuristics */}
      {data.heuristics_triggered.length > 0 && (
        <>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: '#94A3B8', fontFamily: 'Inter, sans-serif' }}>
            Heuristics Triggered
          </p>
          <ul className="mb-3.5" style={{ margin: '0 0 14px', padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '5px' }}>
            {data.heuristics_triggered.map((h, i) => (
              <li key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '7px' }}>
                <span aria-hidden style={{ color: '#00F0FF', fontSize: '11px', marginTop: '2px', flexShrink: 0 }}>▸</span>
                <span style={{ fontSize: '12px', color: '#CBD5E1', fontFamily: 'Inter, sans-serif', lineHeight: '1.55' }}>{h}</span>
              </li>
            ))}
          </ul>
        </>
      )}

      {/* Summary */}
      <div className="p-2.5 sm:p-3.5 rounded-lg" style={{
        background: 'rgba(0,240,255,0.05)', border: '1px solid rgba(0,240,255,0.12)',
      }}>
        <p style={{ margin: 0, fontSize: '12.5px', color: '#CBD5E1', fontFamily: 'Inter, sans-serif', lineHeight: '1.6' }}>
          {data.summary_explanation}
        </p>
      </div>
    </div>
  );
}

// ── Time-ago formatter ────────────────────────────────────────

function timeAgo(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

// ── Live Audit Feed Drawer ────────────────────────────────────

export function LiveAuditFeed({ lang }: { lang: Language }) {
  const [open,       setOpen]       = useState(false);
  const [logs,       setLogs]       = useState<AuditLogEntry[]>([]);
  const [loading,    setLoading]    = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  // ── Polling effect: fetch immediately and every 30 seconds ────
  useEffect(() => {
    let isMounted = true;

    const loadLogs = () => {
      fetchRecentAuditLogs(10)
        .then(data => {
          if (isMounted) {
            setLogs(data);
            setLoading(false);
            setFetchError(null);
          }
        })
        .catch(err => {
          if (isMounted) {
            setFetchError(err instanceof Error ? err.message : 'Failed to fetch audit logs');
            setLoading(false);
          }
        });
    };

    loadLogs();
    const intervalId = setInterval(loadLogs, 30_000);

    return () => {
      isMounted = false;
      clearInterval(intervalId);
    };
  }, []);

  const handleToggle = () => {
    setOpen(prev => !prev);
  };

  return (
    <div className="rounded-xl overflow-hidden" style={{
      background: '#0D1623',
      border: `1px solid ${open ? 'rgba(0,240,255,0.25)' : '#1F2937'}`,
      transition: 'border-color 0.25s ease',
    }}>
      {/* Drawer header */}
      <button
        id="audit-feed-toggle"
        type="button"
        onClick={handleToggle}
        aria-expanded={open}
        className="w-full flex items-center justify-between gap-3 px-4 sm:px-5 py-3.5 sm:py-4 cursor-pointer"
        style={{ background: 'transparent', border: 'none' }}
      >
        <div className="flex items-center gap-2.5">
          <div style={{
            width: 36, height: 36, borderRadius: '9px', fontSize: '18px',
            background: 'rgba(0,240,255,0.08)', border: '1px solid rgba(0,240,255,0.2)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
          }} aria-hidden>📋</div>
          <div style={{ textAlign: 'left' }}>
            <div className="flex items-center gap-2 flex-wrap">
              <p className="text-sm sm:text-[15px]" style={{
                margin: 0, fontWeight: 700, color: '#F1F5F9',
                fontFamily: 'Plus Jakarta Sans, Inter, sans-serif',
              }}>
                {lang === 'hi' ? 'हालिया ऑडिट लॉग' : 'Recent Audit Logs'}
              </p>
              <span className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] text-[#94A3B8] font-mono border border-[#1F2937] bg-[#111827]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#00E676] animate-pulse" />
                30s poll
              </span>
            </div>
            <p style={{ margin: 0, fontSize: '11px', color: '#94A3B8', fontFamily: 'Inter, sans-serif' }}>
              {lang === 'hi' ? 'पिछले स्कैन का लाइव फ़ीड (हर 30 सेकंड में ऑटो-रिफ्रेश)' : 'Live feed of previous scans (auto-refreshed every 30s)'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {logs.length > 0 && (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold" style={{
              color: '#00F0FF', background: 'rgba(0,240,255,0.1)',
              border: '1px solid rgba(0,240,255,0.25)',
              fontFamily: 'JetBrains Mono, monospace',
            }}>{logs.length}</span>
          )}
          <svg aria-hidden width="16" height="16" viewBox="0 0 16 16"
            style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.25s ease', flexShrink: 0 }}>
            <path d="M3 6l5 5 5-5" stroke="#94A3B8" strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </div>
      </button>

      {/* Collapsible feed body */}
      <div style={{
        maxHeight: open ? '650px' : '0',
        overflow: 'hidden',
        transition: 'max-height 0.35s ease',
      }}>
        <div className="px-3 sm:px-5 pb-3.5 sm:pb-4 mobile-card-padding" style={{ borderTop: '1px solid #1F2937' }}>
          {/* Loading state */}
          {loading && logs.length === 0 && (
            <div className="flex items-center justify-center gap-2 py-6" role="status" aria-live="polite">
              <svg aria-hidden width="18" height="18" viewBox="0 0 18 18" style={{ animation: 'pl-spin 1s linear infinite' }}>
                <circle cx="9" cy="9" r="7" stroke="rgba(0,240,255,0.2)" strokeWidth="2" fill="none"/>
                <path d="M9 2a7 7 0 0 1 7 7" stroke="#00F0FF" strokeWidth="2" strokeLinecap="round" fill="none"/>
              </svg>
              <span className="text-xs" style={{ color: '#00F0FF', fontFamily: 'JetBrains Mono, monospace' }}>
                {lang === 'hi' ? 'लॉग लोड हो रहे हैं…' : 'Loading audit logs…'}
              </span>
            </div>
          )}

          {/* Error state */}
          {fetchError && (
            <div role="alert" className="py-3 px-3 rounded-lg mt-3 flex items-center gap-2" style={{
              background: 'rgba(255,51,102,0.07)', border: '1px solid rgba(255,51,102,0.25)',
            }}>
              <span aria-hidden>⚠</span>
              <span className="text-xs" style={{ color: '#FF3366', fontFamily: 'JetBrains Mono, monospace' }}>{fetchError}</span>
            </div>
          )}

          {/* Table / List View */}
          {logs.length > 0 && (
            <div className="mt-3 flex flex-col gap-2 max-h-[440px] overflow-y-auto pr-1"
              style={{ scrollbarWidth: 'thin', scrollbarColor: '#1F2937 transparent' }}
            >
              {/* Header row for medium+ screens */}
              <div className="hidden sm:grid grid-cols-[130px_100px_1fr_110px] gap-3 px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-[#94A3B8] border-b border-[#1F2937]"
                style={{ fontFamily: 'JetBrains Mono, monospace' }}
              >
                <span>Scan ID</span>
                <span>Risk Score</span>
                <span>Verdict</span>
                <span className="text-right">Timestamp</span>
              </div>

              {logs.map(log => {
                const tc = tierColor(log.risk_tier);
                const resolvedVerdict = (lang === 'hi' && log.verdict_hi) ? log.verdict_hi : log.verdict;
                return (
                  <div
                    key={log.scan_id}
                    className="grid grid-cols-1 sm:grid-cols-[130px_100px_1fr_110px] items-start sm:items-center gap-2 sm:gap-3 p-3 rounded-lg transition-colors duration-150"
                    style={{
                      background: '#111827', border: '1px solid #1F2937',
                    }}
                  >
                    {/* 1. Scan ID */}
                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className="sm:hidden text-[10px] text-[#94A3B8] font-bold uppercase font-mono">ID:</span>
                      <code
                        className="text-[11px] font-mono text-[#00F0FF] px-1.5 py-0.5 rounded border border-[rgba(0,240,255,0.2)]"
                        style={{ background: 'rgba(0,240,255,0.06)' }}
                        title={log.scan_id}
                      >
                        {log.scan_id.slice(0, 8)}…
                      </code>
                    </div>

                    {/* 2. Risk Score */}
                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className="sm:hidden text-[10px] text-[#94A3B8] font-bold uppercase font-mono">Score:</span>
                      <span
                        className="px-2 py-0.5 rounded-md text-[11px] font-bold font-mono tracking-wider"
                        style={{
                          color: tc,
                          background: `${tc}15`,
                          border: `1px solid ${tc}35`,
                        }}
                      >
                        {log.overall_risk_score} <span className="text-[9px] opacity-75">/100</span>
                      </span>
                    </div>

                    {/* 3. Verdict */}
                    <p
                      className="m-0 text-xs text-[#CBD5E1] font-sans leading-snug line-clamp-2"
                      title={resolvedVerdict}
                    >
                      {resolvedVerdict}
                    </p>

                    {/* 4. Timestamp */}
                    <div className="flex items-center sm:justify-end gap-1.5 text-[10px] text-[#94A3B8] font-mono shrink-0">
                      <span>{timeAgo(log.timestamp)}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Empty state */}
          {!loading && !fetchError && logs.length === 0 && (
            <p className="text-center py-6 text-xs" style={{ color: '#94A3B8', fontFamily: 'Inter, sans-serif' }}>
              {lang === 'hi' ? 'अभी तक कोई ऑडिट लॉग नहीं है' : 'No audit logs yet'}
            </p>
          )}
        </div>
      </div>

      <style>{`
        @keyframes pl-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}

// ── Main Drawer Component ──────────────────────────────────────

export interface AuditTrailDrawerProps {
  auditTrail: AuditTrail | null;
  recommendation?: string;
  processingTimeMs?: number;
  lang?: Language;
}

export function AuditTrailDrawer({ auditTrail, recommendation, processingTimeMs, lang = 'en' }: AuditTrailDrawerProps) {
  // Default: expand all on first load, let user collapse
  const [expanded, setExpanded] = useState({ url: true, sender: true, intent: true });

  const toggle = (key: keyof typeof expanded) =>
    setExpanded(prev => ({ ...prev, [key]: !prev[key] }));

  return (
    <div className="flex flex-col gap-4 w-full max-sm:w-[100vw] mobile-drawer-fit">
      {auditTrail && (
        <>
          {/* Section header */}
          <div className="flex items-center gap-2.5">
            <div style={{
              width: 36, height: 36, borderRadius: '9px', fontSize: '18px',
              background: 'rgba(0,240,255,0.08)', border: '1px solid rgba(0,240,255,0.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }} aria-hidden>🔬</div>
            <div>
              <h3 className="text-base" style={{ margin: 0, fontWeight: 700, color: '#F1F5F9', fontFamily: 'Plus Jakarta Sans, Inter, sans-serif' }}>
                {lang === 'hi' ? 'ऑडिट ट्रेल' : 'Audit Trail'}
              </h3>
              <p style={{ margin: 0, fontSize: '11.5px', color: '#94A3B8', fontFamily: 'Inter, sans-serif' }}>
                {lang === 'hi' ? '3-एजेंट व्याख्यात्मक विश्लेषण' : '3-agent explainability drilldown'}
              </p>
            </div>
          </div>

          {/* Overall processing time */}
          {processingTimeMs != null && (
            <div className="flex items-center gap-2 px-3.5 py-2 rounded-lg" style={{
              background: 'rgba(0,240,255,0.05)', border: '1px solid rgba(0,240,255,0.15)',
            }}>
              <span aria-hidden style={{ fontSize: '14px' }}>⚡</span>
              <span className="text-xs sm:text-[12.5px] font-bold" style={{
                fontFamily: 'JetBrains Mono, monospace', color: '#00F0FF',
              }}>
                {lang === 'hi' ? `कुल प्रोसेसिंग समय: ${processingTimeMs.toFixed(0)}ms` : `Total Processing Time: ${processingTimeMs.toFixed(0)}ms`}
              </span>
            </div>
          )}

          {/* Recommendation banner */}
          {recommendation && (
            <div className="flex gap-2.5 items-start p-3 sm:p-4 rounded-lg" style={{
              background: 'rgba(0,240,255,0.05)', border: '1px solid rgba(0,240,255,0.18)',
            }}>
              <span aria-hidden className="text-base shrink-0 mt-0.5">💡</span>
              <p className="text-[13px] leading-relaxed" style={{ margin: 0, color: '#CBD5E1', fontFamily: 'Inter, sans-serif' }}>
                {recommendation}
              </p>
            </div>
          )}

          {/* 3 Vector cards */}
          <UrlCard    data={auditTrail.url_analysis}    expanded={expanded.url}    onToggle={() => toggle('url')} />
          <SenderCard data={auditTrail.sender_analysis} expanded={expanded.sender} onToggle={() => toggle('sender')} />
          <IntentCard data={auditTrail.intent_analysis} expanded={expanded.intent} onToggle={() => toggle('intent')} />

          {/* Synthesis */}
          <SynthesisCard data={auditTrail.synthesis_breakdown} />
        </>
      )}

      {/* ── Day 4: Live Audit Feed Drawer ──────────────────── */}
      <LiveAuditFeed lang={lang} />
    </div>
  );
}

export default AuditTrailDrawer;
