// ────────────────────────────────────────────────────────────
//  PhishLens  ·  AuditTrailDrawer Component
//  3 vector cards + synthesis card — explainability drilldown
// ────────────────────────────────────────────────────────────

import { useState } from 'react';
import type { AuditTrail, UrlAgentResult, SenderAgentResult, IntentAgentResult, SynthesisBreakdown } from '../lib/types';

// ── Helpers ───────────────────────────────────────────────────

function scoreColor(n: number): string {
  if (n <= 24) return '#00E676';
  if (n <= 49) return '#FFB800';
  if (n <= 77) return '#FF6B00';
  return '#FF3366';
}

function StatusBadge({ status }: { status: 'SUCCESS' | 'SKIPPED' | 'ERROR' }) {
  const cfg = {
    SUCCESS: { bg: 'rgba(0,230,118,0.1)', border: 'rgba(0,230,118,0.3)', color: '#00E676', icon: '✓' },
    SKIPPED: { bg: 'rgba(75,85,104,0.15)', border: '#374151', color: '#6B7280', icon: '–' },
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
    <span style={{ fontSize: '12px', color: '#374151', fontFamily: 'Inter, sans-serif', fontStyle: 'italic' }}>No flags raised</span>
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
      textTransform: 'uppercase', color: '#4B5563', fontFamily: 'Inter, sans-serif',
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
        style={{
          width: '100%', background: 'transparent', border: 'none', cursor: 'pointer',
          padding: '14px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          gap: '12px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: 34, height: 34, borderRadius: '8px', fontSize: '17px',
            background: `${accentColor}12`, border: `1px solid ${accentColor}28`,
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
          }} aria-hidden>{icon}</div>
          <div style={{ textAlign: 'left' }}>
            <p style={{ margin: 0, fontSize: '13.5px', fontWeight: 700, color: '#F1F5F9', fontFamily: 'Plus Jakarta Sans, Inter, sans-serif' }}>
              {title}
            </p>
            <p style={{ margin: 0, fontSize: '10.5px', color: '#4B5563', fontFamily: 'JetBrains Mono, monospace' }}>
              Agent: {agentName}
            </p>
          </div>
        </div>
        <svg aria-hidden width="16" height="16" viewBox="0 0 16 16"
          style={{ transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.25s ease', flexShrink: 0 }}>
          <path d="M3 6l5 5 5-5" stroke="#4B5563" strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      </button>

      {/* Collapsible body */}
      <div style={{
        maxHeight: expanded ? '800px' : '0',
        overflow: 'hidden',
        transition: 'max-height 0.35s ease',
      }}>
        <div style={{ padding: '0 16px 16px', borderTop: '1px solid #1F2937' }}>
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
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '14px', flexWrap: 'wrap' }}>
        <StatusBadge status={data.status} />
        <ScorePill score={data.risk_score} />
        {data.url_analyzed && (
          <code style={{
            fontSize: '11px', padding: '3px 8px', borderRadius: '6px',
            background: '#111827', color: '#94A3B8', fontFamily: 'JetBrains Mono, monospace',
            border: '1px solid #1F2937', wordBreak: 'break-all', maxWidth: '100%',
          }}>{data.url_analyzed}</code>
        )}
      </div>

      {data.status !== 'SKIPPED' && (
        <>
          <div style={{ display: 'flex', gap: '8px', marginTop: '12px', flexWrap: 'wrap' }}>
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
      <p style={{ margin: 0, fontSize: '12.5px', color: '#94A3B8', fontFamily: 'Inter, sans-serif', lineHeight: '1.6' }}>
        {data.details}
      </p>

      <p style={{ margin: '10px 0 0', fontSize: '10px', color: '#374151', fontFamily: 'JetBrains Mono, monospace' }}>
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
    INTERNATIONAL: '#FFB800', LOOKALIKE_HEADER: '#FF6B00', UNKNOWN: '#6B7280',
  };
  return (
    <AgentCard icon="📡" title="Sender Identity Vector" agentName="Avni" accentColor={c} expanded={expanded} onToggle={onToggle}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '14px', flexWrap: 'wrap' }}>
        <StatusBadge status={data.status} />
        <ScorePill score={data.risk_score} />
        {data.sender_analyzed && (
          <code style={{
            fontSize: '11.5px', padding: '3px 9px', borderRadius: '6px',
            background: '#111827', color: '#94A3B8', fontFamily: 'JetBrains Mono, monospace',
            border: '1px solid #1F2937',
          }}>{data.sender_analyzed}</code>
        )}
      </div>

      {data.status !== 'SKIPPED' && (
        <div style={{ display: 'flex', gap: '8px', marginTop: '12px', flexWrap: 'wrap' }}>
          <span style={{
            padding: '4px 10px', borderRadius: '8px', fontSize: '11px', fontWeight: 700,
            fontFamily: 'JetBrains Mono, monospace',
            color: catColor[data.sender_category] ?? '#94A3B8',
            background: `${catColor[data.sender_category] ?? '#94A3B8'}14`,
            border: `1px solid ${catColor[data.sender_category] ?? '#94A3B8'}35`,
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
              fontFamily: 'Inter, sans-serif', color: '#94A3B8',
              background: 'rgba(148,163,184,0.08)', border: '1px solid #1F2937',
            }}>Claims: {data.brand_claimed}</span>
          )}
        </div>
      )}

      <SectionLabel>Flags</SectionLabel>
      <FlagList flags={data.flags} />
      <SectionLabel>Agent Analysis</SectionLabel>
      <p style={{ margin: 0, fontSize: '12.5px', color: '#94A3B8', fontFamily: 'Inter, sans-serif', lineHeight: '1.6' }}>
        {data.details}
      </p>
      <p style={{ margin: '10px 0 0', fontSize: '10px', color: '#374151', fontFamily: 'JetBrains Mono, monospace' }}>
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
  const ic = intentColors[data.detected_intent] ?? '#94A3B8';

  return (
    <AgentCard icon="🧠" title="Psycholinguistic Vector" agentName="Vikas" accentColor={c} expanded={expanded} onToggle={onToggle}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '14px', flexWrap: 'wrap' }}>
        <StatusBadge status={data.status} />
        <ScorePill score={data.risk_score} />
        <span style={{
          padding: '4px 11px', borderRadius: '8px', fontSize: '11px', fontWeight: 700,
          fontFamily: 'JetBrains Mono, monospace',
          color: ic, background: `${ic}14`, border: `1px solid ${ic}35`,
        }}>{data.detected_intent.replace(/_/g, ' ')}</span>
        <span style={{
          padding: '4px 11px', borderRadius: '8px', fontSize: '11px', fontWeight: 600,
          fontFamily: 'JetBrains Mono, monospace', color: '#94A3B8',
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
        fontSize: '12.5px', color: '#94A3B8', fontFamily: 'Inter, sans-serif',
        lineHeight: '1.65', fontStyle: 'italic',
      }}>
        {data.reasoning}
      </blockquote>

      <SectionLabel>Flags</SectionLabel>
      <FlagList flags={data.flags} />
      <p style={{ margin: '10px 0 0', fontSize: '10px', color: '#374151', fontFamily: 'JetBrains Mono, monospace' }}>
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
    <div style={{
      background: 'linear-gradient(135deg, #0D1623 0%, #111827 100%)',
      border: '1px solid rgba(0,240,255,0.18)',
      borderRadius: '12px', padding: '18px',
      boxShadow: '0 0 24px rgba(0,240,255,0.05)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
        <div style={{
          width: 34, height: 34, borderRadius: '8px', fontSize: '17px',
          background: 'rgba(0,240,255,0.1)', border: '1px solid rgba(0,240,255,0.25)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }} aria-hidden>⚖️</div>
        <div>
          <p style={{ margin: 0, fontSize: '13.5px', fontWeight: 700, color: '#F1F5F9', fontFamily: 'Plus Jakarta Sans, Inter, sans-serif' }}>
            Avika · Synthesis Engine
          </p>
          <p style={{ margin: 0, fontSize: '10.5px', color: '#4B5563', fontFamily: 'JetBrains Mono, monospace' }}>
            Dynamic weight orchestration
          </p>
        </div>
      </div>

      {/* Weight bars */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '16px', flexWrap: 'wrap' }}>
        {weights.map(w => (
          <div key={w.label} style={{ flex: 1, minWidth: '80px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
              <span style={{ fontSize: '10.5px', color: '#6B7280', fontFamily: 'JetBrains Mono, monospace' }}>{w.label}</span>
              <span style={{ fontSize: '10.5px', color: w.color, fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>
                {(w.value * 100).toFixed(0)}%
              </span>
            </div>
            <div style={{ height: '5px', borderRadius: '3px', background: '#1F2937', overflow: 'hidden' }}>
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
          <p style={{ margin: '0 0 8px', fontSize: '10px', fontWeight: 700, letterSpacing: '0.9px', textTransform: 'uppercase', color: '#4B5563', fontFamily: 'Inter, sans-serif' }}>
            Heuristics Triggered
          </p>
          <ul style={{ margin: '0 0 14px', padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '5px' }}>
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
      <div style={{
        padding: '10px 14px', borderRadius: '9px',
        background: 'rgba(0,240,255,0.05)', border: '1px solid rgba(0,240,255,0.12)',
      }}>
        <p style={{ margin: 0, fontSize: '12.5px', color: '#94A3B8', fontFamily: 'Inter, sans-serif', lineHeight: '1.6' }}>
          {data.summary_explanation}
        </p>
      </div>
    </div>
  );
}

// ── Main Drawer Component ──────────────────────────────────────

export interface AuditTrailDrawerProps {
  auditTrail: AuditTrail | null;
  recommendation?: string;
  processingTimeMs?: number;
}

export function AuditTrailDrawer({ auditTrail, recommendation, processingTimeMs }: AuditTrailDrawerProps) {
  // Default: expand all on first load, let user collapse
  const [expanded, setExpanded] = useState({ url: true, sender: true, intent: true });

  const toggle = (key: keyof typeof expanded) =>
    setExpanded(prev => ({ ...prev, [key]: !prev[key] }));

  if (!auditTrail) return null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Section header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <div style={{
          width: 36, height: 36, borderRadius: '9px', fontSize: '18px',
          background: 'rgba(0,240,255,0.08)', border: '1px solid rgba(0,240,255,0.2)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }} aria-hidden>🔬</div>
        <div>
          <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#F1F5F9', fontFamily: 'Plus Jakarta Sans, Inter, sans-serif' }}>
            Audit Trail
          </h3>
          <p style={{ margin: 0, fontSize: '11.5px', color: '#4B5563', fontFamily: 'Inter, sans-serif' }}>
            3-agent explainability drilldown
          </p>
        </div>
      </div>

      {/* Overall processing time */}
      {processingTimeMs != null && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: '8px',
          padding: '8px 14px', borderRadius: '9px',
          background: 'rgba(0,240,255,0.05)', border: '1px solid rgba(0,240,255,0.15)',
        }}>
          <span aria-hidden style={{ fontSize: '14px' }}>⚡</span>
          <span style={{
            fontSize: '12.5px', fontWeight: 700,
            fontFamily: 'JetBrains Mono, monospace', color: '#00F0FF',
          }}>
            Total Processing Time: {processingTimeMs.toFixed(0)}ms
          </span>
        </div>
      )}

      {/* Recommendation banner */}
      {recommendation && (
        <div style={{
          padding: '12px 16px', borderRadius: '10px',
          background: 'rgba(0,240,255,0.05)', border: '1px solid rgba(0,240,255,0.18)',
          display: 'flex', gap: '10px', alignItems: 'flex-start',
        }}>
          <span aria-hidden style={{ fontSize: '16px', flexShrink: 0, marginTop: '1px' }}>💡</span>
          <p style={{ margin: 0, fontSize: '13px', color: '#CBD5E1', fontFamily: 'Inter, sans-serif', lineHeight: '1.6' }}>
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
    </div>
  );
}

export default AuditTrailDrawer;
