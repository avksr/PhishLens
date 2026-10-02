// ────────────────────────────────────────────────────────────
//  PhishLens  ·  AuditTrailDrawer Component  (Day 4 Revision)
//  3 vector cards + synthesis + Live Audit Feed drawer
// ────────────────────────────────────────────────────────────

import { useState, useEffect } from 'react';
import { Button } from "@/components/ui/button";
import type { AuditTrail, UrlAgentResult, SenderAgentResult, IntentAgentResult, SynthesisBreakdown, AuditLogEntry, RiskTier, Language } from '../lib/types';
import { fetchRecentAuditLogs } from '../lib/api';

// ── Helpers ───────────────────────────────────────────────────

function getScoreBadgeClass(n: number): string {
  if (n <= 24) return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30 shadow-[0_0_12px_rgba(52,211,153,0.15)]';
  if (n <= 49) return 'text-amber-400 bg-amber-500/10 border-amber-500/30 shadow-[0_0_12px_rgba(251,191,36,0.15)]';
  if (n <= 77) return 'text-orange-400 bg-orange-500/10 border-orange-500/30 shadow-[0_0_12px_rgba(251,146,60,0.15)]';
  return 'text-rose-400 bg-rose-500/10 border-rose-500/30 shadow-[0_0_12px_rgba(244,63,94,0.15)]';
}

function getTierBadgeClass(tier: RiskTier): string {
  switch (tier) {
    case 'SAFE':
      return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30 shadow-[0_0_10px_rgba(52,211,153,0.15)]';
    case 'CAUTION':
      return 'text-amber-400 bg-amber-500/10 border-amber-500/30 shadow-[0_0_10px_rgba(251,191,36,0.15)]';
    case 'HIGH_RISK':
      return 'text-orange-400 bg-orange-500/10 border-orange-500/30 shadow-[0_0_10px_rgba(251,146,60,0.15)]';
    case 'CRITICAL':
      return 'text-rose-400 bg-rose-500/10 border-rose-500/30 shadow-[0_0_10px_rgba(244,63,94,0.15)]';
  }
}

function StatusBadge({ status }: { status: 'SUCCESS' | 'SKIPPED' | 'ERROR' }) {
  const cfg = {
    SUCCESS: {
      className: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.1)]',
      icon: '✓',
    },
    SKIPPED: {
      className: 'bg-zinc-900 border-white/[0.08] text-zinc-400',
      icon: '–',
    },
    ERROR: {
      className: 'bg-rose-500/10 border-rose-500/30 text-rose-400 shadow-[0_0_10px_rgba(244,63,94,0.15)]',
      icon: '!',
    },
  }[status];

  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10.5px] font-bold font-mono tracking-wider border ${cfg.className}`}>
      <span>{cfg.icon}</span> {status}
    </span>
  );
}

function ScorePill({ score }: { score: number }) {
  const badgeClass = getScoreBadgeClass(score);
  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold font-mono border ${badgeClass}`}>
      {score}
      <span className="text-[10px] font-normal opacity-70">/100</span>
    </span>
  );
}

function FlagList({ flags }: { flags: string[] }) {
  if (!flags.length) {
    return (
      <span className="text-xs text-zinc-500 font-sans italic">No flags raised</span>
    );
  }
  return (
    <ul className="m-0 p-0 list-none flex flex-col gap-1.5">
      {flags.map((f, i) => (
        <li key={i} className="flex items-start gap-2">
          <span aria-hidden className="text-orange-400 text-xs mt-0.5 shrink-0">⚑</span>
          <span className="text-xs text-zinc-300 font-mono leading-relaxed break-words">{f}</span>
        </li>
      ))}
    </ul>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p className="mt-3.5 mb-1.5 text-[10px] font-bold tracking-wider uppercase text-zinc-500 font-sans">
      {children}
    </p>
  );
}

function AgentCard({
  icon,
  title,
  agentName,
  children,
  expanded,
  onToggle,
  isElevatedRisk = false,
}: {
  icon: string;
  title: string;
  agentName: string;
  children: React.ReactNode;
  expanded: boolean;
  onToggle: () => void;
  isElevatedRisk?: boolean;
}) {
  return (
    <div
      className={`rounded-xl overflow-hidden transition-all duration-300 bg-zinc-950 border ${
        expanded
          ? isElevatedRisk
            ? 'border-rose-500/25 shadow-[0_0_20px_rgba(244,63,94,0.08)]'
            : 'border-white/[0.12] shadow-[0_0_20px_rgba(0,240,255,0.04)]'
          : 'border-white/[0.08] hover:border-white/[0.12]'
      }`}
    >
      {/* Card header — clickable Button */}
      <Button
        type="button"
        variant="ghost"
        onClick={onToggle}
        aria-expanded={expanded}
        className="w-full h-auto p-3 sm:p-4 flex items-center justify-between gap-3 text-left hover:bg-white/[0.02] rounded-none transition-colors"
      >
        <div className="flex items-center gap-3">
          <div
            className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 text-base transition-colors ${
              isElevatedRisk
                ? 'bg-rose-500/10 border border-rose-500/25 text-rose-400'
                : 'bg-cyan-500/10 border border-cyan-500/25 text-cyan-400'
            }`}
            aria-hidden
          >
            {icon}
          </div>
          <div>
            <p className="text-sm font-bold text-zinc-100 tracking-tight font-sans m-0">
              {title}
            </p>
            <p className="text-[11px] text-zinc-500 font-mono m-0">
              Agent: {agentName}
            </p>
          </div>
        </div>
        <svg
          aria-hidden
          width="16"
          height="16"
          viewBox="0 0 16 16"
          className={`shrink-0 transition-transform duration-300 text-zinc-500 ${expanded ? 'rotate-180 text-cyan-400' : ''}`}
        >
          <path d="M3 6l5 5 5-5" stroke="currentColor" strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      </Button>

      {/* Collapsible body */}
      <div
        className={`transition-all duration-300 ease-in-out ${
          expanded ? 'max-h-[1000px] opacity-100' : 'max-h-0 opacity-0 overflow-hidden'
        }`}
      >
        <div className="px-3 sm:px-4 pb-4 pt-1 mobile-card-padding border-t border-white/[0.06]">
          {children}
        </div>
      </div>
    </div>
  );
}

// ── URL Vector Card ───────────────────────────────────────────

function UrlCard({ data, expanded, onToggle }: { data: UrlAgentResult; expanded: boolean; onToggle: () => void }) {
  const isElevated = data.risk_score > 49;
  return (
    <AgentCard
      icon="🔗"
      title="URL / Domain Vector"
      agentName="Atharv"
      expanded={expanded}
      onToggle={onToggle}
      isElevatedRisk={isElevated}
    >
      <div className="flex items-center gap-2.5 mt-3 flex-wrap">
        <StatusBadge status={data.status} />
        <ScorePill score={data.risk_score} />
        {data.url_analyzed && (
          <code className="text-[11px] px-2.5 py-1 rounded-lg font-mono break-all max-w-full bg-black/40 text-zinc-300 border border-white/[0.06]">
            {data.url_analyzed}
          </code>
        )}
      </div>

      {data.status !== 'SKIPPED' && (
        <>
          <div className="flex gap-2 mt-3 flex-wrap">
            {data.domain_age_days !== null && (
              <span
                className={`px-2.5 py-1 rounded-lg text-xs font-semibold font-mono border ${
                  data.domain_age_days < 30
                    ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                    : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                }`}
              >
                🕒 Domain age: {data.domain_age_days}d
              </span>
            )}
            {data.is_typosquatting && (
              <span className="px-2.5 py-1 rounded-lg text-xs font-semibold font-mono bg-rose-500/10 text-rose-400 border border-rose-500/30 shadow-[0_0_10px_rgba(244,63,94,0.15)]">
                ⚠ Typosquatting
              </span>
            )}
            <span
              className={`px-2.5 py-1 rounded-lg text-xs font-semibold font-mono border ${
                data.tld_reputation === 'HIGH_RISK'
                  ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                  : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              }`}
            >
              TLD: {data.tld_reputation}
            </span>
          </div>

          {data.target_brand && (
            <>
              <SectionLabel>Impersonated Brand</SectionLabel>
              <p className="m-0 text-xs font-semibold text-zinc-200 font-sans">{data.target_brand}</p>
            </>
          )}
        </>
      )}

      <SectionLabel>Flags</SectionLabel>
      <FlagList flags={data.flags} />

      <SectionLabel>Agent Analysis</SectionLabel>
      <p className="m-0 text-xs text-zinc-300 font-sans leading-relaxed">
        {data.details}
      </p>

      <p className="mt-3 text-[10px] text-zinc-500 font-mono flex items-center gap-1.5">
        <span className="text-cyan-400">⚡</span> {data.latency_ms}ms
      </p>
    </AgentCard>
  );
}

// ── Sender Vector Card ────────────────────────────────────────

function SenderCard({ data, expanded, onToggle }: { data: SenderAgentResult; expanded: boolean; onToggle: () => void }) {
  const isElevated = data.risk_score > 49;

  const getSenderCategoryClass = (cat: string) => {
    switch (cat) {
      case 'OFFICIAL_TRAI_HEADER':
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      case 'PERSONAL_GSM':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'INTERNATIONAL':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'LOOKALIKE_HEADER':
        return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      default:
        return 'text-zinc-300 bg-zinc-900 border-white/[0.08]';
    }
  };

  return (
    <AgentCard
      icon="📡"
      title="Sender Identity Vector"
      agentName="Avni"
      expanded={expanded}
      onToggle={onToggle}
      isElevatedRisk={isElevated}
    >
      <div className="flex items-center gap-2.5 mt-3 flex-wrap">
        <StatusBadge status={data.status} />
        <ScorePill score={data.risk_score} />
        {data.sender_analyzed && (
          <code className="text-[11px] px-2.5 py-1 rounded-lg font-mono bg-black/40 text-zinc-300 border border-white/[0.06]">
            {data.sender_analyzed}
          </code>
        )}
      </div>

      {data.status !== 'SKIPPED' && (
        <div className="flex gap-2 mt-3 flex-wrap">
          <span className={`px-2.5 py-1 rounded-lg text-xs font-bold font-mono border ${getSenderCategoryClass(data.sender_category)}`}>
            {data.sender_category.replace(/_/g, ' ')}
          </span>

          {data.is_spoofed_header && (
            <span className="px-2.5 py-1 rounded-lg text-xs font-bold font-mono text-rose-400 bg-rose-500/10 border border-rose-500/30 shadow-[0_0_10px_rgba(244,63,94,0.15)]">
              ⚠ SPOOFED HEADER
            </span>
          )}

          {data.brand_claimed && (
            <span className="px-2.5 py-1 rounded-lg text-xs font-medium font-sans text-zinc-300 bg-zinc-900 border border-white/[0.06]">
              Claims: {data.brand_claimed}
            </span>
          )}
        </div>
      )}

      <SectionLabel>Flags</SectionLabel>
      <FlagList flags={data.flags} />

      <SectionLabel>Agent Analysis</SectionLabel>
      <p className="m-0 text-xs text-zinc-300 font-sans leading-relaxed">
        {data.details}
      </p>

      <p className="mt-3 text-[10px] text-zinc-500 font-mono flex items-center gap-1.5">
        <span className="text-cyan-400">⚡</span> {data.latency_ms}ms
      </p>
    </AgentCard>
  );
}

// ── Intent Vector Card ────────────────────────────────────────

function IntentCard({ data, expanded, onToggle }: { data: IntentAgentResult; expanded: boolean; onToggle: () => void }) {
  const isElevated = data.risk_score > 49;

  const getIntentBadgeClass = (intent: string) => {
    switch (intent) {
      case 'BENIGN':
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      case 'SUSPICIOUS':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'PANIC_URGENCY':
      case 'LOTTERY_REWARD':
        return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'FINANCIAL_EXTORTION':
      case 'KYC_VERIFICATION':
      case 'OTP_HARVEST':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30 shadow-[0_0_10px_rgba(244,63,94,0.15)]';
      default:
        return 'text-zinc-300 bg-zinc-900 border-white/[0.08]';
    }
  };

  return (
    <AgentCard
      icon="🧠"
      title="Psycholinguistic Vector"
      agentName="Vikas"
      expanded={expanded}
      onToggle={onToggle}
      isElevatedRisk={isElevated}
    >
      <div className="flex items-center gap-2.5 mt-3 flex-wrap">
        <StatusBadge status={data.status} />
        <ScorePill score={data.risk_score} />
        <span className={`px-2.5 py-1 rounded-lg text-xs font-bold font-mono border ${getIntentBadgeClass(data.detected_intent)}`}>
          {data.detected_intent.replace(/_/g, ' ')}
        </span>
        <span className="px-2.5 py-1 rounded-lg text-xs font-semibold font-mono text-zinc-300 bg-zinc-900 border border-white/[0.06]">
          Confidence: {(data.confidence * 100).toFixed(0)}%
        </span>
      </div>

      {data.manipulation_tactics.length > 0 && (
        <>
          <SectionLabel>Manipulation Tactics</SectionLabel>
          <ul className="m-0 p-0 list-none flex flex-col gap-1.5">
            {data.manipulation_tactics.map((t, i) => (
              <li key={i} className="flex items-start gap-2">
                <span aria-hidden className="text-orange-400 text-xs shrink-0 mt-0.5">◈</span>
                <span className="text-xs text-zinc-300 font-sans leading-relaxed">{t}</span>
              </li>
            ))}
          </ul>
        </>
      )}

      <SectionLabel>LLM Reasoning</SectionLabel>
      <blockquote className="m-0 p-3 sm:p-3.5 border-l-2 border-cyan-400 rounded-r-xl bg-cyan-500/[0.03] text-xs text-zinc-300 font-sans leading-relaxed italic border border-y-0 border-r-0">
        {data.reasoning}
      </blockquote>

      <SectionLabel>Flags</SectionLabel>
      <FlagList flags={data.flags} />

      <p className="mt-3 text-[10px] text-zinc-500 font-mono flex items-center gap-1.5">
        <span className="text-cyan-400">⚡</span> {data.latency_ms}ms
      </p>
    </AgentCard>
  );
}

// ── Synthesis Card ────────────────────────────────────────────

function SynthesisCard({ data }: { data: SynthesisBreakdown }) {
  const weights = [
    { label: 'URL', value: data.weights_applied.url_weight, barColor: 'bg-cyan-400 shadow-[0_0_6px_rgba(0,240,255,0.3)]', textColor: 'text-cyan-400' },
    { label: 'Sender', value: data.weights_applied.sender_weight, barColor: 'bg-purple-400 shadow-[0_0_6px_rgba(167,139,250,0.3)]', textColor: 'text-purple-400' },
    { label: 'Intent', value: data.weights_applied.intent_weight, barColor: 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.3)]', textColor: 'text-emerald-400' },
  ];

  return (
    <div className="p-4 sm:p-5 rounded-xl bg-zinc-950 border border-white/[0.1] shadow-[0_0_20px_rgba(0,240,255,0.03)] relative overflow-hidden">
      <div className="flex items-center gap-3 mb-4">
        <div
          className="w-9 h-9 rounded-xl text-base bg-cyan-500/10 border border-cyan-500/25 flex items-center justify-center text-cyan-400 shrink-0"
          aria-hidden
        >
          ⚖️
        </div>
        <div>
          <p className="m-0 text-sm font-bold text-zinc-100 font-sans tracking-tight">
            Avika · Synthesis Engine
          </p>
          <p className="m-0 text-[11px] text-zinc-500 font-mono">
            Dynamic weight orchestration
          </p>
        </div>
      </div>

      {/* Weight bars */}
      <div className="flex flex-col sm:flex-row gap-3 mb-4">
        {weights.map(w => (
          <div key={w.label} className="flex-1 min-w-[80px]">
            <div className="flex justify-between mb-1.5">
              <span className="text-[11px] text-zinc-500 font-mono">{w.label}</span>
              <span className={`text-[11px] font-mono font-bold ${w.textColor}`}>
                {(w.value * 100).toFixed(0)}%
              </span>
            </div>
            <div className="h-1.5 rounded-full overflow-hidden bg-white/[0.04]">
              <div
                className={`h-full rounded-full transition-all duration-700 ease-out ${w.barColor}`}
                style={{ width: `${w.value * 100}%` }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Heuristics */}
      {data.heuristics_triggered.length > 0 && (
        <>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2 text-zinc-500 font-sans">
            Heuristics Triggered
          </p>
          <ul className="mb-3.5 m-0 p-0 list-none flex flex-col gap-1.5">
            {data.heuristics_triggered.map((h, i) => (
              <li key={i} className="flex items-start gap-2">
                <span aria-hidden className="text-cyan-400 text-xs mt-0.5 shrink-0">▸</span>
                <span className="text-xs text-zinc-300 font-sans leading-relaxed">{h}</span>
              </li>
            ))}
          </ul>
        </>
      )}

      {/* Summary */}
      <div className="p-3 sm:p-3.5 rounded-lg bg-cyan-500/[0.03] border border-white/[0.06]">
        <p className="m-0 text-xs text-zinc-300 font-sans leading-relaxed">
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
    <div className={`rounded-xl overflow-hidden transition-all duration-300 bg-zinc-950 border ${
      open ? 'border-white/[0.12] shadow-[0_0_20px_rgba(0,240,255,0.04)]' : 'border-white/[0.08] hover:border-white/[0.12]'
    }`}>
      {/* Drawer header - Shadcn Button */}
      <Button
        id="audit-feed-toggle"
        type="button"
        variant="ghost"
        onClick={handleToggle}
        aria-expanded={open}
        className="w-full h-auto p-3.5 sm:p-4 flex items-center justify-between gap-3 text-left hover:bg-white/[0.02] rounded-none transition-colors"
      >
        <div className="flex items-center gap-3">
          <div
            className="w-9 h-9 rounded-xl text-base bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center shrink-0 text-cyan-400"
            aria-hidden
          >
            📋
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <p className="m-0 text-sm font-bold text-zinc-100 font-sans tracking-tight">
                {lang === 'hi' ? 'हालिया ऑडिट लॉग' : 'Recent Audit Logs'}
              </p>
              <span className="hidden sm:inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] text-zinc-500 font-mono border border-white/[0.06] bg-black/40">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_6px_#34d399]" />
                30s poll
              </span>
            </div>
            <p className="m-0 text-[11px] text-zinc-500 font-sans">
              {lang === 'hi' ? 'पिछले स्कैन का लाइव फ़ीड (हर 30 सेकंड में ऑटो-रिफ्रेश)' : 'Live feed of previous scans (auto-refreshed every 30s)'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {logs.length > 0 && (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 shadow-[0_0_8px_rgba(0,240,255,0.15)]">
              {logs.length}
            </span>
          )}
          <svg
            aria-hidden
            width="16"
            height="16"
            viewBox="0 0 16 16"
            className={`shrink-0 transition-transform duration-300 text-zinc-500 ${open ? 'rotate-180 text-cyan-400' : ''}`}
          >
            <path d="M3 6l5 5 5-5" stroke="currentColor" strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </div>
      </Button>

      {/* Collapsible feed body */}
      <div
        className={`transition-all duration-300 ease-in-out ${
          open ? 'max-h-[700px] opacity-100' : 'max-h-0 opacity-0 overflow-hidden'
        }`}
      >
        <div className="px-3 sm:px-5 pb-4 mobile-card-padding border-t border-white/[0.06]">
          {/* Loading state */}
          {loading && logs.length === 0 && (
            <div className="flex items-center justify-center gap-2 py-6" role="status" aria-live="polite">
              <svg aria-hidden width="18" height="18" viewBox="0 0 16 16" className="animate-spin text-cyan-400">
                <circle cx="8" cy="8" r="6" stroke="currentColor" strokeOpacity="0.2" strokeWidth="2" fill="none"/>
                <path d="M8 2a6 6 0 0 1 6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" fill="none"/>
              </svg>
              <span className="text-xs text-cyan-400 font-mono">
                {lang === 'hi' ? 'लॉग लोड हो रहे हैं…' : 'Loading audit logs…'}
              </span>
            </div>
          )}

          {/* Error state */}
          {fetchError && (
            <div role="alert" className="py-2.5 px-3 rounded-xl mt-3 flex items-center gap-2 bg-rose-500/10 border border-rose-500/25 text-rose-400 text-xs font-mono">
              <span aria-hidden>⚠</span>
              <span>{fetchError}</span>
            </div>
          )}

          {/* Table / List View */}
          {logs.length > 0 && (
            <div className="mt-3 flex flex-col gap-2 max-h-[440px] overflow-y-auto pr-1">
              {/* Header row for medium+ screens */}
              <div className="hidden sm:grid grid-cols-[130px_100px_1fr_110px] gap-3 px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-zinc-500 border-b border-white/[0.06] font-mono">
                <span>Scan ID</span>
                <span>Risk Score</span>
                <span>Verdict</span>
                <span className="text-right">Timestamp</span>
              </div>

              {logs.map(log => {
                const tierClass = getTierBadgeClass(log.risk_tier);
                const resolvedVerdict = (lang === 'hi' && log.verdict_hi) ? log.verdict_hi : log.verdict;
                return (
                  <div
                    key={log.scan_id}
                    className="grid grid-cols-1 sm:grid-cols-[130px_100px_1fr_110px] items-start sm:items-center gap-2 sm:gap-3 p-3 rounded-xl bg-black/40 border border-white/[0.06] hover:border-white/[0.1] transition-colors duration-150"
                  >
                    {/* 1. Scan ID */}
                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className="sm:hidden text-[10px] text-zinc-500 font-bold uppercase font-mono">ID:</span>
                      <code
                        className="text-[11px] font-mono text-cyan-400 px-2 py-0.5 rounded-md border border-cyan-500/20 bg-cyan-500/5"
                        title={log.scan_id}
                      >
                        {log.scan_id.slice(0, 8)}…
                      </code>
                    </div>

                    {/* 2. Risk Score */}
                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className="sm:hidden text-[10px] text-zinc-500 font-bold uppercase font-mono">Score:</span>
                      <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold font-mono tracking-wider border ${tierClass}`}>
                        {log.overall_risk_score} <span className="text-[9px] opacity-75">/100</span>
                      </span>
                    </div>

                    {/* 3. Verdict */}
                    <p
                      className="m-0 text-xs text-zinc-300 font-sans leading-snug line-clamp-2"
                      title={resolvedVerdict}
                    >
                      {resolvedVerdict}
                    </p>

                    {/* 4. Timestamp */}
                    <div className="flex items-center sm:justify-end gap-1.5 text-[10px] text-zinc-600 font-mono shrink-0">
                      <span>{timeAgo(log.timestamp)}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Empty state */}
          {!loading && !fetchError && logs.length === 0 && (
            <p className="text-center py-6 text-xs text-zinc-500 font-sans">
              {lang === 'hi' ? 'अभी तक कोई ऑडिट लॉग नहीं है' : 'No audit logs yet'}
            </p>
          )}
        </div>
      </div>
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
          <div className="flex items-center gap-3">
            <div
              className="w-10 h-10 rounded-xl text-lg bg-cyan-500/8 border border-cyan-500/20 text-cyan-400 flex items-center justify-center shrink-0"
              aria-hidden
            >
              🔬
            </div>
            <div>
              <h3 className="text-base sm:text-lg font-bold text-zinc-100 font-sans tracking-tight m-0">
                {lang === 'hi' ? 'ऑडिट ट्रेल' : 'Audit Trail'}
              </h3>
              <p className="text-xs text-zinc-500 font-sans m-0">
                {lang === 'hi' ? '3-एजेंट व्याख्यात्मक विश्लेषण' : '3-agent explainability drilldown'}
              </p>
            </div>
          </div>

          {/* Overall processing time */}
          {processingTimeMs != null && (
            <div className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-cyan-500/[0.05] border border-white/[0.08] text-cyan-400">
              <span aria-hidden className="text-sm">⚡</span>
              <span className="text-xs sm:text-[12.5px] font-bold font-mono">
                {lang === 'hi' ? `कुल प्रोसेसिंग समय: ${processingTimeMs.toFixed(0)}ms` : `Total Processing Time: ${processingTimeMs.toFixed(0)}ms`}
              </span>
            </div>
          )}

          {/* Recommendation banner */}
          {recommendation && (
            <div className="flex gap-3 items-start p-3.5 sm:p-4 rounded-xl bg-cyan-500/[0.03] border border-white/[0.06]">
              <span aria-hidden className="text-base shrink-0 mt-0.5">💡</span>
              <p className="m-0 text-xs sm:text-sm text-zinc-200 font-sans leading-relaxed">
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
