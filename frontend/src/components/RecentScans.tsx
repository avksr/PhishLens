// ────────────────────────────────────────────────────────────
//  PhishLens  ·  RecentScans Component
//  Renders the /audit/recent scan history from mock data.
//  Dark-themed table with risk tier badges, threat flags,
//  and responsive mobile/desktop layouts.
// ────────────────────────────────────────────────────────────

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ThreatBadges } from './ThreatBadges';
import { mockScanHistory } from '../lib/mockData';
import type { ScanHistoryEntry } from '../lib/mockData';
import type { RiskTier, Language } from '../lib/types';

// ── Helpers ──────────────────────────────────────────────────

function getTierStyle(tier: RiskTier) {
  switch (tier) {
    case 'SAFE':
      return {
        className: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30 shadow-[0_0_10px_rgba(52,211,153,0.15)]',
        icon: '✓',
      };
    case 'CAUTION':
      return {
        className: 'text-amber-400 bg-amber-500/10 border-amber-500/30 shadow-[0_0_10px_rgba(251,191,36,0.15)]',
        icon: '⚡',
      };
    case 'HIGH_RISK':
      return {
        className: 'text-orange-400 bg-orange-500/10 border-orange-500/30 shadow-[0_0_10px_rgba(251,146,60,0.15)]',
        icon: '⚠',
      };
    case 'CRITICAL':
      return {
        className: 'text-rose-400 bg-rose-500/10 border-rose-500/30 shadow-[0_0_10px_rgba(244,63,94,0.15)]',
        icon: '🚨',
      };
  }
}

function getScoreColor(score: number): string {
  if (score <= 24) return 'text-emerald-400';
  if (score <= 49) return 'text-amber-400';
  if (score <= 77) return 'text-orange-400';
  return 'text-rose-400';
}

function timeAgo(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function formatDate(ts: string): string {
  return new Date(ts).toLocaleString('en-IN', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true,
  });
}

// ── Component Props ──────────────────────────────────────────

interface RecentScansProps {
  lang?: Language;
  /** Override history data (defaults to mockScanHistory) */
  history?: ScanHistoryEntry[];
}

// ── Component ────────────────────────────────────────────────

export function RecentScans({ lang = 'en', history }: RecentScansProps) {
  const scans = history ?? mockScanHistory;
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const toggleExpand = (id: string) => {
    setExpandedId(prev => (prev === id ? null : id));
  };

  return (
    <div className="w-full">
      {/* ── Section Header ────────────────────────────────── */}
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-3">
          <div
            className="w-10 h-10 rounded-xl text-lg bg-cyan-500/8 border border-cyan-500/20 text-cyan-400 flex items-center justify-center shrink-0"
            aria-hidden
          >
            📊
          </div>
          <div>
            <h3 className="text-base sm:text-lg font-bold text-zinc-100 font-sans tracking-tight m-0">
              {lang === 'hi' ? 'हालिया स्कैन इतिहास' : 'Recent Scan History'}
            </h3>
            <p className="text-xs text-zinc-500 font-sans m-0">
              {lang === 'hi'
                ? `/audit/recent · ${scans.length} रिकॉर्ड`
                : `/audit/recent · ${scans.length} records`}
            </p>
          </div>
        </div>

        {/* Stats summary pill */}
        <div className="hidden sm:flex items-center gap-3">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-rose-500/8 border border-rose-500/20">
            <span className="text-[10px] text-zinc-500 font-mono">Critical:</span>
            <span className="text-xs font-bold text-rose-400 font-mono">
              {scans.filter(s => s.risk_tier === 'CRITICAL').length}
            </span>
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-emerald-500/8 border border-emerald-500/20">
            <span className="text-[10px] text-zinc-500 font-mono">Safe:</span>
            <span className="text-xs font-bold text-emerald-400 font-mono">
              {scans.filter(s => s.risk_tier === 'SAFE').length}
            </span>
          </div>
        </div>
      </div>

      {/* ── Table Header (desktop) ────────────────────────── */}
      <div className="hidden lg:grid grid-cols-[140px_80px_110px_1fr_100px_100px] gap-3 px-4 py-2.5 text-[10px] font-bold uppercase tracking-wider text-zinc-500 border-b border-white/[0.06] font-mono mb-1">
        <span>Scan ID</span>
        <span>Score</span>
        <span>Risk Tier</span>
        <span>Verdict</span>
        <span>Channel</span>
        <span className="text-right">Timestamp</span>
      </div>

      {/* ── Scan Rows ─────────────────────────────────────── */}
      <div className="flex flex-col gap-2 max-h-[520px] overflow-y-auto pr-1">
        {scans.map((scan, index) => {
          const tierStyle = getTierStyle(scan.risk_tier);
          const scoreColor = getScoreColor(scan.threat_score);
          const isExpanded = expandedId === scan.scan_id;
          const resolvedVerdict = lang === 'hi' && scan.verdict_hi ? scan.verdict_hi : scan.verdict;

          return (
            <motion.div
              key={scan.scan_id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: index * 0.04 }}
            >
              {/* ── Main Row ── */}
              <button
                type="button"
                onClick={() => toggleExpand(scan.scan_id)}
                className={`
                  w-full text-left cursor-pointer
                  grid grid-cols-1 lg:grid-cols-[140px_80px_110px_1fr_100px_100px]
                  items-start lg:items-center gap-2 lg:gap-3
                  p-3 lg:p-3.5 rounded-xl
                  bg-black/40 border transition-all duration-200
                  ${isExpanded
                    ? 'border-cyan-500/20 shadow-[0_0_16px_rgba(0,240,255,0.06)] rounded-b-none'
                    : 'border-white/[0.06] hover:border-white/[0.1] hover:bg-white/[0.01]'
                  }
                `}
              >
                {/* 1 — Scan ID */}
                <div className="flex items-center gap-1.5 shrink-0">
                  <span className="lg:hidden text-[10px] text-zinc-500 font-bold uppercase font-mono">ID:</span>
                  <code
                    className="text-[11px] font-mono text-cyan-400 px-2 py-0.5 rounded-md border border-cyan-500/20 bg-cyan-500/5"
                    title={scan.scan_id}
                  >
                    {scan.scan_id.slice(0, 12)}…
                  </code>
                </div>

                {/* 2 — Score */}
                <div className="flex items-center gap-1.5 shrink-0">
                  <span className="lg:hidden text-[10px] text-zinc-500 font-bold uppercase font-mono">Score:</span>
                  <span className={`text-sm font-bold font-mono ${scoreColor}`}>
                    {scan.threat_score}
                    <span className="text-[9px] text-zinc-600 ml-0.5">/100</span>
                  </span>
                </div>

                {/* 3 — Risk Tier */}
                <div className="flex items-center gap-1.5 shrink-0">
                  <span className="lg:hidden text-[10px] text-zinc-500 font-bold uppercase font-mono">Tier:</span>
                  <span
                    className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold font-mono tracking-wider border ${tierStyle.className}`}
                  >
                    <span aria-hidden>{tierStyle.icon}</span>
                    {scan.risk_tier.replace('_', ' ')}
                  </span>
                </div>

                {/* 4 — Verdict */}
                <p className="m-0 text-xs text-zinc-300 font-sans leading-snug line-clamp-1" title={resolvedVerdict}>
                  {resolvedVerdict}
                </p>

                {/* 5 — Channel */}
                <div className="flex items-center gap-1.5 shrink-0">
                  <span className="lg:hidden text-[10px] text-zinc-500 font-bold uppercase font-mono">Channel:</span>
                  <span className="px-2 py-0.5 rounded-md text-[10px] font-mono text-zinc-400 bg-zinc-900 border border-white/[0.06] uppercase">
                    {scan.channel}
                  </span>
                </div>

                {/* 6 — Timestamp */}
                <div className="flex items-center lg:justify-end gap-1.5 shrink-0">
                  <span className="lg:hidden text-[10px] text-zinc-500 font-bold uppercase font-mono">Time:</span>
                  <span className="text-[10px] text-zinc-500 font-mono" title={formatDate(scan.timestamp)}>
                    {timeAgo(scan.timestamp)}
                  </span>
                </div>
              </button>

              {/* ── Expanded Detail Panel ── */}
              <AnimatePresence>
                {isExpanded && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.25, ease: 'easeInOut' }}
                    className="overflow-hidden"
                  >
                    <div className="p-4 border border-t-0 border-cyan-500/20 rounded-b-xl bg-zinc-950/80 backdrop-blur-sm">
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        {/* Target */}
                        <div>
                          <p className="text-[10px] font-bold uppercase tracking-wider text-zinc-500 font-mono mb-1.5">
                            Target
                          </p>
                          <code className="text-[11px] font-mono text-zinc-200 px-2.5 py-1 rounded-lg bg-black/40 border border-white/[0.06] break-all">
                            {scan.target}
                          </code>
                        </div>

                        {/* Processing time */}
                        <div>
                          <p className="text-[10px] font-bold uppercase tracking-wider text-zinc-500 font-mono mb-1.5">
                            Processing Time
                          </p>
                          <span className="text-xs font-mono text-cyan-400 flex items-center gap-1.5">
                            <span className="text-cyan-400" aria-hidden>⚡</span>
                            {scan.processing_time_ms}ms
                          </span>
                        </div>

                        {/* Full timestamp */}
                        <div>
                          <p className="text-[10px] font-bold uppercase tracking-wider text-zinc-500 font-mono mb-1.5">
                            Exact Timestamp
                          </p>
                          <span className="text-[11px] font-mono text-zinc-400">
                            {formatDate(scan.timestamp)}
                          </span>
                        </div>

                        {/* Full verdict */}
                        <div>
                          <p className="text-[10px] font-bold uppercase tracking-wider text-zinc-500 font-mono mb-1.5">
                            Full Verdict
                          </p>
                          <p className="m-0 text-xs text-zinc-300 font-sans leading-relaxed">
                            {resolvedVerdict}
                          </p>
                        </div>
                      </div>

                      {/* Threat Flags */}
                      {scan.detectedFlags.length > 0 && (
                        <div className="mt-4 pt-3 border-t border-white/[0.06]">
                          <p className="text-[10px] font-bold uppercase tracking-wider text-zinc-500 font-mono mb-2">
                            Threat Flags
                          </p>
                          <ThreatBadges detectedFlags={scan.detectedFlags} compact />
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          );
        })}
      </div>

      {/* ── Empty State ───────────────────────────────────── */}
      {scans.length === 0 && (
        <div className="text-center py-10">
          <div className="size-14 mx-auto rounded-2xl flex items-center justify-center text-2xl bg-zinc-900 border border-white/[0.06] mb-3">
            📭
          </div>
          <p className="text-sm text-zinc-500 font-sans m-0">
            {lang === 'hi' ? 'कोई स्कैन इतिहास उपलब्ध नहीं' : 'No scan history available'}
          </p>
        </div>
      )}
    </div>
  );
}

export default RecentScans;
