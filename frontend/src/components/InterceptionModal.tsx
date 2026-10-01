// ────────────────────────────────────────────────────────────
//  PhishLens  ·  InterceptionModal Component  (Day 4 Revision)
//  Full-screen hard-block for CRITICAL risk tier + Bilingual
// ────────────────────────────────────────────────────────────

import { useCallback, useEffect, useRef, useState } from 'react';
import type { ScanResponse, Language } from '../lib/types';

// ── Countdown hook ────────────────────────────────────────────

function useCountdown(seconds: number, active: boolean) {
  const [remaining, setRemaining] = useState(seconds);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!active) return;
    intervalRef.current = setInterval(() => {
      setRemaining(prev => {
        if (prev <= 1) { clearInterval(intervalRef.current!); return 0; }
        return prev - 1;
      });
    }, 1000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [active, seconds]);

  return remaining;
}

// ── Props ─────────────────────────────────────────────────────

export interface InterceptionModalProps {
  result: ScanResponse;
  lang: Language;
  onAbort: () => void;
  onProceedAnyway: () => void;
}

// ── Component ─────────────────────────────────────────────────

export function InterceptionModal({ result, lang, onAbort, onProceedAnyway }: InterceptionModalProps) {
  const COUNTDOWN = 8;
  const countdown = useCountdown(COUNTDOWN, true);
  const proceedEnabled = countdown === 0;

  const [reportCopied, setReportCopied] = useState(false);
  const reportTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Cleanup report timer on unmount
  useEffect(() => {
    return () => { if (reportTimerRef.current) clearTimeout(reportTimerRef.current); };
  }, []);

  // ── Bilingual text resolution ─────────────────────────────
  const recommendation = (lang === 'hi' && result.recommendation_hi)
    ? result.recommendation_hi
    : result.recommendation;
  const verdict = (lang === 'hi' && result.verdict_hi)
    ? result.verdict_hi
    : result.verdict;

  // ── 1930 Report → clipboard + visual feedback ────────────
  const handleAbortAndReport = useCallback(() => {
    const urlField = result.audit_trail.url_analysis.url_analyzed;
    const report = [
      'Suspected Scam Report (1930)',
      `Sender: ${result.audit_trail.sender_analysis.sender_analyzed ?? 'Unknown'}`,
      `Message: ${verdict}`,
      `Suspicious URL: ${urlField ?? 'N/A'}`,
      `AI Threat Analysis: ${recommendation}`,
    ].join('\n');

    navigator.clipboard.writeText(report).then(() => {
      setReportCopied(true);
      reportTimerRef.current = setTimeout(() => {
        setReportCopied(false);
        onAbort();
      }, 3000);
    }, () => {
      // Clipboard write failed — still abort
      onAbort();
    });
  }, [result, onAbort, verdict, recommendation]);

  // Trap focus inside modal
  const modalRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const firstBtn = modalRef.current?.querySelector<HTMLElement>('button');
    firstBtn?.focus();
    return () => { prev?.focus(); };
  }, []);

  // ESC key → abort
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onAbort(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onAbort]);

  // Lock body scroll
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = ''; };
  }, []);

  const isHighRisk = result.risk_tier === 'HIGH_RISK';
  const borderColor = isHighRisk ? '#FF6B00' : '#FF3366';
  const glowColor   = isHighRisk ? 'rgba(255,107,0,0.35)' : 'rgba(255,51,102,0.35)';
  const label = lang === 'hi'
    ? (isHighRisk ? 'उच्च जोखिम का पता चला' : '⚠ लेनदेन फिशलेंस द्वारा अवरुद्ध')
    : (isHighRisk ? 'HIGH RISK DETECTED' : '⚠ TRANSACTION INTERCEPTED BY PHISHLENS');

  return (
    <>
      {/* ── Backdrop ────────────────────────────────────────── */}
      <div
        aria-hidden
        onClick={onAbort}
        className="fixed inset-0 z-[1000]"
        style={{
          background: 'rgba(0,0,0,0.85)',
          backdropFilter: 'blur(8px)',
          animation: 'pl-modal-bg 0.3s ease',
        }}
      />

      {/* ── Modal panel ─────────────────────────────────────── */}
      <div
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="modal-headline"
        aria-describedby="modal-desc"
        ref={modalRef}
        className="fixed inset-0 z-[1001] flex items-center justify-center p-4 pointer-events-none"
      >
        <div
          className="pointer-events-auto w-full max-w-[640px] max-h-[90svh] overflow-y-auto relative overflow-hidden rounded-2xl"
          style={{
            background: '#0B0F19',
            border: `1px solid ${borderColor}`,
            boxShadow: `0 0 0 1px ${borderColor}55, 0 0 60px ${glowColor}, 0 24px 80px rgba(0,0,0,0.8)`,
            animation: 'pl-modal-in 0.35s cubic-bezier(0.175, 0.885, 0.32, 1.275)',
          }}
        >
          {/* Animated scanline sweep */}
          <div aria-hidden className="absolute top-0 left-0 right-0 h-0.5"
            style={{
              background: `linear-gradient(90deg, transparent, ${borderColor}, transparent)`,
              animation: 'pl-scanline 2.5s ease-in-out infinite',
            }}
          />

          {/* Corner accents */}
          {(['top-left', 'top-right', 'bottom-left', 'bottom-right'] as const).map(corner => (
            <div key={corner} aria-hidden className="absolute w-5 h-5" style={{
              ...(corner.includes('top') ? { top: 0 } : { bottom: 0 }),
              ...(corner.includes('left') ? { left: 0 } : { right: 0 }),
              borderTop: corner.includes('top') ? `2px solid ${borderColor}` : 'none',
              borderBottom: corner.includes('bottom') ? `2px solid ${borderColor}` : 'none',
              borderLeft: corner.includes('left') ? `2px solid ${borderColor}` : 'none',
              borderRight: corner.includes('right') ? `2px solid ${borderColor}` : 'none',
              borderRadius: corner === 'top-left' ? '16px 0 0 0' : corner === 'top-right' ? '0 16px 0 0'
                : corner === 'bottom-left' ? '0 0 0 16px' : '0 0 16px 0',
            }} />
          ))}

          <div className="p-6 sm:p-8 pb-6 sm:pb-7">
            {/* ── Warning icon + tier badge ──────────────────── */}
            <div className="flex items-center justify-between mb-5">
              <div style={{
                width: 56, height: 56, borderRadius: '14px', fontSize: '28px',
                background: `${borderColor}15`, border: `1px solid ${borderColor}45`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                animation: 'pl-icon-pulse 1.5s ease-in-out infinite',
                boxShadow: `0 0 24px ${borderColor}30`,
              }} aria-hidden>🚨</div>

              <div className="px-3.5 py-1.5 rounded-full text-xs font-extrabold" style={{
                fontFamily: 'JetBrains Mono, monospace', letterSpacing: '1px',
                color: borderColor, border: `1px solid ${borderColor}55`,
                background: `${borderColor}12`,
                boxShadow: `0 0 16px ${borderColor}30`,
                animation: 'pl-badge-flash 1s ease-in-out infinite',
              }}>
                {result.risk_tier}
              </div>
            </div>

            {/* ── Headline ──────────────────────────────────── */}
            <h2
              id="modal-headline"
              className="text-lg sm:text-2xl font-extrabold mb-3.5"
              style={{
                margin: '0 0 14px',
                fontFamily: 'Plus Jakarta Sans, Inter, sans-serif',
                color: '#F1F5F9',
                letterSpacing: '-0.3px',
                lineHeight: 1.25,
              }}
            >
              {label}
            </h2>

            {/* Risk score bar */}
            <div className="flex items-center gap-3 mb-4">
              <span className="text-3xl font-extrabold leading-none" style={{
                fontFamily: 'JetBrains Mono, monospace',
                color: borderColor,
              }}>{result.overall_risk_score}</span>
              <div className="flex-1">
                <div className="flex justify-between mb-1">
                  <span className="text-[10px]" style={{ color: '#94A3B8', fontFamily: 'Inter, sans-serif' }}>
                    {lang === 'hi' ? 'जोखिम स्कोर' : 'Risk Score'}
                  </span>
                  <span className="text-[10px]" style={{ color: '#94A3B8', fontFamily: 'Inter, sans-serif' }}>/ 100</span>
                </div>
                <div className="h-1.5 rounded-sm overflow-hidden" style={{ background: '#1F2937' }}>
                  <div style={{
                    height: '100%', borderRadius: '3px',
                    width: `${result.overall_risk_score}%`,
                    background: `linear-gradient(90deg, ${isHighRisk ? '#FF6B00' : '#FF3366'}, ${isHighRisk ? '#FF3366' : '#FF0055'})`,
                    boxShadow: `0 0 10px ${borderColor}80`,
                    transition: 'width 0.8s ease',
                  }} />
                </div>
              </div>
            </div>

            {/* ── Reason box ────────────────────────────────── */}
            <div
              id="modal-desc"
              className="p-3.5 sm:p-4 rounded-lg mb-4"
              style={{
                background: `${borderColor}0D`, border: `1px solid ${borderColor}30`,
              }}
            >
              <p className="text-[10.5px] font-bold uppercase tracking-wider mb-2" style={{
                color: borderColor, fontFamily: 'Inter, sans-serif',
              }}>
                {lang === 'hi' ? 'खतरा विश्लेषण' : 'Threat Analysis'}
              </p>
              <p className="text-[13.5px] leading-relaxed font-medium" style={{
                margin: 0, color: '#F1F5F9', fontFamily: 'Inter, sans-serif',
              }}>
                {recommendation}
              </p>
            </div>

            {/* ── Verdict ───────────────────────────────────── */}
            <p className="text-xs mb-6 p-2 sm:p-3 rounded-lg" style={{
              margin: '0 0 24px',
              color: '#CBD5E1',
              fontFamily: 'JetBrains Mono, monospace', lineHeight: '1.5',
              background: '#111827', border: '1px solid #1F2937',
            }}>
              <span style={{ color: '#94A3B8' }}>{lang === 'hi' ? 'फैसला: ' : 'verdict: '}</span>
              {verdict}
            </p>

            {/* ── Agent flags summary ───────────────────────── */}
            <div className="flex gap-2 flex-wrap mb-6">
              {[
                { label: lang === 'hi' ? 'URL स्कोर' : 'URL Score', value: `${result.audit_trail.url_analysis.risk_score}`, show: result.audit_trail.url_analysis.status !== 'SKIPPED' },
                { label: lang === 'hi' ? 'प्रेषक स्कोर' : 'Sender Score', value: `${result.audit_trail.sender_analysis.risk_score}`, show: result.audit_trail.sender_analysis.status !== 'SKIPPED' },
                { label: lang === 'hi' ? 'इरादा स्कोर' : 'Intent Score', value: `${result.audit_trail.intent_analysis.risk_score}`, show: true },
                { label: lang === 'hi' ? 'विलंबता' : 'Latency', value: `${result.processing_time_ms.toFixed(0)}ms`, show: true },
              ].filter(x => x.show).map(m => (
                <div key={m.label} className="flex flex-col items-center gap-0.5 px-3 py-1.5 rounded-lg" style={{
                  background: '#111827', border: '1px solid #1F2937',
                }}>
                  <span className="text-sm font-bold" style={{ color: '#F1F5F9', fontFamily: 'JetBrains Mono, monospace' }}>{m.value}</span>
                  <span className="text-[9.5px] uppercase tracking-wider" style={{ color: '#6B7280', fontFamily: 'Inter, sans-serif' }}>{m.label}</span>
                </div>
              ))}
            </div>

            {/* ── Action buttons ────────────────────────────── */}
            <div className="flex flex-col gap-2.5">
              {/* Primary — Abort */}
              <button
                id="modal-abort-btn"
                type="button"
                onClick={handleAbortAndReport}
                disabled={reportCopied}
                className="w-full py-3.5 sm:py-4 px-6 rounded-xl border-none text-white text-sm sm:text-base font-extrabold flex items-center justify-center gap-2 transition-all duration-300"
                style={{
                  fontFamily: 'Plus Jakarta Sans, Inter, sans-serif',
                  cursor: reportCopied ? 'default' : 'pointer',
                  letterSpacing: '0.2px',
                  background: reportCopied
                    ? 'linear-gradient(135deg, #00E676, #00C853)'
                    : `linear-gradient(135deg, ${isHighRisk ? '#FF6B00' : '#FF3366'}, ${isHighRisk ? '#FF3366' : '#CC002A'})`,
                  boxShadow: reportCopied
                    ? '0 0 24px rgba(0,230,118,0.5), 0 4px 16px rgba(0,0,0,0.5)'
                    : `0 0 24px ${borderColor}50, 0 4px 16px rgba(0,0,0,0.5)`,
                }}
              >
                {reportCopied
                  ? (lang === 'hi' ? '✅ रिपोर्ट कॉपी हो गई! 1930 डायल करें' : '✅ Report Copied! Dial 1930')
                  : (lang === 'hi' ? <>🛑 लेनदेन रद्द करें और रिपोर्ट करें</> : <>🛑 Abort Transaction &amp; Report</>)}
              </button>

              {/* Secondary — Proceed anyway (with countdown friction) */}
              <button
                id="modal-proceed-btn"
                type="button"
                onClick={proceedEnabled ? onProceedAnyway : undefined}
                disabled={!proceedEnabled}
                className="w-full py-3 px-6 rounded-xl text-sm flex items-center justify-center gap-2 transition-all duration-200"
                style={{
                  border: `1px solid ${proceedEnabled ? '#374151' : '#1F2937'}`,
                  background: 'transparent',
                  color: proceedEnabled ? '#94A3B8' : '#4B5563',
                  fontFamily: 'Inter, sans-serif', fontWeight: 500,
                  cursor: proceedEnabled ? 'pointer' : 'not-allowed',
                }}
              >
                {proceedEnabled ? (
                  lang === 'hi' ? 'मैं जोखिम समझता/समझती हूँ (फिर भी आगे बढ़ें)' : 'I Understand the Risks (Proceed Anyway)'
                ) : (
                  <>
                    <svg aria-hidden width="14" height="14" viewBox="0 0 14 14"
                      style={{ animation: 'pl-spin 1s linear infinite', flexShrink: 0 }}>
                      <circle cx="7" cy="7" r="5" stroke="#374151" strokeWidth="1.5" fill="none"/>
                      <path d="M7 2a5 5 0 0 1 5 5" stroke="#6B7280" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
                    </svg>
                    {lang === 'hi'
                      ? `मैं जोखिम समझता/समझती हूँ — ${countdown}s प्रतीक्षा करें`
                      : `I Understand the Risks — wait ${countdown}s`}
                  </>
                )}
              </button>
            </div>

            {/* Footer note */}
            <p className="text-[10.5px] text-center mt-4 leading-relaxed" style={{
              margin: '16px 0 0', color: '#6B7280',
              fontFamily: 'JetBrains Mono, monospace',
            }}>
              scan_id: {result.scan_id} · {lang === 'hi' ? 'इंटरसेप्ट किया' : 'intercepted in'} {result.processing_time_ms.toFixed(0)}ms
            </p>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes pl-modal-bg { from { opacity: 0 } to { opacity: 1 } }
        @keyframes pl-modal-in {
          from { opacity: 0; transform: scale(0.88) translateY(20px); }
          to   { opacity: 1; transform: scale(1)    translateY(0); }
        }
        @keyframes pl-scanline {
          0%   { transform: translateX(-100%); opacity: 0; }
          10%  { opacity: 1; }
          90%  { opacity: 1; }
          100% { transform: translateX(200%); opacity: 0; }
        }
        @keyframes pl-icon-pulse {
          0%, 100% { transform: scale(1);    box-shadow: 0 0 24px rgba(255,51,102,0.3); }
          50%       { transform: scale(1.08); box-shadow: 0 0 40px rgba(255,51,102,0.55); }
        }
        @keyframes pl-badge-flash {
          0%, 100% { opacity: 1; }
          50%       { opacity: 0.65; }
        }
        @keyframes pl-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </>
  );
}

export default InterceptionModal;
