// ────────────────────────────────────────────────────────────
//  PhishLens  ·  InterceptionModal Component
//  Full-screen hard-block for CRITICAL risk tier
// ────────────────────────────────────────────────────────────

import { useCallback, useEffect, useRef, useState } from 'react';
import type { ScanResponse } from '../lib/types';

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
  onAbort: () => void;
  onProceedAnyway: () => void;
}

// ── Component ─────────────────────────────────────────────────

export function InterceptionModal({ result, onAbort, onProceedAnyway }: InterceptionModalProps) {
  const COUNTDOWN = 8;
  const countdown = useCountdown(COUNTDOWN, true);
  const proceedEnabled = countdown === 0;

  const [reportCopied, setReportCopied] = useState(false);
  const reportTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Cleanup report timer on unmount
  useEffect(() => {
    return () => { if (reportTimerRef.current) clearTimeout(reportTimerRef.current); };
  }, []);

  // ── 1930 Report → clipboard + visual feedback ────────────
  const handleAbortAndReport = useCallback(() => {
    const urlField = result.audit_trail.url_analysis.url_analyzed;
    const report = [
      'Suspected Scam Report (1930)',
      `Sender: ${result.audit_trail.sender_analysis.sender_analyzed ?? 'Unknown'}`,
      `Message: ${result.verdict}`,
      `Suspicious URL: ${urlField ?? 'N/A'}`,
      `AI Threat Analysis: ${result.recommendation}`,
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
  }, [result, onAbort]);

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
  const label       = isHighRisk ? 'HIGH RISK DETECTED' : '⚠ TRANSACTION INTERCEPTED BY PHISHLENS';

  return (
    <>
      {/* ── Backdrop ────────────────────────────────────────── */}
      <div
        aria-hidden
        onClick={onAbort}
        style={{
          position: 'fixed', inset: 0, zIndex: 1000,
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
        style={{
          position: 'fixed', inset: 0, zIndex: 1001,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          padding: '16px',
          pointerEvents: 'none',
        }}
      >
        <div style={{
          pointerEvents: 'all',
          width: '100%', maxWidth: '640px', maxHeight: '90svh', overflowY: 'auto',
          background: '#0B0F19',
          border: `1px solid ${borderColor}`,
          borderRadius: '18px',
          boxShadow: `0 0 0 1px ${borderColor}55, 0 0 60px ${glowColor}, 0 24px 80px rgba(0,0,0,0.8)`,
          animation: 'pl-modal-in 0.35s cubic-bezier(0.175, 0.885, 0.32, 1.275)',
          position: 'relative', overflow: 'hidden',
        }}>
          {/* Animated crimson scanline sweep */}
          <div aria-hidden style={{
            position: 'absolute', top: 0, left: 0, right: 0, height: '2px',
            background: `linear-gradient(90deg, transparent, ${borderColor}, transparent)`,
            animation: 'pl-scanline 2.5s ease-in-out infinite',
          }} />

          {/* Corner accents */}
          {['top-left', 'top-right', 'bottom-left', 'bottom-right'].map(corner => (
            <div key={corner} aria-hidden style={{
              position: 'absolute', width: '20px', height: '20px',
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

          <div style={{ padding: '32px 32px 28px' }}>
            {/* ── Warning icon + tier badge ──────────────────── */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
              <div style={{
                width: 56, height: 56, borderRadius: '14px', fontSize: '28px',
                background: `${borderColor}15`, border: `1px solid ${borderColor}45`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                animation: 'pl-icon-pulse 1.5s ease-in-out infinite',
                boxShadow: `0 0 24px ${borderColor}30`,
              }} aria-hidden>🚨</div>

              <div style={{
                padding: '6px 14px', borderRadius: '20px', fontSize: '11px', fontWeight: 800,
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
              style={{
                margin: '0 0 14px',
                fontSize: 'clamp(18px, 4vw, 24px)',
                fontWeight: 800,
                fontFamily: 'Plus Jakarta Sans, Inter, sans-serif',
                color: '#F1F5F9',
                letterSpacing: '-0.3px',
                lineHeight: 1.25,
              }}
            >
              {label}
            </h2>

            {/* Risk score bar */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '18px' }}>
              <span style={{
                fontSize: '32px', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace',
                color: borderColor, lineHeight: 1,
              }}>{result.overall_risk_score}</span>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <span style={{ fontSize: '10px', color: '#4B5563', fontFamily: 'Inter, sans-serif' }}>Risk Score</span>
                  <span style={{ fontSize: '10px', color: '#4B5563', fontFamily: 'Inter, sans-serif' }}>/ 100</span>
                </div>
                <div style={{ height: '6px', borderRadius: '3px', background: '#1F2937', overflow: 'hidden' }}>
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
              style={{
                padding: '14px 16px', borderRadius: '10px', marginBottom: '18px',
                background: `${borderColor}0D`, border: `1px solid ${borderColor}30`,
              }}
            >
              <p style={{ margin: '0 0 8px', fontSize: '10.5px', fontWeight: 700, letterSpacing: '0.8px', textTransform: 'uppercase', color: borderColor, fontFamily: 'Inter, sans-serif' }}>
                Threat Analysis
              </p>
              <p style={{ margin: 0, fontSize: '13.5px', color: '#F1F5F9', fontFamily: 'Inter, sans-serif', lineHeight: '1.65', fontWeight: 500 }}>
                {result.recommendation}
              </p>
            </div>

            {/* ── Verdict ───────────────────────────────────── */}
            <p style={{
              margin: '0 0 24px', fontSize: '12.5px', color: '#6B7280',
              fontFamily: 'JetBrains Mono, monospace', lineHeight: '1.5',
              padding: '8px 12px', borderRadius: '8px', background: '#111827',
              border: '1px solid #1F2937',
            }}>
              <span style={{ color: '#4B5563' }}>verdict: </span>
              {result.verdict}
            </p>

            {/* ── Agent flags summary ───────────────────────── */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '24px' }}>
              {[
                { label: 'URL Score', value: `${result.audit_trail.url_analysis.risk_score}`, show: result.audit_trail.url_analysis.status !== 'SKIPPED' },
                { label: 'Sender Score', value: `${result.audit_trail.sender_analysis.risk_score}`, show: result.audit_trail.sender_analysis.status !== 'SKIPPED' },
                { label: 'Intent Score', value: `${result.audit_trail.intent_analysis.risk_score}`, show: true },
                { label: 'Latency', value: `${result.processing_time_ms.toFixed(0)}ms`, show: true },
              ].filter(x => x.show).map(m => (
                <div key={m.label} style={{
                  padding: '6px 12px', borderRadius: '8px',
                  background: '#111827', border: '1px solid #1F2937',
                  display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '2px',
                }}>
                  <span style={{ fontSize: '14px', fontWeight: 700, color: '#F1F5F9', fontFamily: 'JetBrains Mono, monospace' }}>{m.value}</span>
                  <span style={{ fontSize: '9.5px', color: '#374151', fontFamily: 'Inter, sans-serif', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{m.label}</span>
                </div>
              ))}
            </div>

            {/* ── Action buttons ────────────────────────────── */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {/* Primary — Abort */}
              <button
                id="modal-abort-btn"
                type="button"
                onClick={handleAbortAndReport}
                disabled={reportCopied}
                style={{
                  width: '100%', padding: '15px 24px', borderRadius: '11px', border: 'none',
                  background: reportCopied
                    ? 'linear-gradient(135deg, #00E676, #00C853)'
                    : `linear-gradient(135deg, ${isHighRisk ? '#FF6B00' : '#FF3366'}, ${isHighRisk ? '#FF3366' : '#CC002A'})`,
                  color: '#fff', fontSize: '15px', fontWeight: 800,
                  fontFamily: 'Plus Jakarta Sans, Inter, sans-serif',
                  cursor: reportCopied ? 'default' : 'pointer', letterSpacing: '0.2px',
                  boxShadow: reportCopied
                    ? '0 0 24px rgba(0,230,118,0.5), 0 4px 16px rgba(0,0,0,0.5)'
                    : `0 0 24px ${borderColor}50, 0 4px 16px rgba(0,0,0,0.5)`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
                  transition: 'all 0.3s ease',
                }}
                onMouseEnter={e => {
                  if (!reportCopied) {
                    e.currentTarget.style.transform = 'translateY(-1px)';
                    e.currentTarget.style.boxShadow = `0 0 36px ${borderColor}70, 0 6px 20px rgba(0,0,0,0.6)`;
                  }
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.transform = 'translateY(0)';
                  if (!reportCopied) {
                    e.currentTarget.style.boxShadow = `0 0 24px ${borderColor}50, 0 4px 16px rgba(0,0,0,0.5)`;
                  }
                }}
              >
                {reportCopied ? '✅ Report Copied! Dial 1930' : <>🛑 Abort Transaction &amp; Report</>}
              </button>

              {/* Secondary — Proceed anyway (with countdown friction) */}
              <button
                id="modal-proceed-btn"
                type="button"
                onClick={proceedEnabled ? onProceedAnyway : undefined}
                disabled={!proceedEnabled}
                style={{
                  width: '100%', padding: '12px 24px', borderRadius: '11px',
                  border: `1px solid ${proceedEnabled ? '#374151' : '#1F2937'}`,
                  background: 'transparent',
                  color: proceedEnabled ? '#6B7280' : '#374151',
                  fontSize: '13px', fontFamily: 'Inter, sans-serif', fontWeight: 500,
                  cursor: proceedEnabled ? 'pointer' : 'not-allowed',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
                  transition: 'all 0.2s ease',
                }}
              >
                {proceedEnabled ? (
                  'I Understand the Risks (Proceed Anyway)'
                ) : (
                  <>
                    <svg aria-hidden width="14" height="14" viewBox="0 0 14 14"
                      style={{ animation: 'pl-spin 1s linear infinite', flexShrink: 0 }}>
                      <circle cx="7" cy="7" r="5" stroke="#374151" strokeWidth="1.5" fill="none"/>
                      <path d="M7 2a5 5 0 0 1 5 5" stroke="#6B7280" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
                    </svg>
                    I Understand the Risks — wait {countdown}s
                  </>
                )}
              </button>
            </div>

            {/* Footer note */}
            <p style={{
              margin: '16px 0 0', fontSize: '10.5px', color: '#374151',
              fontFamily: 'JetBrains Mono, monospace', textAlign: 'center', lineHeight: '1.5',
            }}>
              scan_id: {result.scan_id} · intercepted in {result.processing_time_ms.toFixed(0)}ms
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
