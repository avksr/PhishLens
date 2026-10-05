// ────────────────────────────────────────────────────────────
//  PhishLens  ·  InterceptionModal Component  (Day 4 Revision)
//  Full-screen hard-block for CRITICAL risk tier + Bilingual
// ────────────────────────────────────────────────────────────

import { useCallback, useEffect, useRef, useState } from 'react';
import { Button } from "@/components/ui/button";
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
  const label = lang === 'hi'
    ? (isHighRisk ? 'उच्च जोखिम का पता चला' : '⚠ लेनदेन फिशलेंस द्वारा अवरुद्ध')
    : (isHighRisk ? 'HIGH RISK DETECTED' : '⚠ TRANSACTION INTERCEPTED BY PHISHLENS');

  return (
    <>
      {/* ── Backdrop ────────────────────────────────────────── */}
      <div
        aria-hidden
        onClick={onAbort}
        className="fixed inset-0 z-[1000] bg-black/90 backdrop-blur-sm animate-in fade-in duration-300"
      />

      {/* ── Modal panel ─────────────────────────────────────── */}
      <div
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="modal-headline"
        aria-describedby="modal-desc"
        ref={modalRef}
        className="fixed inset-0 z-[1001] flex items-center justify-center p-3 sm:p-4 pointer-events-none"
      >
        <div
          className={`pointer-events-auto w-[95vw] sm:w-full max-w-[640px] max-h-[92svh] overflow-y-auto relative rounded-2xl mobile-modal-fit bg-zinc-950 border ${
            isHighRisk
              ? 'border-orange-500/30 shadow-[0_0_40px_rgba(249,115,22,0.15)]'
              : 'border-rose-500/30 shadow-[0_0_40px_rgba(244,63,94,0.15)]'
          } animate-in zoom-in-95 duration-300`}
        >
          {/* Animated scanline sweep */}
          <div
            aria-hidden
            className={`absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent ${
              isHighRisk ? 'via-orange-500' : 'via-rose-500'
            } to-transparent animate-pulse`}
          />

          <div className="p-5 sm:p-8 mobile-card-padding">
            {/* ── Warning icon + tier badge ──────────────────── */}
            <div className="flex items-center justify-between mb-5">
              <div
                className={`w-14 h-14 rounded-2xl text-2xl flex items-center justify-center shrink-0 border ${
                  isHighRisk
                    ? 'bg-orange-500/10 border-orange-500/30 text-orange-400 shadow-[0_0_24px_rgba(249,115,22,0.25)]'
                    : 'bg-rose-500/10 border-rose-500/30 text-rose-400 shadow-[0_0_24px_rgba(244,63,94,0.25)]'
                }`}
                aria-hidden
              >
                🚨
              </div>

              <div
                className={`px-3.5 py-1.5 rounded-full text-xs font-extrabold font-mono tracking-wider border backdrop-blur-sm ${
                  isHighRisk
                    ? 'text-orange-400 border-orange-500/40 bg-orange-500/10 shadow-[0_0_16px_rgba(249,115,22,0.2)]'
                    : 'text-rose-400 border-rose-500/40 bg-rose-500/10 shadow-[0_0_16px_rgba(244,63,94,0.2)]'
                }`}
              >
                {result.risk_tier}
              </div>
            </div>

            {/* ── Headline ──────────────────────────────────── */}
            <h2
              id="modal-headline"
              className="text-lg sm:text-2xl font-extrabold text-zinc-100 font-sans tracking-tight leading-tight mb-3.5 m-0"
            >
              {label}
            </h2>

            {/* Risk score bar */}
            <div className="flex items-center gap-3.5 mb-4">
              <span
                className={`text-3xl font-extrabold leading-none font-mono ${
                  isHighRisk ? 'text-orange-400' : 'text-rose-400'
                }`}
              >
                {result.overall_risk_score}
              </span>
              <div className="flex-1">
                <div className="flex justify-between mb-1">
                  <span className="text-[10px] text-zinc-500 font-sans">
                    {lang === 'hi' ? 'जोखिम स्कोर' : 'Risk Score'}
                  </span>
                  <span className="text-[10px] text-zinc-500 font-sans">/ 100</span>
                </div>
                <div className="h-1.5 rounded-full overflow-hidden bg-white/[0.04]">
                  <div
                    className={`h-full rounded-full transition-all duration-700 ease-out ${
                      isHighRisk
                        ? 'bg-gradient-to-r from-orange-500 to-rose-500 shadow-[0_0_10px_rgba(249,115,22,0.6)]'
                        : 'bg-gradient-to-r from-rose-500 to-red-600 shadow-[0_0_10px_rgba(244,63,94,0.6)]'
                    }`}
                    style={{ width: `${result.overall_risk_score}%` }}
                  />
                </div>
              </div>
            </div>

            {/* ── Reason box ────────────────────────────────── */}
            <div
              id="modal-desc"
              className={`p-3.5 sm:p-4 rounded-xl mb-4 border ${
                isHighRisk
                  ? 'bg-orange-500/5 border-orange-500/25'
                  : 'bg-rose-500/5 border-rose-500/25'
              }`}
            >
              <p
                className={`text-[11px] font-bold uppercase tracking-wider mb-1.5 font-sans ${
                  isHighRisk ? 'text-orange-400' : 'text-rose-400'
                }`}
              >
                {lang === 'hi' ? 'खतरा विश्लेषण' : 'Threat Analysis'}
              </p>
              <p className="m-0 text-[13px] sm:text-[13.5px] leading-relaxed font-medium text-zinc-100 font-sans">
                {recommendation}
              </p>
            </div>

            {/* ── Verdict ───────────────────────────────────── */}
            <p className="text-xs mb-5 p-2.5 sm:p-3 rounded-xl bg-black/40 border border-white/[0.06] text-zinc-300 font-mono leading-relaxed m-0">
              <span className="text-zinc-600">{lang === 'hi' ? 'फैसला: ' : 'verdict: '}</span>
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
                <div key={m.label} className="flex flex-col items-center gap-0.5 px-3 py-1.5 rounded-xl bg-black/40 border border-white/[0.06]">
                  <span className="text-sm font-bold font-mono text-zinc-100">{m.value}</span>
                  <span className="text-[9.5px] uppercase tracking-wider text-zinc-500 font-sans">{m.label}</span>
                </div>
              ))}
            </div>

            {/* ── Action buttons ────────────────────────────── */}
            <div className="flex flex-col gap-2.5">
              {/* Primary — Abort */}
              <Button
                id="modal-abort-btn"
                type="button"
                onClick={handleAbortAndReport}
                disabled={reportCopied}
                className={`w-full h-auto py-3.5 sm:py-4 px-6 rounded-xl font-bold text-sm sm:text-base flex items-center justify-center gap-2 transition-all duration-300 text-white ${
                  reportCopied
                    ? 'bg-gradient-to-r from-emerald-500 to-green-600 hover:from-emerald-400 hover:to-green-500 shadow-[0_0_25px_rgba(0,230,118,0.4)]'
                    : isHighRisk
                    ? 'bg-gradient-to-r from-orange-500 to-rose-600 hover:from-orange-400 hover:to-rose-500 shadow-[0_0_25px_rgba(249,115,22,0.4)]'
                    : 'bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-500 hover:to-red-500 shadow-[0_0_25px_rgba(244,63,94,0.4)]'
                }`}
              >
                {reportCopied
                  ? (lang === 'hi' ? '✅ रिपोर्ट कॉपी हो गई! 1930 डायल करें' : '✅ Report Copied! Dial 1930')
                  : (lang === 'hi' ? <>🛑 लेनदेन रद्द करें और रिपोर्ट करें</> : <>🛑 Abort Transaction &amp; Report</>)}
              </Button>

              {/* Secondary — Proceed anyway (with countdown friction) */}
              <Button
                id="modal-proceed-btn"
                type="button"
                variant="outline"
                onClick={proceedEnabled ? onProceedAnyway : undefined}
                disabled={!proceedEnabled}
                className="w-full h-auto py-3 px-6 rounded-xl text-xs sm:text-sm font-medium border-white/[0.08] bg-zinc-950 text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.03] disabled:opacity-40 disabled:cursor-not-allowed transition-all"
              >
                {proceedEnabled ? (
                  lang === 'hi' ? 'मैं जोखिम समझता/समझती हूँ (फिर भी आगे बढ़ें)' : 'I Understand the Risks (Proceed Anyway)'
                ) : (
                  <>
                    <svg aria-hidden width="14" height="14" viewBox="0 0 16 16" className="animate-spin shrink-0 text-zinc-500">
                      <circle cx="8" cy="8" r="6" stroke="currentColor" strokeOpacity="0.2" strokeWidth="2" fill="none"/>
                      <path d="M8 2a6 6 0 0 1 6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" fill="none"/>
                    </svg>
                    {lang === 'hi'
                      ? `मैं जोखिम समझता/समझती हूँ — ${countdown}s प्रतीक्षा करें`
                      : `I Understand the Risks — wait ${countdown}s`}
                  </>
                )}
              </Button>
            </div>

            {/* Footer note */}
            <p className="text-[10.5px] text-center mt-4 leading-relaxed text-zinc-600 font-mono m-0">
              scan_id: {result.scan_id} · {lang === 'hi' ? 'इंटरसेप्ट किया' : 'intercepted in'} {result.processing_time_ms.toFixed(0)}ms
            </p>
          </div>
        </div>
      </div>
    </>
  );
}

export default InterceptionModal;
