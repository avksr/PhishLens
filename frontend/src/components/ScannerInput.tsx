// ────────────────────────────────────────────────────────────
//  PhishLens  ·  ScannerInput Component  (Day 4 Revision)
//  Single-box auto-detection with GooeyInput + StatefulButton + GlowingEffect
// ────────────────────────────────────────────────────────────

import { useState, useRef, useCallback, useMemo } from 'react';
import { Button } from "@/components/ui/button";
import { GooeyInput } from "@/components/ui/gooey-input";
import { StatefulButton } from "@/components/ui/stateful-button";
import { GlowingEffect } from "@/components/ui/glowing-effect";
import { scanMessage } from '../lib/api';
import type { ScanResponse, ScanRequest } from '../lib/types';
import highRisk from '../../../datasets/payloads_high_risk.json';
import safe     from '../../../datasets/payloads_safe.json';

// ── Presets (loaded from dataset JSON) ────────────────────────

interface Preset {
  id: string;
  label: string;
  icon: string;
  payload: ScanRequest;
}

const PRESETS: Preset[] = [
  {
    id: 'critical-scam',
    label: 'Critical Scam',
    icon: '🚨',
    payload: highRisk[1].payload as ScanRequest, // hr_002 — Electricity Power Cut Extortion
  },
  {
    id: 'verified-safe',
    label: 'Verified Safe',
    icon: '🛡️',
    payload: safe[0].payload as ScanRequest,      // safe_001 — HDFC Bank OTP
  },
  {
    id: 'gsm-impersonation',
    label: 'GSM Impersonation',
    icon: '⚠️',
    payload: highRisk[0].payload as ScanRequest,  // hr_001 — SBI KYC Phishing (.top domain)
  },
];

// ── Auto-Detection Logic ──────────────────────────────────────

const URL_REGEX = /https?:\/\//i;
const UPI_REGEX = /\w+@[a-zA-Z]+/;

function detectInputType(text: string): string {
  if (URL_REGEX.test(text)) {
    return '🌐 Detected: Web URL';
  }
  if (UPI_REGEX.test(text)) {
    return '💳 Detected: UPI ID';
  }
  return '💬 Detected: SMS / Message';
}

// ── Props ─────────────────────────────────────────────────────

export interface ScannerInputProps {
  onScanComplete: (result: ScanResponse) => void;
  onScanError?: (err: Error) => void;
  disabled?: boolean;
}

// ── Component ─────────────────────────────────────────────────

export function ScannerInput({ onScanComplete, onScanError, disabled = false }: ScannerInputProps) {
  const [content,      setContent]      = useState('');
  const [isLoading,    setIsLoading]    = useState(false);
  const [activePreset, setActivePreset] = useState<string | null>(null);
  const [focused,      setFocused]      = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const MAX = 8000;
  const charFrac = content.length / MAX;
  const charColor = charFrac > 0.9 ? '#FF3366' : charFrac > 0.75 ? '#FF6B00' : '#94A3B8';

  // ── Auto-detect input type on every keystroke ───────────────

  const detectedBadge = useMemo(() => detectInputType(content), [content]);

  // ── Preset loader ─────────────────────────────────────────

  const loadPreset = useCallback((preset: Preset) => {
    setContent(preset.payload.content);
    setActivePreset(preset.id);
    setTimeout(() => textareaRef.current?.focus(), 50);
  }, []);

  // ── Submit ────────────────────────────────────────────────

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim() || isLoading || disabled) return;
    setIsLoading(true);
    try {
      const result = await scanMessage({
        content: content.trim(),
      });
      onScanComplete(result);
    } catch (err) {
      onScanError?.(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  };

  const handleClear = () => {
    setContent('');
    setActivePreset(null);
    textareaRef.current?.focus();
  };

  // ── Input style helper ─────────────────────────────────────
  const isDisabled = disabled || isLoading;

  // ── Render ────────────────────────────────────────────────

  return (
    <div className="relative">
      {/* ✨ Futuristic Glowing Effect Wrapper */}
      <GlowingEffect spread={40} glowColor="rgba(0, 240, 255, 0.22)">
        <form
          id="scanner-form"
          onSubmit={handleSubmit}
          aria-label="PhishLens threat scanner"
          className="relative z-[1] flex flex-col gap-4 sm:gap-5 p-3.5 sm:p-7 rounded-xl sm:rounded-2xl mobile-scanner-container bg-slate-900/80 backdrop-blur-md border border-slate-800 shadow-2xl transition-colors duration-300"
        >
          {/* ── Header ────────────────────────────────────────── */}
          <div className="flex max-sm:flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mobile-header-stack">
            <div className="flex items-center gap-2.5 sm:gap-3.5">
              <div
                className="flex items-center justify-center shrink-0 w-9 h-9 sm:w-11 sm:h-11 rounded-xl text-lg sm:text-[22px] bg-cyan-500/10 border border-cyan-500/20 text-cyan-400"
                aria-hidden
              >
                🛡️
              </div>
              <div>
                <h2 className="text-sm sm:text-base md:text-lg font-bold text-slate-100 m-0 tracking-tight">
                  Threat Scanner
                </h2>
                <p className="text-[11px] sm:text-xs text-slate-400 m-0">
                  Paste SMS · WhatsApp · Email · UPI prompt to inspect
                </p>
              </div>
            </div>
            {/* LIVE badge */}
            <div
              className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20"
              aria-label="Scanner active"
            >
              <span aria-hidden className="inline-block shrink-0 w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_#34d399] animate-pulse" />
              <span className="text-[11px] font-bold text-emerald-400 tracking-wide font-mono">LIVE</span>
            </div>
          </div>

          {/* ── Preset buttons ─────────────────────────────────── */}
          <div>
            <p className="text-[10.5px] sm:text-xs mb-2 text-slate-400 uppercase font-bold tracking-wider">
              Quick Load Scenarios
            </p>
            <div role="group" aria-label="Preset scenarios" className="flex flex-wrap gap-2">
              {PRESETS.map((p) => {
                const active = activePreset === p.id;
                return (
                  <Button
                    key={p.id}
                    id={`preset-${p.id}`}
                    type="button"
                    variant={active ? "default" : "secondary"}
                    size="sm"
                    onClick={() => loadPreset(p)}
                    disabled={isDisabled}
                    className={`text-xs transition-all ${
                      active
                        ? 'bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 border border-cyan-500/50 shadow-[0_0_15px_rgba(0,240,255,0.1)]'
                        : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                    }`}
                  >
                    <span aria-hidden className="mr-1.5">{p.icon}</span>{p.label}
                  </Button>
                );
              })}
            </div>
          </div>

          {/* ── Textarea with GooeyInput + Pointer Highlight ──── */}
          <div>
            <label htmlFor="scanner-msg" className="block mb-2 text-[11px] font-semibold tracking-wide uppercase text-slate-400">
              Message Content <span className="text-rose-500">*</span>
            </label>

            {/* ✨ Replaced standard textarea with GooeyInput */}
            <GooeyInput
              id="scanner-msg"
              ref={textareaRef}
              value={content}
              onChange={e => {
                setContent(e.target.value.slice(0, MAX));
                setActivePreset(null);
              }}
              onFocus={() => setFocused(true)}
              onBlur={() => setFocused(false)}
              disabled={isDisabled}
              required
              rows={4}
              placeholder="Paste the suspicious SMS, WhatsApp message, email body, UPI payment note, or URL here…"
              containerClassName={focused ? 'ring-1 ring-cyan-500/40 shadow-[0_0_15px_rgba(0,240,255,0.12)]' : ''}
            />

            {/* ── Dynamic Pill / Badge Below Textarea & Character Count ── */}
            <div className="mt-3 flex items-center justify-between flex-wrap gap-2">
              <div
                id="scanner-detected-pill"
                role="status"
                aria-live="polite"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold tracking-wide bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono shadow-[0_0_10px_rgba(0,240,255,0.1)]"
              >
                <span>{detectedBadge}</span>
              </div>

              <span
                aria-live="polite"
                className="text-xs font-mono transition-colors"
                style={{ color: charColor }}
              >
                {content.length.toLocaleString()} / {MAX.toLocaleString()}
              </span>
            </div>
          </div>

          {/* ── Action row ─────────────────────────────────────── */}
          <div className="flex flex-col-reverse sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-5 border-t border-slate-800">
            {/* Clear Button */}
            <Button
              id="scanner-clear-btn"
              type="button"
              variant="ghost"
              onClick={handleClear}
              disabled={isDisabled || !content}
              className="text-slate-400 hover:text-slate-200"
            >
              <span aria-hidden className="mr-2">✕</span> Clear
            </Button>

            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
              {isLoading && (
                <span role="status" aria-live="assertive" className="flex items-center justify-center gap-2 text-xs text-cyan-400 font-mono animate-in fade-in slide-in-from-right-4">
                  <svg aria-hidden width="16" height="16" viewBox="0 0 16 16" className="animate-spin shrink-0">
                    <circle cx="8" cy="8" r="6" stroke="currentColor" strokeOpacity="0.2" strokeWidth="2" fill="none"/>
                    <path d="M8 2a6 6 0 0 1 6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" fill="none"/>
                  </svg>
                  Scanning 3 agents…
                </span>
              )}

              {/* ✨ Replaced standard submit button with Cyberpunk StatefulButton */}
              <StatefulButton
                id="scanner-submit-btn"
                type="submit"
                status={isLoading ? 'loading' : 'idle'}
                disabled={isDisabled || !content.trim()}
                loadingText="Analyzing 3 Agents…"
                idleText={
                  <>
                    <span aria-hidden className="mr-1.5">⚡</span> Inspect &amp; Intercept
                  </>
                }
              />
            </div>
          </div>
        </form>
      </GlowingEffect>
    </div>
  );
}

export default ScannerInput;