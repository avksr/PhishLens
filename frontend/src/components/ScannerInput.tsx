// ────────────────────────────────────────────────────────────
//  PhishLens  ·  ScannerInput Component  (Day 4 Revision)
//  Single-box auto-detection with real-time badge + presets
// ────────────────────────────────────────────────────────────

import { useState, useRef, useCallback, useMemo } from 'react';
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

  const inputBorder = focused ? 'rgba(0,240,255,0.5)' : '#1F2937';
  const inputShadow = focused ? '0 0 0 3px rgba(0,240,255,0.07)' : 'none';
  const isDisabled = disabled || isLoading;

  // ── Render ────────────────────────────────────────────────

  return (
    <div className="relative">
      {/* Ambient top glow */}
      <div aria-hidden className="absolute inset-[-1px] rounded-2xl z-0 pointer-events-none"
        style={{ background: 'radial-gradient(ellipse at 50% 0%, rgba(0,240,255,0.07) 0%, transparent 65%)' }}
      />

      <form
        id="scanner-form"
        onSubmit={handleSubmit}
        aria-label="PhishLens threat scanner"
        className="relative z-[1] flex flex-col gap-4 sm:gap-5 p-3.5 sm:p-7 rounded-xl sm:rounded-2xl mobile-scanner-container"
        style={{
          background: '#111827',
          border: `1px solid ${isLoading ? 'rgba(0,240,255,0.4)' : '#1F2937'}`,
          boxShadow: '0 8px 40px rgba(0,0,0,0.5)',
          transition: 'border-color 0.3s',
        }}
      >
        {/* ── Header ────────────────────────────────────────── */}
        <div className="flex max-sm:flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mobile-header-stack">
          <div className="flex items-center gap-2.5 sm:gap-3.5">
            <div
              className="flex items-center justify-center shrink-0 w-9 h-9 sm:w-11 sm:h-11 rounded-[10px] text-lg sm:text-[22px]"
              style={{
                background: 'rgba(0,240,255,0.08)', border: '1px solid rgba(0,240,255,0.2)',
              }}
              aria-hidden
            >🛡️</div>
            <div>
              <h2
                className="text-sm sm:text-base md:text-lg font-extrabold text-[#F1F5F9] m-0"
                style={{
                  fontFamily: 'Plus Jakarta Sans, Inter, sans-serif',
                  letterSpacing: '-0.3px',
                }}
              >Threat Scanner</h2>
              <p className="text-[11px] sm:text-xs text-[#94A3B8] m-0" style={{ fontFamily: 'Inter, sans-serif' }}>
                Paste SMS · WhatsApp · Email · UPI prompt to inspect
              </p>
            </div>
          </div>
          {/* LIVE badge */}
          <div
            className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1 sm:py-1.5 rounded-full"
            style={{
              background: 'rgba(0,230,118,0.07)',
              border: '1px solid rgba(0,230,118,0.22)',
            }}
            aria-label="Scanner active"
          >
            <span aria-hidden className="inline-block shrink-0 w-2 h-2 rounded-full bg-[#00E676]" style={{
              boxShadow: '0 0 8px #00E676', animation: 'pl-pulse 2s ease-in-out infinite',
            }} />
            <span style={{
              fontSize: '11px', fontWeight: 700, color: '#00E676',
              letterSpacing: '0.6px', fontFamily: 'JetBrains Mono, monospace',
            }}>LIVE</span>
          </div>
        </div>

        {/* ── Preset buttons ─────────────────────────────────── */}
        <div>
          <p className="text-[10.5px] sm:text-xs mb-2 text-[#94A3B8] uppercase font-bold tracking-wider" style={{
            fontFamily: 'Inter, sans-serif',
          }}>Quick Load Scenarios</p>
          <div role="group" aria-label="Preset scenarios" className="flex flex-wrap gap-2">
            {PRESETS.map((p) => {
              const active = activePreset === p.id;
              return (
                <button
                  key={p.id}
                  id={`preset-${p.id}`}
                  type="button"
                  onClick={() => loadPreset(p)}
                  disabled={isDisabled}
                  aria-pressed={active}
                  className="flex items-center gap-1.5 px-3 sm:px-4 py-1.5 sm:py-2 rounded-lg text-xs sm:text-[12.5px] font-semibold cursor-pointer transition-all duration-150"
                  style={{
                    border: `1px solid ${active ? 'rgba(0,240,255,0.55)' : '#1F2937'}`,
                    background: active ? 'rgba(0,240,255,0.09)' : '#0B0F19',
                    color: active ? '#00F0FF' : '#CBD5E1',
                    fontFamily: 'Inter, sans-serif',
                    boxShadow: active ? '0 0 14px rgba(0,240,255,0.18)' : 'none',
                    opacity: isDisabled ? 0.4 : 1,
                  }}
                >
                  <span aria-hidden>{p.icon}</span>{p.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* ── Single Textarea ───────────────────────────────── */}
        <div>
          <label htmlFor="scanner-msg" className="block mb-2 text-[11px] font-semibold tracking-[0.9px] uppercase" style={{
            color: focused ? '#00F0FF' : '#94A3B8',
            transition: 'color 0.2s',
            fontFamily: 'Inter, sans-serif',
          }}>
            Message Content <span style={{ color: '#FF3366' }}>*</span>
          </label>
          <div className="relative">
            <textarea
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
              className="w-full resize-y text-[0.9rem] min-h-[100px] mobile-textarea"
              style={{
                fontSize: '0.9rem',
                minHeight: '100px',
                padding: '12px 14px',
                borderRadius: '10px',
                border: `1px solid ${inputBorder}`,
                background: '#0B0F19',
                color: '#F1F5F9',
                fontFamily: 'Inter, sans-serif',
                outline: 'none',
                boxShadow: inputShadow,
                transition: 'border-color 0.2s, box-shadow 0.2s',
                cursor: isDisabled ? 'not-allowed' : 'text',
                opacity: isDisabled ? 0.55 : 1,
                lineHeight: '1.65',
              }}
            />
          </div>

          {/* ── Dynamic Pill / Badge Below Textarea & Character Count ── */}
          <div className="mt-2.5 flex items-center justify-between flex-wrap gap-2">
            <div
              id="scanner-detected-pill"
              role="status"
              aria-live="polite"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold tracking-wide border transition-all duration-200"
              style={{
                background: 'rgba(0, 240, 255, 0.08)',
                borderColor: 'rgba(0, 240, 255, 0.35)',
                color: '#00F0FF',
                boxShadow: '0 0 12px rgba(0, 240, 255, 0.15)',
                fontFamily: 'JetBrains Mono, monospace',
              }}
            >
              <span>{detectedBadge}</span>
            </div>

            <span
              aria-live="polite"
              className="text-[11px]"
              style={{
                fontFamily: 'JetBrains Mono, monospace',
                color: charColor,
                transition: 'color 0.2s',
              }}
            >
              {content.length.toLocaleString()} / {MAX.toLocaleString()}
            </span>
          </div>
        </div>

        {/* ── Action row ─────────────────────────────────────── */}
        <div className="flex flex-col-reverse sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-3.5 sm:pt-4"
          style={{ borderTop: '1px solid #1F2937' }}
        >
          <button
            id="scanner-clear-btn"
            type="button"
            onClick={handleClear}
            disabled={isDisabled || !content}
            className="flex items-center justify-center gap-1.5 px-4 sm:px-5 py-2 sm:py-2.5 rounded-lg text-xs sm:text-sm font-medium cursor-pointer transition-all duration-150"
            style={{
              border: '1px solid #1F2937', background: 'transparent',
              color: '#94A3B8', fontFamily: 'Inter, sans-serif',
              opacity: isDisabled || !content ? 0.35 : 1,
            }}
          >
            <span aria-hidden>✕</span> Clear
          </button>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 sm:gap-3">
            {isLoading && (
              <span role="status" aria-live="assertive" className="flex items-center justify-center gap-2 text-xs"
                style={{
                  color: '#00F0FF', fontFamily: 'JetBrains Mono, monospace',
                  animation: 'pl-fadein 0.25s ease',
                }}
              >
                <svg aria-hidden width="16" height="16" viewBox="0 0 16 16" style={{ animation: 'pl-spin 1s linear infinite', flexShrink: 0 }}>
                  <circle cx="8" cy="8" r="6" stroke="rgba(0,240,255,0.2)" strokeWidth="2" fill="none"/>
                  <path d="M8 2a6 6 0 0 1 6 6" stroke="#00F0FF" strokeWidth="2" strokeLinecap="round" fill="none"/>
                </svg>
                Scanning 3 agents…
              </span>
            )}
            <button
              id="scanner-submit-btn"
              type="submit"
              disabled={isDisabled || !content.trim()}
              aria-label="Scan message for phishing threats"
              className="flex items-center justify-center gap-2 px-5 sm:px-7 py-2.5 sm:py-3 rounded-xl text-xs sm:text-sm font-extrabold cursor-pointer transition-all duration-200 overflow-hidden"
              style={{
                border: 'none',
                background: isDisabled || !content.trim()
                  ? '#1C2433'
                  : 'linear-gradient(135deg, #00D4E8 0%, #00F0FF 100%)',
                color: isDisabled || !content.trim() ? '#94A3B8' : '#030712',
                fontFamily: 'Plus Jakarta Sans, Inter, sans-serif',
                letterSpacing: '0.2px',
                boxShadow: !isDisabled && content.trim()
                  ? '0 0 24px rgba(0,240,255,0.4), 0 4px 12px rgba(0,0,0,0.4)'
                  : 'none',
              }}
            >
              {isLoading
                ? <><span aria-hidden>⟳</span> Analyzing…</>
                : <><span aria-hidden>⚡</span> Inspect &amp; Intercept</>
              }
            </button>
          </div>
        </div>
      </form>

      <style>{`
        @keyframes pl-pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.4;transform:scale(.75)} }
        @keyframes pl-spin   { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes pl-fadein { from{opacity:0;transform:translateX(6px)} to{opacity:1;transform:translateX(0)} }
      `}</style>
    </div>
  );
}

export default ScannerInput;
