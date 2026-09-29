// ────────────────────────────────────────────────────────────
//  PhishLens  ·  ScannerInput Component
//  Ingestion bar — textarea + sender + channel + presets
// ────────────────────────────────────────────────────────────

import { useState, useRef, useCallback } from 'react';
import { scanMessage } from '../lib/api';
import type { ScanResponse, ScanRequest, Channel } from '../lib/types';
import highRisk from '../../../datasets/payloads_high_risk.json';
import safe     from '../../../datasets/payloads_safe.json';

// ── Presets (pulled from actual datasets) ─────────────────────

interface Preset {
  id: string;
  label: string;
  icon: string;
  payload: ScanRequest;
}

const PRESETS: Preset[] = [
  {
    id: 'sbi-kyc',
    label: 'SBI KYC Scam',
    icon: '🚨',
    payload: highRisk[0].payload as ScanRequest,
  },
  {
    id: 'electricity',
    label: 'Electricity Threat',
    icon: '⚡',
    payload: highRisk[1].payload as ScanRequest,
  },
  {
    id: 'hdfc-otp',
    label: 'Legit Bank OTP',
    icon: '🛡️',
    payload: safe[0].payload as ScanRequest,
  },
];

const CHANNELS: { value: Channel; label: string; icon: string }[] = [
  { value: 'sms',        label: 'SMS',       icon: '💬' },
  { value: 'whatsapp',   label: 'WhatsApp',  icon: '📱' },
  { value: 'email',      label: 'Email',     icon: '📧' },
  { value: 'qr_payment', label: 'QR Pay',    icon: '📷' },
  { value: 'web_url',    label: 'Web URL',   icon: '🌐' },
  { value: 'unknown',    label: 'Unknown',   icon: '❓' },
];

// ── Props ─────────────────────────────────────────────────────

export interface ScannerInputProps {
  onScanComplete: (result: ScanResponse) => void;
  onScanError?: (err: Error) => void;
  disabled?: boolean;
}

// ── CSS helpers (scoped inline, no Tailwind class conflicts) ──

const s = {
  label: (active: boolean): React.CSSProperties => ({
    display: 'block',
    marginBottom: '8px',
    fontSize: '11px',
    fontWeight: 600,
    letterSpacing: '0.9px',
    textTransform: 'uppercase' as const,
    color: active ? '#00F0FF' : '#4B5563',
    transition: 'color 0.2s',
    fontFamily: 'Inter, sans-serif',
  }),
  input: (focused: boolean, disabled: boolean): React.CSSProperties => ({
    width: '100%',
    padding: '12px 16px',
    borderRadius: '10px',
    border: `1px solid ${focused ? 'rgba(0,240,255,0.5)' : '#1F2937'}`,
    background: '#0B0F19',
    color: '#F1F5F9',
    fontSize: '13px',
    fontFamily: 'Inter, sans-serif',
    outline: 'none',
    boxShadow: focused ? '0 0 0 3px rgba(0,240,255,0.07)' : 'none',
    transition: 'border-color 0.2s, box-shadow 0.2s',
    cursor: disabled ? 'not-allowed' : 'text',
    opacity: disabled ? 0.55 : 1,
  }),
};

// ── Component ─────────────────────────────────────────────────

export function ScannerInput({ onScanComplete, onScanError, disabled = false }: ScannerInputProps) {
  const [content,      setContent]      = useState('');
  const [sender,       setSender]       = useState('');
  const [channel,      setChannel]      = useState<Channel>('sms');
  const [isLoading,    setIsLoading]    = useState(false);
  const [activePreset, setActivePreset] = useState<string | null>(null);
  const [focused,      setFocused]      = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const MAX = 8000;
  const charFrac = content.length / MAX;
  const charColor = charFrac > 0.9 ? '#FF3366' : charFrac > 0.75 ? '#FF6B00' : '#4B5563';

  // ── Preset loader ─────────────────────────────────────────

  const loadPreset = useCallback((preset: Preset) => {
    setContent(preset.payload.content);
    setSender(preset.payload.sender ?? '');
    setChannel((preset.payload.channel as Channel) ?? 'sms');
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
        sender: sender.trim() || undefined,
        channel,
      });
      onScanComplete(result);
    } catch (err) {
      onScanError?.(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  };

  const handleClear = () => {
    setContent(''); setSender(''); setChannel('sms'); setActivePreset(null);
    textareaRef.current?.focus();
  };

  // ── Render ────────────────────────────────────────────────

  return (
    <div style={{ position: 'relative' }}>
      {/* Ambient top glow */}
      <div aria-hidden style={{
        position: 'absolute', inset: '-1px', borderRadius: '16px', zIndex: 0, pointerEvents: 'none',
        background: 'radial-gradient(ellipse at 50% 0%, rgba(0,240,255,0.07) 0%, transparent 65%)',
      }} />

      <form
        id="scanner-form"
        onSubmit={handleSubmit}
        aria-label="PhishLens threat scanner"
        style={{
          position: 'relative', zIndex: 1,
          background: '#111827', borderRadius: '16px',
          border: `1px solid ${isLoading ? 'rgba(0,240,255,0.4)' : '#1F2937'}`,
          padding: '28px', display: 'flex', flexDirection: 'column', gap: '22px',
          boxShadow: '0 8px 40px rgba(0,0,0,0.5)',
          transition: 'border-color 0.3s',
        }}
      >
        {/* ── Header ────────────────────────────────────────── */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div style={{
              width: 44, height: 44, borderRadius: '11px', fontSize: '22px',
              background: 'rgba(0,240,255,0.08)', border: '1px solid rgba(0,240,255,0.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }} aria-hidden>🛡️</div>
            <div>
              <h2 style={{
                margin: 0, fontSize: '19px', fontWeight: 800, color: '#F1F5F9',
                fontFamily: 'Plus Jakarta Sans, Inter, sans-serif', letterSpacing: '-0.3px',
              }}>Threat Scanner</h2>
              <p style={{ margin: 0, fontSize: '12px', color: '#4B5563', fontFamily: 'Inter, sans-serif' }}>
                Paste SMS · WhatsApp · Email · UPI prompt to inspect
              </p>
            </div>
          </div>
          {/* LIVE badge */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: '7px',
            padding: '5px 12px', borderRadius: '20px',
            background: 'rgba(0,230,118,0.07)', border: '1px solid rgba(0,230,118,0.22)',
          }} aria-label="Scanner active">
            <span aria-hidden style={{
              width: 8, height: 8, borderRadius: '50%', background: '#00E676',
              boxShadow: '0 0 8px #00E676', animation: 'pl-pulse 2s ease-in-out infinite',
              display: 'inline-block',
            }} />
            <span style={{
              fontSize: '11px', fontWeight: 700, color: '#00E676',
              letterSpacing: '0.6px', fontFamily: 'JetBrains Mono, monospace',
            }}>LIVE</span>
          </div>
        </div>

        {/* ── Preset buttons ─────────────────────────────────── */}
        <div>
          <p style={{
            margin: '0 0 10px', fontSize: '10.5px', fontWeight: 700,
            letterSpacing: '1px', color: '#374151', textTransform: 'uppercase',
            fontFamily: 'Inter, sans-serif',
          }}>Quick Load Scenarios</p>
          <div role="group" aria-label="Preset scenarios" style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {PRESETS.map((p) => {
              const active = activePreset === p.id;
              return (
                <button
                  key={p.id}
                  id={`preset-${p.id}`}
                  type="button"
                  onClick={() => loadPreset(p)}
                  disabled={disabled || isLoading}
                  aria-pressed={active}
                  style={{
                    display: 'flex', alignItems: 'center', gap: '6px',
                    padding: '8px 16px', borderRadius: '9px', cursor: 'pointer',
                    border: `1px solid ${active ? 'rgba(0,240,255,0.55)' : '#1F2937'}`,
                    background: active ? 'rgba(0,240,255,0.09)' : '#0B0F19',
                    color: active ? '#00F0FF' : '#6B7280',
                    fontSize: '12.5px', fontWeight: 600, fontFamily: 'Inter, sans-serif',
                    boxShadow: active ? '0 0 14px rgba(0,240,255,0.18)' : 'none',
                    transition: 'all 0.18s ease',
                    opacity: disabled || isLoading ? 0.4 : 1,
                  }}
                  onMouseEnter={e => {
                    if (!active && !disabled && !isLoading) {
                      const el = e.currentTarget;
                      el.style.borderColor = 'rgba(0,240,255,0.2)';
                      el.style.color = '#94A3B8';
                    }
                  }}
                  onMouseLeave={e => {
                    if (!active) {
                      const el = e.currentTarget;
                      el.style.borderColor = '#1F2937';
                      el.style.color = '#6B7280';
                    }
                  }}
                >
                  <span aria-hidden>{p.icon}</span>{p.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* ── Textarea ───────────────────────────────────────── */}
        <div>
          <label htmlFor="scanner-msg" style={s.label(focused === 'msg')}>
            Message Content <span style={{ color: '#FF3366' }}>*</span>
          </label>
          <div style={{ position: 'relative' }}>
            <textarea
              id="scanner-msg"
              ref={textareaRef}
              value={content}
              onChange={e => { setContent(e.target.value.slice(0, MAX)); setActivePreset(null); }}
              onFocus={() => setFocused('msg')}
              onBlur={() => setFocused(null)}
              disabled={disabled || isLoading}
              required
              rows={6}
              placeholder="Paste the suspicious SMS, WhatsApp message, email body, or UPI payment note here…"
              style={{
                ...s.input(focused === 'msg', disabled || isLoading),
                resize: 'vertical', minHeight: '148px', lineHeight: '1.65',
                paddingBottom: '28px',
              }}
            />
            <span aria-live="polite" style={{
              position: 'absolute', bottom: '10px', right: '14px',
              fontSize: '10.5px', fontFamily: 'JetBrains Mono, monospace',
              color: charColor, transition: 'color 0.2s', pointerEvents: 'none',
            }}>
              {content.length.toLocaleString()} / {MAX.toLocaleString()}
            </span>
          </div>
        </div>

        {/* ── Sender + Channel ───────────────────────────────── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 140px', gap: '14px', alignItems: 'start' }}>
          <div>
            <label htmlFor="scanner-sender" style={s.label(focused === 'sender')}>
              Sender Identifier
              <span style={{ color: '#374151', fontWeight: 400, letterSpacing: 0, textTransform: 'none', marginLeft: '6px', fontSize: '11px' }}>(optional)</span>
            </label>
            <div style={{ position: 'relative' }}>
              <span aria-hidden style={{
                position: 'absolute', left: '13px', top: '50%', transform: 'translateY(-50%)',
                fontSize: '15px', pointerEvents: 'none',
              }}>📡</span>
              <input
                id="scanner-sender"
                type="text"
                value={sender}
                onChange={e => { setSender(e.target.value); setActivePreset(null); }}
                onFocus={() => setFocused('sender')}
                onBlur={() => setFocused(null)}
                disabled={disabled || isLoading}
                placeholder="+91-9876543210 or VM-SBIINB"
                style={{ ...s.input(focused === 'sender', disabled || isLoading), paddingLeft: '38px', fontFamily: 'JetBrains Mono, monospace', fontSize: '12.5px' }}
              />
            </div>
            <p style={{ margin: '6px 0 0', fontSize: '11px', color: '#374151', fontFamily: 'Inter, sans-serif' }}>
              Phone number, TRAI DLT header, or email address
            </p>
          </div>
          <div>
            <label htmlFor="scanner-channel" style={s.label(focused === 'ch')}>Channel</label>
            <select
              id="scanner-channel"
              value={channel}
              onChange={e => setChannel(e.target.value as Channel)}
              onFocus={() => setFocused('ch')}
              onBlur={() => setFocused(null)}
              disabled={disabled || isLoading}
              style={{
                ...s.input(focused === 'ch', disabled || isLoading),
                appearance: 'none' as const,
                backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='11' height='7' viewBox='0 0 11 7'%3E%3Cpath d='M1 1l4.5 4.5L10 1' stroke='%234B5563' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E")`,
                backgroundRepeat: 'no-repeat',
                backgroundPosition: 'right 12px center',
                paddingRight: '32px',
                cursor: disabled || isLoading ? 'not-allowed' : 'pointer',
              }}
            >
              {CHANNELS.map(ch => (
                <option key={ch.value} value={ch.value}>{ch.icon} {ch.label}</option>
              ))}
            </select>
          </div>
        </div>

        {/* ── Action row ─────────────────────────────────────── */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px',
          paddingTop: '16px', borderTop: '1px solid #1F2937',
        }}>
          <button
            id="scanner-clear-btn"
            type="button"
            onClick={handleClear}
            disabled={disabled || isLoading || (!content && !sender)}
            style={{
              padding: '10px 20px', borderRadius: '9px',
              border: '1px solid #1F2937', background: 'transparent',
              color: '#4B5563', fontSize: '13px', fontFamily: 'Inter, sans-serif',
              fontWeight: 500, cursor: 'pointer', transition: 'all 0.18s',
              opacity: disabled || isLoading || (!content && !sender) ? 0.35 : 1,
              display: 'flex', alignItems: 'center', gap: '6px',
            }}
          >
            <span aria-hidden>✕</span> Clear
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            {isLoading && (
              <span role="status" aria-live="assertive" style={{
                display: 'flex', alignItems: 'center', gap: '8px',
                fontSize: '12px', color: '#00F0FF', fontFamily: 'JetBrains Mono, monospace',
                animation: 'pl-fadein 0.25s ease',
              }}>
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
              disabled={disabled || isLoading || !content.trim()}
              aria-label="Scan message for phishing threats"
              style={{
                padding: '12px 28px', borderRadius: '10px', border: 'none',
                background: disabled || isLoading || !content.trim()
                  ? '#1C2433'
                  : 'linear-gradient(135deg, #00D4E8 0%, #00F0FF 100%)',
                color: disabled || isLoading || !content.trim() ? '#374151' : '#030712',
                fontSize: '14px', fontWeight: 800,
                fontFamily: 'Plus Jakarta Sans, Inter, sans-serif',
                letterSpacing: '0.2px', cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: '8px',
                boxShadow: !disabled && !isLoading && content.trim()
                  ? '0 0 24px rgba(0,240,255,0.4), 0 4px 12px rgba(0,0,0,0.4)'
                  : 'none',
                transition: 'all 0.22s ease',
                transform: 'translateY(0)',
                position: 'relative', overflow: 'hidden',
              }}
              onMouseEnter={e => {
                if (!disabled && !isLoading && content.trim()) {
                  e.currentTarget.style.transform = 'translateY(-1px)';
                  e.currentTarget.style.boxShadow = '0 0 32px rgba(0,240,255,0.55), 0 6px 16px rgba(0,0,0,0.5)';
                }
              }}
              onMouseLeave={e => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = !disabled && !isLoading && content.trim()
                  ? '0 0 24px rgba(0,240,255,0.4), 0 4px 12px rgba(0,0,0,0.4)' : 'none';
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
