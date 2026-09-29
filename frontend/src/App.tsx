// ────────────────────────────────────────────────────────────
//  PhishLens  ·  App  —  Full Dashboard
// ────────────────────────────────────────────────────────────

import './index.css';
import { useState } from 'react';
import { getUiTreatment } from './lib/api';
import type { ScanResponse } from './lib/types';

import { ScannerInput }      from './components/ScannerInput';
import { RiskGauge }         from './components/RiskGauge';
import { AuditTrailDrawer }  from './components/AuditTrailDrawer';
import { InterceptionModal } from './components/InterceptionModal';

// ── Component ─────────────────────────────────────────────────

export default function App() {
  const [result,     setResult]     = useState<ScanResponse | null>(null);
  const [isLoading,  setIsLoading]  = useState(false);
  const [error,      setError]      = useState<string | null>(null);
  const [showModal,  setShowModal]  = useState(false);
  const [scanCount,  setScanCount]  = useState(0);

  const treatment = result ? getUiTreatment(result.risk_tier, result.action_required) : null;

  // ── Scan handlers ─────────────────────────────────────────

  const handleScanComplete = (r: ScanResponse) => {
    setResult(r);
    setIsLoading(false);
    setScanCount(n => n + 1);
    const t = getUiTreatment(r.risk_tier, r.action_required);
    if (t.showModal) setShowModal(true);
  };

  const handleScanError = (err: Error) => {
    setError(err.message);
    setIsLoading(false);
  };

  const handleAbort = () => { setShowModal(false); };
  const handleProceed = () => { setShowModal(false); };

  // ── Layout ────────────────────────────────────────────────

  return (
    <div style={{ minHeight: '100svh', background: '#0B0F19', position: 'relative' }}>

      {/* ── Top nav bar ─────────────────────────────────────── */}
      <nav style={{
        position: 'sticky', top: 0, zIndex: 100,
        background: 'rgba(11,15,25,0.85)',
        backdropFilter: 'blur(12px)',
        borderBottom: '1px solid #1F2937',
        padding: '0 24px',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        height: '60px',
      }}>
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '24px' }} aria-hidden>🛡️</span>
          <div>
            <span style={{
              fontSize: '18px', fontWeight: 800,
              background: 'linear-gradient(135deg, #00F0FF 0%, #94A3B8 100%)',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
              fontFamily: 'Plus Jakarta Sans, Inter, sans-serif',
              letterSpacing: '-0.4px',
            }}>PhishLens</span>
            <span style={{
              marginLeft: '8px', fontSize: '10.5px', color: '#374151',
              fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.4px',
            }}>ScamShield AI</span>
          </div>
        </div>

        {/* Nav right — scan counter + status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          {scanCount > 0 && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              padding: '4px 12px', borderRadius: '16px',
              background: 'rgba(0,240,255,0.06)', border: '1px solid rgba(0,240,255,0.15)',
            }}>
              <span style={{ fontSize: '11px', color: '#4B5563', fontFamily: 'JetBrains Mono, monospace' }}>Scans:</span>
              <span style={{ fontSize: '13px', fontWeight: 700, color: '#00F0FF', fontFamily: 'JetBrains Mono, monospace' }}>
                {scanCount}
              </span>
            </div>
          )}

          {/* Current tier pill */}
          {treatment && (
            <div style={{
              padding: '4px 14px', borderRadius: '16px', fontSize: '11.5px', fontWeight: 700,
              fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.6px',
              color: treatment.accentColor,
              background: `${treatment.accentColor}12`,
              border: `1px solid ${treatment.accentColor}35`,
              transition: 'all 0.4s ease',
            }}>
              {treatment.label}
            </div>
          )}

          <div style={{
            width: '8px', height: '8px', borderRadius: '50%',
            background: isLoading ? '#FFB800' : '#00E676',
            boxShadow: isLoading ? '0 0 8px #FFB800' : '0 0 8px #00E676',
            animation: isLoading ? 'pl-pulse 0.8s ease-in-out infinite' : 'none',
            transition: 'all 0.3s',
          }} aria-hidden />
        </div>
      </nav>

      {/* ── Page body ───────────────────────────────────────── */}
      <main style={{ maxWidth: '1280px', margin: '0 auto', padding: '32px 20px 80px' }}>

        {/* Hero tag line */}
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <p style={{
            display: 'inline-flex', alignItems: 'center', gap: '8px',
            padding: '5px 16px', borderRadius: '20px', fontSize: '12px',
            fontFamily: 'JetBrains Mono, monospace', fontWeight: 600, letterSpacing: '0.5px',
            color: '#00F0FF', background: 'rgba(0,240,255,0.07)', border: '1px solid rgba(0,240,255,0.18)',
            marginBottom: '16px',
          }}>
            <span aria-hidden>▸</span> Real-time Multi-Agent Threat Interception
          </p>
          <h1 style={{
            margin: '0 0 12px', fontSize: 'clamp(28px, 5vw, 44px)', fontWeight: 800,
            fontFamily: 'Plus Jakarta Sans, Inter, sans-serif',
            background: 'linear-gradient(135deg, #F1F5F9 30%, #94A3B8 100%)',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            letterSpacing: '-0.8px', lineHeight: 1.15,
          }}>
            Detect Scams Before<br />They Reach You
          </h1>
          <p style={{
            margin: '0 auto', fontSize: '15px', color: '#4B5563',
            fontFamily: 'Inter, sans-serif', maxWidth: '480px',
          }}>
            Powered by 3 parallel AI agents — URL analysis, sender verification, and psycholinguistic intent detection.
          </p>
        </div>

        {/* ── Main 2-col grid ────────────────────────────────── */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: result ? 'minmax(0,1fr) 300px' : '1fr',
          gap: '24px',
          alignItems: 'start',
          transition: 'grid-template-columns 0.4s ease',
        }}>
          {/* Left column — Scanner + Audit */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            {/* Scanner */}
            <ScannerInput
              onScanComplete={handleScanComplete}
              onScanError={handleScanError}
              disabled={isLoading || showModal}
            />

            {/* Loading skeleton */}
            {isLoading && !result && (
              <div style={{
                background: '#111827', border: '1px solid #1F2937', borderRadius: '16px',
                padding: '28px', display: 'flex', flexDirection: 'column', gap: '14px',
              }}>
                {[1, 2, 3].map(i => (
                  <div key={i} style={{
                    height: '18px', borderRadius: '9px',
                    background: 'linear-gradient(90deg, #1F2937 0%, #374151 50%, #1F2937 100%)',
                    backgroundSize: '200% 100%',
                    animation: 'pl-shimmer 1.5s ease-in-out infinite',
                    width: i === 3 ? '60%' : '100%',
                  }} aria-hidden />
                ))}
              </div>
            )}

            {/* Error banner */}
            {error && (
              <div role="alert" style={{
                padding: '14px 18px', borderRadius: '10px',
                border: '1px solid rgba(255,51,102,0.35)',
                background: 'rgba(255,51,102,0.07)',
                color: '#FF3366', fontSize: '13px',
                fontFamily: 'JetBrains Mono, monospace',
                display: 'flex', alignItems: 'center', gap: '8px',
              }}>
                <span aria-hidden>⚠</span> {error}
              </div>
            )}

            {/* Audit Trail */}
            {result && (
              <AuditTrailDrawer
                auditTrail={result.audit_trail}
                recommendation={result.recommendation}
              />
            )}
          </div>

          {/* Right column — Risk Gauge (only when result exists) */}
          {result && (
            <div style={{ position: 'sticky', top: '80px' }}>
              <RiskGauge result={result} isLoading={isLoading} />
            </div>
          )}
        </div>

        {/* ── Empty state ──────────────────────────────────── */}
        {!result && !isLoading && !error && (
          <div style={{
            marginTop: '40px', textAlign: 'center',
            display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px',
          }}>
            <div style={{
              width: '80px', height: '80px', borderRadius: '20px', fontSize: '40px',
              background: 'rgba(0,240,255,0.05)', border: '1px solid rgba(0,240,255,0.12)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>🔍</div>
            <p style={{ margin: 0, fontSize: '14px', color: '#374151', fontFamily: 'Inter, sans-serif' }}>
              Load a preset scenario or paste your own message above to begin scanning.
            </p>
          </div>
        )}
      </main>

      {/* ── Footer ──────────────────────────────────────────── */}
      <footer style={{
        borderTop: '1px solid #1F2937', padding: '16px 24px',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        flexWrap: 'wrap', gap: '8px',
      }}>
        <span style={{ fontSize: '11.5px', color: '#374151', fontFamily: 'JetBrains Mono, monospace' }}>
          PhishLens · ScamShield AI · TechExpo 2026
        </span>
        <span style={{ fontSize: '11.5px', color: '#374151', fontFamily: 'JetBrains Mono, monospace' }}>
          Agents: Atharv · Avni · Vikas · Avika
        </span>
      </footer>

      {/* ── Interception Modal ───────────────────────────────── */}
      {showModal && result && (
        <InterceptionModal
          result={result}
          onAbort={handleAbort}
          onProceedAnyway={handleProceed}
        />
      )}

      {/* ── Global animation keyframes ─────────────────────── */}
      <style>{`
        @keyframes pl-pulse   { 0%,100%{opacity:1} 50%{opacity:.35} }
        @keyframes pl-shimmer { 0%{background-position:200% 0} 100%{background-position:-200% 0} }
      `}</style>
    </div>
  );
}
