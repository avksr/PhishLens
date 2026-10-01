// ────────────────────────────────────────────────────────────
//  PhishLens  ·  App  —  Full Dashboard  (Day 4 Revision)
//  + Bilingual toggle (EN / HI) + responsive layout
// ────────────────────────────────────────────────────────────

import './index.css';
import { useState } from 'react';
import { getUiTreatment } from './lib/api';
import type { ScanResponse, Language } from './lib/types';

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
  const [lang,       setLang]       = useState<Language>('en');

  const treatment = result ? getUiTreatment(result.risk_tier, result.action_required) : null;

  // ── Bilingual helpers ──────────────────────────────────────

  const resolveVerdict = (r: ScanResponse): string =>
    (lang === 'hi' && r.verdict_hi) ? r.verdict_hi : r.verdict;

  const resolveRecommendation = (r: ScanResponse): string =>
    (lang === 'hi' && r.recommendation_hi) ? r.recommendation_hi : r.recommendation;

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
    <div className="min-h-svh relative" style={{ background: '#0B0F19' }}>

      {/* ── Top nav bar ─────────────────────────────────────── */}
      <nav className="sticky top-0 z-[100] flex items-center justify-between px-4 sm:px-6 h-[60px]"
        style={{
          background: 'rgba(11,15,25,0.85)',
          backdropFilter: 'blur(12px)',
          borderBottom: '1px solid #1F2937',
        }}
      >
        {/* Logo */}
        <div className="flex items-center gap-2.5">
          <span className="text-2xl" aria-hidden>🛡️</span>
          <div>
            <span style={{
              fontSize: '18px', fontWeight: 800,
              background: 'linear-gradient(135deg, #00F0FF 0%, #94A3B8 100%)',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
              fontFamily: 'Plus Jakarta Sans, Inter, sans-serif',
              letterSpacing: '-0.4px',
            }}>PhishLens</span>
            <span className="hidden sm:inline-block ml-2 text-[10.5px]" style={{
              color: '#6B7280',
              fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.4px',
            }}>ScamShield AI</span>
          </div>
        </div>

        {/* Nav right — lang toggle + scan counter + status */}
        <div className="flex items-center gap-2.5 sm:gap-4">
          {/* ── Language Toggle ─────────────────────────────── */}
          <button
            id="lang-toggle-btn"
            type="button"
            onClick={() => setLang(prev => prev === 'en' ? 'hi' : 'en')}
            aria-label={`Switch language to ${lang === 'en' ? 'Hindi' : 'English'}`}
            className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-full cursor-pointer transition-all duration-200"
            style={{
              background: 'rgba(0,240,255,0.06)',
              border: '1px solid rgba(0,240,255,0.2)',
              fontSize: '12px', fontWeight: 600,
              fontFamily: 'Inter, sans-serif',
              color: '#00F0FF',
            }}
          >
            <span aria-hidden className="text-sm">{lang === 'en' ? '🇬🇧' : '🇮🇳'}</span>
            <span className="hidden sm:inline">{lang === 'en' ? 'EN' : 'हिंदी'}</span>
          </button>

          {scanCount > 0 && (
            <div className="hidden sm:flex items-center gap-1.5 px-3 py-1 rounded-2xl"
              style={{
                background: 'rgba(0,240,255,0.06)', border: '1px solid rgba(0,240,255,0.15)',
              }}
            >
              <span style={{ fontSize: '11px', color: '#94A3B8', fontFamily: 'JetBrains Mono, monospace' }}>
                {lang === 'hi' ? 'स्कैन:' : 'Scans:'}
              </span>
              <span style={{ fontSize: '13px', fontWeight: 700, color: '#00F0FF', fontFamily: 'JetBrains Mono, monospace' }}>
                {scanCount}
              </span>
            </div>
          )}

          {/* Current tier pill */}
          {treatment && (
            <div className="hidden sm:block px-3.5 py-1 rounded-2xl text-[11.5px] font-bold tracking-wider transition-all duration-400"
              style={{
                fontFamily: 'JetBrains Mono, monospace',
                color: treatment.accentColor,
                background: `${treatment.accentColor}12`,
                border: `1px solid ${treatment.accentColor}35`,
              }}
            >
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
      <main className="max-w-[1280px] mx-auto px-4 sm:px-5 pt-6 sm:pt-8 pb-20">

        {/* Hero tag line */}
        <div className="text-center mb-8 sm:mb-10">
          <p className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full text-xs mb-4"
            style={{
              fontFamily: 'JetBrains Mono, monospace', fontWeight: 600, letterSpacing: '0.5px',
              color: '#00F0FF', background: 'rgba(0,240,255,0.07)', border: '1px solid rgba(0,240,255,0.18)',
            }}
          >
            <span aria-hidden>▸</span>
            {lang === 'hi' ? 'रियल-टाइम मल्टी-एजेंट थ्रेट इंटरसेप्शन' : 'Real-time Multi-Agent Threat Interception'}
          </p>
          <h1 className="text-[clamp(24px,5vw,44px)] font-extrabold mb-3 leading-[1.15]"
            style={{
              margin: '0 0 12px',
              fontFamily: 'Plus Jakarta Sans, Inter, sans-serif',
              background: 'linear-gradient(135deg, #F1F5F9 30%, #94A3B8 100%)',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
              letterSpacing: '-0.8px',
            }}
          >
            {lang === 'hi' ? <>स्कैम का पता लगाएं<br />इससे पहले कि वे आप तक पहुंचें</> : <>Detect Scams Before<br />They Reach You</>}
          </h1>
          <p className="text-sm sm:text-[15px] mx-auto max-w-[480px]"
            style={{ margin: '0 auto', color: '#94A3B8', fontFamily: 'Inter, sans-serif' }}
          >
            {lang === 'hi'
              ? '3 समानांतर AI एजेंटों द्वारा संचालित — URL विश्लेषण, प्रेषक सत्यापन, और मनोभाषाई इरादा पहचान।'
              : 'Powered by 3 parallel AI agents — URL analysis, sender verification, and psycholinguistic intent detection.'}
          </p>
        </div>

        {/* ── Main grid ────────────────────────────────────── */}
        <div
          className="grid gap-5 sm:gap-6 items-start"
          style={{
            gridTemplateColumns: result ? 'minmax(0,1fr) 300px' : '1fr',
            transition: 'grid-template-columns 0.4s ease',
          }}
        >
          {/* Left column — Scanner + Audit */}
          <div className="flex flex-col gap-5 sm:gap-6 min-w-0">
            {/* Scanner */}
            <ScannerInput
              onScanComplete={handleScanComplete}
              onScanError={handleScanError}
              disabled={isLoading || showModal}
            />

            {/* Loading skeleton */}
            {isLoading && !result && (
              <div className="flex flex-col gap-3.5 p-6 sm:p-7 rounded-2xl"
                style={{ background: '#111827', border: '1px solid #1F2937' }}
              >
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
              <div role="alert" className="flex items-center gap-2 px-4 py-3.5 rounded-lg text-[13px]"
                style={{
                  border: '1px solid rgba(255,51,102,0.35)',
                  background: 'rgba(255,51,102,0.07)',
                  color: '#FF3366',
                  fontFamily: 'JetBrains Mono, monospace',
                }}
              >
                <span aria-hidden>⚠</span> {error}
              </div>
            )}

            {/* ── HIGH_RISK inline warning card ── */}
            {result && result.risk_tier === 'HIGH_RISK' && (
              <div
                role="alert"
                className="p-5 rounded-[14px]"
                style={{
                  background: '#0B0F19',
                  border: '1px solid #FF6B0055',
                  boxShadow: '0 0 24px rgba(255,107,0,0.12), 0 4px 20px rgba(0,0,0,0.5)',
                  animation: 'pl-fadein 0.35s ease',
                }}
              >
                {/* Header row */}
                <div className="flex items-center justify-between mb-3.5 flex-wrap gap-2">
                  <div className="flex items-center gap-2.5">
                    <div style={{
                      width: 40, height: 40, borderRadius: '10px', fontSize: '20px',
                      background: 'rgba(255,107,0,0.12)', border: '1px solid rgba(255,107,0,0.35)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }} aria-hidden>⚠️</div>
                    <div>
                      <p className="text-[15px] font-extrabold" style={{
                        margin: 0, color: '#F1F5F9',
                        fontFamily: 'Plus Jakarta Sans, Inter, sans-serif',
                      }}>
                        {lang === 'hi' ? 'उच्च जोखिम का पता चला' : 'HIGH RISK DETECTED'}
                      </p>
                      <p style={{ margin: 0, fontSize: '11px', color: '#94A3B8', fontFamily: 'JetBrains Mono, monospace' }}>
                        {lang === 'hi' ? 'स्कोर' : 'Score'}: {result.overall_risk_score}/100 · {result.processing_time_ms.toFixed(0)}ms
                      </p>
                    </div>
                  </div>
                  <div className="px-3 py-1.5 rounded-2xl text-[11px] font-extrabold tracking-wider"
                    style={{
                      fontFamily: 'JetBrains Mono, monospace',
                      color: '#FF6B00', background: 'rgba(255,107,0,0.12)',
                      border: '1px solid rgba(255,107,0,0.35)',
                    }}
                  >
                    HIGH RISK
                  </div>
                </div>

                {/* Recommendation */}
                <div className="p-3 sm:p-3.5 rounded-lg mb-3.5" style={{
                  background: 'rgba(255,107,0,0.06)', border: '1px solid rgba(255,107,0,0.2)',
                }}>
                  <p className="text-[13px] leading-relaxed font-medium" style={{
                    margin: 0, color: '#F1F5F9', fontFamily: 'Inter, sans-serif',
                  }}>
                    {resolveRecommendation(result)}
                  </p>
                </div>

                {/* Verdict */}
                <p className="text-xs p-2.5 sm:p-3 rounded-lg leading-relaxed" style={{
                  margin: 0, color: '#CBD5E1',
                  fontFamily: 'JetBrains Mono, monospace',
                  background: '#111827', border: '1px solid #1F2937',
                }}>
                  <span style={{ color: '#94A3B8' }}>{lang === 'hi' ? 'फैसला: ' : 'verdict: '}</span>
                  {resolveVerdict(result)}
                </p>
              </div>
            )}

            {/* Audit Trail */}
            {result && (
              <AuditTrailDrawer
                auditTrail={result.audit_trail}
                recommendation={resolveRecommendation(result)}
                processingTimeMs={result.processing_time_ms}
                lang={lang}
              />
            )}
          </div>

          {/* Right column — Risk Gauge (only when result exists) */}
          {result && (
            <div className="sticky top-[80px] hidden sm:block">
              <RiskGauge result={result} isLoading={isLoading} />
            </div>
          )}
        </div>

        {/* Mobile Risk Gauge — shown below scanner on small screens */}
        {result && (
          <div className="block sm:hidden mt-5">
            <RiskGauge result={result} isLoading={isLoading} />
          </div>
        )}

        {/* ── Empty state ──────────────────────────────────── */}
        {!result && !isLoading && !error && (
          <div className="mt-8 sm:mt-10 text-center flex flex-col items-center gap-4">
            <div className="flex items-center justify-center" style={{
              width: '80px', height: '80px', borderRadius: '20px', fontSize: '40px',
              background: 'rgba(0,240,255,0.05)', border: '1px solid rgba(0,240,255,0.12)',
            }}>🔍</div>
            <p className="text-sm" style={{ margin: 0, color: '#6B7280', fontFamily: 'Inter, sans-serif' }}>
              {lang === 'hi'
                ? 'स्कैनिंग शुरू करने के लिए ऊपर एक प्रीसेट परिदृश्य लोड करें या अपना संदेश पेस्ट करें।'
                : 'Load a preset scenario or paste your own message above to begin scanning.'}
            </p>
          </div>
        )}
      </main>

      {/* ── Footer ──────────────────────────────────────────── */}
      <footer className="flex items-center justify-between flex-wrap gap-2 px-4 sm:px-6 py-4"
        style={{ borderTop: '1px solid #1F2937' }}
      >
        <span className="text-[11.5px]" style={{ color: '#6B7280', fontFamily: 'JetBrains Mono, monospace' }}>
          PhishLens · ScamShield AI · TechExpo 2026
        </span>
        <span className="text-[11.5px]" style={{ color: '#6B7280', fontFamily: 'JetBrains Mono, monospace' }}>
          Agents: Atharv · Avni · Vikas · Avika
        </span>
      </footer>

      {/* ── Interception Modal ───────────────────────────────── */}
      {showModal && result && (
        <InterceptionModal
          result={result}
          lang={lang}
          onAbort={handleAbort}
          onProceedAnyway={handleProceed}
        />
      )}

      {/* ── Global animation keyframes ─────────────────────── */}
      <style>{`
        @keyframes pl-pulse   { 0%,100%{opacity:1} 50%{opacity:.35} }
        @keyframes pl-shimmer { 0%{background-position:200% 0} 100%{background-position:-200% 0} }
        @keyframes pl-fadein  { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
      `}</style>
    </div>
  );
}
