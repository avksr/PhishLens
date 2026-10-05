// ────────────────────────────────────────────────────────────
//  PhishLens  ·  RiskGauge Component
//  Animated 0–100 semi-circle speedometer with tier coloring
// ────────────────────────────────────────────────────────────

import { useEffect, useRef, useState } from 'react';
import type { RiskTier, ScanResponse } from '../lib/types';

// ── Score → Color ─────────────────────────────────────────────

function scoreToColor(score: number): string {
  if (score <= 24) return '#00E676';  // SAFE    — Terminal Green
  if (score <= 49) return '#FFB800';  // CAUTION — Warning Amber
  if (score <= 77) return '#FF6B00';  // HIGH    — Safety Orange
  return '#FF3366';                   // CRITICAL — Alert Crimson
}

function tierLabel(tier: RiskTier): string {
  switch (tier) {
    case 'SAFE':      return 'SAFE';
    case 'CAUTION':   return 'CAUTION';
    case 'HIGH_RISK': return 'HIGH RISK';
    case 'CRITICAL':  return 'CRITICAL';
  }
}

// ── SVG Arc math ──────────────────────────────────────────────

const CX = 110, CY = 110, R = 88;


function degToRad(d: number) { return (d * Math.PI) / 180; }

function arcPoint(deg: number) {
  const rad = degToRad(deg);
  return { x: CX + R * Math.cos(rad), y: CY + R * Math.sin(rad) };
}

function buildArc(fromDeg: number, toDeg: number, r: number): string {
  const from = arcPoint(fromDeg);
  const to   = arcPoint(toDeg);
  const sweep = ((toDeg - fromDeg + 360) % 360) > 180 ? 1 : 0;
  return `M ${from.x} ${from.y} A ${r} ${r} 0 ${sweep} 1 ${to.x} ${to.y}`;
}

// Score → degrees along the 240° sweep arc (start at 210°)
function scoreToDeg(score: number): number {
  return 210 + (score / 100) * 240;
}

// ── Tick marks ────────────────────────────────────────────────

const TICKS = [0, 25, 50, 75, 100];

function Tick({ score, active }: { score: number; active: boolean }) {
  const deg = scoreToDeg(score);
  const inner = { x: CX + (R - 10) * Math.cos(degToRad(deg)), y: CY + (R - 10) * Math.sin(degToRad(deg)) };
  const outer = { x: CX + (R + 4)  * Math.cos(degToRad(deg)), y: CY + (R + 4)  * Math.sin(degToRad(deg)) };
  const label = { x: CX + (R + 18) * Math.cos(degToRad(deg)), y: CY + (R + 18) * Math.sin(degToRad(deg)) };
  return (
    <g>
      <line x1={inner.x} y1={inner.y} x2={outer.x} y2={outer.y}
        stroke={active ? '#94A3B8' : '#374151'} strokeWidth="1.5" strokeLinecap="round" />
      <text x={label.x} y={label.y} textAnchor="middle" dominantBaseline="middle"
        fill={active ? '#CBD5E1' : '#94A3B8'}
        fontSize="9" fontFamily="JetBrains Mono, monospace">{score}</text>
    </g>
  );
}

// ── Props ─────────────────────────────────────────────────────

export interface RiskGaugeProps {
  result: ScanResponse | null;
  isLoading?: boolean;
}

// ── Component ─────────────────────────────────────────────────

export function RiskGauge({ result, isLoading = false }: RiskGaugeProps) {
  const [displayScore, setDisplayScore] = useState(0);
  const [animating,    setAnimating]    = useState(false);
  const rafRef = useRef<number | null>(null);

  // Animate score on result change
  useEffect(() => {
    if (!result) { setDisplayScore(0); return; }
    const target = result.overall_risk_score;
    const start  = displayScore;
    const startTime = performance.now();
    const duration  = 1200;
    setAnimating(true);

    const step = (now: number) => {
      const elapsed  = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // easeOutExpo
      const eased = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
      setDisplayScore(Math.round(start + (target - start) * eased));
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(step);
      } else {
        setAnimating(false);
      }
    };
    rafRef.current = requestAnimationFrame(step);
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result]);

  const color      = result ? scoreToColor(result.overall_risk_score) : '#1F2937';
  const dispColor  = scoreToColor(displayScore);
  const tier       = result?.risk_tier ?? null;
  const needleDeg  = scoreToDeg(displayScore);

  // Track arc end-point
  const trackStart = arcPoint(210);
  const fillEnd    = arcPoint(needleDeg);
  const fillSweep  = ((needleDeg - 210 + 360) % 360) > 180 ? 1 : 0;

  // Needle tip
  const needleTipR  = R - 8;
  const needleTip   = { x: CX + needleTipR * Math.cos(degToRad(needleDeg)), y: CY + needleTipR * Math.sin(degToRad(needleDeg)) };
  const needleBase1 = { x: CX + 8 * Math.cos(degToRad(needleDeg + 90)), y: CY + 8 * Math.sin(degToRad(needleDeg + 90)) };
  const needleBase2 = { x: CX + 8 * Math.cos(degToRad(needleDeg - 90)), y: CY + 8 * Math.sin(degToRad(needleDeg - 90)) };

  return (
    <div
      className="mobile-card-padding"
      style={{
        background: '#111827', border: '1px solid #1F2937', borderRadius: '16px',
        padding: '24px 20px', display: 'flex', flexDirection: 'column', alignItems: 'center',
        gap: '0', boxShadow: '0 8px 40px rgba(0,0,0,0.5)', position: 'relative', overflow: 'hidden',
        width: '100%', maxWidth: '340px',
      }}
    >
      {/* Glow behind gauge when score > 0 */}
      {result && (
        <div aria-hidden style={{
          position: 'absolute', width: '180px', height: '180px', borderRadius: '50%', top: '30px',
          left: '50%', transform: 'translateX(-50%)',
          background: `radial-gradient(circle, ${color}22 0%, transparent 70%)`,
          transition: 'background 0.8s ease',
          pointerEvents: 'none',
        }} />
      )}

      {/* Header */}
      <div style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: 36, height: 36, borderRadius: '9px', fontSize: '18px',
            background: 'rgba(0,240,255,0.08)', border: '1px solid rgba(0,240,255,0.18)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }} aria-hidden>📊</div>
          <div>
            <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: '#F1F5F9', fontFamily: 'Plus Jakarta Sans, Inter, sans-serif' }}>
              Risk Score
            </h3>
            <p style={{ margin: 0, fontSize: '11px', color: '#94A3B8', fontFamily: 'Inter, sans-serif' }}>
              Composite threat probability
            </p>
          </div>
        </div>
        {/* Tier badge */}
        {tier && (
          <div style={{
            padding: '5px 12px', borderRadius: '20px', fontSize: '11px', fontWeight: 700,
            fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.8px',
            color: color, border: `1px solid ${color}44`,
            background: `${color}12`,
            boxShadow: `0 0 12px ${color}22`,
            transition: 'all 0.5s ease',
          }}>
            {tierLabel(tier)}
          </div>
        )}
      </div>

      {/* ── SVG Gauge ──────────────────────────────────────── */}
      <svg viewBox="0 0 220 155" width="260" height="180" aria-label={`Risk score: ${displayScore}`} role="img">
        <defs>
          <linearGradient id="pl-track-grad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%"   stopColor="#00E676" />
            <stop offset="33%"  stopColor="#FFB800" />
            <stop offset="66%"  stopColor="#FF6B00" />
            <stop offset="100%" stopColor="#FF3366" />
          </linearGradient>
          <filter id="pl-glow">
            <feGaussianBlur stdDeviation="3" result="blur"/>
            <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
        </defs>

        {/* Background track */}
        <path
          d={buildArc(210, 90, R)}
          fill="none" stroke="#1F2937" strokeWidth="12" strokeLinecap="round"
        />

        {/* Color fill arc */}
        {displayScore > 0 && (
          <path
            d={`M ${trackStart.x} ${trackStart.y} A ${R} ${R} 0 ${fillSweep} 1 ${fillEnd.x} ${fillEnd.y}`}
            fill="none"
            stroke={dispColor}
            strokeWidth="12"
            strokeLinecap="round"
            filter="url(#pl-glow)"
            style={{ transition: animating ? 'none' : 'stroke 0.4s ease' }}
          />
        )}

        {/* Tick marks */}
        {TICKS.map(t => <Tick key={t} score={t} active={!!result} />)}

        {/* Needle */}
        {(displayScore > 0 || isLoading) && (
          <polygon
            points={`${needleTip.x},${needleTip.y} ${needleBase1.x},${needleBase1.y} ${needleBase2.x},${needleBase2.y}`}
            fill={dispColor}
            opacity={0.9}
            filter="url(#pl-glow)"
            style={{ transition: animating ? 'none' : 'all 0.3s ease' }}
          />
        )}
        {/* Needle pivot */}
        <circle cx={CX} cy={CY} r="7" fill="#1F2937" stroke={dispColor} strokeWidth="2.5"
          style={{ transition: 'stroke 0.4s ease' }} />
        <circle cx={CX} cy={CY} r="3" fill={dispColor}
          style={{ transition: 'fill 0.4s ease' }} />

        {/* Center score text */}
        <text x={CX} y={CY + 30}
          textAnchor="middle" dominantBaseline="middle"
          fill={displayScore > 0 ? dispColor : '#374151'}
          fontSize="32" fontWeight="700" fontFamily="JetBrains Mono, monospace"
          style={{ transition: 'fill 0.4s ease' }}
        >
          {isLoading ? '…' : displayScore}
        </text>
        <text x={CX} y={CY + 48}
          textAnchor="middle" fill="#4B5563"
          fontSize="9" fontFamily="Inter, sans-serif" letterSpacing="1">
          / 100
        </text>
      </svg>

      {/* ── Metadata row ─────────────────────────────────────── */}
      {result ? (
        <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '4px' }}>
          {/* Latency */}
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px',
            padding: '7px 0',
            borderTop: '1px solid #1F2937',
          }}>
            <span aria-hidden style={{ fontSize: '13px' }}>⚡</span>
            <span style={{ fontSize: '12px', fontFamily: 'JetBrains Mono, monospace', color: '#00F0FF' }}>
              Intercepted in {result.processing_time_ms.toFixed(0)}ms
            </span>
          </div>

          {/* Verdict */}
          <p style={{
            margin: 0, padding: '10px 14px', borderRadius: '9px',
            background: `${color}0D`, border: `1px solid ${color}2A`,
            fontSize: '12.5px', lineHeight: '1.55', color: '#CBD5E1',
            fontFamily: 'Inter, sans-serif', textAlign: 'center',
            transition: 'all 0.5s ease',
          }}>
            {result.verdict}
          </p>

          {/* Scan ID */}
          <p style={{
            margin: 0, fontSize: '10px', color: '#94A3B8',
            fontFamily: 'JetBrains Mono, monospace', textAlign: 'center',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            scan_id: {result.scan_id}
          </p>
        </div>
      ) : (
        <p style={{
          margin: '8px 0 0', fontSize: '12px', color: '#94A3B8',
          fontFamily: 'Inter, sans-serif', textAlign: 'center',
        }}>
          {isLoading ? 'Running parallel agent analysis…' : 'Submit a message to see the risk score'}
        </p>
      )}
    </div>
  );
}

export default RiskGauge;
