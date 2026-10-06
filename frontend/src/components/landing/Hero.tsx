// ─────────────────────────────────────────────────────────────
//  PhishLens Enterprise Landing · Hero Section
//  Strictly matched to Stitch screen projects/1873559564137532359
//  Light theme with subtle wireframe node/globe graphic
// ─────────────────────────────────────────────────────────────
import { ArrowRight, ShieldAlert, Check, Lock, Zap, Calendar } from 'lucide-react';

function WireframeGlobe() {
  return (
    <div
      className="pointer-events-none absolute inset-0 -z-10 flex items-center justify-center overflow-hidden opacity-75"
      aria-hidden="true"
    >
      <svg
        className="w-[740px] h-[740px] text-blue-600/20 select-none animate-pulse"
        style={{ animationDuration: '6s' }}
        viewBox="0 0 600 600"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <radialGradient id="globeGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#2563EB" stopOpacity="0.08" />
            <stop offset="55%" stopColor="#2563EB" stopOpacity="0.02" />
            <stop offset="100%" stopColor="#2563EB" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* Ambient radial sphere glow */}
        <circle cx="300" cy="300" r="250" fill="url(#globeGlow)" />

        {/* Concentric latitude & longitude rings */}
        <circle cx="300" cy="300" r="240" stroke="currentColor" strokeWidth="1" strokeDasharray="4 4" />
        <circle cx="300" cy="300" r="185" stroke="currentColor" strokeWidth="0.8" />
        <circle cx="300" cy="300" r="125" stroke="currentColor" strokeWidth="0.8" strokeDasharray="3 3" />
        <circle cx="300" cy="300" r="65" stroke="currentColor" strokeWidth="0.7" />

        {/* Latitude ellipses */}
        <ellipse cx="300" cy="300" rx="240" ry="70" stroke="currentColor" strokeWidth="0.85" />
        <ellipse cx="300" cy="300" rx="240" ry="145" stroke="currentColor" strokeWidth="0.85" />
        <ellipse cx="300" cy="300" rx="240" ry="215" stroke="currentColor" strokeWidth="0.65" strokeDasharray="4 4" />

        {/* Longitude ellipses */}
        <ellipse cx="300" cy="300" rx="70" ry="240" stroke="currentColor" strokeWidth="0.85" />
        <ellipse cx="300" cy="300" rx="145" ry="240" stroke="currentColor" strokeWidth="0.85" />
        <ellipse cx="300" cy="300" rx="215" ry="240" stroke="currentColor" strokeWidth="0.65" strokeDasharray="4 4" />

        {/* Crosshair coordinate axes */}
        <line x1="60" y1="300" x2="540" y2="300" stroke="currentColor" strokeWidth="0.8" strokeDasharray="4 4" />
        <line x1="300" y1="60" x2="300" y2="540" stroke="currentColor" strokeWidth="0.8" strokeDasharray="4 4" />

        {/* Geodesic connecting telemetry links */}
        <line x1="210" y1="210" x2="300" y2="155" stroke="#2563EB" strokeOpacity="0.3" strokeWidth="0.8" />
        <line x1="300" y1="155" x2="390" y2="210" stroke="#2563EB" strokeOpacity="0.3" strokeWidth="0.8" />
        <line x1="390" y1="210" x2="445" y2="300" stroke="#2563EB" strokeOpacity="0.3" strokeWidth="0.8" />
        <line x1="445" y1="300" x2="390" y2="390" stroke="#2563EB" strokeOpacity="0.3" strokeWidth="0.8" />
        <line x1="390" y1="390" x2="300" y2="445" stroke="#2563EB" strokeOpacity="0.3" strokeWidth="0.8" />
        <line x1="300" y1="445" x2="210" y2="390" stroke="#2563EB" strokeOpacity="0.3" strokeWidth="0.8" />
        <line x1="210" y1="390" x2="155" y2="300" stroke="#2563EB" strokeOpacity="0.3" strokeWidth="0.8" />
        <line x1="155" y1="300" x2="210" y2="210" stroke="#2563EB" strokeOpacity="0.3" strokeWidth="0.8" />

        {/* Global sensor telemetry nodes */}
        <circle cx="300" cy="155" r="3.5" fill="#2563EB" fillOpacity="0.8" />
        <circle cx="300" cy="445" r="3" fill="#2563EB" fillOpacity="0.6" />
        <circle cx="155" cy="300" r="3" fill="#2563EB" fillOpacity="0.7" />
        <circle cx="445" cy="300" r="3.5" fill="#2563EB" fillOpacity="0.8" />
        <circle cx="210" cy="210" r="2.5" fill="#3B82F6" fillOpacity="0.7" />
        <circle cx="390" cy="210" r="3" fill="#2563EB" fillOpacity="0.8" />
        <circle cx="210" cy="390" r="2.5" fill="#3B82F6" fillOpacity="0.6" />
        <circle cx="390" cy="390" r="3" fill="#2563EB" fillOpacity="0.7" />
      </svg>
    </div>
  );
}

export function Hero() {
  return (
    <section className="pt-12 pb-16 sm:pt-20 sm:pb-24 px-4 sm:px-6 max-w-5xl mx-auto text-center relative z-10 bg-white">
      {/* Subtle Geometric Node / Wireframe Globe Background Graphic */}
      <WireframeGlobe />
      
      {/* Top Pill Tag */}
      <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-slate-100/90 border border-slate-200/80 text-[12px] font-medium text-slate-700 mb-6 shadow-xs hover:border-blue-300 transition-colors">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-600" />
        </span>
        <span>PhishLens Engine v4.2</span>
        <span className="text-slate-300">|</span>
        <a
          href="#scanner"
          className="text-blue-600 font-semibold flex items-center gap-1 hover:underline cursor-pointer group"
        >
          <span>Zero-day heuristic scanner</span>
          <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
        </a>
      </div>

      {/* Main Headline */}
      <h1 className="text-4xl sm:text-6xl font-extrabold tracking-[-0.03em] text-slate-900 leading-[1.08] max-w-4xl mx-auto">
        Detect Scams <br className="hidden sm:inline" />
        <span className="highlight-marker text-slate-900">Before They Reach You</span>
      </h1>

      {/* Subheadline */}
      <p className="mt-6 text-base sm:text-xl text-slate-600 leading-relaxed max-w-2xl mx-auto font-normal">
        Real-time telemetry and linguistic zero-shot AI engineered to neutralise fraudulent payloads
        across Telegram, WhatsApp, SMS, and corporate mail before human error occurs.
      </p>

      {/* CTA Buttons Row */}
      <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-3 sm:gap-4">
        <a
          href="#scanner"
          className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-lg bg-[#0B1120] text-white font-medium text-sm shadow-md hover:bg-slate-800 hover:shadow-lg transition-all active:scale-[0.98] focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 cursor-pointer"
        >
          <ShieldAlert className="w-4 h-4 text-blue-400" />
          <span>Start Scanning Free</span>
        </a>
        <a
          href="#pricing"
          className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-lg bg-white border border-slate-300 text-slate-700 font-medium text-sm hover:bg-slate-50 hover:text-slate-900 hover:border-slate-400 transition-all active:scale-[0.98] focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 cursor-pointer shadow-xs"
        >
          <Calendar className="w-3.5 h-3.5 text-slate-500" />
          <span>Book Demo</span>
        </a>
      </div>

      {/* Trust Microcopy */}
      <div className="mt-6 flex items-center justify-center gap-4 text-xs text-slate-500 font-medium flex-wrap">
        <span className="flex items-center gap-1.5">
          <Check className="w-3.5 h-3.5 text-blue-600" />
          No credit card required
        </span>
        <span className="text-slate-300">·</span>
        <span className="flex items-center gap-1.5">
          <Lock className="w-3.5 h-3.5 text-slate-500" />
          SOC 2 Type II
        </span>
        <span className="text-slate-300 hidden sm:inline">·</span>
        <span className="hidden sm:inline-flex items-center gap-1.5">
          <Zap className="w-3.5 h-3.5 text-amber-500" />
          14ms API latency
        </span>
      </div>

    </section>
  );
}
