// ────────────────────────────────────────────────────────────
//  PhishLens  ·  App  —  Bento Grid Dashboard (Cryptgen Aesthetic)
//  Pitch-black, ultra-minimal borders, ambient glows
//  + Bilingual toggle (EN / HI) + responsive layout
//  + Landing Page route (?page=landing)
// ────────────────────────────────────────────────────────────

import './index.css';
import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { LayoutDashboard, Shield, FileText, Settings, Activity, Radio, ShieldAlert } from 'lucide-react';
import { Sidebar, SidebarBody, SidebarLink, type Links } from './components/ui/sidebar';
import { BentoGrid, BentoGridItem } from './components/ui/bento-grid';
import { AnimatedNumber } from './components/ui/animated-number';
import { getUiTreatment } from './lib/api';
import type { ScanResponse, Language } from './lib/types';

import { ScannerInput }      from './components/ScannerInput';
import { RiskGauge }         from './components/RiskGauge';
import { AuditTrailDrawer }  from './components/AuditTrailDrawer';
import { InterceptionModal } from './components/InterceptionModal';
import { RecentScans }       from './components/RecentScans';
import { ThreatBadges }      from './components/ThreatBadges';
import { mockScanResult }    from './lib/mockData';
import { LandingPage }       from './components/landing/LandingPage';

// ── Threat Intel Feed — auto-cycling with framer-motion ──────

const THREAT_ITEMS = [
  { time: '2m ago', msg: 'New phishing domain detected: secure-bank*.in', severity: 'high' as const },
  { time: '5m ago', msg: 'SMS spoofing campaign targeting HDFC users', severity: 'high' as const },
  { time: '8m ago', msg: 'UPI scam pattern identified in 3 reports', severity: 'medium' as const },
  { time: '12m ago', msg: 'KYC verification phish wave detected', severity: 'high' as const },
  { time: '15m ago', msg: 'Telecom impersonation campaign active', severity: 'high' as const },
  { time: '22m ago', msg: 'Fake lottery reward links spreading via WhatsApp', severity: 'medium' as const },
  { time: '45m ago', msg: 'New typosquatting domain: paytm-secure*.com', severity: 'high' as const },
  { time: '1h ago', msg: 'Blocklist updated: +142 domains', severity: 'low' as const },
];

function ThreatIntelFeed({ lang }: { lang: Language }) {
  const [visibleStart, setVisibleStart] = useState(0);
  const VISIBLE_COUNT = 4;

  useEffect(() => {
    const interval = setInterval(() => {
      setVisibleStart(prev => (prev + 1) % THREAT_ITEMS.length);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const visibleItems = Array.from({ length: VISIBLE_COUNT }, (_, i) =>
    THREAT_ITEMS[(visibleStart + i) % THREAT_ITEMS.length]
  );

  const severityDot = (severity: 'high' | 'medium' | 'low') => {
    if (severity === 'high') return 'bg-rose-400 shadow-[0_0_4px_rgba(251,113,133,0.5)] animate-pulse';
    if (severity === 'medium') return 'bg-amber-400 shadow-[0_0_4px_rgba(251,191,36,0.4)]';
    return 'bg-zinc-500';
  };

  return (
    <BentoGridItem
      id="threat-intel"
      className="md:col-span-1 md:row-span-1 overflow-hidden"
      icon={
        <div className="size-8 rounded-lg bg-cyan-500/8 border border-cyan-500/20 flex items-center justify-center">
          <Radio className="size-4 text-cyan-400" />
        </div>
      }
      title={
        <div className="flex items-center gap-2">
          <span>{lang === 'hi' ? 'लाइव थ्रेट इंटेल फीड' : 'Live Threat Intel Feed'}</span>
          <span className="flex items-center gap-1 px-1.5 py-0.5 rounded-full bg-rose-500/8 border border-rose-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse shadow-[0_0_6px_rgba(251,113,133,0.5)]" />
            <span className="text-[9px] font-mono text-rose-400 font-semibold">LIVE</span>
          </span>
        </div>
      }
      description={lang === 'hi' ? 'रियल-टाइम खतरा अपडेट' : 'Real-time threat stream'}
    >
      <div className="mt-4 space-y-1 relative min-h-[120px]">
        <AnimatePresence mode="popLayout">
          {visibleItems.map((item, i) => (
            <motion.div
              key={`${item.msg}-${visibleStart}`}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.35, delay: i * 0.05 }}
              className="flex items-start gap-2.5 py-1"
            >
              <div className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${severityDot(item.severity)}`} />
              <div className="min-w-0">
                <p className="text-[11px] text-zinc-300 font-sans leading-snug truncate m-0">{item.msg}</p>
                <span className="text-[9px] text-zinc-600 font-mono">{item.time}</span>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </BentoGridItem>
  );
}

// ── Component ─────────────────────────────────────────────────

export default function App() {
  // ── Page routing (stateful + URL param) ───────────────────
  const [currentPage, setCurrentPage] = useState<'landing' | 'dashboard'>(() => {
    const page = new URLSearchParams(window.location.search).get('page');
    return page === 'dashboard' ? 'dashboard' : 'landing';
  });

  useEffect(() => {
    const onPopState = () => {
      const page = new URLSearchParams(window.location.search).get('page');
      setCurrentPage(page === 'dashboard' ? 'dashboard' : 'landing');
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  const navigateTo = (page: 'landing' | 'dashboard') => {
    setCurrentPage(page);
    const url = new URL(window.location.href);
    url.searchParams.set('page', page);
    window.history.pushState({}, '', url.toString());
    window.scrollTo({ top: 0, behavior: 'instant' });
  };

  if (currentPage === 'landing') {
    return <LandingPage onNavigateToDashboard={() => navigateTo('dashboard')} />;
  }

  return <DashboardView onNavigateToLanding={() => navigateTo('landing')} />;
}

// ── Dashboard Component ───────────────────────────────────────
function DashboardView({ onNavigateToLanding }: { onNavigateToLanding?: () => void }) {
  const [open, setOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<'dashboard' | 'threat-intel' | 'audit-logs' | 'settings'>('dashboard');

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

  // ── Sidebar Navigation Links ──────────────────────────────

  const links: Links[] = [
    {
      label: "Landing Page",
      href: "?page=landing",
      icon: <Radio className="size-5 shrink-0 text-blue-400" />,
      active: false,
      onClick: () => {
        onNavigateToLanding?.();
      },
    },
    {
      label: "Dashboard",
      href: "#dashboard",
      icon: <LayoutDashboard className="size-5 shrink-0" />,
      active: activeTab === 'dashboard',
      onClick: () => {
        setActiveTab('dashboard');
        window.scrollTo({ top: 0, behavior: 'smooth' });
      },
    },
    {
      label: "Threat Intel",
      href: "#threat-intel",
      icon: <Shield className="size-5 shrink-0" />,
      active: activeTab === 'threat-intel',
      onClick: () => {
        setActiveTab('threat-intel');
        document.getElementById('threat-intel')?.scrollIntoView({ behavior: 'smooth' });
      },
    },
    {
      label: "Audit Logs",
      href: "#audit-logs",
      icon: <FileText className="size-5 shrink-0" />,
      active: activeTab === 'audit-logs',
      onClick: () => {
        setActiveTab('audit-logs');
        document.getElementById('audit-feed-toggle')?.scrollIntoView({ behavior: 'smooth' });
      },
    },
    {
      label: "Settings",
      href: "#settings",
      icon: <Settings className="size-5 shrink-0" />,
      active: activeTab === 'settings',
      onClick: () => {
        setActiveTab('settings');
        setLang(l => (l === 'en' ? 'hi' : 'en'));
      },
    },
  ];

  // ── Layout ────────────────────────────────────────────────

  return (
    <div className="flex flex-col md:flex-row bg-black w-full min-h-screen text-zinc-100 overflow-x-hidden font-sans">
      {/* ── Aceternity Sidebar ── */}
      <Sidebar open={open} setOpen={setOpen}>
        <SidebarBody className="justify-between gap-10">
          <div className="flex flex-col flex-1 overflow-y-auto overflow-x-hidden">
            {/* Logo in Sidebar */}
            <div className="flex items-center gap-3 px-1 py-1">
              <div className="size-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-lg shrink-0 shadow-[0_0_12px_rgba(0,240,255,0.15)]">
                🛡️
              </div>
              <div className="flex flex-col whitespace-pre overflow-hidden">
                <span className="text-base font-extrabold tracking-tight bg-gradient-to-r from-cyan-400 to-zinc-200 bg-clip-text text-transparent font-sans">
                  PhishLens
                </span>
                <span className="text-[10px] text-zinc-500 font-mono tracking-wider -mt-0.5">
                  ScamShield AI
                </span>
              </div>
            </div>

            {/* Navigation Links */}
            <div className="mt-8 flex flex-col gap-2">
              {links.map((link, idx) => (
                <SidebarLink key={idx} link={link} />
              ))}
            </div>
          </div>

          {/* Sidebar bottom indicator */}
          <div className="border-t border-white/[0.06] pt-4">
            <SidebarLink
              link={{
                label: "PhishLens Sentinel",
                href: "#",
                icon: (
                  <div className="size-6 rounded-full bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-[10px] font-mono font-bold text-cyan-400">
                    PL
                  </div>
                ),
              }}
            />
          </div>
        </SidebarBody>
      </Sidebar>

      {/* ── Main Content Area — Cryptgen Pitch-Black ── */}
      <div className="flex-1 flex flex-col min-w-0 bg-black relative min-h-screen">
        {/* ── Aceternity Pure CSS Grid Background ── */}
        <div className="absolute inset-0 z-0 pointer-events-none overflow-hidden">
          {/* Grid lines */}
          <div className="absolute inset-0 bg-black bg-grid-white" />
          {/* Radial Gradient Mask — fading to edges */}
          <div className="absolute inset-0 bg-black [mask-image:radial-gradient(ellipse_at_center,transparent_20%,black)]" />
        </div>

        {/* Ambient background glow — very subtle on pitch black */}
        <div
          aria-hidden
          className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-4xl h-72 pointer-events-none z-0"
          style={{
            background: 'radial-gradient(ellipse at 50% 0%, rgba(0, 240, 255, 0.06) 0%, transparent 70%)',
          }}
        />

        {/* ── Main Content wrapper (z-10 over grid) ── */}
        <div className="relative z-10 flex-1 flex flex-col min-w-0">
          {/* ── Top Bar ── */}
          <nav
            className="sticky top-0 z-30 flex max-sm:flex-col max-sm:items-start max-sm:h-auto max-sm:py-3 max-sm:gap-2.5 sm:flex-row items-center justify-between px-4 sm:px-8 sm:h-[64px] bg-black/80 backdrop-blur-md border-b border-white/[0.06] mobile-header-stack"
          >
            {/* Header left */}
            <div className="flex items-center gap-3">
              <span className="text-xl sm:text-2xl md:hidden" aria-hidden>🛡️</span>
              <div>
                <span className="text-sm sm:text-base font-bold text-zinc-100 tracking-tight">
                  {lang === 'hi' ? 'साइबर थ्रेट इंटेलिजेंस कंसोल' : 'Cyber Threat Intelligence Console'}
                </span>
                <span className="hidden sm:inline-block ml-2 text-[10px] font-mono text-cyan-400 px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/20">
                  v2.4
                </span>
              </div>
            </div>

            {/* Header right — lang toggle + scan counter + status */}
            <div className="flex items-center gap-2.5 sm:gap-4 max-sm:w-full max-sm:justify-between">
              {/* Language Toggle */}
              <button
                id="lang-toggle-btn"
                type="button"
                onClick={() => setLang(prev => prev === 'en' ? 'hi' : 'en')}
                aria-label={`Switch language to ${lang === 'en' ? 'Hindi' : 'English'}`}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-full cursor-pointer transition-all duration-200 text-xs font-semibold font-sans text-cyan-400 bg-cyan-500/10 border border-cyan-500/25 hover:bg-cyan-500/20 shadow-[0_0_10px_rgba(0,240,255,0.08)]"
              >
                {lang === 'en' ? '🇮🇳 हिंदी' : '🇬🇧 English'}
              </button>

              {scanCount > 0 && (
                <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-zinc-950 border border-white/[0.08]">
                  <span className="text-[11px] text-zinc-500 font-mono">
                    {lang === 'hi' ? 'स्कैन:' : 'Scans:'}
                  </span>
                  <span className="text-xs font-bold text-cyan-400 font-mono">
                    {scanCount}
                  </span>
                </div>
              )}

              {/* Current tier pill */}
              {treatment && (
                <div
                  className="px-3 py-1 rounded-full text-[11px] font-bold tracking-wider font-mono border transition-all duration-300"
                  style={{
                    color: treatment.accentColor,
                    background: `${treatment.accentColor}10`,
                    borderColor: `${treatment.accentColor}25`,
                  }}
                >
                  {treatment.label}
                </div>
              )}

              {/* Status dot */}
              <div
                className={`w-2.5 h-2.5 rounded-full transition-all duration-300 ${
                  isLoading
                    ? 'bg-amber-400 shadow-[0_0_8px_#f59e0b] animate-pulse'
                    : 'bg-emerald-400 shadow-[0_0_8px_#34d399]'
                }`}
                aria-hidden
              />
            </div>
          </nav>

          {/* ── Page body ── */}
          <main className="max-w-[1280px] w-full mx-auto px-4 sm:px-6 pt-6 sm:pt-8 pb-20 relative z-10 flex-1">
            {/* Hero tag line */}
            <div className="text-center mb-8 sm:mb-10">
              <p className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs mb-3 font-mono font-semibold tracking-wide text-cyan-400 bg-cyan-500/8 border border-cyan-500/20 shadow-[0_0_12px_rgba(0,240,255,0.06)]">
                <span aria-hidden>▸</span>
                {lang === 'hi' ? 'रियल-टाइम मल्टी-एजेंट थ्रेट इंटरसेप्शन' : 'Real-time Multi-Agent Threat Interception'}
              </p>
              <h1 className="text-[clamp(24px,5vw,42px)] font-extrabold mb-3 leading-[1.15] tracking-tight bg-gradient-to-r from-zinc-100 via-zinc-300 to-zinc-500 bg-clip-text text-transparent font-sans">
                {lang === 'hi' ? <>स्कैम का पता लगाएं<br />इससे पहले कि वे आप तक पहुंचें</> : <>Detect Scams Before<br />They Reach You</>}
              </h1>
              <p className="text-xs sm:text-sm mx-auto max-w-[520px] text-zinc-500 font-sans leading-relaxed">
                {lang === 'hi'
                  ? '3 समानांतर AI एजेंटों द्वारा संचालित — URL विश्लेषण, प्रेषक सत्यापन, और मनोभाषाई इरादा पहचान।'
                  : 'Powered by 3 parallel AI agents — URL analysis, sender verification, and psycholinguistic intent detection.'}
              </p>
            </div>

            {/* ══════════════════════════════════════════════════
                 BENTO GRID LAYOUT — Cryptgen Aesthetic
               ══════════════════════════════════════════════════ */}
            <BentoGrid className="md:grid-cols-3 md:auto-rows-[minmax(180px,auto)] gap-4">

              {/* ── Primary: Scanner Input — spans 2 cols, 2 rows ── */}
              <BentoGridItem
                className="md:col-span-2 md:row-span-2"
              >
                <ScannerInput
                  onScanComplete={handleScanComplete}
                  onScanError={handleScanError}
                  disabled={isLoading || showModal}
                />
              </BentoGridItem>

              {/* ── System Status — top right ── */}
              <BentoGridItem
                className="md:col-span-1 md:row-span-1"
                icon={
                  <div className="size-8 rounded-lg bg-emerald-500/8 border border-emerald-500/20 flex items-center justify-center">
                    <Activity className="size-4 text-emerald-400" />
                  </div>
                }
                title={
                  <div className="flex items-center gap-2">
                    <span>{lang === 'hi' ? 'सिस्टम स्टेटस' : 'System Status'}</span>
                    <span className="flex items-center gap-1 px-1.5 py-0.5 rounded-full bg-emerald-500/8 border border-emerald-500/20">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_6px_rgba(52,211,153,0.6)]" />
                      <span className="text-[9px] font-mono text-emerald-400 font-semibold">LIVE</span>
                    </span>
                  </div>
                }
                description={lang === 'hi' ? 'AI एजेंट सिस्टम मॉनिटरिंग' : 'AI agent system monitoring'}
              >
                <div className="mt-4 space-y-3">
                  {/* Agent status rows */}
                  {[
                    { name: 'URL Analyzer', status: 'Online' },
                    { name: 'Sender Verifier', status: 'Online' },
                    { name: 'Intent Detector', status: 'Online' },
                  ].map((agent) => (
                    <div key={agent.name} className="flex items-center justify-between">
                      <span className="text-[11px] text-zinc-400 font-mono">{agent.name}</span>
                      <div className="flex items-center gap-1.5">
                        <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_6px_rgba(52,211,153,0.6)]" />
                        <span className="text-[10px] font-mono font-semibold text-emerald-400">{agent.status}</span>
                      </div>
                    </div>
                  ))}
                  {/* Uptime */}
                  <div className="pt-2 border-t border-white/[0.05]">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-zinc-500 font-mono">{lang === 'hi' ? 'अपटाइम' : 'Uptime'}</span>
                      <AnimatedNumber value={99.97} decimals={2} suffix="%" className="text-[10px] font-mono font-bold text-zinc-300" duration={2} />
                    </div>
                    <div className="mt-1.5 h-1 rounded-full bg-white/[0.04] overflow-hidden">
                      <motion.div
                        className="h-full rounded-full bg-gradient-to-r from-emerald-500/60 to-emerald-400/40"
                        initial={{ width: 0 }}
                        animate={{ width: '99.97%' }}
                        transition={{ duration: 2, ease: 'easeOut' }}
                      />
                    </div>
                  </div>
                </div>
              </BentoGridItem>

              {/* ── Live Threat Intel Feed — middle right ── */}
              <ThreatIntelFeed lang={lang} />

              {/* ── Loading skeleton ── */}
              {isLoading && !result && (
                <BentoGridItem className="md:col-span-2">
                  <div className="flex flex-col gap-3.5">
                    {[1, 2, 3].map(i => (
                      <div
                        key={i}
                        className={`h-4 rounded-full bg-white/[0.04] animate-pulse ${i === 3 ? 'w-3/5' : 'w-full'}`}
                        aria-hidden
                      />
                    ))}
                  </div>
                </BentoGridItem>
              )}

              {/* ── Error banner ── */}
              {error && (
                <BentoGridItem className="md:col-span-3 !border-rose-500/20">
                  <div role="alert" className="flex items-center gap-2 text-xs sm:text-[13px] font-mono text-rose-400">
                    <span aria-hidden>⚠</span> {error}
                  </div>
                </BentoGridItem>
              )}

              {/* ── HIGH_RISK inline warning card ── */}
              {result && result.risk_tier === 'HIGH_RISK' && (
                <BentoGridItem className="md:col-span-2 !border-orange-500/20 !bg-orange-500/[0.03]">
                  <div role="alert">
                    {/* Header row */}
                    <div className="flex items-center justify-between mb-3.5 flex-wrap gap-2">
                      <div className="flex items-center gap-3">
                        <div
                          className="w-10 h-10 rounded-xl text-xl flex items-center justify-center bg-orange-500/10 border border-orange-500/30 text-orange-400"
                          aria-hidden
                        >
                          ⚠️
                        </div>
                        <div>
                          <p className="text-sm sm:text-[15px] font-extrabold text-zinc-100 font-sans m-0">
                            {lang === 'hi' ? 'उच्च जोखिम का पता चला' : 'HIGH RISK DETECTED'}
                          </p>
                          <p className="text-[11px] text-zinc-500 font-mono m-0">
                            {lang === 'hi' ? 'स्कोर' : 'Score'}: {result.overall_risk_score}/100 · {result.processing_time_ms.toFixed(0)}ms
                          </p>
                        </div>
                      </div>
                      <div className="px-3 py-1 rounded-full text-[11px] font-extrabold font-mono tracking-wider text-orange-400 bg-orange-500/8 border border-orange-500/25 shadow-[0_0_12px_rgba(249,115,22,0.1)]">
                        HIGH RISK
                      </div>
                    </div>

                    {/* Recommendation */}
                    <div className="p-3 sm:p-3.5 rounded-xl mb-3.5 bg-orange-500/[0.04] border border-orange-500/15">
                      <p className="text-xs sm:text-[13px] leading-relaxed font-medium text-zinc-200 font-sans m-0">
                        {resolveRecommendation(result)}
                      </p>
                    </div>

                    {/* Verdict */}
                    <p className="text-xs p-2.5 sm:p-3 rounded-xl leading-relaxed text-zinc-400 font-mono bg-black/40 border border-white/[0.05] m-0">
                      <span className="text-zinc-600">{lang === 'hi' ? 'फैसला: ' : 'verdict: '}</span>
                      {resolveVerdict(result)}
                    </p>
                  </div>
                </BentoGridItem>
              )}

              {/* ── Recent Interceptions — spans full width when results exist ── */}
              <BentoGridItem
                className="md:col-span-1"
                icon={
                  <div className="size-8 rounded-lg bg-violet-500/8 border border-violet-500/20 flex items-center justify-center">
                    <ShieldAlert className="size-4 text-violet-400" />
                  </div>
                }
                title={lang === 'hi' ? 'हालिया इंटरसेप्शन' : 'Recent Interceptions'}
                description={lang === 'hi' ? 'ब्लॉक किए गए खतरे' : 'Blocked threats summary'}
              >
                <div className="mt-4 space-y-3">
                  {/* Stats row */}
                  <div className="grid grid-cols-2 gap-2.5">
                    <div className="p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.05]">
                      <p className="text-[10px] text-zinc-600 font-mono m-0">{lang === 'hi' ? 'आज ब्लॉक' : 'Blocked Today'}</p>
                      <AnimatedNumber value={scanCount > 0 ? scanCount + 12 : 12} className="text-lg font-bold text-zinc-200 font-mono block mt-0.5" duration={1.2} />
                    </div>
                    <div className="p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.05]">
                      <p className="text-[10px] text-zinc-600 font-mono m-0">{lang === 'hi' ? 'सफलता दर' : 'Catch Rate'}</p>
                      <AnimatedNumber value={98.4} decimals={1} suffix="%" className="text-lg font-bold text-emerald-400 font-mono block mt-0.5" duration={1.8} />
                    </div>
                  </div>
                  {/* Mini bar chart visualization — animated bars */}
                  <div className="flex items-end gap-1 h-8">
                    {[40, 65, 30, 80, 55, 70, 90, 45, 60, 75, 85, 50].map((h, i) => (
                      <motion.div
                        key={i}
                        className="flex-1 rounded-sm bg-gradient-to-t from-violet-500/30 to-violet-400/10"
                        initial={{ height: 0 }}
                        animate={{ height: `${h}%` }}
                        transition={{ duration: 0.8, delay: i * 0.06, ease: 'easeOut' }}
                      />
                    ))}
                  </div>
                  <p className="text-[9px] text-zinc-600 font-mono m-0 text-right">{lang === 'hi' ? 'पिछले 12 घंटे' : 'Last 12 hours'}</p>
                </div>
              </BentoGridItem>

              {/* ── Risk Gauge — shows when result exists ── */}
              {result && (
                <BentoGridItem className="md:col-span-1 md:row-span-2 hidden sm:block">
                  <RiskGauge result={result} isLoading={isLoading} />
                </BentoGridItem>
              )}

              {/* ── Audit Trail & Live Feed — spans 2 cols ── */}
              <BentoGridItem className={result ? "md:col-span-2" : "md:col-span-3"}>
                <AuditTrailDrawer
                  auditTrail={result ? result.audit_trail : null}
                  recommendation={result ? resolveRecommendation(result) : undefined}
                  processingTimeMs={result ? result.processing_time_ms : undefined}
                  lang={lang}
                />
              </BentoGridItem>

            </BentoGrid>

            {/* ══════════════════════════════════════════════════
                 RECENT SCAN HISTORY — Full width section
               ══════════════════════════════════════════════════ */}
            <div className="mt-6">
              <BentoGrid className="md:grid-cols-1 gap-4">
                <BentoGridItem className="md:col-span-1">
                  <RecentScans lang={lang} />
                </BentoGridItem>
              </BentoGrid>
            </div>

            {/* Mobile Risk Gauge — scaled down for mobile screens */}
            {result && (
              <div className="block sm:hidden mt-4 flex justify-center w-full overflow-hidden">
                <div className="transform scale-85 origin-center mobile-gauge-scale w-full flex justify-center">
                  <RiskGauge result={result} isLoading={isLoading} />
                </div>
              </div>
            )}

            {/* ── Empty state ── */}
            {!result && !isLoading && !error && (
              <div className="mt-8 sm:mt-10 text-center flex flex-col items-center gap-4">
                <div className="size-16 sm:size-20 rounded-2xl flex items-center justify-center text-3xl sm:text-4xl bg-cyan-500/5 border border-white/[0.06] shadow-[0_0_20px_rgba(0,240,255,0.03)]">
                  🔍
                </div>
                <p className="text-xs sm:text-sm max-w-sm text-zinc-500 font-sans m-0 leading-relaxed">
                  {lang === 'hi'
                    ? 'स्कैनिंग शुरू करने के लिए ऊपर एक प्रीसेट परिदृश्य लोड करें या अपना संदेश पेस्ट करें।'
                    : 'Load a preset scenario or paste your own message above to begin scanning.'}
                </p>

                {/* Mock data indicator */}
                {mockScanResult.isSimulated && (
                  <div className="flex flex-col items-center gap-2 mt-2">
                    <span className="text-gray-500 italic text-xs border border-gray-700 px-2 rounded-full">
                      Simulated Mode
                    </span>
                    <ThreatBadges detectedFlags={mockScanResult.detectedFlags} compact />
                  </div>
                )}
              </div>
            )}
          </main>

          {/* ── Footer ── */}
          <footer className="flex items-center justify-between flex-wrap gap-2 px-4 sm:px-8 py-4 bg-black border-t border-white/[0.06] mt-auto">
            <span className="text-[11px] text-zinc-600 font-mono">
              PhishLens · ScamShield AI · TechExpo 2026
            </span>
            <span className="text-[11px] text-zinc-600 font-mono">
              Agents: Atharv · Avni · Vikas · Avika
            </span>
          </footer>
        </div>
      </div>

      {/* ── Interception Modal ── */}
      {showModal && result && (
        <InterceptionModal
          result={result}
          lang={lang}
          onAbort={handleAbort}
          onProceedAnyway={handleProceed}
        />
      )}
    </div>
  );
}
