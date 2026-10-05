// ─────────────────────────────────────────────────────────────
//  PhishLens Enterprise Landing · Navbar
//  Strictly matched to Stitch screen projects/1873559564137532359
//  Light theme: bg-white/80, backdrop-blur-md, border-slate-200/70
// ─────────────────────────────────────────────────────────────
import { useState } from 'react';
import { Menu, X, ArrowRight } from 'lucide-react';

interface NavbarProps {
  onNavigateToDashboard?: () => void;
}

export function Navbar({ onNavigateToDashboard }: NavbarProps) {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <header
      id="navbar"
      className="sticky top-0 z-50 transition-all duration-300 bg-white/80 backdrop-blur-md border-b border-slate-200/70"
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        
        {/* Brand Logo Lockup */}
        <a
          href="#"
          className="flex items-center gap-2.5 group focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 rounded-md"
        >
          <div className="w-8 h-8 rounded-lg bg-[#0B1120] text-white flex items-center justify-center shadow-sm group-hover:bg-slate-800 transition-colors">
            {/* Shield & Eye Composition */}
            <svg
              className="w-4 h-4 text-blue-400"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <circle cx="12" cy="11" r="2.5" />
            </svg>
          </div>
          <div className="flex items-baseline">
            <span className="font-bold text-lg tracking-tight text-slate-900">
              Phish<span className="text-blue-600">Lens</span>
            </span>
            <span className="ml-1.5 px-1.5 py-0.5 text-[9px] font-semibold bg-slate-100 border border-slate-200 rounded text-slate-600 uppercase tracking-wider hidden sm:inline-block">
              Enterprise
            </span>
          </div>
        </a>

        {/* Desktop Nav Links */}
        <nav className="hidden md:flex items-center gap-8 text-[14px] font-medium text-slate-600">
          <a href="#scanner" className="hover:text-slate-900 transition-colors">
            Platform
          </a>
          <a href="#features" className="hover:text-slate-900 transition-colors">
            Coverage
          </a>
          <a href="#how-it-works" className="hover:text-slate-900 transition-colors">
            How It Works
          </a>
          <a href="#pricing" className="hover:text-slate-900 transition-colors">
            Pricing
          </a>
          <a href="#docs" className="hover:text-slate-900 transition-colors">
            Docs
          </a>
        </nav>

        {/* Nav Actions */}
        <div className="flex items-center gap-2.5 sm:gap-4">
          {onNavigateToDashboard ? (
            <button
              onClick={onNavigateToDashboard}
              className="text-[13px] sm:text-[14px] font-medium text-slate-700 hover:text-slate-900 px-2 sm:px-3 py-1.5 rounded-md hover:bg-slate-100 transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <span>Dashboard</span>
              <ArrowRight className="w-3.5 h-3.5 text-blue-600 hidden sm:inline" />
            </button>
          ) : (
            <a
              href="?page=dashboard"
              className="text-[13px] sm:text-[14px] font-medium text-slate-700 hover:text-slate-900 px-2 sm:px-3 py-1.5 rounded-md hover:bg-slate-100 transition-colors"
            >
              Dashboard
            </a>
          )}

          <a
            href="#scanner"
            className="inline-flex items-center justify-center text-[13px] sm:text-[14px] font-medium bg-[#0B1120] text-white px-3.5 sm:px-4 py-2 rounded-lg shadow-sm hover:bg-slate-800 active:scale-[0.98] transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-600"
          >
            <span>Start Scanning</span>
          </a>

          {/* Mobile hamburger menu toggle */}
          <button
            id="mobile-menu-btn"
            onClick={() => setMobileOpen(!mobileOpen)}
            className="md:hidden p-2 text-slate-600 hover:text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 rounded-md cursor-pointer"
            aria-label="Toggle navigation menu"
          >
            {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>

      </div>

      {/* Mobile Drawer / Dropdown */}
      {mobileOpen && (
        <div
          id="mobile-menu"
          className="md:hidden border-b border-slate-200 bg-white/95 px-4 pt-3 pb-5 space-y-2 backdrop-blur-lg animate-in fade-in slide-in-from-top-2 duration-150"
        >
          <a
            href="#scanner"
            onClick={() => setMobileOpen(false)}
            className="block py-2 text-sm font-medium text-slate-700 hover:text-blue-600"
          >
            Platform Scanner
          </a>
          <a
            href="#features"
            onClick={() => setMobileOpen(false)}
            className="block py-2 text-sm font-medium text-slate-700 hover:text-blue-600"
          >
            Features &amp; Bento
          </a>
          <a
            href="#how-it-works"
            onClick={() => setMobileOpen(false)}
            className="block py-2 text-sm font-medium text-slate-700 hover:text-blue-600"
          >
            How It Works
          </a>
          <a
            href="#pricing"
            onClick={() => setMobileOpen(false)}
            className="block py-2 text-sm font-medium text-slate-700 hover:text-blue-600"
          >
            Enterprise Pricing
          </a>
          <a
            href="?page=dashboard"
            onClick={() => setMobileOpen(false)}
            className="block py-2 text-sm font-semibold text-blue-600"
          >
            Open Live Dashboard →
          </a>
          <div className="pt-3 border-t border-slate-100 flex items-center justify-between">
            <span className="text-xs text-slate-500 font-mono-code">SOC2 Type II Certified</span>
            <span className="inline-flex items-center gap-1 text-xs text-emerald-600 font-medium">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              Threat Cloud Active
            </span>
          </div>
        </div>
      )}
    </header>
  );
}
