// ─────────────────────────────────────────────────────────────
//  PhishLens Enterprise Landing · Footer
//  Strictly matched to Stitch screen projects/1873559564137532359
//  Light theme: bg-white, border-t border-slate-200, text-slate-600
// ─────────────────────────────────────────────────────────────

export function Footer() {
  return (
    <footer className="bg-white border-t border-slate-200 text-slate-600 text-xs py-12 px-4 sm:px-6 relative z-10">
      <div className="max-w-7xl mx-auto grid grid-cols-2 md:grid-cols-5 gap-8">
        
        {/* Brand column */}
        <div className="col-span-2">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-6 h-6 rounded bg-[#0B1120] text-blue-400 flex items-center justify-center font-bold text-xs">
              PL
            </div>
            <span className="font-bold text-slate-900 text-base">PhishLens</span>
          </div>
          <p className="text-slate-500 text-xs max-w-sm leading-relaxed">
            Enterprise cyber defense platform delivering zero-shot phishing &amp; social engineering
            neutralization for modern distributed workforces.
          </p>
          <div className="mt-4 flex items-center gap-3 text-slate-400">
            <span className="inline-flex items-center gap-1 text-[11px] text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200 font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              <span>Systems Operational</span>
            </span>
            <span className="text-[11px] font-mono-code">v4.2.1-prod</span>
          </div>
        </div>

        {/* Links 1 */}
        <div>
          <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-3">
            Product
          </h4>
          <ul className="space-y-2">
            <li>
              <a href="#scanner" className="hover:text-slate-900 transition-colors">
                Heuristic Engine
              </a>
            </li>
            <li>
              <a href="#features" className="hover:text-slate-900 transition-colors">
                Computer Vision OCR
              </a>
            </li>
            <li>
              <a href="#how-it-works" className="hover:text-slate-900 transition-colors">
                Anti-Cloak Sandbox
              </a>
            </li>
            <li>
              <a href="#features" className="hover:text-slate-900 transition-colors">
                Telegram Bot Defense
              </a>
            </li>
            <li>
              <a href="#features" className="hover:text-slate-900 transition-colors">
                WhatsApp Guard API
              </a>
            </li>
          </ul>
        </div>

        {/* Links 2 */}
        <div>
          <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-3">
            Enterprise &amp; Trust
          </h4>
          <ul className="space-y-2">
            <li>
              <a href="#docs" className="hover:text-slate-900 transition-colors">
                Security Whitepaper
              </a>
            </li>
            <li>
              <a href="#docs" className="hover:text-slate-900 transition-colors">
                SOC 2 Type II Report
              </a>
            </li>
            <li>
              <a href="#docs" className="hover:text-slate-900 transition-colors">
                Vulnerability Disclosure
              </a>
            </li>
            <li>
              <a href="#docs" className="hover:text-slate-900 transition-colors">
                GDPR Privacy Policy
              </a>
            </li>
            <li>
              <a href="#docs" className="hover:text-slate-900 transition-colors">
                Subprocessors
              </a>
            </li>
          </ul>
        </div>

        {/* Links 3 */}
        <div>
          <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-3">
            Developers
          </h4>
          <ul className="space-y-2">
            <li>
              <a href="#docs" className="hover:text-slate-900 transition-colors">
                API Documentation
              </a>
            </li>
            <li>
              <a href="#docs" className="hover:text-slate-900 transition-colors">
                Python SDK
              </a>
            </li>
            <li>
              <a href="#docs" className="hover:text-slate-900 transition-colors">
                Go / Rust Crates
              </a>
            </li>
            <li>
              <a href="#docs" className="hover:text-slate-900 transition-colors">
                Splunk App
              </a>
            </li>
            <li>
              <a href="#docs" className="hover:text-slate-900 transition-colors">
                Changelog
              </a>
            </li>
          </ul>
        </div>

      </div>

      <div className="max-w-7xl mx-auto mt-10 pt-6 border-t border-slate-100 flex flex-col sm:flex-row items-center justify-between text-slate-400 gap-4">
        <div>© 2025 PhishLens Technologies Inc. All rights reserved.</div>
        <div className="flex items-center gap-6">
          <a href="#privacy" className="hover:text-slate-600 transition-colors">
            Privacy
          </a>
          <a href="#terms" className="hover:text-slate-600 transition-colors">
            Terms of Service
          </a>
          <a href="#cookies" className="hover:text-slate-600 transition-colors">
            Cookie Preferences
          </a>
        </div>
      </div>
    </footer>
  );
}
