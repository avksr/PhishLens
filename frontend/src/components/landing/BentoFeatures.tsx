// ─────────────────────────────────────────────────────────────
//  PhishLens Enterprise Landing · Bento Features Grid
//  Strictly matched to Stitch screen projects/1873559564137532359
//  Light theme with rich technical mini-UI snippets & SOAR dispatch
// ─────────────────────────────────────────────────────────────
import {
  Eye,
  ChevronRight,
  CheckCircle2,
  Share2,
  ArrowUpRight,
} from 'lucide-react';

export function BentoFeatures() {
  return (
    <section id="features" className="py-16 sm:py-24 bg-gray-50 border-b border-slate-200/70">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        
        {/* Section Header */}
        <div className="max-w-2xl mb-12 sm:mb-16">
          <div className="text-xs font-mono-code uppercase tracking-wider text-blue-600 font-semibold mb-2">
            Architectural Superiority
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-slate-900">
            Engineered for zero trust. <br />
            Trained on adversarial telemetry.
          </h2>
          <p className="mt-3 text-base text-slate-600 leading-relaxed">
            Standard filters inspect known blocklists. PhishLens operates dynamic headless sandboxes
            that evaluate intent, DNS churn, and neural linguistic markers.
          </p>
        </div>

      {/* Bento Grid (Structured Asymmetrical Cards) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

        {/* Bento Card 1: 2-column wide card (Computer Vision Clone Engine) */}
        <div className="md:col-span-2 rounded-xl bg-white border border-slate-200/90 p-6 sm:p-8 shadow-sm hover:shadow-md hover:-translate-y-0.5 transition-all duration-200 flex flex-col justify-between">
          <div>
            {/* Mini UI Snippet Mockup: Visual Twin Compare */}
            <div className="rounded-lg bg-slate-900 text-white p-4 font-mono-code text-xs mb-6 border border-slate-800">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800 text-[11px] text-slate-400">
                <span className="flex items-center gap-1.5">
                  <Eye className="w-3.5 h-3.5 text-blue-400" />
                  <span>Computer Vision Clone Engine</span>
                </span>
                <span className="text-rose-400">99.7% Brand Match (Spoof)</span>
              </div>
              <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
                <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                  <div className="text-slate-400 text-[10px] mb-1">Authentic Target</div>
                  <div className="text-emerald-400 font-medium truncate">login.microsoftonline.com</div>
                  <div className="mt-2 text-[10px] text-slate-400">Cert: DigiCert EV TLS</div>
                </div>
                <div className="bg-slate-950 p-2.5 rounded border border-rose-900/60 relative">
                  <span className="absolute top-1 right-1 text-[9px] bg-rose-500/20 text-rose-300 px-1 rounded">
                    ROGUE
                  </span>
                  <div className="text-slate-400 text-[10px] mb-1">Scanned Host</div>
                  <div className="text-rose-300 font-medium truncate">ms-auth-sso.online</div>
                  <div className="mt-2 text-[10px] text-slate-400">Diff: Reverse Proxy Script</div>
                </div>
              </div>
            </div>

            <h3 className="text-xl font-bold text-slate-900 tracking-tight">
              Visual &amp; DOM Perceptual Hashing
            </h3>
            <p className="mt-2 text-sm text-slate-600 leading-relaxed">
              Detects pixel-perfect cloned login screens even when hosted on new domain names with
              valid SSL certificates. Our headless Chromium renderers compare visual embeddings
              against 25,000+ top financial &amp; enterprise brands.
            </p>
          </div>
          <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>OCR &amp; Canvas Fingerprinting</span>
            <span className="text-blue-600 flex items-center gap-1">
              <span>Deep analysis</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </span>
          </div>
        </div>

        {/* Bento Card 2: 1-column card (Linguistic LLM Intent) */}
        <div className="rounded-xl bg-white border border-slate-200/90 p-6 sm:p-8 shadow-sm hover:shadow-md hover:-translate-y-0.5 transition-all duration-200 flex flex-col justify-between">
          <div>
            {/* Mini UI Snippet: NLP markers */}
            <div className="rounded-lg bg-slate-50 p-3.5 border border-slate-200/80 mb-6 text-xs font-mono-code space-y-2">
              <div className="text-[10px] text-slate-500 uppercase tracking-wider">
                Linguistic Classifier
              </div>
              <div className="flex items-center justify-between bg-white px-2.5 py-1.5 rounded border border-slate-200 text-slate-800">
                <span>Urgency Trigger</span>
                <span className="text-rose-600 font-bold">HIGH (94%)</span>
              </div>
              <div className="flex items-center justify-between bg-white px-2.5 py-1.5 rounded border border-slate-200 text-slate-800">
                <span>Executive Impersonation</span>
                <span className="text-rose-600 font-bold">MATCH</span>
              </div>
              <div className="flex items-center justify-between bg-white px-2.5 py-1.5 rounded border border-slate-200 text-slate-800">
                <span>Out-of-band Wire/Card</span>
                <span className="text-amber-600 font-bold">DETECTED</span>
              </div>
            </div>

            <h3 className="text-lg font-bold text-slate-900 tracking-tight">
              Zero-Shift Semantic Intent
            </h3>
            <p className="mt-2 text-sm text-slate-600 leading-relaxed">
              Stops text-only social engineering, VIP gift card scams, and WhatsApp payroll diversion
              attacks that have no links or attachments.
            </p>
          </div>
          <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Contextual Transformer</span>
            <CheckCircle2 className="w-4 h-4 text-blue-600 inline" />
          </div>
        </div>

        {/* Bento Card 3: 1-column card (Instant Sandbox Execution) */}
        <div className="rounded-xl bg-white border border-slate-200/90 p-6 sm:p-8 shadow-sm hover:shadow-md hover:-translate-y-0.5 transition-all duration-200 flex flex-col justify-between">
          <div>
            {/* Mini UI Snippet: Sandboxing */}
            <div className="rounded-lg bg-slate-900 text-white p-3.5 font-mono-code text-[11px] mb-6 border border-slate-800">
              <div className="flex items-center justify-between text-slate-400 pb-2 border-b border-slate-800">
                <span>Sandbox Container</span>
                <span className="text-emerald-400">ISOLATED</span>
              </div>
              <div className="mt-2 text-slate-300 space-y-1">
                <div>&gt; Emulating iOS Mobile Safari...</div>
                <div>&gt; CAPTCHA Cloaking bypassed</div>
                <div className="text-rose-400">&gt; JS Exfiltrating LocalStorage!</div>
              </div>
            </div>

            <h3 className="text-lg font-bold text-slate-900 tracking-tight">
              Anti-Cloaking Execution
            </h3>
            <p className="mt-2 text-sm text-slate-600 leading-relaxed">
              Scammers show innocent pages to security bots and malicious payloads to real users.
              Our sandbox rotates 40+ mobile user agents and residential IPs.
            </p>
          </div>
          <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Headless Puppeteer Grid</span>
            <span className="text-blue-600 font-mono-code text-[11px]">80+ geo-exit nodes</span>
          </div>
        </div>

        {/* Bento Card 4: 2-column wide card (Automated SOC Remediation & Webhook Integration) */}
        <div className="md:col-span-2 rounded-xl bg-white border border-slate-200/90 p-6 sm:p-8 shadow-sm hover:shadow-md hover:-translate-y-0.5 transition-all duration-200 flex flex-col justify-between">
          <div>
            {/* Mini UI Snippet: Webhook payload & SIEM Dispatch */}
            <div className="rounded-lg bg-slate-50 p-4 border border-slate-200 mb-6 font-mono-code text-xs">
              <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-200 text-slate-500 text-[11px]">
                <span className="flex items-center gap-1.5">
                  <Share2 className="w-3.5 h-3.5 text-blue-600" />
                  <span>Event Stream: Splunk / Sentinel / Slack</span>
                </span>
                <span className="bg-blue-100 text-blue-700 px-2 py-0.5 rounded text-[10px] font-semibold">
                  HTTP 200 OK
                </span>
              </div>
              <pre className="text-slate-700 text-[11px] overflow-x-auto whitespace-pre-wrap leading-tight">
{`{
  "event": "threat.mitigated",
  "actor": "fin7_phishing_cluster",
  "dns_sinkhole": "active",
  "affected_users": ["sarah.ciso@acme.corp"],
  "action": "REVOKED_ACTIVE_OAUTH_TOKENS"
}`}
              </pre>
            </div>

            <h3 className="text-xl font-bold text-slate-900 tracking-tight">
              Automated SOAR &amp; SIEM Injection
            </h3>
            <p className="mt-2 text-sm text-slate-600 leading-relaxed">
              When a weaponized payload is detected on any employee device or team inbox, PhishLens
              triggers instant cross-channel revocation, blocks the malicious domain network-wide,
              and logs high-fidelity forensic data to Splunk or CrowdStrike.
            </p>
          </div>
          <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>REST API &amp; Webhooks</span>
            <a
              href="#docs"
              className="text-blue-600 flex items-center gap-1 hover:underline cursor-pointer"
            >
              <span>Review API Spec</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>

      </div>
      </div>
    </section>
  );
}
