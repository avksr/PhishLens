// ─────────────────────────────────────────────────────────────
//  PhishLens Enterprise Landing · Pricing
//  Strictly matched to Stitch screen projects/1873559564137532359
//  3-tier cards with Highlighted Dark Navy (#0B1120) Enterprise Pro
// ─────────────────────────────────────────────────────────────
import { Check, Minus } from 'lucide-react';

export function Pricing() {
  return (
    <section id="pricing" className="py-16 sm:py-24 px-4 sm:px-6 max-w-6xl mx-auto">
      
      {/* Header */}
      <div className="text-center max-w-xl mx-auto mb-16">
        <div className="text-xs font-mono-code uppercase tracking-wider text-blue-600 font-semibold mb-2">
          Predictable Enterprise Tiers
        </div>
        <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-slate-900">
          Transparent protection for teams of any scale
        </h2>
        <p className="mt-3 text-sm sm:text-base text-slate-600">
          All plans include full zero-day heuristic updates and unlimited scan queries.
        </p>
      </div>

      {/* 3 Tier Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-stretch">
        
        {/* Tier 1: Starter */}
        <div className="rounded-2xl bg-white border border-slate-200 p-7 sm:p-8 flex flex-col justify-between shadow-xs hover:border-slate-300 transition-colors">
          <div>
            <div className="text-xs font-mono-code uppercase tracking-wider text-slate-500 font-semibold mb-2">
              Developer / Startup
            </div>
            <h3 className="text-2xl font-bold text-slate-900">Starter</h3>
            <p className="mt-2 text-xs sm:text-sm text-slate-600">
              For small teams securing internal communications and APIs.
            </p>
            
            <div className="mt-6 flex items-baseline gap-1">
              <span className="text-4xl font-extrabold tracking-tight text-slate-900">$49</span>
              <span className="text-slate-500 text-sm font-medium">/ month</span>
            </div>

            <ul className="mt-8 space-y-3 text-sm text-slate-600">
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-600 shrink-0" />
                <span>Up to 25 protected seats</span>
              </li>
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-600 shrink-0" />
                <span>Telegram &amp; WhatsApp webhook API</span>
              </li>
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-600 shrink-0" />
                <span>10,000 real-time link scans / mo</span>
              </li>
              <li className="flex items-center gap-2.5 text-slate-400">
                <Minus className="w-4 h-4 text-slate-300 shrink-0" />
                <span>Dedicated SOC integration</span>
              </li>
            </ul>
          </div>

          <div className="mt-8 pt-6 border-t border-slate-100">
            <a
              href="#scanner"
              className="block w-full text-center py-2.5 px-4 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-900 font-medium text-sm transition-colors cursor-pointer"
            >
              Deploy Starter
            </a>
          </div>
        </div>

        {/* Tier 2: Enterprise Business (HIGHLIGHTED: #0B1120 Dark Navy Theme) */}
        <div className="rounded-2xl bg-[#0B1120] text-white p-7 sm:p-8 flex flex-col justify-between shadow-xl relative border border-slate-700/80 -my-2 lg:-my-4">
          
          {/* Badge */}
          <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 rounded-full bg-blue-600 text-white font-mono-code text-[11px] font-semibold tracking-wider uppercase shadow-md whitespace-nowrap">
            Most Popular · CISO Choice
          </div>

          <div>
            <div className="text-xs font-mono-code uppercase tracking-wider text-blue-400 font-semibold mb-2">
              Growth &amp; Mid-Market
            </div>
            <h3 className="text-2xl font-bold text-white">Enterprise Business</h3>
            <p className="mt-2 text-xs sm:text-sm text-slate-400">
              Complete threat prevention across email, chat, and mobile messaging.
            </p>
            
            <div className="mt-6 flex items-baseline gap-1">
              <span className="text-4xl font-extrabold tracking-tight text-white">$199</span>
              <span className="text-slate-400 text-sm font-medium">/ month</span>
            </div>

            <ul className="mt-8 space-y-3 text-sm text-slate-300">
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-400 shrink-0" />
                <span>Up to 250 protected team members</span>
              </li>
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-400 shrink-0" />
                <span>All channels: SMS, Slack, Telegram, M365</span>
              </li>
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-400 shrink-0" />
                <span>Real-time DOM clone analysis &amp; sandbox</span>
              </li>
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-400 shrink-0" />
                <span>Automated DNS sinkhole &amp; token revocation</span>
              </li>
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-400 shrink-0" />
                <span>SIEM export (Splunk, Datadog)</span>
              </li>
            </ul>
          </div>

          <div className="mt-8 pt-6 border-t border-slate-800">
            <a
              href="#scanner"
              className="block w-full text-center py-3 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-sm transition-all shadow-md cursor-pointer"
            >
              Start 14-Day Enterprise Trial
            </a>
          </div>
        </div>

        {/* Tier 3: Custom / Fortune 500 */}
        <div className="rounded-2xl bg-white border border-slate-200 p-7 sm:p-8 flex flex-col justify-between shadow-xs hover:border-slate-300 transition-colors">
          <div>
            <div className="text-xs font-mono-code uppercase tracking-wider text-slate-500 font-semibold mb-2">
              Global Scale
            </div>
            <h3 className="text-2xl font-bold text-slate-900">Custom / Sovereign</h3>
            <p className="mt-2 text-xs sm:text-sm text-slate-600">
              On-premise appliance, air-gapped sandboxes, and sovereign telemetry.
            </p>
            
            <div className="mt-6 flex items-baseline gap-1">
              <span className="text-4xl font-extrabold tracking-tight text-slate-900">Custom</span>
              <span className="text-slate-500 text-sm font-medium">annual billing</span>
            </div>

            <ul className="mt-8 space-y-3 text-sm text-slate-600">
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-600 shrink-0" />
                <span>Unlimited seats &amp; enterprise telemetry</span>
              </li>
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-600 shrink-0" />
                <span>On-premise air-gapped cluster option</span>
              </li>
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-600 shrink-0" />
                <span>Custom zero-day threat feeds &amp; SLA</span>
              </li>
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-600 shrink-0" />
                <span>24/7 Dedicated Threat Intelligence Analyst</span>
              </li>
            </ul>
          </div>

          <div className="mt-8 pt-6 border-t border-slate-100">
            <a
              href="mailto:sales@phishlens.ai"
              className="block w-full text-center py-2.5 px-4 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium text-sm transition-colors cursor-pointer"
            >
              Speak with Security Architect
            </a>
          </div>
        </div>

      </div>

      {/* Compliance reassurance footer */}
      <div className="mt-12 text-center text-xs text-slate-500 flex flex-wrap items-center justify-center gap-6">
        <span>ISO 27001 Certified</span>
        <span>•</span>
        <span>HIPAA &amp; HITECH Compliant</span>
        <span>•</span>
        <span>GDPR &amp; CCPA Data Sovereignty</span>
        <span>•</span>
        <span>99.99% Guaranteed SLA</span>
      </div>

    </section>
  );
}
