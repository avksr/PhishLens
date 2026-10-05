// ─────────────────────────────────────────────────────────────
//  PhishLens Enterprise Landing · How It Works
//  Strictly matched to Stitch screen projects/1873559564137532359
//  Horizontal 3-step timeline on desktop with connecting track line
// ─────────────────────────────────────────────────────────────

export function HowItWorks() {
  return (
    <section id="how-it-works" className="py-16 sm:py-24 bg-slate-50/70 border-y border-slate-200/80">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        
        {/* Header */}
        <div className="text-center max-w-xl mx-auto mb-16">
          <div className="text-xs font-mono-code uppercase tracking-wider text-blue-600 font-semibold mb-2">
            Process Architecture
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-slate-900">
            From Suspicion to Quarantine in 14ms
          </h2>
          <p className="mt-3 text-sm sm:text-base text-slate-600">
            A frictionless pipeline engineered to minimize false positives without slowing down messaging pipelines.
          </p>
        </div>

        {/* 3 Steps Grid with connecting line indicator */}
        <div className="relative grid grid-cols-1 md:grid-cols-3 gap-8">
          
          {/* Desktop connecting line */}
          <div
            className="hidden md:block absolute top-1/2 left-[15%] right-[15%] h-0.5 bg-slate-200 -translate-y-8 z-0"
            aria-hidden="true"
          />

          {/* Step 1 */}
          <div className="relative z-10 bg-white p-6 sm:p-7 rounded-xl border border-slate-200 shadow-xs flex flex-col items-start">
            <div className="w-12 h-12 rounded-xl bg-slate-900 text-white flex items-center justify-center font-bold text-lg mb-5 shadow-sm">
              01
            </div>
            <h3 className="text-lg font-bold text-slate-900 mb-2">Payload Interception</h3>
            <p className="text-sm text-slate-600 leading-relaxed">
              API webhooks or client-side lightweight extensions intercept incoming message payloads,
              shortened URLs, or suspicious QR code attachments before click execution.
            </p>
            <div className="mt-4 text-xs font-mono-code text-slate-400">Zero-latency passthrough</div>
          </div>

          {/* Step 2 */}
          <div className="relative z-10 bg-white p-6 sm:p-7 rounded-xl border border-slate-200 shadow-xs flex flex-col items-start">
            <div className="w-12 h-12 rounded-xl bg-blue-600 text-white flex items-center justify-center font-bold text-lg mb-5 shadow-sm">
              02
            </div>
            <h3 className="text-lg font-bold text-slate-900 mb-2">Deep Sandboxing &amp; AI</h3>
            <p className="text-sm text-slate-600 leading-relaxed">
              Our isolated serverless cluster follows redirects, evaluates SSL issuer fingerprints,
              executes dynamic scripts, and checks perceptual similarity against verified brands.
            </p>
            <div className="mt-4 text-xs font-mono-code text-slate-400">14ms average execution</div>
          </div>

          {/* Step 3 */}
          <div className="relative z-10 bg-white p-6 sm:p-7 rounded-xl border border-slate-200 shadow-xs flex flex-col items-start">
            <div className="w-12 h-12 rounded-xl bg-slate-900 text-white flex items-center justify-center font-bold text-lg mb-5 shadow-sm">
              03
            </div>
            <h3 className="text-lg font-bold text-slate-900 mb-2">Automated Neutralization</h3>
            <p className="text-sm text-slate-600 leading-relaxed">
              The threat is instantly blocked at the DNS/browser layer. An automated advisory warning
              replaces the malicious link, and a forensic report is pushed to the SOC.
            </p>
            <div className="mt-4 text-xs font-mono-code text-slate-400">Zero employee disruption</div>
          </div>

        </div>

      </div>
    </section>
  );
}
