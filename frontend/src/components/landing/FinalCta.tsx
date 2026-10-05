// ─────────────────────────────────────────────────────────────
//  PhishLens Enterprise Landing · Final CTA Strip
//  Strictly matched to Stitch screen projects/1873559564137532359
//  High-impact dark slate section (#0F172A / bg-slate-900)
// ─────────────────────────────────────────────────────────────

export function FinalCta() {
  return (
    <section className="bg-[#0B1120] text-white py-16 sm:py-20 px-4 sm:px-6 border-t border-slate-800 relative overflow-hidden">
      {/* Subtle ambient glow */}
      <div
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-blue-600/10 rounded-full blur-3xl pointer-events-none"
        aria-hidden="true"
      />
      <div className="relative max-w-4xl mx-auto text-center z-10">
        <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
          Stop phishing payloads before your users click.
        </h2>
        <p className="mt-4 text-base text-slate-400 max-w-xl mx-auto leading-relaxed">
          Integrate PhishLens into your enterprise communication stack in less than 5 minutes with our universal API key.
        </p>
        <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
          <a
            href="#scanner"
            className="w-full sm:w-auto px-7 py-3.5 rounded-lg bg-blue-600 hover:bg-blue-500 font-semibold text-sm text-white transition-all shadow-lg shadow-blue-600/25 active:scale-[0.98] cursor-pointer"
          >
            Start Scanning Free
          </a>
          <a
            href="#pricing"
            className="w-full sm:w-auto px-7 py-3.5 rounded-lg bg-slate-800/90 hover:bg-slate-700 text-slate-300 font-medium text-sm transition-colors border border-slate-700 cursor-pointer active:scale-[0.98]"
          >
            Schedule Enterprise Demo
          </a>
        </div>
      </div>
    </section>
  );
}
