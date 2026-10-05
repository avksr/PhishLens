// ─────────────────────────────────────────────────────────────
//  PhishLens Enterprise Landing · Trust Banner (Channels Row)
//  Strictly matched to Stitch screen projects/1873559564137532359
//  Light theme: bg-slate-50/60, border-b border-slate-200/80
// ─────────────────────────────────────────────────────────────
import { MessageSquareText } from 'lucide-react';

export function TrustBanner() {
  return (
    <section className="py-12 border-b border-slate-200/80 bg-slate-50/60">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 text-center">
        <p className="text-xs uppercase tracking-widest font-semibold text-slate-400 mb-6">
          Analyzes &amp; neutralizes threats across enterprise channels
        </p>

        <div className="flex flex-wrap items-center justify-center gap-6 sm:gap-12 opacity-80">
          
          {/* Telegram */}
          <div className="group flex items-center gap-2 text-slate-500 hover:text-slate-900 transition-colors cursor-default">
            <svg
              className="w-5 h-5 text-slate-400 group-hover:text-[#229ED9] transition-colors"
              viewBox="0 0 24 24"
              fill="currentColor"
            >
              <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69a.2.2 0 00-.05-.18c-.06-.05-.14-.03-.21-.02-.09.02-1.49.95-4.22 2.79-.4.27-.76.41-1.08.4-.36-.01-1.04-.2-1.55-.37-.63-.2-1.12-.31-1.08-.66.02-.18.27-.36.75-.55 2.92-1.27 4.86-2.11 5.83-2.51 2.78-1.16 3.35-1.36 3.73-1.36.08 0 .27.02.39.12.1.08.13.19.14.27-.01.06.01.24 0 .37z" />
            </svg>
            <span className="text-sm font-semibold tracking-tight">Telegram</span>
          </div>

          {/* WhatsApp */}
          <div className="group flex items-center gap-2 text-slate-500 hover:text-slate-900 transition-colors cursor-default">
            <svg
              className="w-5 h-5 text-slate-400 group-hover:text-[#25D366] transition-colors"
              viewBox="0 0 24 24"
              fill="currentColor"
            >
              <path d="M12.04 2c-5.46 0-9.91 4.45-9.91 9.91 0 1.75.46 3.45 1.32 4.95L2.05 22l5.25-1.38c1.45.79 3.08 1.21 4.74 1.21 5.46 0 9.91-4.45 9.91-9.91 0-2.65-1.03-5.14-2.9-7.01A9.816 9.816 0 0012.04 2m.01 1.67c2.2 0 4.26.86 5.82 2.42a8.225 8.225 0 012.41 5.83c0 4.54-3.7 8.24-8.24 8.24-1.48 0-2.93-.4-4.2-1.15l-.3-.18-3.12.82.83-3.04-.2-.31a8.196 8.196 0 01-1.26-4.38c0-4.54 3.7-8.24 8.24-8.24" />
            </svg>
            <span className="text-sm font-semibold tracking-tight">WhatsApp</span>
          </div>

          {/* Google Workspace */}
          <div className="group flex items-center gap-2 text-slate-500 hover:text-slate-900 transition-colors cursor-default">
            <svg
              className="w-5 h-5 text-slate-400 group-hover:text-[#EA4335] transition-colors"
              viewBox="0 0 24 24"
              fill="currentColor"
            >
              <path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z" />
            </svg>
            <span className="text-sm font-semibold tracking-tight">Google Workspace</span>
          </div>

          {/* SMS / Cellular Carriers */}
          <div className="group flex items-center gap-2 text-slate-500 hover:text-slate-900 transition-colors cursor-default">
            <MessageSquareText className="w-5 h-5 text-slate-400 group-hover:text-blue-600 transition-colors" />
            <span className="text-sm font-semibold tracking-tight">SMS Gateway</span>
          </div>

          {/* Microsoft 365 */}
          <div className="group flex items-center gap-2 text-slate-500 hover:text-slate-900 transition-colors cursor-default">
            <svg
              className="w-5 h-5 text-slate-400 group-hover:text-[#0078D4] transition-colors"
              viewBox="0 0 24 24"
              fill="currentColor"
            >
              <path d="M11.5 3H3v8.5h8.5V3zm9.5 0h-8.5v8.5H21V3zm-9.5 9.5H3V21h8.5v-8.5zm9.5 0h-8.5V21H21v-8.5z" />
            </svg>
            <span className="text-sm font-semibold tracking-tight">Microsoft 365</span>
          </div>

          {/* Slack */}
          <div className="group flex items-center gap-2 text-slate-500 hover:text-slate-900 transition-colors cursor-default">
            <svg
              className="w-5 h-5 text-slate-400 group-hover:text-[#4A154B] transition-colors"
              viewBox="0 0 24 24"
              fill="currentColor"
            >
              <path d="M6 15a2 2 0 0 1-2 2 2 2 0 0 1-2-2 2 2 0 0 1 2-2h2v2zm1 0a2 2 0 0 1 2-2 2 2 0 0 1 2 2v5a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-5zm2-7a2 2 0 0 1-2-2 2 2 0 0 1 2-2 2 2 0 0 1 2 2v2H9zm0 1a2 2 0 0 1 2 2 2 2 0 0 1-2 2H4a2 2 0 0 1-2-2 2 2 0 0 1 2-2h5zm6 2a2 2 0 0 1 2-2 2 2 0 0 1 2 2 2 2 0 0 1-2 2h-2v-2zm-1 0a2 2 0 0 1-2 2 2 2 0 0 1-2-2V6a2 2 0 0 1 2-2 2 2 0 0 1 2 2v5zm-2 7a2 2 0 0 1 2 2 2 2 0 0 1-2 2 2 2 0 0 1-2-2v-2h2zm0-1a2 2 0 0 1-2-2 2 2 0 0 1 2-2h5a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-5z" />
            </svg>
            <span className="text-sm font-semibold tracking-tight">Slack Connect</span>
          </div>

        </div>
      </div>
    </section>
  );
}
