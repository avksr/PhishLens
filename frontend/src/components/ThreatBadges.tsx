// ────────────────────────────────────────────────────────────
//  PhishLens  ·  ThreatBadges Component
//  Dynamic mapping of detected threat flags to styled badges
//  with per-flag emoji, color theming, and ambient glows.
// ────────────────────────────────────────────────────────────

import { motion } from 'framer-motion';
import type { ThreatFlag } from '../lib/mockData';

// ── Badge Configuration Map ──────────────────────────────────

interface BadgeConfig {
  emoji: string;
  label: string;
  /** Tailwind classes for background, text, border, and glow */
  className: string;
}

const BADGE_MAP: Record<ThreatFlag, BadgeConfig> = {
  fake_upi: {
    emoji: '💳',
    label: 'Fake UPI',
    className:
      'bg-rose-500/12 text-rose-400 border-rose-500/30 shadow-[0_0_14px_rgba(244,63,94,0.2)]',
  },
  flagged_nx: {
    emoji: '⚠️',
    label: 'Flagged Nx',
    className:
      'bg-amber-500/12 text-amber-400 border-amber-500/30 shadow-[0_0_14px_rgba(251,191,36,0.2)]',
  },
  ai_text: {
    emoji: '🤖',
    label: 'AI Text',
    className:
      'bg-violet-500/12 text-violet-400 border-violet-500/30 shadow-[0_0_14px_rgba(167,139,250,0.2)]',
  },
  manipulated_photo: {
    emoji: '📸',
    label: 'Manipulated',
    className:
      'bg-orange-500/12 text-orange-400 border-orange-500/30 shadow-[0_0_14px_rgba(251,146,60,0.2)]',
  },
  forged_doc: {
    emoji: '❌',
    label: 'Forged',
    className:
      'bg-red-900/25 text-red-400 border-red-800/40 shadow-[0_0_14px_rgba(220,38,38,0.25)]',
  },
};

// ── Component Props ──────────────────────────────────────────

interface ThreatBadgesProps {
  detectedFlags: ThreatFlag[];
  /** Optional: compact sizing for inline usage */
  compact?: boolean;
}

// ── Component ────────────────────────────────────────────────

export function ThreatBadges({ detectedFlags, compact = false }: ThreatBadgesProps) {
  if (!detectedFlags.length) {
    return (
      <span className="text-xs text-zinc-600 font-mono italic">
        No threat flags detected
      </span>
    );
  }

  return (
    <div className="flex flex-wrap gap-2" role="list" aria-label="Detected threat flags">
      {detectedFlags.map((flag, index) => {
        const config = BADGE_MAP[flag];
        if (!config) return null;

        return (
          <motion.span
            key={flag}
            role="listitem"
            initial={{ opacity: 0, scale: 0.85, y: 6 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            transition={{
              duration: 0.35,
              delay: index * 0.08,
              ease: 'easeOut',
            }}
            className={`
              inline-flex items-center gap-1.5
              ${compact ? 'px-2 py-0.5 text-[10px]' : 'px-3 py-1.5 text-xs'}
              rounded-full font-bold font-mono tracking-wide
              border backdrop-blur-sm
              transition-all duration-200
              hover:scale-105 hover:brightness-125
              cursor-default select-none
              ${config.className}
            `}
          >
            <span aria-hidden className={compact ? 'text-[11px]' : 'text-sm'}>
              {config.emoji}
            </span>
            <span>{config.label}</span>
          </motion.span>
        );
      })}
    </div>
  );
}

export default ThreatBadges;
