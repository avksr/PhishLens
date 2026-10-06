// ────────────────────────────────────────────────────────────
//  PhishLens  ·  StatefulButton Component
//  Handles Idle, Loading, Success states with Cyberpunk Glow & Animated Border
// ────────────────────────────────────────────────────────────

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';
import { Check, Loader2 } from 'lucide-react';

export type ButtonStatus = 'idle' | 'loading' | 'success';

export interface StatefulButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  status?: ButtonStatus;
  loadingText?: React.ReactNode;
  successText?: React.ReactNode;
  idleText?: React.ReactNode;
}

export const StatefulButton = React.forwardRef<HTMLButtonElement, StatefulButtonProps>(
  (
    {
      status = 'idle',
      children,
      loadingText = 'Analyzing Threats…',
      successText = 'Scan Complete',
      idleText,
      disabled,
      className,
      ...props
    },
    ref
  ) => {
    const isLoading = status === 'loading';
    const isSuccess = status === 'success';

    return (
      <div className="relative group/btn inline-flex rounded-xl p-[1px] overflow-hidden">
        {/* Animated Cyberpunk Glowing Border (Conic Sweep) */}
        <span
          className={cn(
            "absolute inset-[-1000%] animate-[spin_3s_linear_infinite] transition-opacity duration-300",
            isSuccess
              ? "bg-[conic-gradient(from_90deg_at_50%_50%,#10B981_0%,#34D399_50%,#10B981_100%)] opacity-90"
              : isLoading
              ? "bg-[conic-gradient(from_90deg_at_50%_50%,#00F0FF_0%,#3B82F6_50%,#00F0FF_100%)] opacity-100"
              : "bg-[conic-gradient(from_90deg_at_50%_50%,#00F0FF_0%,#3B82F6_50%,#00F0FF_100%)] opacity-70 group-hover/btn:opacity-100"
          )}
        />

        {/* Ambient Neon Shadow Glow */}
        <div
          className={cn(
            "absolute inset-0 rounded-xl blur-md transition-all duration-300 -z-10",
            isSuccess
              ? "bg-emerald-500/30 shadow-[0_0_25px_rgba(16,185,129,0.5)]"
              : isLoading
              ? "bg-cyan-500/40 shadow-[0_0_30px_rgba(0,240,255,0.6)]"
              : "bg-cyan-500/25 group-hover/btn:shadow-[0_0_25px_rgba(0,240,255,0.4)]"
          )}
        />

        {/* Interactive Button Surface */}
        <button
          ref={ref}
          disabled={disabled || isLoading}
          className={cn(
            "relative z-10 w-full h-10 px-5 py-2 rounded-xl text-xs sm:text-sm font-bold font-sans",
            "inline-flex items-center justify-center gap-2 select-none outline-none",
            "transition-all duration-200 active:scale-[0.98]",
            isSuccess
              ? "bg-gradient-to-r from-emerald-600 to-teal-600 text-white"
              : isLoading
              ? "bg-slate-900/90 text-cyan-300"
              : "bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg",
            "disabled:opacity-50 disabled:cursor-not-allowed disabled:active:scale-100",
            className
          )}
          {...props}
        >
          <AnimatePresence mode="wait">
            {isLoading ? (
              <motion.span
                key="loading"
                initial={{ opacity: 0, y: 6, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -6, scale: 0.95 }}
                transition={{ duration: 0.18 }}
                className="inline-flex items-center gap-2"
              >
                <Loader2 className="size-4 animate-spin text-cyan-400" />
                <span className="font-mono tracking-tight">{loadingText}</span>
              </motion.span>
            ) : isSuccess ? (
              <motion.span
                key="success"
                initial={{ opacity: 0, y: 6, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -6, scale: 0.95 }}
                transition={{ duration: 0.18 }}
                className="inline-flex items-center gap-2"
              >
                <Check className="size-4 text-emerald-300" />
                <span className="font-mono tracking-tight">{successText}</span>
              </motion.span>
            ) : (
              <motion.span
                key="idle"
                initial={{ opacity: 0, y: 6, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -6, scale: 0.95 }}
                transition={{ duration: 0.18 }}
                className="inline-flex items-center gap-2"
              >
                {idleText || children}
              </motion.span>
            )}
          </AnimatePresence>
        </button>
      </div>
    );
  }
);

StatefulButton.displayName = 'StatefulButton';

export default StatefulButton;
