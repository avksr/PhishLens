// ────────────────────────────────────────────────────────────
//  PhishLens  ·  GooeyInput Component
//  Textarea with fluid/gooey focus animation & Pointer Highlight
// ────────────────────────────────────────────────────────────

import React, { useState, forwardRef } from 'react';
import { motion, useMotionTemplate, useMotionValue, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';

export interface GooeyInputProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  containerClassName?: string;
}

export const GooeyInput = forwardRef<HTMLTextAreaElement, GooeyInputProps>(
  ({ className, containerClassName, onFocus, onBlur, ...props }, ref) => {
    const [isFocused, setIsFocused] = useState(false);
    const mouseX = useMotionValue(0);
    const mouseY = useMotionValue(0);

    const handleMouseMove = ({ currentTarget, clientX, clientY }: React.MouseEvent<HTMLDivElement>) => {
      const { left, top } = currentTarget.getBoundingClientRect();
      mouseX.set(clientX - left);
      mouseY.set(clientY - top);
    };

    const pointerBackground = useMotionTemplate`radial-gradient(
      320px circle at ${mouseX}px ${mouseY}px,
      rgba(0, 240, 255, 0.14),
      transparent 80%
    )`;

    return (
      <div
        onMouseMove={handleMouseMove}
        className={cn(
          "relative group/gooey rounded-2xl p-[1px] transition-all duration-300",
          containerClassName
        )}
      >
        {/* SVG Gooey Filter */}
        <svg className="absolute w-0 h-0 pointer-events-none" aria-hidden="true">
          <defs>
            <filter id="phishlens-gooey-filter">
              <feGaussianBlur in="SourceGraphic" stdDeviation="5" result="blur" />
              <feColorMatrix
                in="blur"
                mode="matrix"
                values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 18 -8"
                result="goo"
              />
              <feComposite in="SourceGraphic" in2="goo" operator="atop" />
            </filter>
          </defs>
        </svg>

        {/* Pointer Highlight Effect Layer */}
        <motion.div
          className="pointer-events-none absolute -inset-[1px] rounded-2xl opacity-0 group-hover/gooey:opacity-100 transition-opacity duration-300 z-0"
          style={{ background: pointerBackground }}
        />

        {/* Fluid / Gooey Focus Glow Blobs */}
        <AnimatePresence>
          {isFocused && (
            <motion.div
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.98 }}
              transition={{ duration: 0.3 }}
              className="absolute -inset-[2px] rounded-2xl pointer-events-none z-0 overflow-hidden"
              style={{ filter: "url(#phishlens-gooey-filter)" }}
            >
              <motion.div
                animate={{
                  x: [0, 40, -30, 20, 0],
                  y: [0, -10, 15, -5, 0],
                  scale: [1, 1.15, 0.9, 1.05, 1],
                }}
                transition={{
                  repeat: Infinity,
                  duration: 6,
                  ease: "easeInOut",
                }}
                className="absolute -top-4 left-1/4 w-44 h-12 bg-cyan-400/35 rounded-full blur-md"
              />
              <motion.div
                animate={{
                  x: [0, -35, 30, -15, 0],
                  y: [0, 12, -10, 8, 0],
                  scale: [1, 0.9, 1.2, 1],
                }}
                transition={{
                  repeat: Infinity,
                  duration: 7,
                  ease: "easeInOut",
                }}
                className="absolute -bottom-4 right-1/4 w-48 h-12 bg-blue-500/35 rounded-full blur-md"
              />
            </motion.div>
          )}
        </AnimatePresence>

        {/* Ambient border layer */}
        <div
          className={cn(
            "relative z-10 w-full rounded-2xl transition-all duration-300",
            isFocused
              ? "ring-1 ring-cyan-500/60 shadow-[0_0_24px_rgba(0,240,255,0.18)]"
              : "ring-1 ring-slate-800 group-hover/gooey:ring-slate-700/80"
          )}
        >
          <textarea
            ref={ref}
            onFocus={(e) => {
              setIsFocused(true);
              onFocus?.(e);
            }}
            onBlur={(e) => {
              setIsFocused(false);
              onBlur?.(e);
            }}
            className={cn(
              "w-full resize-y text-sm min-h-[110px] p-4 rounded-2xl",
              "bg-slate-950/70 backdrop-blur-md text-slate-100 placeholder:text-slate-500",
              "outline-none transition-all duration-200 leading-relaxed font-sans",
              "disabled:opacity-50 disabled:cursor-not-allowed",
              className
            )}
            {...props}
          />
        </div>
      </div>
    );
  }
);

GooeyInput.displayName = 'GooeyInput';

export default GooeyInput;
