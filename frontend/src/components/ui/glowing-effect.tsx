// ────────────────────────────────────────────────────────────
//  PhishLens  ·  GlowingEffect Component
//  Futuristic mouse-tracking & ambient Cyberpunk glow wrapper
// ────────────────────────────────────────────────────────────

import React, { useRef } from 'react';
import { motion, useMotionTemplate, useMotionValue } from 'framer-motion';
import { cn } from '@/lib/utils';

export interface GlowingEffectProps {
  children?: React.ReactNode;
  className?: string;
  glowClassName?: string;
  spread?: number;
  glowColor?: string;
  disabled?: boolean;
}

export function GlowingEffect({
  children,
  className,
  glowClassName,
  spread = 36,
  glowColor = 'rgba(0, 240, 255, 0.22)',
  disabled = false,
}: GlowingEffectProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const mouseX = useMotionValue(-1000);
  const mouseY = useMotionValue(-1000);

  const handleMouseMove = ({ currentTarget, clientX, clientY }: React.MouseEvent) => {
    if (disabled) return;
    const { left, top } = currentTarget.getBoundingClientRect();
    mouseX.set(clientX - left);
    mouseY.set(clientY - top);
  };

  const handleMouseLeave = () => {
    mouseX.set(-1000);
    mouseY.set(-1000);
  };

  const background = useMotionTemplate`radial-gradient(
    ${spread * 10}px circle at ${mouseX}px ${mouseY}px,
    ${glowColor},
    transparent 80%
  )`;

  return (
    <div
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      className={cn('relative rounded-2xl group/glow', className)}
    >
      {/* Interactive mouse-following neon spotlight */}
      {!disabled && (
        <motion.div
          className={cn(
            'pointer-events-none absolute -inset-[1px] rounded-2xl opacity-0 group-hover/glow:opacity-100 transition-opacity duration-500 z-0',
            glowClassName
          )}
          style={{ background }}
        />
      )}

      {/* Ambient cybernetic perimeter glow */}
      <div
        aria-hidden
        className="pointer-events-none absolute -inset-[1px] rounded-2xl opacity-60 z-0"
        style={{
          background:
            'linear-gradient(135deg, rgba(0, 240, 255, 0.12) 0%, transparent 45%, rgba(59, 130, 246, 0.08) 100%)',
        }}
      />

      <div className="relative z-10 w-full h-full">{children}</div>
    </div>
  );
}

export default GlowingEffect;
