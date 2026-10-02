// ────────────────────────────────────────────────────────────
//  PhishLens · AnimatedNumber — Framer Motion count-up
//  Reusable stat counter with spring animation
// ────────────────────────────────────────────────────────────

import { useEffect, useRef } from "react";
import { useInView, useMotionValue, animate } from "framer-motion";

interface AnimatedNumberProps {
  /** Target value to animate to */
  value: number;
  /** Number of decimal places (default 0) */
  decimals?: number;
  /** Suffix appended after the number (e.g. "%" or "ms") */
  suffix?: string;
  /** Prefix before the number (e.g. "$") */
  prefix?: string;
  /** CSS className for the wrapper span */
  className?: string;
  /** Spring stiffness (default 50) */
  stiffness?: number;
  /** Spring damping (default 20) */
  damping?: number;
  /** Duration for the animate function in seconds (default 1.5) */
  duration?: number;
}

export function AnimatedNumber({
  value,
  decimals = 0,
  suffix = "",
  prefix = "",
  className = "",
  duration = 1.5,
}: AnimatedNumberProps) {
  const ref = useRef<HTMLSpanElement>(null);
  const motionValue = useMotionValue(0);
  const isInView = useInView(ref, { once: true, margin: "-40px" });

  useEffect(() => {
    if (!isInView) return;

    const controls = animate(motionValue, value, {
      duration,
      ease: "easeOut",
      onUpdate: (latest) => {
        if (ref.current) {
          ref.current.textContent = `${prefix}${latest.toFixed(decimals)}${suffix}`;
        }
      },
    });

    return () => controls.stop();
  }, [isInView, value, decimals, suffix, prefix, duration, motionValue]);

  return (
    <span ref={ref} className={className}>
      {prefix}0{suffix}
    </span>
  );
}

export default AnimatedNumber;
