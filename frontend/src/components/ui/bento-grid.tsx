// ────────────────────────────────────────────────────────────
//  PhishLens · Aceternity-style Bento Grid
//  Minimal dark aesthetic — thin borders, ambient glows
// ────────────────────────────────────────────────────────────

import { cn } from "@/lib/utils";

export function BentoGrid({
  className,
  children,
}: {
  className?: string;
  children?: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "grid grid-cols-1 md:grid-cols-3 gap-4 max-w-7xl mx-auto",
        className
      )}
    >
      {children}
    </div>
  );
}

export function BentoGridItem({
  className,
  id,
  title,
  description,
  header,
  icon,
  children,
}: {
  className?: string;
  id?: string;
  title?: string | React.ReactNode;
  description?: string | React.ReactNode;
  header?: React.ReactNode;
  icon?: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <div
      id={id}
      className={cn(
        "group/bento relative row-span-1 rounded-xl p-4",
        "border border-white/[0.08]",
        "bg-zinc-950/80",
        "transition-all duration-300 ease-out",
        "hover:border-white/[0.15] hover:shadow-[0_0_30px_rgba(0,240,255,0.04)]",
        className
      )}
    >
      {/* Subtle top-edge ambient glow on hover */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-500/20 to-transparent opacity-0 group-hover/bento:opacity-100 transition-opacity duration-500"
      />

      {header && (
        <div className="mb-4">{header}</div>
      )}

      <div className="transition duration-200">
        {icon && (
          <div className="mb-2">{icon}</div>
        )}
        {title && (
          <div className="text-sm font-semibold text-zinc-100 tracking-tight font-sans mb-1">
            {title}
          </div>
        )}
        {description && (
          <div className="text-xs text-zinc-500 font-sans leading-relaxed">
            {description}
          </div>
        )}
      </div>

      {children}
    </div>
  );
}
