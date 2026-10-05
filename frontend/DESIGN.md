# PhishLens Enterprise Design System (DESIGN.md)

> **Source**: Stitch Project `projects/1873559564137532359`  
> **Screen**: `PhishLens Enterprise Landing Page` (`screens/dfa26b73ff9f4b369baf131652ba6b63`)  
> **Aesthetic**: Premium Light Enterprise Cybersecurity with High-Contrast Navy Scanner Block  
> **Status**: Verified against Stitch Screen HTML and Full-Resolution Capture

---

## 1. Design Philosophy

PhishLens employs a **clean, authoritative light theme** designed for enterprise security leaders (CISOs, SOC managers, DevOps engineers). 
- **Base Canvas**: Crisp white (`#FFFFFF`) with subtle geometric grid patterns and gentle slate section alternation (`#F8FAFC`).
- **High-Contrast Focal Element**: The **Live Threat Scanner Console** is housed in a focused, high-contrast dark navy block (`#0B1120`) that evokes real-time security terminal telemetry.
- **Accents**: Trust-inspiring royal blue (`#2563EB`) with subtle skewed marker underlines, high-visibility status indicators (emerald, amber, rose), and crisp monochrome typography.

---

## 2. Color Palette & Tokens

### 2.1 Surfaces & Canvas (Light Theme)
| Token | Value | Tailwind Class / Role | Usage |
| :--- | :--- | :--- | :--- |
| `--bg-base` | `#FFFFFF` | `bg-white` | Primary page canvas, cards, navbar background |
| `--bg-slate` | `#F8FAFC` | `bg-slate-50` | Alternating section fills (Trust banner, How it works) |
| `--bg-slate-subtle` | `#F1F5F9` | `bg-slate-100` | Pill badge backgrounds, input surrounds, subtle hover |
| `--border-subtle` | `rgba(226,232,240,0.8)` | `border-slate-200/80` | Card borders, navbar divider, container lines |
| `--border-light` | `#F1F5F9` | `border-slate-100` | Subtle internal card dividers |

### 2.2 Dark Navy Contrast Surfaces (Scanner Console & Highlight Tiers)
| Token | Value | Tailwind Class / Role | Usage |
| :--- | :--- | :--- | :--- |
| `--navy-scanner` | `#0B1120` | `bg-[#0B1120]` | Scanner section backdrop, primary CTAs, logo badge, Enterprise pricing card |
| `--navy-terminal` | `#020617` | `bg-slate-950` | Inner scanner console terminal shell, code blocks |
| `--navy-card` | `#0F172A` | `bg-slate-900` | Diagnostic metric cards, sample pill chips, final CTA strip |
| `--border-dark` | `rgba(51,65,85,0.6)` | `border-slate-700/60` | Scanner terminal borders, input pill outline |
| `--border-dark-subtle` | `rgba(30,41,59,0.8)` | `border-slate-800` | Inner metric card borders, scanline dividers |

### 2.3 Typography & Text
| Token | Value | Tailwind Class / Role | Usage |
| :--- | :--- | :--- | :--- |
| `--text-headline` | `#0F172A` | `text-slate-900` | Main titles, card headings, key metrics |
| `--text-body` | `#475569` | `text-slate-600` | Explanatory copy, feature descriptions |
| `--text-muted` | `#94A3B8` | `text-slate-400` | Metadata, microcopy, disabled states, terminal subheaders |
| `--text-inverse` | `#F8FAFC` | `text-slate-100` | Text inside dark scanner terminal & navy components |

### 2.4 Brand & Interactive Accent
| Token | Value | Tailwind Class / Role | Usage |
| :--- | :--- | :--- | :--- |
| `--blue-accent` | `#2563EB` | `text-blue-600`, `bg-blue-600` | Primary buttons, brand marks, active indicators |
| `--blue-hover` | `#1D4ED8` | `hover:bg-blue-700` | Button hover state |
| `--blue-light` | `rgba(37,99,235,0.12)` | `bg-blue-600/12` | Highlight marker underline, active pill backgrounds |
| `--blue-focus` | `rgba(37,99,235,0.25)` | `ring-blue-600/25` | Input focus rings, focus-visible outlines |

### 2.5 Diagnostic Status Scale
| Status | Hex | Background Tint | Border Tint | Usage |
| :--- | :--- | :--- | :--- | :--- |
| **Critical / Phishing** | `#F43F5E` (Rose-500) | `rgba(244,63,94,0.10)` | `rgba(244,63,94,0.25)` | Malicious verdicts, risk scores 80–100, urgent threat badges |
| **Warning / Suspicious** | `#F59E0B` (Amber-500) | `rgba(245,158,11,0.10)` | `rgba(245,158,11,0.25)` | Bulletproof ASN flags, urgency indicators, moderate scores |
| **Benign / Verified** | `#10B981` (Emerald-500) | `rgba(16,185,129,0.10)` | `rgba(16,185,129,0.25)` | Verified domains, EV TLS status, system operational beacon |

---

## 3. Typography & Font Hierarchy

### 3.1 Font Families
- **Primary Sans**: `'Geist', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`
- **Monospace Code**: `'JetBrains Mono', ui-monospace, SFMono-Regular, monospace` (`.font-mono-code`)

### 3.2 Type Scale
| Role | Size / Leading | Weight | Tracking | Usage |
| :--- | :--- | :--- | :--- | :--- |
| **Hero Display H1** | `text-4xl sm:text-6xl` (36px/60px, `leading-[1.08]`) | `800` (Extrabold) | `-0.03em` | Main hero value statement |
| **Section H2** | `text-3xl sm:text-4xl` (30px/36px, `leading-tight`) | `800` (Extrabold) | `-0.025em` | Bento, How It Works, Pricing headers |
| **Card H3** | `text-lg sm:text-xl` (18px/20px) | `700` (Bold) | `-0.01em` | Feature titles, plan names |
| **Subhead** | `text-base sm:text-xl` (16px/20px, `leading-relaxed`) | `400` (Normal) | `normal` | Hero subheadline |
| **Body Standard** | `text-sm` (14px, `leading-relaxed`) | `400` / `500` | `normal` | Paragraphs, step descriptions |
| **Microcopy & Pills**| `text-xs sm:text-[13px]` (12px/13px) | `500` / `600` | `+0.02em` | Tag pills, badge labels, navigation links |
| **Mono Diagnostics** | `text-[11px]` / `text-xs` | `400` / `500` | `normal` | Terminal output, JSON telemetry, hash tokens |

---

## 4. Spacing & Container Hierarchy

```
Site Max Widths:
├─ Navbar & Footer: max-w-7xl mx-auto (1280px)
├─ Hero Section:    max-w-5xl mx-auto (1024px)
├─ Scanner Section: max-w-4xl mx-auto (896px)
├─ Trust Channels:  max-w-6xl mx-auto (1152px)
├─ Bento Features:  max-w-6xl mx-auto (1152px)
├─ How It Works:    max-w-6xl mx-auto (1152px)
├─ Pricing:         max-w-6xl mx-auto (1152px)
└─ Final CTA:       max-w-4xl mx-auto (896px)

Section Spacing:
├─ Top / Bottom Section Padding: py-14 sm:py-20 or py-16 sm:py-24
├─ Component Card Gap:           gap-6 or gap-8
└─ Inline Item Gap:              gap-2.5 to gap-4
```

---

## 5. Border Radius & Shadows

| Token | CSS Value | Tailwind Class | Application |
| :--- | :--- | :--- | :--- |
| `--radius-sm` | `8px` | `rounded-lg` | Pill tags, action buttons, sample chips |
| `--radius-md` | `12px` | `rounded-xl` | Feature cards, step containers, inner console boxes |
| `--radius-lg` | `16px` | `rounded-2xl` | Scanner shell, pricing cards |
| `rounded-full`| `9999px` | `rounded-full` | Pulse indicator dots, floating pills, status badges |

### Shadow Tokens
- `shadow-xs`: `0 1px 2px 0 rgba(0, 0, 0, 0.05)` (Pill tags)
- `shadow-sm`: `0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1)` (Buttons, cards)
- `shadow-md`: `0 4px 6px -1px rgba(0, 0, 0, 0.1)` (Card hover, active popovers)
- `shadow-2xl`: `0 25px 50px -12px rgba(0, 0, 0, 0.25)` (Scanner console shell elevation)
- `scanner-glow`: `0 0 24px 6px rgba(37, 99, 235, 0.25)` (Animated ambient pulse around the dark scanner block)

---

## 6. Motion & Visual Signatures

1. **Highlight Marker Effect (`.highlight-marker`)**:
   - A subtle marker underline under "Before They Reach You":
   - `background: rgba(37, 99, 235, 0.12)`, `skewX(-6deg)`, `border-radius: 4px`.
   - Expands smoothly with `@keyframes markerExpand` (`0.8s cubic-bezier(0.16, 1, 0.3, 1)`).

2. **Radar Scanline Pulse (`.animate-scanline`)**:
   - Continuous scanning laser bar sweeping downward over the terminal block.
   - `3.5s cubic-bezier(0.4, 0, 0.2, 1) infinite`.

3. **Background Grid Overlay (`.bg-grid-pattern`)**:
   - `24px x 24px` grid pattern (`rgba(15, 23, 42, 0.045)`).
   - Bottom fade mask (`mask-image: linear-gradient(to bottom, black 65%, transparent 100%)`).

4. **Card Hover**:
   - `hover:shadow-md hover:-translate-y-0.5 transition-all duration-200`.

5. **Desktop Interactive Cursor Dot**:
   - Lerped 8px blue dot following the mouse pointer, expanding to 38px with soft tint on interactive elements. Suppressed on coarse touch devices.
