// ─────────────────────────────────────────────────────────────
//  PhishLens Enterprise Landing · Page Orchestrator
//  Strictly matched to Stitch screen projects/1873559564137532359
//  Light theme with dark contrast Scanner block & Final CTA strip
// ─────────────────────────────────────────────────────────────
import { useEffect } from 'react';
import { Navbar } from './Navbar';
import { Hero } from './Hero';
import { ScannerSection } from './ScannerSection';
import { TrustBanner } from './TrustBanner';
import { BentoFeatures } from './BentoFeatures';
import { HowItWorks } from './HowItWorks';
import { Pricing } from './Pricing';
import { FinalCta } from './FinalCta';
import { Footer } from './Footer';
import { CustomCursor } from './CustomCursor';

interface LandingPageProps {
  onNavigateToDashboard?: () => void;
}

export function LandingPage({ onNavigateToDashboard }: LandingPageProps) {
  useEffect(() => {
    document.title = 'PhishLens — Enterprise Scam & Phishing Detection';
    // Ensure document background is clean white
    document.body.style.backgroundColor = '#FFFFFF';
    document.body.style.color = '#0F172A';

    return () => {
      document.body.style.backgroundColor = '';
      document.body.style.color = '';
    };
  }, []);

  return (
    <div className="relative min-h-screen bg-white text-slate-900 selection:bg-blue-100 selection:text-blue-900">
      {/* Desktop Lerped Cursor Dot */}
      <CustomCursor />

      {/* Global Subtle Geometric Grid Overlay */}
      <div
        className="fixed inset-0 pointer-events-none bg-grid-pattern z-0 opacity-80"
        aria-hidden="true"
      />

      {/* Sticky Enterprise Navbar */}
      <Navbar onNavigateToDashboard={onNavigateToDashboard} />

      {/* Main Page Flow */}
      <main className="relative z-10">
        <Hero />
        <ScannerSection />
        <TrustBanner />
        <BentoFeatures />
        <HowItWorks />
        <Pricing />
        <FinalCta />
      </main>

      {/* Enterprise Footer */}
      <Footer />
    </div>
  );
}

export default LandingPage;
