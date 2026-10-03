"""
phishlens.agents.url_agent.url_agent — Production-Grade URL Threat Intelligence Orchestrator.

Orchestrates multi-signal analysis across 4 specialized sub-modules:
  1. RedirectTracer: Multi-hop redirect tracing, anti-cloaking dual-pass check.
  2. HomographEngine: IDN/Punycode decoding, Unicode confusables, typosquatting & brand impersonation.
  3. SSLAnalyzer: TLS handshake, temporal certificate age, disposable CA auditing, non-standard port checks.
  4. DOMInspector: Favicon Murmur3 hash brand matching, credential theft DOM indicators, cross-domain forms.

Aggregates signals into a standardized weighted risk score (0-100) and structured threat intelligence output.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

try:
    from phishlens.agents.url_agent.models.schema import (
        RiskSignal,
        URLAgentInput,
        URLAgentOutput,
    )
    from phishlens.agents.url_agent.core.redirect_tracer import (
        RedirectTraceResult,
        RedirectTracer,
    )
    from phishlens.agents.url_agent.core.homograph_engine import (
        HomographEngine,
        HomographResult,
    )
    from phishlens.agents.url_agent.core.ssl_analyzer import (
        SSLAnalysisResult,
        SSLAnalyzer,
    )
    from phishlens.agents.url_agent.core.dom_inspector import (
        DOMAnalysisResult,
        DOMInspector,
    )
except ImportError:
    from .models.schema import (
        RiskSignal,
        URLAgentInput,
        URLAgentOutput,
    )
    from .core.redirect_tracer import (
        RedirectTraceResult,
        RedirectTracer,
    )
    from .core.homograph_engine import (
        HomographEngine,
        HomographResult,
    )
    from .core.ssl_analyzer import (
        SSLAnalysisResult,
        SSLAnalyzer,
    )
    from .core.dom_inspector import (
        DOMAnalysisResult,
        DOMInspector,
    )

logger = logging.getLogger(__name__)

# High-risk / untrusted TLDs commonly abused in automated redirect campaigns
UNTRUSTED_TLDS = frozenset({
    "zip", "mov", "top", "xyz", "work", "click", "buzz", "cam", "country",
    "live", "loan", "cfd", "rest", "sbs", "icu", "quest", "monster", "fit",
    "gq", "ml", "cf", "ga", "tk", "su", "link", "party", "date", "racing",
})


class URLAgent:
    """
    State-of-the-art URL analysis agent combining active network inspection,
    cryptographic certificate audits, visual DOM inspection, and lexical heuristics.
    """

    def __init__(
        self,
        redirect_tracer: Optional[RedirectTracer] = None,
        homograph_engine: Optional[HomographEngine] = None,
        ssl_analyzer: Optional[SSLAnalyzer] = None,
        dom_inspector: Optional[DOMInspector] = None,
    ) -> None:
        self.redirect_tracer = redirect_tracer or RedirectTracer()
        self.homograph_engine = homograph_engine or HomographEngine()
        self.ssl_analyzer = ssl_analyzer or SSLAnalyzer()
        self.dom_inspector = dom_inspector or DOMInspector()

    async def analyze(
        self,
        input_data: Union[URLAgentInput, str, Dict[str, Any]],
    ) -> URLAgentOutput:
        """
        Execute deep inspection pipeline for the target URL.

        Args:
            input_data: URLAgentInput model, string URL, or dict.

        Returns:
            URLAgentOutput containing final destination, risk score, signals, and explanation.
        """
        start_time = time.monotonic()

        # Normalize input
        if isinstance(input_data, str):
            config = URLAgentInput(url=input_data.strip())
        elif isinstance(input_data, dict):
            config = URLAgentInput(**input_data)
        elif isinstance(input_data, URLAgentInput):
            config = input_data
        else:
            raise ValueError(f"Unsupported input type: {type(input_data)}")

        url = config.url.strip()
        if not url:
            return URLAgentOutput(
                input_url="",
                final_destination_url="",
                risk_score=0,
                threat_level="SAFE",
                redirect_chain=[],
                signals=[RiskSignal(category="INPUT", severity="LOW", description="Empty URL provided.")],
                metadata={"scan_duration_ms": 0.0},
                explanation="No URL provided for analysis.",
            )

        # Ensure scheme
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "https://" + url

        collected_signals: List[RiskSignal] = []
        raw_score = 0
        metadata: Dict[str, Any] = {}

        # ---------------------------------------------------------------------
        # 1. Homograph & Typosquatting Analysis (Input Domain)
        # ---------------------------------------------------------------------
        homograph_res: Optional[HomographResult] = None
        try:
            homograph_res = self.homograph_engine.analyze(url)
            collected_signals.extend(homograph_res.signals)
            metadata["homograph"] = {
                "registered_domain": homograph_res.domain,
                "is_punycode": homograph_res.is_punycode,
                "unicode_domain": homograph_res.unicode_domain,
                "skeleton": homograph_res.skeleton,
                "impersonated_brand": homograph_res.impersonated_brand,
                "brand_similarity": homograph_res.brand_similarity,
                "is_combosquatting": homograph_res.is_combosquatting,
                "is_subdomain_spoof": homograph_res.is_subdomain_spoof,
            }
        except Exception as exc:
            logger.warning("Homograph analysis encountered error for %s: %s", url, exc)
            collected_signals.append(
                RiskSignal(category="HOMOGRAPH", severity="LOW", description=f"Homograph inspection fallback: {exc}")
            )

        # ---------------------------------------------------------------------
        # 2. Redirect Tracing & Anti-Cloaking Dual-Pass Check
        # ---------------------------------------------------------------------
        redirect_res: Optional[RedirectTraceResult] = None
        try:
            redirect_res = await self.redirect_tracer.trace_redirects(
                url=url,
                user_agent_override=config.user_agent_override,
                deep_scan=config.deep_scan,
            )
            collected_signals.extend(redirect_res.signals)
            metadata["redirect"] = {
                "final_destination": redirect_res.final_url,
                "hop_count": redirect_res.hop_count,
                "is_cloaked": redirect_res.is_cloaked,
                "chain": [hop.url for hop in redirect_res.hops],
            }
        except Exception as exc:
            logger.warning("Redirect tracing encountered error for %s: %s", url, exc)
            collected_signals.append(
                RiskSignal(category="REDIRECT", severity="LOW", description=f"Redirect tracer fallback: {exc}")
            )

        # Determine effective final destination URL
        final_destination_url = redirect_res.final_url if redirect_res else url
        redirect_chain = [hop.url for hop in redirect_res.hops] if redirect_res else [url]

        # ---------------------------------------------------------------------
        # 3. SSL Infrastructure & Certificate Analysis
        # ---------------------------------------------------------------------
        ssl_res: Optional[SSLAnalysisResult] = None
        try:
            ssl_res = await self.ssl_analyzer.analyze(final_destination_url)
            collected_signals.extend(ssl_res.signals)
            metadata["ssl"] = {
                "issuer": ssl_res.issuer,
                "certificate_age_hours": ssl_res.certificate_age_hours,
                "san_count": ssl_res.san_count,
                "is_disposable_issuer": ssl_res.is_disposable_issuer,
                "is_non_standard_port": ssl_res.is_non_standard_port,
                "port": ssl_res.port,
            }
        except Exception as exc:
            logger.warning("SSL analysis encountered error for %s: %s", final_destination_url, exc)
            collected_signals.append(
                RiskSignal(category="SSL", severity="LOW", description=f"SSL analysis fallback: {exc}")
            )

        # ---------------------------------------------------------------------
        # 4. DOM & Visual Favicon Inspector
        # ---------------------------------------------------------------------
        dom_res: Optional[DOMAnalysisResult] = None
        pass_b_body = redirect_res.pass_b_body if redirect_res else None
        try:
            # Re-use HTML fetched during redirect tracing if available to save bandwidth
            dom_res = await self.dom_inspector.inspect(
                url=final_destination_url,
                html_content=pass_b_body,
            )
            collected_signals.extend(dom_res.signals)
            metadata["dom"] = {
                "favicon_hash": dom_res.favicon_hash,
                "favicon_brand_match": dom_res.favicon_brand_match,
                "is_brand_mismatch": dom_res.is_brand_mismatch,
                "has_password_input": dom_res.has_password_input,
                "has_payment_input": dom_res.has_payment_input,
                "external_form_actions": dom_res.external_form_actions,
            }
        except Exception as exc:
            logger.warning("DOM inspection encountered error for %s: %s", final_destination_url, exc)
            collected_signals.append(
                RiskSignal(category="DOM", severity="LOW", description=f"DOM inspection fallback: {exc}")
            )

        # ---------------------------------------------------------------------
        # 5. Weighted Scoring Calculation (per Project Specification)
        # ---------------------------------------------------------------------
        applied_rules: List[str] = []

        # Rule 1: Homograph / Brand Impersonation: +35 points
        if homograph_res and (
            homograph_res.is_impersonating
            or homograph_res.is_combosquatting
            or homograph_res.is_subdomain_spoof
            or (homograph_res.is_punycode and homograph_res.brand_similarity >= 0.70)
        ):
            raw_score += 35
            applied_rules.append(
                f"Homograph/Brand Impersonation detected (+35): target brand '{homograph_res.impersonated_brand}'"
            )
        elif homograph_res and homograph_res.is_punycode:
            raw_score += 20
            applied_rules.append("Punycode/IDN confusable detected (+20)")

        # Rule 2: Young SSL Cert (<24 hrs) + Password Input Present: +40 points
        cert_young_24 = (
            ssl_res is not None
            and ssl_res.certificate_age_hours is not None
            and ssl_res.certificate_age_hours < 24
        )
        password_present = dom_res is not None and dom_res.has_password_input

        if cert_young_24 and password_present:
            raw_score += 40
            applied_rules.append(
                f"High-threat combination: Fresh SSL certificate ({ssl_res.certificate_age_hours:.1f}h old) "
                f"with password login field present (+40)"
            )
        else:
            # Partial signals if only one matches
            if ssl_res and ssl_res.certificate_age_hours is not None:
                if ssl_res.certificate_age_hours < 24:
                    raw_score += 20
                    applied_rules.append(
                        f"Newly issued SSL certificate (<24h: {ssl_res.certificate_age_hours:.1f}h) (+20)"
                    )
                elif ssl_res.certificate_age_hours < 48:
                    raw_score += 15
                    applied_rules.append(
                        f"Recently issued SSL certificate (<48h: {ssl_res.certificate_age_hours:.1f}h) (+15)"
                    )

            if password_present and not cert_young_24:
                # Standalone password field on suspicious infrastructure
                if ssl_res and ssl_res.is_disposable_issuer:
                    raw_score += 15
                    applied_rules.append("Password input served with disposable/free SSL issuer (+15)")

        # Rule 3: Favicon Hash Brand Mismatch: +45 points
        if dom_res and dom_res.is_brand_mismatch:
            raw_score += 45
            applied_rules.append(
                f"Critical visual spoofing: Brand favicon mismatch. "
                f"Official '{dom_res.favicon_brand_match}' favicon hosted on untrusted domain (+45)"
            )

        # Rule 4: Cloaking / Evasive User-Agent Behavior: +30 points
        if redirect_res and redirect_res.is_cloaked:
            raw_score += 30
            applied_rules.append(
                "Dynamic anti-analysis cloaking detected: "
                "Server delivered divergent content to security crawler vs mobile client (+30)"
            )

        # Rule 5: Multi-Hop Redirect to Untrusted TLD: +20 points
        is_multi_hop_untrusted = False
        if redirect_res:
            parsed_final = urlparse(redirect_res.final_url)
            final_ext = parsed_final.netloc.split(".")[-1].lower() if parsed_final.netloc else ""
            final_is_untrusted = final_ext in UNTRUSTED_TLDS

            has_untrusted_hop = False
            for hop in redirect_res.hops:
                hop_ext = urlparse(hop.url).netloc.split(".")[-1].lower()
                if hop_ext in UNTRUSTED_TLDS:
                    has_untrusted_hop = True
                    break

            if redirect_res.hop_count >= 2 and (final_is_untrusted or has_untrusted_hop):
                is_multi_hop_untrusted = True
            elif redirect_res.hop_count >= 3:
                is_multi_hop_untrusted = True

        if is_multi_hop_untrusted:
            raw_score += 20
            applied_rules.append(
                f"Evasive multi-hop redirect chain ({redirect_res.hop_count} hops) "
                f"ending on or routing through suspicious TLD (+20)"
            )

        # Cross-domain form credential harvest check (bonus critical modifier)
        if dom_res and dom_res.external_form_actions:
            raw_score += 25
            applied_rules.append(
                f"Form action posts credentials to cross-domain endpoint: {dom_res.external_form_actions[0]} (+25)"
            )

        # Non-standard web port check
        if ssl_res and ssl_res.is_non_standard_port:
            raw_score += 15
            applied_rules.append(f"Web service running on non-standard port ({ssl_res.port}) (+15)")

        # Clamp risk score to [0, 100]
        final_risk_score = max(0, min(100, int(raw_score)))

        # Categorize threat level
        if final_risk_score >= 70:
            threat_level = "MALICIOUS"
        elif final_risk_score >= 35:
            threat_level = "SUSPICIOUS"
        else:
            threat_level = "SAFE"

        # ---------------------------------------------------------------------
        # 6. Structured Threat Explanation Summary
        # ---------------------------------------------------------------------
        explanation = self._build_explanation_summary(
            final_risk_score=final_risk_score,
            threat_level=threat_level,
            input_url=url,
            final_destination_url=final_destination_url,
            applied_rules=applied_rules,
            signals=collected_signals,
            homograph_res=homograph_res,
            ssl_res=ssl_res,
            dom_res=dom_res,
            redirect_res=redirect_res,
        )

        metadata["applied_rules"] = applied_rules
        metadata["raw_score"] = raw_score
        metadata["scan_duration_ms"] = round((time.monotonic() - start_time) * 1000, 2)

        return URLAgentOutput(
            input_url=url,
            final_destination_url=final_destination_url,
            risk_score=final_risk_score,
            threat_level=threat_level,
            redirect_chain=redirect_chain,
            signals=collected_signals,
            metadata=metadata,
            explanation=explanation,
        )

    def _build_explanation_summary(
        self,
        final_risk_score: int,
        threat_level: str,
        input_url: str,
        final_destination_url: str,
        applied_rules: List[str],
        signals: List[RiskSignal],
        homograph_res: Optional[HomographResult],
        ssl_res: Optional[SSLAnalysisResult],
        dom_res: Optional[DOMAnalysisResult],
        redirect_res: Optional[RedirectTraceResult],
    ) -> str:
        """
        Generate a clear, human-readable threat explanation formatted
        for the PhishLens security intelligence dashboard.
        """
        lines = [
            f"Threat Level: {threat_level} (Risk Score: {final_risk_score}/100)",
            f"Target URL: {input_url}",
        ]
        if input_url != final_destination_url:
            lines.append(f"Final Destination: {final_destination_url}")

        lines.append("")
        if applied_rules:
            lines.append("Key Threat Indicators:")
            for rule in applied_rules:
                lines.append(f"  • {rule}")
        else:
            lines.append("Key Threat Indicators: None. Domain and infrastructure show standard benign patterns.")

        lines.append("")
        lines.append("Technical Diagnostics:")
        # SSL Summary
        if ssl_res and ssl_res.certificate_age_hours is not None:
            age_desc = f"{ssl_res.certificate_age_hours:.1f} hours"
            issuer_desc = ssl_res.issuer or "Unknown CA"
            lines.append(f"  • SSL Certificate Age: {age_desc} | Issuer: {issuer_desc}")
        elif ssl_res and ssl_res.error:
            lines.append(f"  • SSL Diagnostic: {ssl_res.error}")

        # Redirect Summary
        if redirect_res:
            lines.append(
                f"  • Redirect Hops: {redirect_res.hop_count} | "
                f"Cloaking Detected: {'YES' if redirect_res.is_cloaked else 'NO'}"
            )

        # DOM & Visual Summary
        if dom_res:
            hash_str = str(dom_res.favicon_hash) if dom_res.favicon_hash is not None else "N/A"
            lines.append(
                f"  • Favicon Hash: {hash_str} | "
                f"Credential Form: {'Detected' if dom_res.has_password_input else 'None'}"
            )

        return "\n".join(lines)


# Convenient module-level entrypoint
_GLOBAL_AGENT: Optional[URLAgent] = None


async def run_url_agent(
    input_data: Union[URLAgentInput, str, Dict[str, Any]],
) -> URLAgentOutput:
    """
    Run URL threat intelligence agent against target URL.
    """
    global _GLOBAL_AGENT
    if _GLOBAL_AGENT is None:
        _GLOBAL_AGENT = URLAgent()
    return await _GLOBAL_AGENT.analyze(input_data)
