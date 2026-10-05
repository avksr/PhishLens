"""
backend.agents.url_agent.core.ssl_analyzer — SSL Infrastructure & Certificate Analyzer.

Features:
- Non-blocking async TLS handshake extraction on port 443 (or target URL port).
- Temporal certificate age analysis (currentTime - notBefore).
- Flagging young SSL infrastructure (<48h and <24h).
- Subject Alternative Name (SAN) inspection & disposable/free issuer profiling.
- Port auditing (identifies HTTP/HTTPS on non-standard ports like 8080, 8443, 8888, 3000).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    from backend.agents.url_agent.models.schema import RiskSignal
except ImportError:
    try:
        from agents.url_agent.models.schema import RiskSignal
    except ImportError:
        from ..models.schema import RiskSignal

logger = logging.getLogger(__name__)

# Known free / automated certificate authorities often abused in throwaway campaigns
DISPOSABLE_ISSUERS: frozenset[str] = frozenset({
    "let's encrypt", "cpanel", "zerossl", "buypass", "ssl.com",
    "certbot", "cloudflare", "free ssl",
})

# Suspicious non-standard web ports
NON_STANDARD_WEB_PORTS: frozenset[int] = frozenset({
    8080, 8443, 8888, 8000, 8008, 3000, 5000, 9000, 8181, 9443,
})


@dataclass
class SSLAnalysisResult:
    """Findings from SSL handshake and certificate metadata extraction."""
    has_ssl: bool
    port: int
    is_non_standard_port: bool
    certificate_age_hours: Optional[float]
    is_young_cert: bool
    is_very_young_cert: bool  # < 24h
    issuer: Optional[str]
    subject: Optional[str]
    san_count: int
    sans: List[str]
    is_disposable_issuer: bool
    error: Optional[str] = None
    signals: List[RiskSignal] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


def _parse_cert_date(date_str: str) -> Optional[datetime]:
    """Parse standard OpenSSL ASN1 date string (e.g., 'Sep 18 20:00:19 2026 GMT')."""
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    try:
        # Fallback for ISO format
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception:
        return None


def _extract_issuer_org(issuer_tuple: Any) -> str:
    """Extract Organization (O) or CommonName (CN) from issuer tuple."""
    if not issuer_tuple or not isinstance(issuer_tuple, tuple):
        return ""
    org = ""
    cn = ""
    for rdn in issuer_tuple:
        for key, val in rdn:
            if key == "organizationName":
                org = str(val)
            elif key == "commonName":
                cn = str(val)
    return org or cn


def _sync_ssl_handshake(
    hostname: str,
    port: int,
    timeout: float = 3.5,
) -> Optional[Dict[str, Any]]:
    """Synchronous socket connection and TLS handshake."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # retrieve cert even if self-signed/expired

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert() or {}
    except Exception as exc:
        logger.debug("SSL handshake failed for %s:%d: %s", hostname, port, exc)
        return None


class SSLAnalyzer:
    """
    Analyzes TLS/SSL configurations, certificate freshness, SAN footprints,
    and network ports for phishing infrastructure signals.
    """

    def __init__(self, timeout: float = 4.0) -> None:
        self.timeout = timeout

    def _fetch_certificate(self, hostname: str, port: int) -> Optional[Dict[str, Any]]:
        """Synchronously perform TLS handshake and return certificate dictionary."""
        return _sync_ssl_handshake(hostname, port, self.timeout)

    async def analyze(self, url: str) -> SSLAnalysisResult:
        """Execute asynchronous SSL/TLS inspection on the target URL."""
        signals: List[RiskSignal] = []

        parsed = urlparse(url if "://" in url else f"https://{url}")
        hostname = parsed.hostname or ""
        scheme = parsed.scheme.lower() or "https"

        # Determine target port
        if parsed.port:
            port = parsed.port
        else:
            port = 443 if scheme == "https" else 80

        is_non_standard_port = port in NON_STANDARD_WEB_PORTS
        if is_non_standard_port:
            signals.append(
                RiskSignal(
                    category="SSL",
                    severity="HIGH",
                    description=(
                        f"Non-standard web port detected: service running on :{port} "
                        f"instead of standard 80/443"
                    ),
                )
            )

        # If scheme is plain HTTP on standard port 80 and no SSL requested, return baseline
        if scheme == "http" and port == 80:
            signals.append(
                RiskSignal(
                    category="SSL",
                    severity="MEDIUM",
                    description="Unencrypted cleartext HTTP protocol in use without SSL/TLS",
                )
            )
            return SSLAnalysisResult(
                has_ssl=False,
                port=port,
                is_non_standard_port=is_non_standard_port,
                certificate_age_hours=None,
                is_young_cert=False,
                is_very_young_cert=False,
                issuer=None,
                subject=None,
                san_count=0,
                sans=[],
                is_disposable_issuer=False,
                signals=signals,
                metadata={"scheme": scheme, "port": port},
            )

        # Perform SSL handshake in worker thread to prevent event loop blocking
        target_port = port if port != 80 else 443
        cert_dict: Optional[Dict[str, Any]] = None
        try:
            cert_dict = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, self._fetch_certificate, hostname, target_port
                ),
                timeout=self.timeout + 0.5,
            )
        except Exception as exc:
            logger.debug("SSL analyzer async call failed for %s: %s", hostname, exc)

        if not cert_dict:
            # Failed to establish TLS handshake
            if scheme == "https":
                signals.append(
                    RiskSignal(
                        category="SSL",
                        severity="HIGH",
                        description=f"TLS handshake failure or broken SSL certificate on {hostname}:{target_port}",
                    )
                )
            return SSLAnalysisResult(
                has_ssl=False,
                port=target_port,
                is_non_standard_port=is_non_standard_port,
                certificate_age_hours=None,
                is_young_cert=False,
                is_very_young_cert=False,
                issuer=None,
                subject=None,
                san_count=0,
                sans=[],
                is_disposable_issuer=False,
                signals=signals,
                metadata={"error": "handshake_failed"},
            )

        # ── 1. Temporal Analysis (Certificate Age) ──
        not_before_raw = cert_dict.get("notBefore", "")
        not_before_dt = _parse_cert_date(not_before_raw)
        cert_age_hours: Optional[float] = None
        is_young_cert = False
        is_very_young_cert = False

        if not_before_dt:
            now_utc = datetime.now(timezone.utc)
            delta = now_utc - not_before_dt
            cert_age_hours = round(max(0.0, delta.total_seconds() / 3600.0), 1)

            if cert_age_hours < 24.0:
                is_young_cert = True
                is_very_young_cert = True
                signals.append(
                    RiskSignal(
                        category="SSL",
                        severity="CRITICAL",
                        description=(
                            f"Extremely young SSL certificate issued only {cert_age_hours:.1f} hours ago (<24h active)"
                        ),
                    )
                )
            elif cert_age_hours < 48.0:
                is_young_cert = True
                signals.append(
                    RiskSignal(
                        category="SSL",
                        severity="HIGH",
                        description=(
                            f"Young SSL certificate: issued {cert_age_hours:.1f} hours ago (<48h temporal threshold)"
                        ),
                    )
                )

        # ── 2. Issuer Analysis ──
        issuer_str = _extract_issuer_org(cert_dict.get("issuer", ()))
        is_disposable = any(disp in issuer_str.lower() for disp in DISPOSABLE_ISSUERS)
        if is_disposable and is_young_cert:
            signals.append(
                RiskSignal(
                    category="SSL",
                    severity="HIGH",
                    description=(
                        f"Automated free certificate authority '{issuer_str}' "
                        f"paired with newly issued SSL infrastructure"
                    ),
                )
            )

        # ── 3. SAN Analysis ──
        san_entries = cert_dict.get("subjectAltName", ())
        sans = [str(val) for typ, val in san_entries if typ == "DNS"]
        san_count = len(sans)

        # Check for wildcard-heavy or anomalous SAN count
        has_wildcard = any("*" in s for s in sans)
        if has_wildcard and is_young_cert:
            signals.append(
                RiskSignal(
                    category="SSL",
                    severity="MEDIUM",
                    description=f"Wildcard SAN certificate on young domain infrastructure: {sans[:5]}",
                )
            )

        return SSLAnalysisResult(
            has_ssl=True,
            port=target_port,
            is_non_standard_port=is_non_standard_port,
            certificate_age_hours=cert_age_hours,
            is_young_cert=is_young_cert,
            is_very_young_cert=is_very_young_cert,
            issuer=issuer_str,
            subject=_extract_issuer_org(cert_dict.get("subject", ())),
            san_count=san_count,
            sans=sans[:20],
            is_disposable_issuer=is_disposable,
            signals=signals,
            metadata={
                "not_before": not_before_raw,
                "not_after": cert_dict.get("notAfter", ""),
                "cert_age_hours": cert_age_hours,
                "san_count": san_count,
            },
        )


async def analyze_ssl_certificate(url: str) -> SSLAnalysisResult:
    """Helper function to execute SSL infrastructure analysis."""
    analyzer = SSLAnalyzer()
    return await analyzer.analyze(url)


analyze_ssl_infrastructure = analyze_ssl_certificate
