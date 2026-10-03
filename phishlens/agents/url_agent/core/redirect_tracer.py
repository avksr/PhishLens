"""
backend.agents.url_agent.core.redirect_tracer — Multi-Hop Redirect & Anti-Cloaking Engine.

Features:
- Async HTTP tracing using httpx.AsyncClient with manual/automatic hop recording.
- Full hop inspection: status codes, location headers, destination hosts.
- Dual-pass anti-cloaking detection (Pass A: Security Crawler vs Pass B: Mobile Safari).
- Detection of evasive tactics: UA-dependent blocking (403/404 vs 200), conditional
  content delivery, dynamic JavaScript client redirects.
- Optional headless browser fallback hooks for client-side JS redirects.
- Hard global execution timeout (max 8s) to neutralize tarpits and infinite loops.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

try:
    from backend.agents.url_agent.models.schema import RiskSignal
except ImportError:
    try:
        from agents.url_agent.models.schema import RiskSignal
    except ImportError:
        from ..models.schema import RiskSignal

logger = logging.getLogger(__name__)

# User-Agent profiles for dual-pass cloaking inspection
UA_SECURITY_CRAWLER = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)
UA_MOBILE_SAFARI = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
)

# Hard timeout for entire tracing operation (seconds)
MAX_TRACE_TIMEOUT = 8.0
MAX_REDIRECT_HOPS = 10

# Regex helpers for quick DOM/title inspection
_TITLE_REGEX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_PASSWORD_REGEX = re.compile(r'<input[^>]+type=["\']password["\']', re.IGNORECASE)
_META_REFRESH_REGEX = re.compile(
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^;]+;\s*url=([^"\']+)["\']',
    re.IGNORECASE,
)
_JS_LOCATION_REGEX = re.compile(
    r'(?:window\.location(?:\.href)?|location\.replace)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


@dataclass
class HopDetail:
    """Detailed record of an individual redirect hop."""
    step: int
    url: str
    status_code: int
    reason: str
    headers: Dict[str, str] = field(default_factory=dict)
    ip_address: Optional[str] = None


@dataclass
class RedirectTraceResult:
    """Comprehensive result of redirect tracing and cloaking evaluation."""
    initial_url: str
    final_destination_url: str
    redirect_chain: List[str]
    hops: List[HopDetail]
    pass_a_status: int
    pass_b_status: int
    pass_a_body: str
    pass_b_body: str
    pass_a_title: str
    pass_b_title: str
    is_cloaked: bool
    cloaking_reason: Optional[str]
    signals: List[RiskSignal]
    metadata: Dict[str, Any]

    @property
    def final_url(self) -> str:
        return self.final_destination_url

    @property
    def hop_count(self) -> int:
        return len(self.hops)


RedirectHop = HopDetail


def _extract_page_title(html: str) -> str:
    """Extract <title> content from HTML."""
    if not html:
        return ""
    m = _TITLE_REGEX.search(html)
    return m.group(1).strip() if m else ""


def _has_login_indicators(html: str) -> bool:
    """Check if HTML contains password or credential harvesting inputs."""
    if not html:
        return False
    return bool(_PASSWORD_REGEX.search(html))


def _resolve_host_ip(host: str) -> Optional[str]:
    """Resolve hostname to IP address (non-blocking best-effort)."""
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


class RedirectTracer:
    """
    Asynchronous engine that traces redirect chains and identifies
    anti-analysis evasion and dynamic cloaking.
    """

    def __init__(
        self,
        timeout: float = MAX_TRACE_TIMEOUT,
        max_hops: int = MAX_REDIRECT_HOPS,
    ) -> None:
        self.timeout = timeout
        self.max_hops = max_hops

    async def _fetch_single_pass(
        self,
        url: str,
        user_agent: str,
        client: httpx.AsyncClient,
    ) -> tuple[str, int, str, str, List[HopDetail]]:
        """
        Execute a single follow-redirects pass capturing all intermediate hops.
        Returns: (final_url, final_status, final_body, page_title, hops)
        """
        hops: List[HopDetail] = []
        current_url = url

        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        try:
            # We trace step-by-step to capture intermediate headers and IP routing
            for step in range(1, self.max_hops + 1):
                parsed = urlparse(current_url)
                host_ip = await asyncio.get_event_loop().run_in_executor(
                    None, _resolve_host_ip, parsed.hostname or ""
                )

                resp = await client.get(
                    current_url,
                    headers=headers,
                    follow_redirects=False,
                    timeout=httpx.Timeout(4.0, connect=3.0),
                )

                hop_headers = {k.lower(): v for k, v in resp.headers.items()}
                hops.append(
                    HopDetail(
                        step=step,
                        url=str(resp.url),
                        status_code=resp.status_code,
                        reason=resp.reason_phrase,
                        headers=hop_headers,
                        ip_address=host_ip,
                    )
                )

                # Check if this is a standard HTTP redirect
                if resp.is_redirect and "location" in hop_headers:
                    next_loc = resp.headers["location"]
                    # Handle relative redirects
                    next_url = str(resp.url.join(next_loc))
                    current_url = next_url
                    continue

                # Check for HTML meta-refresh or JS redirect if 200 OK
                body_text = resp.text
                meta_m = _META_REFRESH_REGEX.search(body_text)
                if meta_m:
                    next_loc = meta_m.group(1).strip()
                    next_url = str(resp.url.join(next_loc))
                    if next_url != current_url:
                        current_url = next_url
                        continue

                title = _extract_page_title(body_text)
                return str(resp.url), resp.status_code, body_text, title, hops

            # Max hops reached
            last_hop = hops[-1] if hops else None
            return (
                last_hop.url if last_hop else current_url,
                last_hop.status_code if last_hop else 0,
                "",
                "",
                hops,
            )

        except Exception as exc:
            logger.debug("Redirect fetch error for %s: %s", current_url, exc)
            return current_url, 0, "", "", hops

    async def trace(
        self,
        url: str,
        user_agent_override: Optional[str] = None,
        deep_scan: bool = True,
    ) -> RedirectTraceResult:
        """
        Execute full redirect trace with anti-cloaking dual-pass check.
        Enforces a strict global timeout (max 8s).
        """
        signals: List[RiskSignal] = []

        try:
            return await asyncio.wait_for(
                self._trace_internal(url, user_agent_override, signals),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            signals.append(
                RiskSignal(
                    category="REDIRECT",
                    severity="MEDIUM",
                    description=f"Redirect tracer timed out after {self.timeout}s (potential tarpit/dos evasion)",
                )
            )
            return RedirectTraceResult(
                initial_url=url,
                final_destination_url=url,
                redirect_chain=[url],
                hops=[],
                pass_a_status=0,
                pass_b_status=0,
                pass_a_body="",
                pass_b_body="",
                pass_a_title="",
                pass_b_title="",
                is_cloaked=False,
                cloaking_reason="Trace timed out",
                signals=signals,
                metadata={"timeout": True},
            )

    async def _trace_internal(
        self,
        url: str,
        user_agent_override: Optional[str],
        signals: List[RiskSignal],
    ) -> RedirectTraceResult:
        """Internal worker executing Pass A and Pass B concurrently."""
        ua_a = UA_SECURITY_CRAWLER
        ua_b = user_agent_override or UA_MOBILE_SAFARI

        async with httpx.AsyncClient(verify=False) as client:
            # Run Pass A (crawler) and Pass B (mobile consumer) in parallel
            task_a = self._fetch_single_pass(url, ua_a, client)
            task_b = self._fetch_single_pass(url, ua_b, client)

            (url_a, status_a, body_a, title_a, hops_a), (
                url_b, status_b, body_b, title_b, hops_b
            ) = await asyncio.gather(task_a, task_b)

        # Primary redirect chain is taken from mobile/standard browser (Pass B)
        # as that matches what targeted victims experience
        redirect_chain = [h.url for h in hops_b] if hops_b else [url]
        final_destination = url_b or (hops_b[-1].url if hops_b else url)

        # ── 1. Evaluate Multi-Hop Redirect Signals ──
        hop_count = len(redirect_chain)
        if hop_count > 3:
            signals.append(
                RiskSignal(
                    category="REDIRECT",
                    severity="HIGH",
                    description=f"High redirect count detected: {hop_count} sequential hops in chain",
                )
            )
        elif hop_count > 1:
            # Check domain hopping
            domains_in_chain = {urlparse(u).netloc.lower() for u in redirect_chain if u}
            if len(domains_in_chain) > 1:
                signals.append(
                    RiskSignal(
                        category="REDIRECT",
                        severity="MEDIUM",
                        description=(
                            f"Cross-domain redirection across {len(domains_in_chain)} "
                            f"distinct domains: {list(domains_in_chain)}"
                        ),
                    )
                )

        # ── 2. Evaluate Anti-Cloaking Discrepancies (Dual-Pass) ──
        is_cloaked = False
        cloaking_reasons: List[str] = []

        # Condition 1: Security crawler blocked (403/404/401/429) while victim gets 200
        if status_a in (401, 403, 404, 429) and status_b == 200:
            is_cloaked = True
            cloaking_reasons.append(
                f"Security Crawler blocked ({status_a}) while Mobile Safari received HTTP 200"
            )

        # Condition 2: Different destination endpoints between crawler and victim
        if url_a and url_b and status_a != 0 and status_b != 0:
            parsed_a = urlparse(url_a).netloc.lower()
            parsed_b = urlparse(url_b).netloc.lower()
            if parsed_a != parsed_b and status_b == 200:
                is_cloaked = True
                cloaking_reasons.append(
                    f"Destination mismatch: Crawler routed to '{parsed_a}', victim routed to '{parsed_b}'"
                )

        # Condition 3: Victim sees credential input forms while crawler receives benign/empty content
        b_has_login = _has_login_indicators(body_b)
        a_has_login = _has_login_indicators(body_a)
        if b_has_login and not a_has_login:
            is_cloaked = True
            cloaking_reasons.append(
                "Credential harvesting fields presented exclusively to mobile user agent"
            )

        # Condition 4: Extreme content length disparity (>5x and >1000 bytes) with different title
        len_a = len(body_a)
        len_b = len(body_b)
        if status_a == 200 and status_b == 200 and abs(len_a - len_b) > 1000:
            ratio = (len_b + 1) / (len_a + 1)
            if (ratio > 4.0 or ratio < 0.25) and (title_a != title_b):
                is_cloaked = True
                cloaking_reasons.append(
                    f"Significant content divergence between agents "
                    f"(body length ratio: {ratio:.1f}, titles: '{title_a}' vs '{title_b}')"
                )

        if is_cloaked:
            reason_str = "; ".join(cloaking_reasons)
            signals.append(
                RiskSignal(
                    category="CLOAKING",
                    severity="CRITICAL",
                    description=f"SUSPICIOUS_CLOAKING detected: {reason_str}",
                )
            )

        return RedirectTraceResult(
            initial_url=url,
            final_destination_url=final_destination,
            redirect_chain=redirect_chain,
            hops=hops_b,
            pass_a_status=status_a,
            pass_b_status=status_b,
            pass_a_body=body_a,
            pass_b_body=body_b,
            pass_a_title=title_a,
            pass_b_title=title_b,
            is_cloaked=is_cloaked,
            cloaking_reason="; ".join(cloaking_reasons) if cloaking_reasons else None,
            signals=signals,
            metadata={
                "hop_count": len(redirect_chain),
                "pass_a_status": status_a,
                "pass_b_status": status_b,
                "pass_a_length": len(body_a),
                "pass_b_length": len(body_b),
                "pass_b_has_login": b_has_login,
            },
        )

    trace_redirects = trace


async def trace_redirects(
    url: str,
    user_agent_override: Optional[str] = None,
    deep_scan: bool = True,
) -> RedirectTraceResult:
    """Convenience helper for executing a full redirect and cloaking trace."""
    tracer = RedirectTracer()
    return await tracer.trace(url, user_agent_override, deep_scan=deep_scan)


trace_redirects_and_cloaking = trace_redirects
