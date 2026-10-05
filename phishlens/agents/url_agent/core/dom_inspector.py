"""
backend.agents.url_agent.core.dom_inspector — DOM & Visual Favicon Inspector.

Features:
- Favicon hash extraction using Censys/Shodan standard Murmur3 (mmh3) algorithm.
- Comparison against curated brand favicon hash database (Microsoft, PayPal, Google, Apple, etc.).
- Critical alerting for brand favicon hijacking on unverified/impersonating domains.
- HTML DOM inspection for credential theft mechanisms:
  * Presence of password inputs (<input type="password">).
  * Credit card / payment data harvesting input signatures.
  * Cross-domain form action exfiltration (<form action="https://external-host/submit">).
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

try:
    from backend.agents.url_agent.models.schema import RiskSignal
except ImportError:
    try:
        from agents.url_agent.models.schema import RiskSignal
    except ImportError:
        from ..models.schema import RiskSignal

try:
    import mmh3
    _HAS_MMH3 = True
except ImportError:
    _HAS_MMH3 = False

logger = logging.getLogger(__name__)

# Known brand favicon Murmur3 hashes (Censys/Shodan standard: mmh3 of base64 encoded bytes)
KNOWN_BRAND_FAVICONS: Dict[int, str] = {
    -1302820302: "Microsoft",
    1413388650: "PayPal",
    709403810: "Google",
    -1888307044: "Apple",
    2083949019: "Amazon",
    1457007757: "Netflix",
    1749360799: "Facebook",
    -1281696013: "Coinbase",
    -988291024: "GitHub",
}

# Official verified domain whitelist corresponding to each brand
BRAND_OFFICIAL_DOMAINS: Dict[str, Set[str]] = {
    "Microsoft": {"microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "msn.com", "azure.com"},
    "PayPal": {"paypal.com", "paypal.me"},
    "Google": {"google.com", "gstatic.com", "google.co.in", "google.co.uk", "google.ca"},
    "Apple": {"apple.com", "icloud.com"},
    "Amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com"},
    "Netflix": {"netflix.com"},
    "Facebook": {"facebook.com", "fb.com", "meta.com", "instagram.com"},
    "Coinbase": {"coinbase.com"},
    "GitHub": {"github.com", "githubusercontent.com"},
}

# Credit card & financial harvesting form input keywords
_PAYMENT_INPUT_REGEX = re.compile(
    r"(?:card[_-]?num|cc[_-]?num|credit[_-]?card|cvv|cvc|expir|card[_-]?holder|pan[_-]?number)",
    re.IGNORECASE,
)

# Phishing kit exfiltration endpoints (Telegram Bots & Discord Webhooks)
_TELEGRAM_BOT_EXFIL_REGEX = re.compile(
    r"https?://(?:api\.)?telegram\.org/bot\d+:[A-Za-z0-9_-]+/(?:sendMessage|sendDocument|sendPhoto)?",
    re.IGNORECASE,
)
_DISCORD_WEBHOOK_EXFIL_REGEX = re.compile(
    r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
    re.IGNORECASE,
)


def compute_murmur3_hash(data: bytes) -> int:
    """Compute Murmur3 32-bit integer hash on data (with pure-Python fallback)."""
    if _HAS_MMH3:
        return mmh3.hash(data)

    # Pure Python Murmur3 32-bit implementation
    length = len(data)
    nblocks = length // 4
    h1 = 0
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    for i in range(0, nblocks * 4, 4):
        k1 = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) == 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


def compute_shodan_favicon_hash(favicon_bytes: bytes) -> int:
    """
    Compute Censys/Shodan standard favicon hash:
    Murmur3 hash of the RFC-standard base64-encoded favicon binary.
    """
    if not favicon_bytes:
        return 0
    b64_encoded = base64.encodebytes(favicon_bytes)
    return compute_murmur3_hash(b64_encoded)


class _DOMParser(HTMLParser):
    """HTML parser extracting form actions, password inputs, and favicon URLs."""

    def __init__(self) -> None:
        super().__init__()
        self.favicon_urls: List[str] = []
        self.has_password_input = False
        self.has_payment_input = False
        self.form_actions: List[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        # Check <link rel="icon" ...>
        if tag == "link":
            rel = attr_dict.get("rel", "").lower()
            if "icon" in rel or "shortcut icon" in rel:
                href = attr_dict.get("href")
                if href:
                    self.favicon_urls.append(href)

        # Check <input ...>
        if tag == "input":
            input_type = attr_dict.get("type", "").lower()
            if input_type == "password":
                self.has_password_input = True
            name = attr_dict.get("name", "")
            field_id = attr_dict.get("id", "")
            placeholder = attr_dict.get("placeholder", "")
            combined = f"{name} {field_id} {placeholder}"
            if _PAYMENT_INPUT_REGEX.search(combined):
                self.has_payment_input = True

        # Check <form action="...">
        if tag == "form":
            action = attr_dict.get("action")
            if action:
                self.form_actions.append(action)


@dataclass
class DOMInspectionResult:
    """Findings from DOM structural and visual favicon inspection."""
    favicon_hash: Optional[int]
    matched_brand: Optional[str]
    is_brand_favicon_mismatch: bool
    has_password_input: bool
    has_payment_input: bool
    cross_domain_form_actions: List[str]
    has_exfiltration_webhook: bool = False
    exfiltration_endpoints: List[str] = field(default_factory=list)
    signals: List[RiskSignal] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_brand_mismatch(self) -> bool:
        return self.is_brand_favicon_mismatch

    @property
    def favicon_brand_match(self) -> Optional[str]:
        return self.matched_brand

    @property
    def external_form_actions(self) -> List[str]:
        return self.cross_domain_form_actions


DOMAnalysisResult = DOMInspectionResult


class DOMInspector:
    """
    Inspects DOM structure for credential/payment harvesting forms,
    cross-domain exfiltration, and computes visual favicon brand hashes.
    """

    def __init__(self, timeout: float = 3.5) -> None:
        self.timeout = timeout

    async def _download_favicon(
        self,
        base_url: str,
        candidate_urls: List[str],
        client: httpx.AsyncClient,
    ) -> Optional[bytes]:
        """Attempt downloading favicon from parsed link tags or standard /favicon.ico."""
        urls_to_try: List[str] = []
        for cand in candidate_urls:
            urls_to_try.append(urljoin(base_url, cand))
        urls_to_try.append(urljoin(base_url, "/favicon.ico"))

        for u in urls_to_try:
            try:
                resp = await client.get(
                    u,
                    timeout=httpx.Timeout(2.5, connect=2.0),
                    follow_redirects=True,
                )
                if resp.status_code == 200 and len(resp.content) > 16:
                    return resp.content
            except Exception:
                continue
        return None

    async def inspect(
        self,
        url: str,
        html_body: str = "",
        favicon_bytes: Optional[bytes] = None,
        html_content: Optional[str] = None,
    ) -> DOMInspectionResult:
        """
        Execute comprehensive DOM analysis and visual favicon hash verification.
        """
        if html_content and not html_body:
            html_body = html_content
        signals: List[RiskSignal] = []
        parsed_url = urlparse(url)
        page_domain = parsed_url.netloc.lower()

        # ── 1. Parse HTML DOM Elements ──
        parser = _DOMParser()
        if html_body:
            try:
                parser.feed(html_body)
            except Exception as e:
                logger.debug("HTML parser error on %s: %s", url, e)

        # ── 2. Evaluate Credential & Payment Inputs ──
        if parser.has_password_input:
            signals.append(
                RiskSignal(
                    category="DOM",
                    severity="HIGH",
                    description="Credential harvesting field (<input type='password'>) detected in page body",
                )
            )

        if parser.has_payment_input:
            signals.append(
                RiskSignal(
                    category="DOM",
                    severity="CRITICAL",
                    description="Financial data harvesting fields (Credit Card/CVV/Cardholder) detected in page DOM",
                )
            )

        # ── 3. Evaluate Cross-Domain Form Submissions ──
        cross_domain_actions: List[str] = []
        for action in parser.form_actions:
            if "://" in action:
                action_parsed = urlparse(action)
                action_domain = action_parsed.netloc.lower()
                # If submitting to a completely different domain
                if action_domain and action_domain != page_domain and not page_domain.endswith(f".{action_domain}"):
                    cross_domain_actions.append(action)
                    signals.append(
                        RiskSignal(
                            category="DOM",
                            severity="CRITICAL",
                            description=(
                                f"Cross-domain form action detected: form submits credentials "
                                f"off-site to '{action_domain}'"
                            ),
                        )
                    )

        # ── 4. Visual Favicon Hash Extraction & Brand Check ──
        fav_bytes = favicon_bytes
        if not fav_bytes and url:
            try:
                async with httpx.AsyncClient(verify=False) as client:
                    fav_bytes = await self._download_favicon(url, parser.favicon_urls, client)
            except Exception:
                pass

        favicon_hash: Optional[int] = None
        matched_brand: Optional[str] = None
        is_brand_mismatch = False

        if fav_bytes:
            favicon_hash = compute_shodan_favicon_hash(fav_bytes)
            if favicon_hash in KNOWN_BRAND_FAVICONS:
                matched_brand = KNOWN_BRAND_FAVICONS[favicon_hash]
                allowed_domains = BRAND_OFFICIAL_DOMAINS.get(matched_brand, set())

                # Check if current page domain is authorized for this brand icon
                is_authorized = any(
                    page_domain == allowed or page_domain.endswith(f".{allowed}")
                    for allowed in allowed_domains
                )

                if not is_authorized:
                    is_brand_mismatch = True
                    signals.append(
                        RiskSignal(
                            category="DOM",
                            severity="CRITICAL",
                            description=(
                                f"FAVICON_BRAND_IMPERSONATION: Favicon Murmur3 hash ({favicon_hash}) "
                                f"belongs to '{matched_brand}', but is hosted on unauthorized domain '{page_domain}'"
                            ),
                        )
                    )

        # ── 5. Evaluate Phishing Kit Webhook Exfiltration (Telegram / Discord) ──
        telegram_matches = _TELEGRAM_BOT_EXFIL_REGEX.findall(html_body) if html_body else []
        discord_matches = _DISCORD_WEBHOOK_EXFIL_REGEX.findall(html_body) if html_body else []
        exfil_endpoints = list(dict.fromkeys(telegram_matches + discord_matches))
        has_exfil = bool(exfil_endpoints)

        if has_exfil:
            signals.append(
                RiskSignal(
                    category="DOM",
                    severity="CRITICAL",
                    description=(
                        f"PHISHING_KIT_EXFILTRATION: Direct credential exfiltration channel to "
                        f"Telegram Bot or Discord Webhook detected in page DOM/scripts: {exfil_endpoints[0][:48]}..."
                    ),
                )
            )

        return DOMInspectionResult(
            favicon_hash=favicon_hash,
            matched_brand=matched_brand,
            is_brand_favicon_mismatch=is_brand_mismatch,
            has_password_input=parser.has_password_input,
            has_payment_input=parser.has_payment_input,
            cross_domain_form_actions=cross_domain_actions,
            has_exfiltration_webhook=has_exfil,
            exfiltration_endpoints=exfil_endpoints,
            signals=signals,
            metadata={
                "has_password": parser.has_password_input,
                "has_payment": parser.has_payment_input,
                "form_count": len(parser.form_actions),
                "favicon_hash": favicon_hash,
                "matched_brand": matched_brand,
                "has_exfiltration_webhook": has_exfil,
                "exfiltration_endpoints": exfil_endpoints,
            },
        )


async def inspect_dom_and_favicon(
    url: str,
    html_body: str = "",
    favicon_bytes: Optional[bytes] = None,
) -> DOMInspectionResult:
    """Helper function to execute DOM and favicon brand analysis."""
    inspector = DOMInspector()
    return await inspector.inspect(url, html_body=html_body, favicon_bytes=favicon_bytes)


inspect_dom_and_favicons = inspect_dom_and_favicon
murmur3_favicon_hash = compute_shodan_favicon_hash
