"""
backend.agents.url_agent — URL & Domain Intelligence Agent for PhishLens.

Performs multi-signal analysis of URLs extracted from suspicious messages:
  1. URL extraction (from ``ScanRequest.extracted_url`` or regex fallback)
  2. TLD reputation scoring against a curated high-risk TLD list
  3. Typosquatting / brand-impersonation detection via keyword + Levenshtein similarity
  4. Homoglyph / Punycode lookalike detection (Cyrillic & Unicode confusables)
  5. WHOIS domain-age check with LRU cache (graceful degradation on failure)
  6. Score normalisation and latency tracking

Optimisations (v2):
  - In-memory TTL-aware LRU domain-result cache: repeat domain lookups
    return in <1 ms instead of re-running all analysis stages.
  - Zero-downtime WHOIS fallback: RDAP/WHOIS timeouts degrade to local
    TLD reputation scoring with a configurable penalty — no unhandled
    exceptions ever propagate.

Author : Atharv (URL Agent team)
"""

from __future__ import annotations

import asyncio
import base64
import collections
import csv
import functools
import json
import logging
import os
import re
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import tldextract

try:
    from shared.models import (
        AgentStatusEnum,
        ScanRequest,
        TldReputationEnum,
        UrlAgentResult,
    )
except ImportError:
    from backend.shared.models import (
        AgentStatusEnum,
        ScanRequest,
        TldReputationEnum,
        UrlAgentResult,
    )

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Module-level constants
# ──────────────────────────────────────────────

_URL_REGEX = re.compile(r"https?://[^\s]+")

# Resolve data paths relative to *this* file so the agent works
# regardless of the working directory the caller uses.
_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_HIGH_RISK_TLDS_PATH = _DATA_DIR / "high_risk_tlds.txt"
_BRAND_DOMAINS_PATH = _DATA_DIR / "brand_domains.json"

# Risk-score contributions
_RISK_HIGH_RISK_TLD = 35.0
_RISK_TYPOSQUATTING = 50.0
_RISK_NEW_DOMAIN = 40.0
_RISK_HOMOGLYPH = 45.0
_RISK_SAFE_BROWSING = 30.0
_RISK_WHOIS_TIMEOUT_PENALTY = 15.0  # penalty when WHOIS fails but TLD is high-risk

# WHOIS timeout (seconds)
_WHOIS_TIMEOUT = 1.5

# Domain age threshold (days)
_NEW_DOMAIN_THRESHOLD_DAYS = 30

# Minimum Levenshtein similarity ratio to flag as lookalike
_SIMILARITY_THRESHOLD = 0.55

# Domain-result cache settings
_DOMAIN_CACHE_MAXSIZE = 4096
_DOMAIN_CACHE_TTL_SECONDS = 300  # 5-minute TTL

# Threat intelligence feeds and API settings
_OPENPHISH_FEED_PATH = _DATA_DIR / "openphish_feed.txt"
_URLHAUS_FEED_PATH = _DATA_DIR / "urlhaus_feed.csv"
_FEED_REFRESH_INTERVAL_SECONDS = 3600.0  # hourly refresh

_RISK_OPENPHISH = 35.0
_RISK_URLHAUS = 35.0
_RISK_OTX = 25.0
_RISK_VIRUSTOTAL = 30.0

_OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
_OTX_TIMEOUT = 1.0
_OTX_INDICATOR_ENDPOINT = "https://otx.alienvault.com/api/v1/indicators"

_VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
_VIRUSTOTAL_TIMEOUT = 1.0
_VIRUSTOTAL_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"

# Google Safe Browsing API v4 settings
_GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
_SAFE_BROWSING_TIMEOUT = 1.0  # seconds
_SAFE_BROWSING_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

# ──────────────────────────────────────────────
# Homoglyph / Confusable character map
# ──────────────────────────────────────────────
# Maps Unicode characters that visually mimic ASCII Latin letters.
# Covers Cyrillic, Greek, and common Unicode confusables used in
# IDN homograph attacks (e.g. Cyrillic а → Latin a).
_HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic → Latin
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0443": "y",  # у
    "\u0445": "x",  # х
    "\u043a": "k",  # к
    "\u043d": "h",  # н
    "\u0442": "t",  # т (lowercase italic Cyrillic т looks like t)
    "\u0456": "i",  # і (Ukrainian/Belarusian і)
    "\u0458": "j",  # ј (Serbian ј)
    "\u0455": "s",  # ѕ
    "\u0457": "ï",  # ї
    "\u044a": "b",  # ъ (visually similar in some fonts)
    # Greek → Latin
    "\u03bf": "o",  # ο (omicron)
    "\u03b1": "a",  # α (alpha)
    "\u03b5": "e",  # ε (epsilon)
    "\u03b9": "i",  # ι (iota)
    # Roman numerals & special
    "\u2170": "i",  # ⅰ (small roman numeral one)
    "\u2171": "ii",  # ⅱ
    "\u217a": "xi",  # ⅺ
    "\u2148": "j",  # ⅈ (double-struck italic small j)
    "\uff41": "a",  # ａ (fullwidth a)
    "\uff42": "b",  # ｂ
    "\uff43": "c",  # ｃ
    "\uff44": "d",  # ｄ
    "\uff45": "e",  # ｅ
    "\uff49": "i",  # ｉ
    "\uff4c": "l",  # ｌ
    "\uff4f": "o",  # ｏ
    "\uff53": "s",  # ｓ
    "\uff54": "t",  # ｔ
    "\u0131": "i",  # ı (dotless i)
    "\u1d00": "a",  # ᴀ (small capital A)
}


# ──────────────────────────────────────────────
# Data loaders (cached at module level)
# ──────────────────────────────────────────────

_high_risk_tlds_cache: Optional[Set[str]] = None
_brand_data_cache: Optional[Dict] = None


def _load_high_risk_tlds() -> Set[str]:
    """Return the set of high-risk TLD suffixes (lowercased, without leading dot)."""
    global _high_risk_tlds_cache
    if _high_risk_tlds_cache is not None:
        return _high_risk_tlds_cache

    tlds: Set[str] = set()
    try:
        with open(_HIGH_RISK_TLDS_PATH, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip().lower().lstrip(".")
                if stripped and not stripped.startswith("#"):
                    tlds.add(stripped)
    except FileNotFoundError:
        pass  # degrade gracefully — no TLD scoring if file is missing
    _high_risk_tlds_cache = tlds
    return tlds


def _load_brand_data() -> Dict:
    """Return the brand-domains registry as a dict."""
    global _brand_data_cache
    if _brand_data_cache is not None:
        return _brand_data_cache

    data: Dict = {}
    try:
        with open(_BRAND_DOMAINS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    _brand_data_cache = data
    return data


# ──────────────────────────────────────────────
# In-Memory TTL-aware LRU Domain-Result Cache
# ──────────────────────────────────────────────
# Caches *complete* domain analysis results (TLD, typosquatting, homoglyph,
# WHOIS — all signals) keyed by registered_domain.  Repeat scans of the
# same domain skip every analysis stage and return in <1 ms.

@dataclass(frozen=True)
class _DomainCacheEntry:
    """Immutable snapshot of a full domain analysis result."""
    risk_score: float
    tld_rep: "TldReputationEnum"  # forward ref resolved at runtime
    is_typo: bool
    target_brand: Optional[str]
    is_homoglyph: bool
    homoglyph_brand: Optional[str]
    age_days: Optional[int]
    registrar: Optional[str]
    safe_browsing_threat: Optional[str]
    flags: Tuple[str, ...]  # frozen for hashability
    tld_delta: float
    typo_delta: float
    homoglyph_delta: float
    age_delta: float
    threat_intel: Optional[Dict[str, Any]] = None
    threat_intel_delta: float = 0.0
    created_at: float = field(default_factory=time.monotonic)


class _DomainResultCache:
    """
    Thread-safe, TTL-aware LRU cache for domain analysis results.

    Parameters
    ----------
    maxsize : int
        Maximum number of entries. Eviction follows LRU order.
    ttl : float
        Time-to-live in seconds.  Entries older than this are treated
        as misses and evicted on access.
    """

    __slots__ = ("_maxsize", "_ttl", "_store", "_lock",
                 "_hits", "_misses")

    def __init__(self, maxsize: int = _DOMAIN_CACHE_MAXSIZE,
                 ttl: float = _DOMAIN_CACHE_TTL_SECONDS) -> None:
        self._maxsize = maxsize
        self._ttl = ttl
        self._store: collections.OrderedDict[str, _DomainCacheEntry] = (
            collections.OrderedDict()
        )
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    # -- public API ---------------------------------------------------

    def get(self, domain: str) -> Optional[_DomainCacheEntry]:
        """Return the cached entry or ``None`` (miss / expired)."""
        with self._lock:
            entry = self._store.get(domain)
            if entry is None:
                self._misses += 1
                return None
            if (time.monotonic() - entry.created_at) > self._ttl:
                # Expired — evict and treat as miss
                del self._store[domain]
                self._misses += 1
                return None
            # Move to end (most-recently-used)
            self._store.move_to_end(domain)
            self._hits += 1
            return entry

    def put(self, domain: str, entry: _DomainCacheEntry) -> None:
        """Insert or update an entry, evicting LRU if at capacity."""
        with self._lock:
            if domain in self._store:
                self._store.move_to_end(domain)
            self._store[domain] = entry
            while len(self._store) > self._maxsize:
                self._store.popitem(last=False)  # evict oldest

    def clear(self) -> None:
        """Drop every cached entry and reset counters."""
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0

    def info(self) -> Dict[str, int]:
        """Return cache statistics for monitoring."""
        with self._lock:
            return {
                "hits": self._hits,
                "misses": self._misses,
                "size": len(self._store),
                "maxsize": self._maxsize,
            }


# Module-level singleton
_domain_cache = _DomainResultCache()


def domain_cache_info() -> Dict[str, int]:
    """Expose domain-result cache statistics for monitoring / testing."""
    return _domain_cache.info()


def domain_cache_clear() -> None:
    """Clear the domain-result cache (useful for testing)."""
    _domain_cache.clear()


# ──────────────────────────────────────────────
# WHOIS LRU Cache (sub-millisecond repeated lookups)
# ──────────────────────────────────────────────

@functools.lru_cache(maxsize=2048)
def _lookup_domain_age(domain: str) -> Optional[Tuple[Optional[int], Optional[str]]]:
    """
    Synchronous WHOIS lookup returning ``(domain_age_days, registrar)``.

    Wrapped with ``functools.lru_cache(maxsize=2048)`` so repeated
    queries for the same domain return in sub-millisecond time without
    hitting the network.

    Returns ``None`` on import / network failure.  Otherwise returns a
    tuple of ``(age_days | None, registrar_name | None)``.
    """
    try:
        import whois  # type: ignore[import-untyped]
    except ImportError:
        return None

    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        registrar = getattr(w, "registrar", None)
        if creation is None:
            return (None, registrar)
        if isinstance(creation, datetime):
            age = (datetime.now(timezone.utc) - creation.replace(tzinfo=timezone.utc)).days
            return (age, registrar)
        return (None, registrar)
    except Exception:
        return None
    return None


def whois_cache_info():
    """Expose cache statistics for monitoring and testing."""
    return _lookup_domain_age.cache_info()


def whois_cache_clear():
    """Clear the WHOIS LRU cache (useful for testing)."""
    _lookup_domain_age.cache_clear()


# ──────────────────────────────────────────────
# Cache pre-warming
# ──────────────────────────────────────────────

# Top 50 Indian banking, telecom, and utility domains for cache pre-warming.
# These are the most commonly checked domains during demo scans.
_PREWARM_DOMAINS: List[str] = [
    # Banking
    "sbi.co.in", "onlinesbi.sbi", "sbionline.in", "sbi.gov.in",
    "sbimf.com", "sbicard.com", "sbilife.co.in",
    "hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcfund.com",
    "icicibank.com", "icicidirect.com", "iciciprulife.com",
    "axisbank.com", "axismf.com", "axisdirect.in",
    "pnbindia.in", "pnbnet.net.in",
    "bankofbaroda.in", "bobibanking.com",
    "kotak.com", "kotakbank.com", "kotakmf.com",
    "indusind.com", "canarabank.com", "ucobank.com",
    # Telecom
    "airtel.in", "airtel.com", "airtelpayments.com",
    "jio.com", "jiomoney.com", "jiomart.com",
    "myvi.in", "vodafone.in",
    "bsnl.co.in", "bsnl.in",
    "mtnl.in",
    # Utility
    "bescom.co.in", "mahadiscom.in", "msedcl.in",
    "tatapower.com", "tatapower-ddl.com",
    "adanielectricity.in",
    # Payments / e-commerce
    "paytm.com", "phonepe.com", "razorpay.com",
    "amazon.in", "flipkart.com",
    # Government
    "irctc.co.in", "uidai.gov.in", "epfindia.gov.in",
    "incometax.gov.in",
]


def prewarm_whois_cache(timeout_per_domain: float = 2.0) -> int:
    """
    Pre-warm the WHOIS LRU cache with top Indian domains.

    Runs synchronous WHOIS lookups (best-effort) for each domain in
    ``_PREWARM_DOMAINS``. Failed lookups are silently skipped.

    Parameters
    ----------
    timeout_per_domain : float
        Maximum seconds per individual WHOIS lookup during pre-warming.

    Returns
    -------
    int
        Number of domains successfully cached.
    """
    cached = 0
    for domain in _PREWARM_DOMAINS:
        try:
            result = _lookup_domain_age(domain)
            if result is not None:
                cached += 1
        except Exception:
            pass  # best-effort: skip failures silently
    logger.info(
        "WHOIS cache pre-warmed: %d/%d domains cached",
        cached, len(_PREWARM_DOMAINS),
    )
    return cached


# ──────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────

def _extract_url(req: ScanRequest) -> Optional[str]:
    """
    Return the first URL to analyse.

    Priority:
      1. ``req.extracted_url`` (if not None / empty)
      2. First ``http(s)://…`` match found in ``req.content``
    """
    if req.extracted_url:
        return req.extracted_url.strip()
    match = _URL_REGEX.search(req.content or "")
    return match.group(0) if match else None


def _parse_domain(url: str) -> Tuple[str, str, str, str]:
    """
    Parse *url* and return ``(subdomain, domain_label, registered_domain, suffix/tld)``.

    Uses ``tldextract`` for accurate public-suffix–aware parsing.

    - ``domain_label``: the second-level label (e.g. ``sbi-kyc-verify``)
    - ``registered_domain``: label + suffix (e.g. ``sbi-kyc-verify.top``)
    """
    ext = tldextract.extract(url)
    return ext.subdomain, ext.domain, ext.top_domain_under_public_suffix, ext.suffix


def _check_tld_reputation(suffix: str) -> Tuple[TldReputationEnum, float, List[str]]:
    """
    Score the TLD reputation.

    Returns ``(reputation_enum, score_delta, new_flags)``.
    """
    tlds = _load_high_risk_tlds()
    suffix_lower = suffix.lower().lstrip(".")
    if suffix_lower in tlds:
        return TldReputationEnum.HIGH_RISK, _RISK_HIGH_RISK_TLD, ["HIGH_RISK_TLD"]
    return TldReputationEnum.NEUTRAL, 0.0, []


def _levenshtein_ratio(a: str, b: str) -> float:
    """Return the SequenceMatcher similarity ratio between *a* and *b*."""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


# ──────────────────────────────────────────────
# Homoglyph & Punycode detection
# ──────────────────────────────────────────────

def _normalise_homoglyphs(text: str) -> str:
    """
    Replace known confusable Unicode characters with their ASCII equivalents.

    This converts strings like ``sbⅰ-bank`` → ``sbi-bank`` so Levenshtein
    and keyword matching can catch visually-similar but technically-different
    domain labels.
    """
    result = []
    for ch in text:
        if ch in _HOMOGLYPH_MAP:
            result.append(_HOMOGLYPH_MAP[ch])
        else:
            result.append(ch)
    return "".join(result)


def _has_mixed_scripts(text: str) -> bool:
    """
    Return True if *text* contains characters from multiple Unicode scripts.

    A domain mixing Latin + Cyrillic (or other scripts) is a strong signal
    of an IDN homograph attack.
    """
    scripts: Set[str] = set()
    for ch in text:
        if ch.isalpha():
            # unicodedata.name() gives us the script via the character name
            try:
                name = unicodedata.name(ch, "")
                if "CYRILLIC" in name:
                    scripts.add("CYRILLIC")
                elif "GREEK" in name:
                    scripts.add("GREEK")
                elif "LATIN" in name:
                    scripts.add("LATIN")
                elif "CJK" in name:
                    scripts.add("CJK")
                else:
                    # Check category for other scripts
                    cat = unicodedata.category(ch)
                    if cat.startswith("L"):
                        scripts.add("OTHER")
            except ValueError:
                pass
    # Mixed-script if more than one script family is present
    return len(scripts) > 1


def _is_punycode_domain(domain_label: str) -> bool:
    """Return True if the domain label starts with the xn-- punycode prefix."""
    return domain_label.lower().startswith("xn--")


def _decode_punycode(domain_label: str) -> str:
    """
    Attempt to decode a punycode domain label to its Unicode form.

    Returns the original label unchanged if decoding fails.
    """
    try:
        return domain_label.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return domain_label


def _check_homoglyph(
    domain_label: str,
    registered_domain: str,
) -> Tuple[bool, Optional[str], float, List[str]]:
    """
    Detect lookalike domains using homoglyph substitution or punycode tricks.

    Checks:
      1. Punycode domains (xn--...) are decoded and re-analysed
      2. Mixed-script detection (Latin + Cyrillic in same label)
      3. Homoglyph normalisation → re-run brand keyword matching

    Returns ``(is_homoglyph, target_brand, score_delta, new_flags)``.
    """
    flags: List[str] = []
    actual_label = domain_label
    decoded_domain = registered_domain

    # ── Step 1: Punycode decode ──
    if _is_punycode_domain(domain_label):
        actual_label = _decode_punycode(domain_label)
        flags.append("PUNYCODE_DOMAIN")

    # ── Step 2: Mixed-script detection ──
    if _has_mixed_scripts(actual_label):
        flags.append("MIXED_SCRIPT_DETECTED")

    # ── Step 3: Homoglyph normalisation ──
    normalised = _normalise_homoglyphs(actual_label.lower())

    # If normalisation changed anything, we have confusable characters
    if normalised != actual_label.lower():
        flags.append("HOMOGLYPH_CHARACTERS")

        # Re-check against brand keywords with the normalised label
        brand_data = _load_brand_data()
        for _brand_key, info in brand_data.items():
            brand_name: str = info.get("brand_name", _brand_key)
            keywords: List[str] = [k.lower() for k in info.get("keywords", [])]
            official_domains: List[str] = [d.lower() for d in info.get("official_domains", [])]

            if any(kw in normalised for kw in keywords):
                # The normalised form matches a brand → likely homoglyph attack
                if decoded_domain.lower() not in official_domains:
                    flags.append("HOMOGLYPH_BRAND_IMPERSONATION")
                    return (
                        True,
                        brand_name,
                        _RISK_HOMOGLYPH,
                        flags,
                    )

    # If mixed scripts or punycode detected but no brand match, still flag
    if flags:
        return True, None, _RISK_HOMOGLYPH * 0.5, flags

    return False, None, 0.0, []


def _check_typosquatting(
    domain_label: str,
    registered_domain: str,
) -> Tuple[bool, Optional[str], float, List[str]]:
    """
    Detect brand impersonation / typosquatting.

    Three-pass approach:
      0. **Official check** — if registered_domain is an official domain of
         any known brand, it is authentic; never flag it.
      1. **Keyword match** — does any brand keyword appear in the domain label
         while the full registered domain is NOT in the brand's official list?
         Checked across all brands first so direct keyword matches take precedence.
      2. **Levenshtein similarity** — is the registered domain suspiciously
         close to any official domain (ratio >= threshold)?

    Parameters
    ----------
    domain_label : str
        The second-level domain label only (e.g. ``sbi-kyc-verify``).
    registered_domain : str
        The full domain under the public suffix (e.g. ``sbi-kyc-verify.top``).

    Returns ``(is_typosquatting, target_brand, score_delta, new_flags)``.
    """
    brand_data = _load_brand_data()
    label_lower = domain_label.lower()
    full_lower = registered_domain.lower()

    # Pass 0 — If registered_domain is an official domain of ANY brand, it's authentic
    for info in brand_data.values():
        official_domains = [d.lower() for d in info.get("official_domains", [])]
        if full_lower in official_domains:
            return False, None, 0.0, []

    # Pass 1 — Keyword hit in the domain label across all brands
    for _brand_key, info in brand_data.items():
        brand_name: str = info.get("brand_name", _brand_key)
        keywords: List[str] = [k.lower() for k in info.get("keywords", [])]
        official_domains: List[str] = [d.lower() for d in info.get("official_domains", [])]

        if any(kw in label_lower for kw in keywords):
            if full_lower in official_domains:
                return False, None, 0.0, []
            return (
                True,
                brand_name,
                _RISK_TYPOSQUATTING,
                ["TYPOSQUATTING_DETECTED"],
            )

    # Pass 2 — Levenshtein similarity against each official domain
    best_brand: Optional[str] = None
    best_ratio: float = 0.0

    for _brand_key, info in brand_data.items():
        brand_name = info.get("brand_name", _brand_key)
        official_domains = [d.lower() for d in info.get("official_domains", [])]

        for official in official_domains:
            ratio = _levenshtein_ratio(full_lower, official)
            if ratio >= _SIMILARITY_THRESHOLD and ratio > best_ratio:
                best_ratio = ratio
                best_brand = brand_name

    if best_brand is not None:
        return (
            True,
            best_brand,
            _RISK_TYPOSQUATTING,
            ["TYPOSQUATTING_DETECTED"],
        )

    return False, None, 0.0, []


async def _check_whois_age(
    registered_domain: str,
    suffix: str = "",
) -> Tuple[Optional[int], Optional[str], float, List[str]]:
    """
    Look up domain creation date via the LRU-cached ``_lookup_domain_age()``.

    Runs the (potentially) blocking call inside an executor with a
    ``_WHOIS_TIMEOUT`` second ceiling so the agent stays responsive.
    On cache hits, returns in sub-millisecond time.

    **Zero-downtime fallback** — when RDAP / WHOIS times out or raises,
    the function degrades gracefully to a local TLD reputation check:
      * If the domain's TLD is already in the high-risk list, a
        ``_RISK_WHOIS_TIMEOUT_PENALTY`` is applied so the overall risk
        score still reflects suspicion.
      * If the TLD is benign, the penalty is zero — no false positives.
    This ensures the agent **never** raises an unhandled exception and
    always returns a meaningful signal.

    Parameters
    ----------
    registered_domain : str
        The full registered domain (e.g. ``sbi-kyc-verify.top``).
    suffix : str
        The TLD suffix (e.g. ``top``), used for fallback scoring on
        WHOIS failure.

    Returns ``(domain_age_days | None, registrar | None, score_delta, new_flags)``.
    """
    loop = asyncio.get_running_loop()
    try:
        whois_result = await asyncio.wait_for(
            loop.run_in_executor(None, _lookup_domain_age, registered_domain),
            timeout=_WHOIS_TIMEOUT,
        )
    except asyncio.TimeoutError:
        logger.warning(
            "WHOIS/RDAP timeout for '%s' (>%.1fs) — falling back to "
            "offline domain heuristics",
            registered_domain, _WHOIS_TIMEOUT,
        )
        return _run_offline_domain_heuristics(registered_domain, suffix)
    except Exception as exc:
        logger.warning(
            "WHOIS/RDAP error for '%s': %s — falling back to offline "
            "domain heuristics",
            registered_domain, exc,
        )
        return _run_offline_domain_heuristics(registered_domain, suffix)

    # _lookup_domain_age returns None on complete failure, or (age, registrar)
    if whois_result is None:
        return _run_offline_domain_heuristics(registered_domain, suffix)

    age_days, registrar = whois_result

    if age_days is not None and age_days < _NEW_DOMAIN_THRESHOLD_DAYS:
        return (
            age_days,
            registrar,
            _RISK_NEW_DOMAIN,
            [f"NEW_DOMAIN ({age_days} days old)"],
        )
    return age_days, registrar, 0.0, []


def _whois_fallback(
    registered_domain: str,
    suffix: str,
) -> Tuple[Optional[int], float, List[str]]:
    """
    Local-only fallback when WHOIS/RDAP is unreachable.

    If the domain's TLD sits on the high-risk list, a small penalty is
    applied so the signal isn't silently lost.  Otherwise, return zero.
    """
    tlds = _load_high_risk_tlds()
    suffix_lower = suffix.lower().lstrip(".")
    if suffix_lower in tlds:
        logger.info(
            "WHOIS fallback: '%s' has high-risk TLD '.%s' — applying "
            "%.0f-point penalty",
            registered_domain, suffix_lower, _RISK_WHOIS_TIMEOUT_PENALTY,
        )
        return (
            None,
            _RISK_WHOIS_TIMEOUT_PENALTY,
            [f"WHOIS_TIMEOUT_FALLBACK (high-risk TLD .{suffix_lower})"],
        )
    return None, 0.0, ["WHOIS_TIMEOUT_FALLBACK (TLD benign — no penalty)"]


def _run_offline_domain_heuristics(
    registered_domain: str,
    suffix: str,
) -> Tuple[Optional[int], Optional[str], float, List[str]]:
    """
    Offline-capable domain heuristics that run without any network access.

    When WHOIS/RDAP is completely unreachable (timeout, socket error, or
    full offline mode), this function applies local-only signals to estimate
    domain age risk:

      * **High-risk TLD** — domains on suspicious TLDs (e.g. ``.top``,
        ``.xyz``) are presumed newly registered and flagged with
        ``NEW_DOMAIN (<30 days)`` plus the full ``_RISK_NEW_DOMAIN``
        penalty.  This ensures that even when the agent is completely
        disconnected, obviously suspicious domains are still flagged.
      * **Benign TLD** — no penalty is applied to avoid false positives.

    Parameters
    ----------
    registered_domain : str
        The full registered domain (e.g. ``sbi-kyc-verify.top``).
    suffix : str
        The TLD suffix (e.g. ``top``).

    Returns
    -------
    tuple
        ``(domain_age_days | None, registrar | None, score_delta, flags)``.
    """
    tlds = _load_high_risk_tlds()
    suffix_lower = suffix.lower().lstrip(".")

    if suffix_lower in tlds:
        logger.info(
            "Offline heuristics: '%s' has high-risk TLD '.%s' — "
            "presuming new domain, applying %.0f-point penalty",
            registered_domain, suffix_lower, _RISK_NEW_DOMAIN,
        )
        return (
            None,
            None,
            _RISK_NEW_DOMAIN,
            [f"NEW_DOMAIN (<{_NEW_DOMAIN_THRESHOLD_DAYS} days)",
             f"WHOIS_OFFLINE_FALLBACK (high-risk TLD .{suffix_lower})"],
        )
    return (
        None,
        None,
        0.0,
        ["WHOIS_OFFLINE_FALLBACK (TLD benign — no penalty)"],
    )


# ──────────────────────────────────────────────
# Google Safe Browsing API v4 (FR-4)
# ──────────────────────────────────────────────

async def check_google_safe_browsing(
    url: str,
) -> Dict[str, Any]:
    """
    Query the Google Safe Browsing Lookup API v4 for *url*.

    Returns a dict with the following keys:

    * ``is_unsafe`` — ``True`` if Safe Browsing flagged the URL.
    * ``checked``  — ``True`` if the API was actually queried
      (``False`` when the key is missing or the request failed).
    * ``threat_type`` — the threat category string (e.g.
      ``"SOCIAL_ENGINEERING"``) or ``None``.

    **Graceful pass-through fallback**:
      - If ``GOOGLE_SAFE_BROWSING_API_KEY`` is empty or unset, the
        check is silently skipped.
      - If the network request fails or times out (>1.0 s), the
        check is silently skipped — no exception is raised.
    """
    _PASS_THROUGH: Dict[str, Any] = {
        "is_unsafe": False,
        "checked": False,
        "threat_type": None,
    }

    api_key = _GOOGLE_SAFE_BROWSING_API_KEY
    if not api_key:
        logger.debug("Google Safe Browsing API key not configured — skipping")
        return _PASS_THROUGH

    payload = {
        "client": {
            "clientId": "phishlens",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        import aiohttp  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("aiohttp not installed — skipping Safe Browsing check")
        return _PASS_THROUGH

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=_SAFE_BROWSING_TIMEOUT),
        ) as session:
            async with session.post(
                _SAFE_BROWSING_ENDPOINT,
                params={"key": api_key},
                json=payload,
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
    except Exception as exc:
        logger.warning(
            "Google Safe Browsing request failed for '%s': %s — skipping",
            url, exc,
        )
        return _PASS_THROUGH

    matches = data.get("matches")
    if not matches:
        return {"is_unsafe": False, "checked": True, "threat_type": None}

    # Take the first (most severe) match
    threat_type = matches[0].get("threatType", "UNKNOWN")
    return {
        "is_unsafe": True,
        "checked": True,
        "threat_type": threat_type,
    }


# ──────────────────────────────────────────────
# Tiered Threat Intelligence (FR-4 & Community Feeds)
# ──────────────────────────────────────────────

class ThreatFeedCache:
    """
    In-memory cache for local threat intelligence feeds (OpenPhish, URLhaus).
    Refreshes hourly or when explicitly forced.
    """

    def __init__(
        self,
        openphish_path: Path = _OPENPHISH_FEED_PATH,
        urlhaus_path: Path = _URLHAUS_FEED_PATH,
        refresh_interval: float = _FEED_REFRESH_INTERVAL_SECONDS,
    ) -> None:
        self.openphish_path = openphish_path
        self.urlhaus_path = urlhaus_path
        self.refresh_interval = refresh_interval
        self._lock = threading.Lock()
        self.openphish_urls: Set[str] = set()
        self.openphish_domains: Set[str] = set()
        self.urlhaus_urls: Set[str] = set()
        self.urlhaus_domains: Set[str] = set()
        self.last_refreshed: float = time.monotonic()
        self._load_feeds_locked()

    def refresh_if_needed(self, force: bool = False) -> None:
        now = time.monotonic()
        with self._lock:
            if not force and (now - self.last_refreshed) < self.refresh_interval:
                return
            self._load_feeds_locked()
            self.last_refreshed = now

    def _load_feeds_locked(self) -> None:
        self.openphish_urls.clear()
        self.openphish_domains.clear()
        self.urlhaus_urls.clear()
        self.urlhaus_domains.clear()

        # OpenPhish community feed (newline-delimited URLs)
        if self.openphish_path.exists():
            try:
                with open(self.openphish_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            norm = line.rstrip("/").lower()
                            self.openphish_urls.add(norm)
                            try:
                                from urllib.parse import urlparse
                                parsed = urlparse(line if "://" in line else f"http://{line}")
                                if parsed.netloc:
                                    self.openphish_domains.add(parsed.netloc.lower())
                            except Exception:
                                pass
            except Exception as exc:
                logger.warning("Failed loading OpenPhish feed: %s", exc)

        # URLhaus community feed (CSV format: id,dateadded,url,url_status,...)
        if self.urlhaus_path.exists():
            try:
                with open(self.urlhaus_path, "r", encoding="utf-8", errors="ignore") as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if not row or row[0].startswith("#"):
                            continue
                        url_val = ""
                        if len(row) > 2 and row[2].startswith("http"):
                            url_val = row[2].strip()
                        else:
                            for item in row:
                                if item.strip().startswith("http"):
                                    url_val = item.strip()
                                    break
                        if url_val:
                            norm = url_val.rstrip("/").lower()
                            self.urlhaus_urls.add(norm)
                            try:
                                from urllib.parse import urlparse
                                parsed = urlparse(url_val)
                                if parsed.netloc:
                                    self.urlhaus_domains.add(parsed.netloc.lower())
                            except Exception:
                                pass
            except Exception as exc:
                logger.warning("Failed loading URLhaus feed: %s", exc)

    def check(self, url: str, domain: Optional[str] = None) -> Dict[str, Any]:
        self.refresh_if_needed()
        norm_url = url.rstrip("/").lower()
        norm_domain = domain.lower() if domain else None

        openphish_hit = (
            norm_url in self.openphish_urls
            or (norm_domain and norm_domain in self.openphish_domains)
        )
        urlhaus_hit = (
            norm_url in self.urlhaus_urls
            or (norm_domain and norm_domain in self.urlhaus_domains)
        )

        return {
            "openphish_hit": bool(openphish_hit),
            "urlhaus_hit": bool(urlhaus_hit),
            "is_unsafe": bool(openphish_hit or urlhaus_hit),
            "checked": True,
        }

    def clear(self) -> None:
        with self._lock:
            self.openphish_urls.clear()
            self.openphish_domains.clear()
            self.urlhaus_urls.clear()
            self.urlhaus_domains.clear()
            self.last_refreshed = time.monotonic()


_threat_feed_cache = ThreatFeedCache()


class VirusTotalRateLimiter:
    """
    Enforces VirusTotal free tier rate limits:
    - Max 4 requests per 60 seconds
    - Max 500 requests per 24 hours
    """

    def __init__(self, max_per_min: int = 4, max_per_day: int = 500) -> None:
        self.max_per_min = max_per_min
        self.max_per_day = max_per_day
        self._requests: List[float] = []
        self._lock = threading.Lock()

    def allow_request(self) -> bool:
        now = time.monotonic()
        with self._lock:
            # Drop entries older than 24h
            self._requests = [t for t in self._requests if now - t < 86400.0]
            if len(self._requests) >= self.max_per_day:
                return False
            # Check last 60s
            recent = [t for t in self._requests if now - t < 60.0]
            if len(recent) >= self.max_per_min:
                return False
            self._requests.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._requests.clear()


_vt_rate_limiter = VirusTotalRateLimiter()


async def check_alienvault_otx(
    url: str,
    domain: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Query AlienVault OTX indicator details (Tier 3).
    Gracefully passes through if OTX_API_KEY is not set or network fails.
    """
    _PASS_THROUGH: Dict[str, Any] = {
        "is_unsafe": False,
        "checked": False,
        "pulse_count": 0,
    }
    api_key = os.environ.get("OTX_API_KEY", "") or _OTX_API_KEY
    if not api_key:
        return _PASS_THROUGH

    try:
        import aiohttp
    except ImportError:
        return _PASS_THROUGH

    target_domain = domain
    if not target_domain:
        try:
            from urllib.parse import urlparse
            target_domain = urlparse(url).netloc
        except Exception:
            target_domain = None

    if not target_domain:
        return _PASS_THROUGH

    endpoint = f"{_OTX_INDICATOR_ENDPOINT}/domain/{target_domain}/general"
    try:
        headers = {"X-OTX-API-KEY": api_key}
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=_OTX_TIMEOUT),
        ) as session:
            async with session.get(endpoint, headers=headers) as resp:
                if resp.status != 200:
                    return _PASS_THROUGH
                data = await resp.json()
                pulse_info = data.get("pulse_info", {})
                pulse_count = pulse_info.get("count", 0)
                return {
                    "is_unsafe": pulse_count > 0,
                    "checked": True,
                    "pulse_count": pulse_count,
                }
    except Exception as exc:
        logger.debug("AlienVault OTX check failed for '%s': %s", target_domain, exc)
        return _PASS_THROUGH


async def check_virustotal(
    url: str,
    domain: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Query VirusTotal v3 URL analysis (Tier 4).
    Enforces strict 4 req/min and 500 req/day rate limits.
    Gracefully passes through if VIRUSTOTAL_API_KEY is unset or limit reached.
    """
    _PASS_THROUGH: Dict[str, Any] = {
        "is_unsafe": False,
        "checked": False,
        "positives": 0,
    }
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "") or _VIRUSTOTAL_API_KEY
    if not api_key:
        return _PASS_THROUGH

    if not _vt_rate_limiter.allow_request():
        logger.debug("VirusTotal rate limit reached (4/min or 500/day) — skipping VT")
        return {
            "is_unsafe": False,
            "checked": False,
            "rate_limited": True,
            "positives": 0,
        }

    try:
        import aiohttp
    except ImportError:
        return _PASS_THROUGH

    try:
        # Base64url without padding as per VT v3 URL identifier format
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        endpoint = f"{_VIRUSTOTAL_URL_ENDPOINT}/{url_id}"
        headers = {"x-apikey": api_key}
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=_VIRUSTOTAL_TIMEOUT),
        ) as session:
            async with session.get(endpoint, headers=headers) as resp:
                if resp.status != 200:
                    return _PASS_THROUGH
                data = await resp.json()
                stats = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                positives = malicious + suspicious
                return {
                    "is_unsafe": positives > 0,
                    "checked": True,
                    "positives": positives,
                    "malicious": malicious,
                    "suspicious": suspicious,
                }
    except Exception as exc:
        logger.debug("VirusTotal check failed for '%s': %s", url, exc)
        return _PASS_THROUGH


async def check_threat_intel(
    url: str,
    domain: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Tiered threat intelligence orchestrator:
      Tier 1: Local OpenPhish & URLhaus feeds (hourly refresh)
      Tier 2: Google Safe Browsing API v4 (1.0s timeout)
      Tier 3: AlienVault OTX indicator search (1.0s timeout)
      Tier 4: VirusTotal URL report (4/min, 500/day limit, demo only)
    """
    flags: List[str] = []
    risk_delta = 0.0

    # Tier 1: Local Feeds
    t1_result = _threat_feed_cache.check(url, domain=domain)
    if t1_result.get("openphish_hit"):
        flags.append("THREAT_INTEL_OPENPHISH_FLAGGED")
        risk_delta += _RISK_OPENPHISH
    if t1_result.get("urlhaus_hit"):
        flags.append("THREAT_INTEL_URLHAUS_FLAGGED")
        risk_delta += _RISK_URLHAUS

    # Tier 2: Google Safe Browsing
    t2_result = await check_google_safe_browsing(url)
    if t2_result.get("is_unsafe"):
        flags.append("GOOGLE_SAFE_BROWSING_FLAGGED")
        risk_delta += _RISK_SAFE_BROWSING

    # Tier 3: AlienVault OTX
    t3_result = await check_alienvault_otx(url, domain=domain)
    if t3_result.get("is_unsafe"):
        flags.append("OTX_PULSE_FLAGGED")
        risk_delta += _RISK_OTX

    # Tier 4: VirusTotal
    t4_result = await check_virustotal(url, domain=domain)
    if t4_result.get("is_unsafe"):
        flags.append("VIRUSTOTAL_MALICIOUS_FLAGGED")
        risk_delta += _RISK_VIRUSTOTAL

    is_unsafe = (
        t1_result.get("is_unsafe", False)
        or t2_result.get("is_unsafe", False)
        or t3_result.get("is_unsafe", False)
        or t4_result.get("is_unsafe", False)
    )

    return {
        "is_unsafe": is_unsafe,
        "risk_delta": risk_delta,
        "flags": flags,
        "tier1_feeds": t1_result,
        "tier2_safe_browsing": t2_result,
        "tier3_otx": t3_result,
        "tier4_virustotal": t4_result,
    }


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

async def analyze_url(req: ScanRequest) -> UrlAgentResult:
    """
    Analyse the URL in *req* and return a fully populated ``UrlAgentResult``.

    Uses the in-memory TTL-aware domain-result cache (``_domain_cache``)
    so that repeat scans of the same registered domain return in <1 ms
    without re-running TLD, typosquatting, homoglyph, or WHOIS checks.

    This function **never** raises an unhandled exception.
    """
    start = time.perf_counter()
    try:
        # ── Step 1: Extract URL ──
        url = _extract_url(req)
        if url is None:
            elapsed = (time.perf_counter() - start) * 1000
            return UrlAgentResult(
                status=AgentStatusEnum.SKIPPED,
                risk_score=0.0,
                details="No URL detected in payload",
                latency_ms=round(elapsed, 2),
            )

        # ── Step 2: Parse domain ──
        subdomain, domain_label, registered_domain, suffix = _parse_domain(url)

        # ── Step 2b: Domain-result cache probe ──
        cached = _domain_cache.get(registered_domain)
        if cached is not None:
            elapsed = (time.perf_counter() - start) * 1000
            logger.debug(
                "Domain cache HIT for '%s' (%.3f ms)",
                registered_domain, elapsed,
            )
            return UrlAgentResult(
                status=AgentStatusEnum.SUCCESS,
                risk_score=round(cached.risk_score, 2),
                url_analyzed=url,
                domain=registered_domain,
                tld=suffix or None,
                tld_reputation=cached.tld_rep,
                is_typosquatting=cached.is_typo,
                target_brand=cached.target_brand,
                domain_age_days=cached.age_days,
                registrar=cached.registrar,
                safe_browsing_threat=cached.safe_browsing_threat,
                threat_intel=cached.threat_intel,
                flags=list(cached.flags),
                details=f"Analysed {url}; {len(cached.flags)} flag(s) raised [cached]",
                latency_ms=round(elapsed, 2),
            )

        # ── Step 3: TLD reputation ──
        risk_score = 0.0
        flags: List[str] = []

        tld_rep, tld_delta, tld_flags = _check_tld_reputation(suffix)
        risk_score += tld_delta
        flags.extend(tld_flags)

        # ── Step 4: Typosquatting detection ──
        is_typo, target_brand, typo_delta, typo_flags = _check_typosquatting(
            domain_label, registered_domain
        )
        risk_score += typo_delta
        flags.extend(typo_flags)

        # ── Step 4b: Homoglyph / Punycode detection ──
        is_homoglyph, homoglyph_brand, homoglyph_delta, homoglyph_flags = _check_homoglyph(
            domain_label, registered_domain
        )
        if is_homoglyph:
            risk_score += homoglyph_delta
            flags.extend(homoglyph_flags)
            # If typosquatting didn't catch it, upgrade
            if not is_typo and homoglyph_brand:
                is_typo = True
                target_brand = homoglyph_brand

        # ── Step 5: WHOIS age (with zero-downtime fallback) ──
        age_days, registrar, age_delta, age_flags = await _check_whois_age(
            registered_domain, suffix=suffix,
        )
        risk_score += age_delta
        flags.extend(age_flags)

        # ── Step 6: Tiered Threat Intelligence (FR-4 & feeds) ──
        threat_intel = await check_threat_intel(url, domain=registered_domain)
        risk_score += threat_intel["risk_delta"]
        flags.extend(threat_intel["flags"])
        sb_threat = threat_intel.get("tier2_safe_browsing", {}).get("threat_type")

        # ── Step 7: Normalise score ──
        risk_score = max(0.0, min(100.0, risk_score))

        # ── Step 8: Populate domain-result cache ──
        _domain_cache.put(
            registered_domain,
            _DomainCacheEntry(
                risk_score=risk_score,
                tld_rep=tld_rep,
                is_typo=is_typo,
                target_brand=target_brand,
                is_homoglyph=is_homoglyph,
                homoglyph_brand=homoglyph_brand,
                age_days=age_days,
                registrar=registrar,
                safe_browsing_threat=sb_threat,
                threat_intel=threat_intel,
                threat_intel_delta=threat_intel["risk_delta"],
                flags=tuple(flags),
                tld_delta=tld_delta,
                typo_delta=typo_delta,
                homoglyph_delta=homoglyph_delta,
                age_delta=age_delta,
            ),
        )

        elapsed = (time.perf_counter() - start) * 1000
        return UrlAgentResult(
            status=AgentStatusEnum.SUCCESS,
            risk_score=round(risk_score, 2),
            url_analyzed=url,
            domain=registered_domain,
            tld=suffix or None,
            tld_reputation=tld_rep,
            is_typosquatting=is_typo,
            target_brand=target_brand,
            domain_age_days=age_days,
            registrar=registrar,
            safe_browsing_threat=sb_threat,
            threat_intel=threat_intel,
            flags=flags,
            details=f"Analysed {url}; {len(flags)} flag(s) raised",
            latency_ms=round(elapsed, 2),
        )

    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return UrlAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=str(exc),
            latency_ms=round(elapsed, 2),
        )


# ---------------------------------------------------------------------------
# Re-exports for Production-Grade Multi-Signal URL Inspection Pipeline
# ---------------------------------------------------------------------------
try:
    from phishlens.agents.url_agent import (
        DOMAnalysisResult,
        DOMInspector,
        HomographEngine,
        HomographResult,
        RedirectHop,
        RedirectTraceResult,
        RedirectTracer,
        RiskSignal,
        SSLAnalysisResult,
        SSLAnalyzer,
        URLAgent,
        URLAgentInput,
        URLAgentOutput,
        analyze_homograph_and_brands,
        analyze_ssl_infrastructure,
        confusable_skeleton,
        inspect_dom_and_favicons,
        murmur3_favicon_hash,
        run_url_agent,
        trace_redirects_and_cloaking,
    )
except ImportError:
    pass
