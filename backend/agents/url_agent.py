"""
backend.agents.url_agent — URL & Domain Intelligence Agent for PhishLens.

Performs multi-signal analysis of URLs extracted from suspicious messages:
  1. URL extraction (from ``ScanRequest.extracted_url`` or regex fallback)
  2. TLD reputation scoring against a curated high-risk TLD list
  3. Typosquatting / brand-impersonation detection via keyword + Levenshtein similarity
  4. Homoglyph / Punycode lookalike detection (Cyrillic & Unicode confusables)
  5. WHOIS domain-age check with LRU cache (graceful degradation on failure)
  6. Score normalisation and latency tracking

Author : Atharv (URL Agent team)
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import re
import time
import unicodedata
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

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

# WHOIS timeout (seconds)
_WHOIS_TIMEOUT = 1.5

# Domain age threshold (days)
_NEW_DOMAIN_THRESHOLD_DAYS = 30

# Minimum Levenshtein similarity ratio to flag as lookalike
_SIMILARITY_THRESHOLD = 0.55

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
# WHOIS LRU Cache (sub-millisecond repeated lookups)
# ──────────────────────────────────────────────

@functools.lru_cache(maxsize=2048)
def _lookup_domain_age(domain: str) -> Optional[int]:
    """
    Synchronous WHOIS lookup returning domain age in days, or None.

    Wrapped with ``functools.lru_cache(maxsize=2048)`` so repeated
    queries for the same domain return in sub-millisecond time without
    hitting the network.
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
        if creation is None:
            return None
        if isinstance(creation, datetime):
            age = (datetime.now(timezone.utc) - creation.replace(tzinfo=timezone.utc)).days
            return age
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

    Two-pass approach:
      1. **Keyword match** — does any brand keyword appear in the domain label
         while the full registered domain is NOT in the brand's official list?
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

    for _brand_key, info in brand_data.items():
        brand_name: str = info.get("brand_name", _brand_key)
        keywords: List[str] = [k.lower() for k in info.get("keywords", [])]
        official_domains: List[str] = [d.lower() for d in info.get("official_domains", [])]

        # Pass 1 — keyword hit in the domain label
        if any(kw in label_lower for kw in keywords):
            # Is the full registered domain an official one?
            if full_lower in official_domains:
                return False, None, 0.0, []
            return (
                True,
                brand_name,
                _RISK_TYPOSQUATTING,
                ["TYPOSQUATTING_DETECTED"],
            )

        # Pass 2 — Levenshtein similarity against each official domain
        for official in official_domains:
            ratio = _levenshtein_ratio(full_lower, official)
            if ratio >= _SIMILARITY_THRESHOLD:
                # Don't flag exact matches
                if full_lower == official:
                    return False, None, 0.0, []
                return (
                    True,
                    brand_name,
                    _RISK_TYPOSQUATTING,
                    ["TYPOSQUATTING_DETECTED"],
                )

    return False, None, 0.0, []


async def _check_whois_age(registered_domain: str) -> Tuple[Optional[int], float, List[str]]:
    """
    Look up domain creation date via the LRU-cached ``_lookup_domain_age()``.

    Runs the (potentially) blocking call inside an executor with a
    ``_WHOIS_TIMEOUT`` second ceiling so the agent stays responsive.
    On cache hits, returns in sub-millisecond time.

    Parameters
    ----------
    registered_domain : str
        The full registered domain (e.g. ``sbi-kyc-verify.top``).

    Returns ``(domain_age_days | None, score_delta, new_flags)``.
    """
    loop = asyncio.get_running_loop()
    try:
        age_days = await asyncio.wait_for(
            loop.run_in_executor(None, _lookup_domain_age, registered_domain),
            timeout=_WHOIS_TIMEOUT,
        )
    except (asyncio.TimeoutError, Exception):
        return None, 0.0, []

    if age_days is not None and age_days < _NEW_DOMAIN_THRESHOLD_DAYS:
        return (
            age_days,
            _RISK_NEW_DOMAIN,
            [f"NEWLY_REGISTERED_DOMAIN (< {_NEW_DOMAIN_THRESHOLD_DAYS} days)"],
        )
    return age_days, 0.0, []


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

async def analyze_url(req: ScanRequest) -> UrlAgentResult:
    """
    Analyse the URL in *req* and return a fully populated ``UrlAgentResult``.

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

        risk_score = 0.0
        flags: List[str] = []

        # ── Step 3: TLD reputation ──
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

        # ── Step 5: WHOIS age ──
        age_days, age_delta, age_flags = await _check_whois_age(registered_domain)
        risk_score += age_delta
        flags.extend(age_flags)

        # ── Step 6: Normalise score ──
        risk_score = max(0.0, min(100.0, risk_score))

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
