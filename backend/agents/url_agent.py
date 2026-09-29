"""
backend.agents.url_agent — URL & Domain Intelligence Agent for PhishLens.

Performs multi-signal analysis of URLs extracted from suspicious messages:
  1. URL extraction (from ``ScanRequest.extracted_url`` or regex fallback)
  2. TLD reputation scoring against a curated high-risk TLD list
  3. Typosquatting / brand-impersonation detection via keyword + Levenshtein similarity
  4. WHOIS domain-age check (graceful degradation on failure)
  5. Score normalisation and latency tracking

Author : Atharv (URL Agent team)
"""

from __future__ import annotations

import asyncio
import json
import re
import time
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

# WHOIS timeout (seconds)
_WHOIS_TIMEOUT = 1.5

# Domain age threshold (days)
_NEW_DOMAIN_THRESHOLD_DAYS = 30

# Minimum Levenshtein similarity ratio to flag as lookalike
_SIMILARITY_THRESHOLD = 0.55


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
    Look up domain creation date via ``python-whois``.

    Runs the blocking ``whois.whois()`` call inside an executor with a
    ``_WHOIS_TIMEOUT`` second ceiling so the agent stays responsive.

    Parameters
    ----------
    registered_domain : str
        The full registered domain (e.g. ``sbi-kyc-verify.top``).

    Returns ``(domain_age_days | None, score_delta, new_flags)``.
    """
    try:
        import whois  # type: ignore[import-untyped]
    except ImportError:
        # python-whois is not installed — skip gracefully
        return None, 0.0, []

    full_domain = registered_domain

    def _blocking_whois() -> Optional[int]:
        try:
            w = whois.whois(full_domain)
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

    loop = asyncio.get_running_loop()
    try:
        age_days = await asyncio.wait_for(
            loop.run_in_executor(None, _blocking_whois),
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
