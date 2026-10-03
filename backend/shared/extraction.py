"""
backend.shared.extraction — Shared text-extraction utilities for PhishLens.

Provides three primary extractors:

1. **UPI VPA extraction** — detects ``user@handle`` patterns using a curated
   list of known Indian UPI handles so that ordinary email addresses
   (``user@gmail.com``) are *not* falsely matched.
2. **Phone number extraction** — uses the ``phonenumbers`` library with
   India (IN) as the default region.
3. **URL extraction** — finds HTTP(S) URLs in raw text *and* defanged
   variants commonly found in OCR / PDF / threat-intel feeds
   (e.g. ``hxxps://``, ``[.]``, ``[://]``).

Author: Atharv (URL Agent team)
"""

from __future__ import annotations

import re
import logging
from typing import List

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# UPI VPA extraction
# ──────────────────────────────────────────────

# Curated list of known UPI payment handles (PSP handles).
# Only identifiers after the '@' that appear in this set are
# treated as VPA; everything else (e.g. @gmail.com) is ignored.
_KNOWN_UPI_HANDLES: frozenset[str] = frozenset({
    # Major banks
    "upi", "sbi", "oksbi", "okaxis", "okicici", "okhdfcbank",
    "ybl", "ibl", "apl", "axl", "axisbank",
    "icici", "hdfc", "hdfcbank", "axis",
    "boi", "pnb", "kotak", "indus", "federal",
    "idbi", "canarabank", "unionbankofindia",
    "dbs", "rbl", "scb", "hsbc", "citi",
    "dlb", "jkb", "kvb", "mahb", "kbl", "lb",
    "ujjivan", "equitas", "fino",
    "centralbank", "indianbank", "iob",
    "bandhan", "aubank",
    # Payment apps / fintechs
    "paytm", "airtel", "freecharge", "amazonpay",
    "slice", "jupiter", "cred",
    "gpay", "phonepe", "whatsapp",
    "niyobank", "finobank",
    # Wallets / neo-banks
    "postbank", "ippb", "ptyes", "pthdfc", "ptaxis",
    "waicici", "wasbi", "wahdfcbank", "waaxis",
})

# Pattern: one or more word-chars, then @, then a known handle
# (case-insensitive).  We anchor on word boundaries to avoid matching
# fragments inside longer strings.
_VPA_REGEX = re.compile(
    r"\b([a-zA-Z0-9._-]+)@([a-zA-Z0-9]+)(?!\.[a-zA-Z0-9])\b",
    re.IGNORECASE,
)


def extract_vpas(text: str) -> List[str]:
    """
    Extract UPI Virtual Payment Addresses from *text*.

    Only matches where the handle portion (after ``@``) is in the
    curated ``_KNOWN_UPI_HANDLES`` set are returned.  This prevents
    ordinary email addresses from being misidentified as VPAs.

    Returns a de-duplicated list of VPA strings in the order they
    first appear.
    """
    if not text:
        return []

    seen: set[str] = set()
    vpas: List[str] = []

    for match in _VPA_REGEX.finditer(text):
        handle = match.group(2).lower()
        if handle in _KNOWN_UPI_HANDLES:
            vpa = f"{match.group(1)}@{handle}"
            if vpa.lower() not in seen:
                seen.add(vpa.lower())
                vpas.append(vpa)

    return vpas


# ──────────────────────────────────────────────
# Phone number extraction
# ──────────────────────────────────────────────

def extract_phone_numbers(
    text: str,
    region: str = "IN",
) -> List[str]:
    """
    Extract phone numbers from *text* using the ``phonenumbers`` library.

    Numbers are parsed with *region* as the default country (``IN`` for
    India).  Only numbers that ``phonenumbers`` considers *possible*
    are returned, formatted in E.164 (e.g. ``+919876543210``).

    Returns a de-duplicated list in first-appearance order.
    """
    if not text:
        return []

    try:
        import phonenumbers  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("phonenumbers not installed — skipping phone extraction")
        return []

    seen: set[str] = set()
    numbers: List[str] = []

    for match in phonenumbers.PhoneNumberMatcher(text, region):
        formatted = phonenumbers.format_number(
            match.number,
            phonenumbers.PhoneNumberFormat.E164,
        )
        if formatted not in seen:
            seen.add(formatted)
            numbers.append(formatted)

    return numbers


# ──────────────────────────────────────────────
# URL extraction (including defanged)
# ──────────────────────────────────────────────

# Defanging substitutions (order matters: longer patterns first).
_DEFANG_REPLACEMENTS: List[tuple[str, str]] = [
    ("[://]", "://"),
    ("[:]", ":"),
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("hXXps", "https"),
    ("hXXp", "http"),
    ("[.]", "."),
    ("[dot]", "."),
    ("[::]", ":"),
]

# Regex for standard URLs.
_URL_REGEX = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)

# Regex for defanged URLs — matches hxxp(s), [.] patterns, etc.
_DEFANGED_URL_REGEX = re.compile(
    r"\b(?:hxxps?|https?)[^\s<>\"']+",
    re.IGNORECASE,
)

# Dot-based defanged without protocol (e.g. "evil\[.\]com/path")
_DEFANGED_DOT_REGEX = re.compile(
    r"\b[a-zA-Z0-9_-]+(?:\[?\.\]?|\[\.\])[a-zA-Z]{2,}(?:/[^\s<>\"'\)\]]*)?",
    re.IGNORECASE,
)


def refang_url(url: str) -> str:
    """
    Convert a defanged URL back to its standard form.

    Handles common defanging patterns used in threat-intel feeds,
    OCR output, and PDF text:

    - ``hxxps://`` → ``https://``
    - ``[.]`` / ``[dot]`` → ``.``
    - ``[://]`` → ``://``
    - ``[:]`` → ``:``
    """
    result = url
    for pattern, replacement in _DEFANG_REPLACEMENTS:
        result = result.replace(pattern, replacement)
        # Also try case-insensitive for hxxp variants
        result = result.replace(pattern.upper(), replacement)
    return result


def extract_urls(
    text: str,
    include_defanged: bool = True,
) -> List[str]:
    """
    Extract URLs from *text*, optionally including defanged variants.

    When *include_defanged* is ``True`` (the default), patterns like
    ``hxxps://evil[.]com/phish`` are refanged to standard URLs before
    being returned.

    Returns a de-duplicated list in first-appearance order.
    """
    if not text:
        return []

    seen: set[str] = set()
    urls: List[str] = []

    def _add(url: str) -> None:
        cleaned = url.rstrip(".,;!?)]}>\"'")
        if cleaned and cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            urls.append(cleaned)

    # Pass 1: Standard URLs
    for match in _URL_REGEX.finditer(text):
        _add(match.group(0))

    # Pass 2: Defanged URLs
    if include_defanged:
        for match in _DEFANGED_URL_REGEX.finditer(text):
            refanged = refang_url(match.group(0))
            if refanged.startswith(("http://", "https://")):
                _add(refanged)

    return urls
