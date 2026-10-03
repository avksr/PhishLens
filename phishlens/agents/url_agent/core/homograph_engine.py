"""
backend.agents.url_agent.core.homograph_engine — Homograph & Typosquatting Engine.

Features:
- IDN / Punycode decoding and validation using the standard idna library.
- Unicode skeleton confusable transformation across Cyrillic, Greek, Latin-lookalikes.
- Brand impersonation detection using normalized Levenshtein Distance & Jaro-Winkler metrics.
- Combosquatting detection (e.g., paypal-security-update.com, microsoft-login.xyz).
- Subdomain spoofing detection (e.g., paypal.com.account-verify.ru).
"""

from __future__ import annotations

import logging
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import idna
import tldextract

try:
    from backend.agents.url_agent.models.schema import RiskSignal
except ImportError:
    try:
        from agents.url_agent.models.schema import RiskSignal
    except ImportError:
        from ..models.schema import RiskSignal

try:
    from rapidfuzz import distance
    _HAS_RAPIDFUZZ = True
except ImportError:
    from difflib import SequenceMatcher
    _HAS_RAPIDFUZZ = False

logger = logging.getLogger(__name__)

# High-value targeted brands (Global tech, fintech, crypto, Indian utilities & banks)
TARGETED_BRANDS: Dict[str, Tuple[str, ...]] = {
    # Global Tech & Cloud
    "PayPal": ("paypal",),
    "Microsoft": ("microsoft", "office365", "live", "outlook"),
    "Google": ("google", "gmail", "googlepay", "gpay"),
    "Apple": ("apple", "icloud"),
    "Amazon": ("amazon", "aws"),
    "Netflix": ("netflix",),
    "Facebook": ("facebook", "meta", "instagram", "whatsapp"),
    "Coinbase": ("coinbase", "binance", "metamask"),
    "Telegram": ("telegram",),
    # Banking & Financials (Global & Indian)
    "State Bank of India": ("sbi", "onlinesbi"),
    "HDFC Bank": ("hdfc", "hdfcbank"),
    "ICICI Bank": ("icici", "icicibank"),
    "Axis Bank": ("axis", "axisbank"),
    "Kotak Mahindra": ("kotak", "kotakbank"),
    "Punjab National Bank": ("pnb", "pnbindia"),
    # Indian Utilities & Services
    "IRCTC": ("irctc", "indianrail"),
    "Paytm": ("paytm",),
    "PhonePe": ("phonepe",),
    "India Post": ("indiapost",),
    "EPFO": ("epfindia", "epfo"),
    "Parivahan": ("parivahan", "vahan", "sarathi"),
    "BSES": ("bsesdelhi", "bses"),
    "UPPCL": ("uppcl", "uppclonline"),
    "TNEB": ("tneb", "tnebnet"),
    "BESCOM": ("bescom",),
    "Mahadiscom": ("mahadiscom",),
}

# Exhaustive confusable map (Cyrillic, Greek, Math/Roman numerals to Latin)
_CONFUSABLE_MAP: Dict[str, str] = {
    # Cyrillic
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u043a": "k", "\u043d": "h", "\u0442": "t",
    "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u0457": "i", "\u044a": "b",
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0423": "Y", "\u0425": "X",
    # Greek
    "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03bf": "o", "\u03c1": "p",
    "\u03bd": "v", "\u03c5": "u", "\u03c7": "x",
    # Roman Numerals / Fullwidth
    "\u2170": "i", "\u2171": "ii", "\u2172": "iii", "\u217a": "xi",
    "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff44": "d", "\uff45": "e",
}

# Combosquatting intent keywords
_COMBOSQUAT_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "support", "billing", "portal", "auth",
    "wallet", "claim", "kyc", "alert", "service", "help",
})


@dataclass
class HomographAnalysisResult:
    """Result returned by the homograph and typosquatting engine."""
    domain: str
    is_idn: bool
    is_punycode: bool
    punycode_decoded: str
    skeleton_string: str
    is_homoglyph_attack: bool
    is_typosquatting: bool
    is_combosquatting: bool
    is_subdomain_spoof: bool
    target_brand: Optional[str]
    similarity_score: float
    signals: List[RiskSignal] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_impersonating(self) -> bool:
        return (
            self.is_homoglyph_attack
            or self.is_typosquatting
            or self.is_combosquatting
            or self.is_subdomain_spoof
        )

    @property
    def unicode_domain(self) -> str:
        return self.punycode_decoded

    @property
    def skeleton(self) -> str:
        return self.skeleton_string

    @property
    def impersonated_brand(self) -> Optional[str]:
        return self.target_brand

    @property
    def brand_similarity(self) -> float:
        return self.similarity_score


HomographResult = HomographAnalysisResult


def compute_similarity(str1: str, str2: str) -> float:
    """Compute normalized similarity metric between two strings (0.0 to 1.0)."""
    if not str1 or not str2:
        return 0.0
    if str1 == str2:
        return 1.0

    if _HAS_RAPIDFUZZ:
        lev = distance.Levenshtein.normalized_similarity(str1, str2)
        jw = distance.JaroWinkler.similarity(str1, str2)
        return round(max(lev, jw), 4)
    else:
        return round(SequenceMatcher(None, str1, str2).ratio(), 4)


def to_unicode_skeleton(text: str) -> str:
    """Convert Unicode confusables to standard Latin skeleton characters."""
    normalized = unicodedata.normalize("NFKD", text)
    result: List[str] = []
    for char in normalized:
        if char in _CONFUSABLE_MAP:
            result.append(_CONFUSABLE_MAP[char])
        else:
            cat = unicodedata.category(char)
            # Retain standard letter/digit characters
            if not cat.startswith("M"):
                result.append(char)
    return "".join(result).lower()


class HomographEngine:
    """
    High-precision engine for detecting IDN homoglyphs, visual skeleton confusables,
    typosquatting, and combosquatting impersonating trusted brands.
    """

    def __init__(self, similarity_threshold: float = 0.82) -> None:
        self.similarity_threshold = similarity_threshold

    def analyze_domain(self, domain_or_url: str) -> HomographAnalysisResult:
        """Analyze domain for IDN, skeleton confusables, and brand impersonation."""
        signals: List[RiskSignal] = []

        # Parse domain
        clean = domain_or_url.strip()
        if "://" in clean:
            parsed = urlparse(clean)
            hostname = parsed.hostname or clean
        else:
            hostname = clean.split("/")[0]

        extracted = tldextract.extract(hostname)
        subdomain = extracted.subdomain.lower()
        domain_label = extracted.domain.lower()
        suffix = extracted.suffix.lower()
        registered_domain = f"{domain_label}.{suffix}" if suffix else domain_label

        # ── 1. Punycode & IDN Inspection ──
        is_punycode = "xn--" in hostname.lower()
        punycode_decoded = ""
        is_idn = False

        if is_punycode:
            try:
                punycode_decoded = idna.decode(hostname)
                is_idn = True
                signals.append(
                    RiskSignal(
                        category="HOMOGRAPH",
                        severity="HIGH",
                        description=f"Punycode domain detected: '{hostname}' decodes to '{punycode_decoded}'",
                    )
                )
            except Exception as e:
                punycode_decoded = hostname
                logger.debug("Failed decoding punycode %s: %s", hostname, e)
        else:
            try:
                encoded = idna.encode(hostname).decode("ascii")
                if encoded != hostname.lower():
                    is_idn = True
                    is_punycode = True
                    punycode_decoded = hostname
            except Exception:
                pass

        # ── 2. Unicode Skeleton Matching ──
        # Check raw text or decoded text for mixed scripts and visual confusables
        target_text = punycode_decoded if punycode_decoded else hostname
        skeleton = to_unicode_skeleton(target_text)
        is_homoglyph_attack = False

        if skeleton != target_text.lower():
            is_homoglyph_attack = True
            signals.append(
                RiskSignal(
                    category="HOMOGRAPH",
                    severity="CRITICAL",
                    description=(
                        f"Unicode homoglyph / visual skeleton confusable detected: "
                        f"'{target_text}' mimics '{skeleton}'"
                    ),
                )
            )

        # ── 3. Brand Impersonation & Typosquatting ──
        is_typosquatting = False
        is_combosquatting = False
        is_subdomain_spoof = False
        target_brand_identified: Optional[str] = None
        best_similarity = 0.0

        skeleton_label = extracted.domain.lower()
        if is_homoglyph_attack:
            skel_extracted = tldextract.extract(skeleton)
            skeleton_label = skel_extracted.domain.lower()

        # Check combosquatting & brand tokens
        for brand_name, brand_tokens in TARGETED_BRANDS.items():
            for token in brand_tokens:
                # 3a. Subdomain Spoofing check: brand placed in subdomain (e.g. paypal.com.evil.ru)
                if subdomain:
                    sub_parts = subdomain.split(".")
                    if token in sub_parts or f"{token}.com" in subdomain or f"{token}com" in subdomain:
                        is_subdomain_spoof = True
                        target_brand_identified = brand_name
                        signals.append(
                            RiskSignal(
                                category="HOMOGRAPH",
                                severity="CRITICAL",
                                description=(
                                    f"Subdomain brand spoofing: brand '{brand_name}' injected into "
                                    f"subdomain '{subdomain}' on host '{registered_domain}'"
                                ),
                            )
                        )
                        break

                # 3b. Combosquatting check: brand token + security/login keywords (e.g. sbi-kyc-update.com)
                if token in skeleton_label and skeleton_label != token:
                    # Check if remaining parts contain combosquat keywords
                    remaining = skeleton_label.replace(token, "").strip("-_.")
                    if any(kw in remaining for kw in _COMBOSQUAT_KEYWORDS) or len(remaining) > 2:
                        is_combosquatting = True
                        target_brand_identified = brand_name
                        signals.append(
                            RiskSignal(
                                category="HOMOGRAPH",
                                severity="HIGH",
                                description=(
                                    f"Combosquatting detected: brand token '{token}' coupled with "
                                    f"action keywords in '{skeleton_label}'"
                                ),
                            )
                        )
                        break

                # 3c. Typosquatting check (Levenshtein / Jaro-Winkler lookalike)
                if skeleton_label != token:
                    sim = compute_similarity(skeleton_label, token)
                    if sim > best_similarity:
                        best_similarity = sim
                    if sim >= self.similarity_threshold:
                        is_typosquatting = True
                        target_brand_identified = brand_name
                        signals.append(
                            RiskSignal(
                                category="HOMOGRAPH",
                                severity="HIGH",
                                description=(
                                    f"Typosquatting brand lookalike: '{skeleton_label}' is {sim:.0%} "
                                    f"similar to official '{brand_name}' ({token})"
                                ),
                            )
                        )
                        break

            if target_brand_identified and (is_subdomain_spoof or is_combosquatting):
                break

        return HomographAnalysisResult(
            domain=hostname,
            is_idn=is_idn,
            is_punycode=is_punycode,
            punycode_decoded=punycode_decoded,
            skeleton_string=skeleton,
            is_homoglyph_attack=is_homoglyph_attack,
            is_typosquatting=is_typosquatting,
            is_combosquatting=is_combosquatting,
            is_subdomain_spoof=is_subdomain_spoof,
            target_brand=target_brand_identified,
            similarity_score=best_similarity,
            signals=signals,
            metadata={
                "domain_label": domain_label,
                "subdomain": subdomain,
                "suffix": suffix,
                "skeleton": skeleton,
                "similarity": best_similarity,
            },
        )

    analyze = analyze_domain


def check_homograph_and_typosquatting(domain_or_url: str) -> HomographAnalysisResult:
    """Helper function to execute domain homograph and brand spoofing analysis."""
    engine = HomographEngine()
    return engine.analyze_domain(domain_or_url)


analyze_homograph_and_brands = check_homograph_and_typosquatting
confusable_skeleton = to_unicode_skeleton
