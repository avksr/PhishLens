"""
backend/agents/sender_agent.py
-------------------------------
Sender Identity & TRAI DLT Verification Agent for PhishLens (ScamShield AI).

Responsibilities
----------------
1. Extract and normalise the sender identifier from a ScanRequest.
2. Validate against the TRAI DLT certified header registry (O(1) in-memory
   singleton — loaded once at module import, never re-read from disk).
3. Detect personal-GSM-number bank impersonation (high-risk scam pattern).
4. Flag lookalike / spoofed alphabetic headers, including:
   - Lowercase/mixed-case spoofed headers (e.g. vm-sbiinb, vm-hdfcbk).
   - Character-substitution fuzzy spoofs (e.g. VK-SBIBNK mimicking VM-SBIINB).
   - Unicode homoglyph attacks (e.g. Cyrillic 'о' in place of Latin 'O').
5. Apply an emergency-services & government whitelist to prevent false positives
   on legitimate NDMA alerts, EPFO messages, India Post Payments Bank, etc.
6. **TRAI Circle Prefix Verification (Day-3 — AVNI)**: Validate the 2-letter
   operator prefix of every commercial header against the TRAI/NPCI telecom
   circle operator registry (trai_circle_prefix_registry.json).  Prefixes that
   are absent from the registry, or marked inactive (e.g. BZ), are flagged as
   UNREGISTERED_TRAI_CIRCLE_PREFIX / KNOWN_INVALID_TRAI_PREFIX and receive an
   elevated risk score — regardless of whether the entity code resolves.
7. Return a fully-populated SenderAgentResult, NEVER raise an unhandled
   exception (fail-safe design).

Author  : AVNI — Sender Identity & TRAI DLT Agent
Module  : PhishLens v1.0
"""

from __future__ import annotations

import json
import re
import time
import unicodedata
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from shared.models import (
    AgentStatusEnum,
    ScanRequest,
    SenderAgentResult,
    SenderCategoryEnum,
)

# ---------------------------------------------------------------------------
# Constants & Pre-compiled Patterns
# ---------------------------------------------------------------------------

# Absolute path to the TRAI DLT registry data file.
_REGISTRY_PATH: Path = (
    Path(__file__).resolve().parents[1] / "data" / "trai_dlt_registry.json"
)

# Absolute path to the TRAI Circle Prefix registry (operator → telecom circle map).
_CIRCLE_PREFIX_REGISTRY_PATH: Path = (
    Path(__file__).resolve().parents[1] / "data" / "trai_circle_prefix_registry.json"
)

# Official TRAI DLT header format: <2-letter operator>-<6-letter entity code>
# Examples: VM-SBIINB, AX-HDFCBK, AD-ICICIB, VK-PNBSMS
_TRAI_HEADER_RE = re.compile(r"^([A-Z]{2})-([A-Z]{6})$")

# TRAI-like header pattern that allows digit-substituted entity codes.
# e.g. VM-SB1INB (where '1' is substituted for 'I') — used in fuzzy spoof detection.
_TRAI_LIKE_HEADER_RE = re.compile(r"^([A-Z]{2})-([A-Z0-9]{6})$")

# Lookalike header: alphanumeric string with a hyphen that looks brand-related
# but does NOT match the strict TRAI DLT pattern.
# Examples: SBI-ALERT, HDFC-SEC, KOTAK-KYC, PAYTM-OTP
_LOOKALIKE_HEADER_RE = re.compile(r"^[A-Z0-9]{2,10}-[A-Z0-9]{2,10}$")

# Standard Indian 10-digit personal/commercial GSM mobile number.
_INDIAN_GSM_RE = re.compile(r"^[6-9]\d{9}$")

# Phone number embedded in message body (e.g. "call 9876543210" or "+91 98765 43210")
_EMBEDDED_PHONE_RE = re.compile(
    r"(?:call|contact|helpline|reach|dial|whatsapp)\s*[:\-]?\s*"
    r"(?:\+91[\s-]?)?([6-9]\d{4}[\s-]?\d{5})"
    r"|(?<!\d)(\+91[\s-]?)?([6-9]\d{9})(?!\d)",
    re.IGNORECASE,
)

# Country-code prefixes to strip from phone numbers before classification.
_CC_STRIP_RE = re.compile(r"^(?:\+91|91)(\d{10})$")

# Detects mixed-case or lowercase TRAI-format headers before normalisation.
# e.g. "vm-hdfcbk" or "Vm-SbIiNb"
_LOWERCASE_TRAI_RE = re.compile(r"^[A-Za-z]{2}-[A-Za-z]{6}$")

# Detects if any character in the string falls outside ASCII printable range,
# which could indicate Unicode homoglyphs (e.g. Cyrillic 'о', 'а').
_NON_ASCII_RE = re.compile(r"[^\x00-\x7F]")

# Valid TRAI operator prefixes (uppercase, 2-letter)
_VALID_OPERATOR_PREFIXES: Set[str] = {
    "VM", "AX", "AD", "VK", "JK", "TM", "BW", "TA", "AT", "CP"
}

# Keywords that indicate a message is claiming official bank / government origin.
_BANKING_KEYWORDS: List[Tuple[str, str]] = [
    ("SBI", "State Bank of India"),
    ("State Bank", "State Bank of India"),
    ("HDFC", "HDFC Bank"),
    ("ICICI", "ICICI Bank"),
    ("Axis Bank", "Axis Bank"),
    ("PNB", "Punjab National Bank"),
    ("Kotak", "Kotak Mahindra Bank"),
    ("Bank of Baroda", "Bank of Baroda"),
    ("Canara Bank", "Canara Bank"),
    ("Yes Bank", "Yes Bank"),
    ("IDBI", "IDBI Bank"),
    ("Union Bank", "Union Bank of India"),
    ("Indian Bank", "Indian Bank"),
    ("UCO Bank", "UCO Bank"),
    ("Paytm", "Paytm Payments Bank"),
    ("PhonePe", "PhonePe"),
]

_GOVT_KEYWORDS: List[Tuple[str, str]] = [
    ("Aadhaar", "UIDAI (Aadhaar Authority)"),
    ("PAN card", "Income Tax / NSDL"),
    ("PAN Card", "Income Tax / NSDL"),
    ("Income Tax", "Income Tax Department"),
    ("Electricity Bill", "Electricity Provider"),
    ("electricity bill", "Electricity Provider"),
    ("Power cut", "Electricity Provider"),
    ("power cut", "Electricity Provider"),
    ("electricity connection", "Electricity Provider"),
    ("Electricity connection", "Electricity Provider"),
    ("power disconnection", "Electricity Provider"),
    ("Power disconnection", "Electricity Provider"),
    ("electricity supply", "Electricity Provider"),
    ("bijli", "Electricity Provider"),
    ("MSEDCL", "MSEDCL (Maharashtra Electricity)"),
    ("BESCOM", "BESCOM (Bangalore Electricity)"),
    ("TNEB", "TNEB (Tamil Nadu Electricity)"),
    ("Challan", "Government / Traffic Authority"),
    ("GSTN", "GSTN (GST Network)"),
    ("EPF", "EPFO"),
    ("EPFO", "EPFO"),
]

_ALL_OFFICIAL_KEYWORDS = _BANKING_KEYWORDS + _GOVT_KEYWORDS

# ---------------------------------------------------------------------------
# ⚡ Singleton In-Memory Registry (loaded ONCE at module import — O(1) lookup)
# ---------------------------------------------------------------------------
# The registry dict is indexed by entity_code (e.g. "SBIINB") → entry dict.
# A parallel set of all valid (operator_prefix, entity_code) tuples enables
# O(1) existence checks without nested dict traversal.
# ---------------------------------------------------------------------------


def _build_registry() -> Tuple[Dict[str, dict], Set[Tuple[str, str]]]:
    """
    Load the TRAI DLT registry JSON from disk exactly ONCE.
    Returns:
        registry_dict  – entity_code → {brand_name, category, operator_prefixes}
        valid_pairs    – frozenset of (operator_prefix, entity_code) tuples
    """
    with _REGISTRY_PATH.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)
    registry: Dict[str, dict] = raw.get("registry", {})
    valid_pairs: Set[Tuple[str, str]] = set()
    for entity_code, entry in registry.items():
        for prefix in entry.get("operator_prefixes", []):
            valid_pairs.add((prefix, entity_code))
    return registry, valid_pairs


def _build_circle_prefix_registry() -> Tuple[Dict[str, dict], Dict[str, dict]]:
    """
    Load the TRAI Circle Prefix registry from disk exactly ONCE.

    Returns:
        valid_prefixes   – operator_prefix → {operator_name, circles, category, active}
        invalid_prefixes – known invalid/unregistered prefixes → {note, active}
    """
    try:
        with _CIRCLE_PREFIX_REGISTRY_PATH.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        valid: Dict[str, dict] = raw.get("valid_prefixes", {})
        invalid: Dict[str, dict] = raw.get("known_invalid_or_unregistered_prefixes", {})
        return valid, invalid
    except Exception:  # noqa: BLE001 — fail-open if registry is unavailable
        return {}, {}


# Module-level singletons — initialised at import time.
_REGISTRY: Dict[str, dict]
_VALID_PAIRS: Set[Tuple[str, str]]
_REGISTRY, _VALID_PAIRS = _build_registry()

# Flat set of all registered entity codes for quick O(1) membership tests.
_ALL_ENTITY_CODES: Set[str] = set(_REGISTRY.keys())

# Circle-prefix singletons — loaded once alongside the DLT registry.
_CIRCLE_VALID_PREFIXES: Dict[str, dict]
_CIRCLE_INVALID_PREFIXES: Dict[str, dict]
_CIRCLE_VALID_PREFIXES, _CIRCLE_INVALID_PREFIXES = _build_circle_prefix_registry()

# ---------------------------------------------------------------------------
# Unicode Homoglyph Normalisation Map
# ---------------------------------------------------------------------------
# Common Cyrillic / look-alike characters that could be used to spoof an
# ASCII TRAI header when the input is not yet upper-cased.
# Key = Unicode codepoint, Value = ASCII replacement.
_HOMOGLYPH_MAP: Dict[str, str] = {
    "\u0410": "A",  # Cyrillic А → A
    "\u0412": "B",  # Cyrillic В → B (looks like B)
    "\u0421": "C",  # Cyrillic С → C
    "\u0415": "E",  # Cyrillic Е → E
    "\u041D": "H",  # Cyrillic Н → H
    "\u0406": "I",  # Cyrillic І → I
    "\u0408": "J",  # Cyrillic Ј → J
    "\u041A": "K",  # Cyrillic К → K
    "\u041C": "M",  # Cyrillic М → M
    "\u041E": "O",  # Cyrillic О → O
    "\u0420": "R",  # Cyrillic Р → R
    "\u0422": "T",  # Cyrillic Т → T
    "\u0425": "X",  # Cyrillic Х → X
    "\u0430": "a",  # Cyrillic а → a
    "\u0435": "e",  # Cyrillic е → e
    "\u043E": "o",  # Cyrillic о → o
    "\u0440": "r",  # Cyrillic р → r
    "\u0441": "c",  # Cyrillic с → c
    "\u0445": "x",  # Cyrillic х → x
    # Greek homoglyphs
    "\u039F": "O",  # Greek Ο → O
    "\u03A1": "P",  # Greek Ρ → P
    "\u0391": "A",  # Greek Α → A
    "\u0395": "E",  # Greek Ε → E
    "\u0396": "Z",  # Greek Ζ → Z
    "\u0397": "H",  # Greek Η → H
    "\u0399": "I",  # Greek Ι → I
    "\u039A": "K",  # Greek Κ → K
    "\u039C": "M",  # Greek Μ → M
    "\u039D": "N",  # Greek Ν → N
    "\u03A4": "T",  # Greek Τ → T
    "\u03A5": "Y",  # Greek Υ → Y
    # Fullwidth ASCII
    "\uFF21": "A", "\uFF22": "B", "\uFF23": "C", "\uFF24": "D",
    "\uFF25": "E", "\uFF26": "F", "\uFF27": "G", "\uFF28": "H",
    "\uFF29": "I", "\uFF2A": "J", "\uFF2B": "K", "\uFF2C": "L",
    "\uFF2D": "M", "\uFF2E": "N", "\uFF2F": "O", "\uFF30": "P",
    "\uFF31": "Q", "\uFF32": "R", "\uFF33": "S", "\uFF34": "T",
    "\uFF35": "U", "\uFF36": "V", "\uFF37": "W", "\uFF38": "X",
    "\uFF39": "Y", "\uFF3A": "Z",
}

# ---------------------------------------------------------------------------
# Fuzzy Lookalike Detection — Character-Substitution Table
# ---------------------------------------------------------------------------
# These are common 1-character substitutions used by scammers to spoof TRAI
# headers:  I↔1, O↔0, S↔5, B↔8, etc.
# We normalise the candidate entity code through this table before checking
# membership in _ALL_ENTITY_CODES.
_VISUAL_SUBSTITUTIONS: Dict[str, str] = str.maketrans({
    "1": "I",
    "0": "O",
    "5": "S",
    "8": "B",
    "3": "E",
    "4": "A",
    "6": "G",
    "7": "T",
    "!": "I",
    "|": "I",
    "$": "S",
    "@": "A",
})

# ---------------------------------------------------------------------------
# Government & Emergency Services Whitelist
# ---------------------------------------------------------------------------
# Header entity codes that belong to verified government / emergency senders.
# These receive a MAXIMUM risk_score of 5.0 regardless of content keywords.
# NOTE: These must also be present in trai_dlt_registry.json to be reachable.
_GOVT_EMERGENCY_ENTITY_CODES: Set[str] = {
    "UIDAIT",  # UIDAI (Aadhaar Authority)
    "INCOTX",  # Income Tax Department
    "GSTNIN",  # GSTN
    "NSDLPN",  # NSDL PAN Services
    "EPFOHO",  # EPFO
    "MTOUCH",  # India Post Payments Bank (IPPB)
    "NDMAIN",  # NDMA — National Disaster Management Authority
    "TRAISM",  # TRAI
    "IRCTCS",  # IRCTC
    "PMJNBY",  # PMJDY / Jan Dhan Yojana
    "COVIDV",  # CoWIN / NHA
    "NABARD",  # NABARD
    "MSEPCL",  # MSEDCL (Maharashtra Electricity)
    "BESCOM",  # BESCOM (Bangalore Electricity)
    "TNEBSM",  # TNEB (Tamil Nadu Electricity)
}

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _verify_circle_prefix(operator_prefix: str) -> Tuple[bool, bool, str]:
    """
    Validate *operator_prefix* (2-letter, already uppercased) against the
    TRAI telecom circle operator registry.

    Returns a 3-tuple:
        (is_valid_registered, is_known_invalid, detail_msg)

    is_valid_registered : True  → prefix is in the registry AND active.
    is_known_invalid    : True  → prefix is explicitly listed as invalid/inactive.
    detail_msg          : Human-readable description for audit flags.

    Examples
    --------
    >>> _verify_circle_prefix("VM")
    (True, False, "Operator prefix 'VM' is registered to Vodafone Idea (Vi).")
    >>> _verify_circle_prefix("BZ")
    (False, True, "Operator prefix 'BZ' is a known invalid/unregistered TRAI prefix.")
    >>> _verify_circle_prefix("ZQ")
    (False, False, "Operator prefix 'ZQ' is not found in the TRAI circle registry.")
    """
    # Check valid registry first (O(1))
    entry = _CIRCLE_VALID_PREFIXES.get(operator_prefix)
    if entry:
        if entry.get("active", False):
            operator_name = entry.get("operator_name", operator_prefix)
            return (
                True,
                False,
                f"Operator prefix '{operator_prefix}' is registered to {operator_name}.",
            )
        else:
            # Listed in valid_prefixes but marked inactive
            operator_name = entry.get("operator_name", operator_prefix)
            return (
                False,
                True,
                f"Operator prefix '{operator_prefix}' (assigned to {operator_name}) "
                "is marked inactive in the TRAI circle registry.",
            )

    # Check known-invalid registry (O(1))
    invalid_entry = _CIRCLE_INVALID_PREFIXES.get(operator_prefix)
    if invalid_entry:
        note = invalid_entry.get("note", "Listed as invalid in TRAI circle registry.")
        return (False, True, f"Operator prefix '{operator_prefix}' is a known invalid/unregistered TRAI prefix. {note}")

    # Not found in either registry
    return (
        False,
        False,
        f"Operator prefix '{operator_prefix}' is not found in the TRAI circle registry. "
        "This is highly suspicious — legitimate TRAI DLT operators use only registered prefixes.",
    )


def _normalise_homoglyphs(text: str) -> str:
    """
    Replace known Unicode homoglyph characters with their ASCII equivalents.
    Also applies Unicode NFKC normalisation to collapse fullwidth characters.
    """
    # First pass: NFKC normalisation (collapses fullwidth, ligatures, etc.)
    text = unicodedata.normalize("NFKC", text)
    # Second pass: explicit homoglyph map for characters that survive NFKC.
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def _strip_country_code(phone: str) -> str:
    """Remove leading +91 / 91 to yield a plain 10-digit number."""
    phone = phone.replace(" ", "").replace("-", "")
    match = _CC_STRIP_RE.match(phone)
    return match.group(1) if match else phone


def _sanitise_sender(raw: str) -> str:
    """
    Normalise a raw sender string:
    - Strip leading/trailing whitespace.
    - Normalise Unicode homoglyphs to ASCII.
    - Remove embedded hyphens for phone-number candidates only.
    - Strip country-code prefix (+91 / 91) for numeric senders.
    - Uppercase alphabetic sender headers.
    """
    raw = raw.strip()
    # Normalise homoglyphs BEFORE case-normalisation so we catch Cyrillic spoofs.
    raw = _normalise_homoglyphs(raw)
    # If purely numeric after stripping country code, normalise to 10 digits.
    stripped = _strip_country_code(raw)
    if stripped.isdigit():
        return stripped
    # Alphabetic/alphanumeric header — uppercase and strip whitespace only.
    return raw.upper().strip()


def _detect_lowercase_header_spoof(raw: str) -> bool:
    """
    Detect if the raw (pre-normalisation) sender looks like a lowercase or
    mixed-case version of a TRAI DLT header format (e.g. 'vm-hdfcbk',
    'Vm-SbIiNb').  These are never legitimate — TRAI headers are always
    transmitted in ALL-CAPS by registered operators.

    Returns True if the sender matches a TRAI-format pattern but is NOT
    already fully uppercase (i.e. it was submitted in a spoofed lowercase form).
    """
    raw_stripped = raw.strip()
    if _LOWERCASE_TRAI_RE.match(raw_stripped) and raw_stripped != raw_stripped.upper():
        return True
    return False


def _fuzzy_entity_code_lookup(entity_code: str) -> Optional[str]:
    """
    Apply visual-character substitutions to *entity_code* and check if the
    result matches any registered entity code in the whitelist.

    For example: "SB1lNB" → "SBIINB" (after I/1 and l/I substitutions).

    Returns the matched entity_code from the registry if found, else None.
    Only reports a match when the INPUT entity code was DIFFERENT from the
    result (i.e. a substitution was needed), to avoid double-counting
    legitimate headers that are handled by the primary lookup.
    """
    normalised = entity_code.translate(_VISUAL_SUBSTITUTIONS)
    if normalised != entity_code and normalised in _ALL_ENTITY_CODES:
        return normalised
    return None


def _extract_phone_from_content(content: str) -> Optional[str]:
    """
    Scan message body for an embedded phone number.
    Returns the first 10-digit candidate found, or None.
    """
    for match in _EMBEDDED_PHONE_RE.finditer(content):
        # Groups: (keyword-prefixed number, cc, bare number)
        candidate = match.group(1) or match.group(3)
        if candidate:
            candidate = candidate.replace(" ", "").replace("-", "")
            candidate = _strip_country_code(candidate)
            if _INDIAN_GSM_RE.match(candidate):
                return candidate
    return None


def _detect_official_keyword(content: str) -> Optional[str]:
    """
    Scan message body for banking / government authority keywords.
    Returns the brand name of the first match, or None.
    """
    for keyword, brand in _ALL_OFFICIAL_KEYWORDS:
        if keyword.lower() in content.lower():
            return brand
    return None


def _clamp_score(score: float) -> float:
    """Ensure risk_score stays within [0.0, 100.0]."""
    return max(0.0, min(100.0, score))


# ---------------------------------------------------------------------------
# Entity Extractor (FR-2) — Pre-Investigation
# ---------------------------------------------------------------------------

# Pre-compiled patterns for entity extraction from free-form message text.
# Indian phone number: optional +91/91 country prefix (with optional space/dash),
# then 10 digits starting with 6–9, allowing optional spaces or dashes between
# digit groups (e.g. "+91 98765 43210", "987-654-3210", "9876543210").
# The capture group is deliberately wide; digits are normalised post-match.
_ENTITY_PHONE_RE = re.compile(
    r"(?:(?:\+91|91)[\s\-]?)?([6-9][0-9][\s\-]?[0-9][\s\-]?[0-9][\s\-]?[0-9][\s\-]?[0-9][\s\-]?[0-9][\s\-]?[0-9][\s\-]?[0-9][\s\-]?[0-9])(?![0-9])"
)

# TRAI DLT header: exactly 2 uppercase letters, a hyphen, 6 uppercase letters.
_ENTITY_TRAI_HEADER_RE = re.compile(r"\b([A-Z]{2}-[A-Z]{6})\b")

# Currency amounts: Rs / INR / ₹ followed by optional space, then a number
# (supports commas, decimals, e.g. Rs 1,499 / INR 20000 / ₹2.50).
_ENTITY_CURRENCY_RE = re.compile(
    r"(?:Rs\.?|INR|\u20b9)\s*([\d,]+(?:\.\d{1,2})?)",
    re.IGNORECASE,
)


def extract_entities(text: str) -> dict:
    """
    Pre-investigation entity extractor (FR-2).

    Scans *text* for three categories of structured entities that are
    frequently abused in Indian SMS / WhatsApp scams:

    1. **phone_numbers** — Indian mobile numbers (6–9 series, 10 digits),
       with or without +91/91 country prefix.
    2. **trai_headers** — Alphabetic sender headers in TRAI DLT format
       (e.g. VM-SBIINB, AD-BESCOM).
    3. **currency_amounts** — Rupee amounts expressed as
       ``Rs``, ``INR``, or ``₹`` followed by a numeric value.

    Parameters
    ----------
    text : str
        Raw message body (or any free-form string) to scan.

    Returns
    -------
    dict
        ``{
            "phone_numbers":    ["9876543210", ...],
            "trai_headers":     ["VM-SBIINB", ...],
            "currency_amounts": ["1,499", ...]
        }``

    Examples
    --------
    >>> extract_entities("Call 9876543210 for Rs 1,499 refund. Sender VM-SBIINB")
    {'phone_numbers': ['9876543210'], 'trai_headers': ['VM-SBIINB'], 'currency_amounts': ['1,499']}
    """
    # ── Phone numbers ──
    raw_phones = _ENTITY_PHONE_RE.findall(text)
    phones: List[str] = []
    seen_phones: set = set()
    for raw in raw_phones:
        normalised = raw.replace(" ", "").replace("-", "")
        # Strip country code if present to yield 10 digits.
        normalised = _strip_country_code(normalised)
        if _INDIAN_GSM_RE.match(normalised) and normalised not in seen_phones:
            phones.append(normalised)
            seen_phones.add(normalised)

    # ── TRAI headers ──
    raw_headers = _ENTITY_TRAI_HEADER_RE.findall(text)
    headers: List[str] = list(dict.fromkeys(raw_headers))  # preserve order, dedupe

    # ── Currency amounts ──
    raw_amounts = _ENTITY_CURRENCY_RE.findall(text)
    amounts: List[str] = list(dict.fromkeys(raw_amounts))  # preserve order, dedupe

    return {
        "phone_numbers": phones,
        "trai_headers": headers,
        "currency_amounts": amounts,
    }


# ---------------------------------------------------------------------------
# Main Agent Function
# ---------------------------------------------------------------------------

async def analyze_sender(req: ScanRequest) -> SenderAgentResult:
    """
    Sender Identity & TRAI DLT Verification Agent entry point.

    Parameters
    ----------
    req : ScanRequest
        The inbound scan request containing the message content and
        optional sender identifier.

    Returns
    -------
    SenderAgentResult
        A fully-populated result object.  This function NEVER raises;
        any unhandled exception is caught and returned as an ERROR status.
    """
    t_start = time.perf_counter()

    try:
        result = await _run_analysis(req, t_start)
    except Exception as exc:  # noqa: BLE001  — intentional fail-safe
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        result = SenderAgentResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details=str(exc),
            latency_ms=round(latency_ms, 3),
        )

    return result


async def _run_analysis(req: ScanRequest, t_start: float) -> SenderAgentResult:
    """Core analysis logic — called by analyze_sender inside the try block."""

    flags: List[str] = []

    # ------------------------------------------------------------------
    # Step 1: Sender Extraction & Normalisation
    # ------------------------------------------------------------------
    raw_sender: Optional[str] = req.sender

    # ── Lowercase / mixed-case header spoof detection (BEFORE normalisation) ──
    # A genuine TRAI operator always transmits headers in ALL-CAPS.
    # If the raw sender looks like a TRAI header format but contains lowercase
    # characters, it is definitively a spoofed/crafted header.
    is_lc_spoof = False
    if raw_sender:
        is_lc_spoof = _detect_lowercase_header_spoof(raw_sender)

    # ── Unicode homoglyph detection (BEFORE normalisation) ──
    has_homoglyphs = bool(raw_sender and _NON_ASCII_RE.search(raw_sender))

    if raw_sender:
        normalised = _sanitise_sender(raw_sender)
    else:
        # Attempt to extract a phone number from the message body.
        extracted = _extract_phone_from_content(req.content)
        if extracted:
            raw_sender = extracted
            normalised = extracted
        else:
            # No sender metadata whatsoever — return early.
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.UNKNOWN,
                risk_score=20.0,
                details=(
                    "This message arrived without any sender information. "
                    "We could not identify who sent it, which is unusual for "
                    "legitimate SMS from banks or government services."
                ),
                latency_ms=round(latency_ms, 3),
                raw_sender=None,
                normalised_sender=None,
            )

    # ------------------------------------------------------------------
    # Step 2: TRAI DLT Certified Header Validation (O(1) in-memory lookup)
    # ------------------------------------------------------------------
    trai_match = _TRAI_HEADER_RE.match(normalised)
    if trai_match:
        operator_prefix = trai_match.group(1)   # e.g. "VM"
        entity_code = trai_match.group(2)        # e.g. "SBIINB"

        # ── TRAI Circle Prefix Verification (AVNI — Day-3) ──────────────
        # Validate the 2-letter operator prefix against the TRAI telecom
        # circle operator registry, BEFORE checking the entity code.
        prefix_valid, prefix_known_invalid, prefix_detail = _verify_circle_prefix(
            operator_prefix
        )
        if prefix_known_invalid:
            # Explicitly invalid prefix (e.g. BZ- headers)
            flags.append("KNOWN_INVALID_TRAI_PREFIX")
            flags.append("UNVERIFIED_LOOKALIKE_HEADER")
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.LOOKALIKE_HEADER,
                risk_score=_clamp_score(82.0),
                is_spoofed_header=True,
                flags=flags,
                details=(
                    f"Header '{raw_sender}' uses an operator prefix "
                    f"('{operator_prefix}') that is a KNOWN INVALID / "
                    "unregistered TRAI prefix. "
                    f"{prefix_detail}"
                ),
                latency_ms=round(latency_ms, 3),
                raw_sender=raw_sender,
                normalised_sender=normalised,
            )
        elif not prefix_valid:
            # Prefix not found in either registry → unregistered, suspicious
            flags.append("UNREGISTERED_TRAI_CIRCLE_PREFIX")
            flags.append("SUSPICIOUS_OPERATOR_PREFIX")
            # Elevate risk; still fall through to entity-code checks
            # (we may gather additional evidence before returning)

        # ── O(1) lookup against singleton in-memory registry ──
        entry = _REGISTRY.get(entity_code)
        pair_valid = (operator_prefix, entity_code) in _VALID_PAIRS

        if entry and pair_valid:
            # ── Government/Emergency whitelist: immune to false positive on keywords ──
            is_govt = entity_code in _GOVT_EMERGENCY_ENTITY_CODES

            # ── Lowercase/Homoglyph spoof: even if it resolves, flag it ──
            if is_lc_spoof or has_homoglyphs:
                flags.append("LOWERCASE_SPOOFED_HEADER" if is_lc_spoof else "HOMOGLYPH_SPOOFED_HEADER")
                flags.append("UNVERIFIED_LOOKALIKE_HEADER")
                latency_ms = (time.perf_counter() - t_start) * 1000.0
                return SenderAgentResult(
                    status=AgentStatusEnum.SUCCESS,
                    sender_category=SenderCategoryEnum.LOOKALIKE_HEADER,
                    risk_score=_clamp_score(85.0),
                    is_spoofed_header=True,
                    brand_claimed=entry.get("brand_name"),
                    flags=flags,
                    details=(
                        f"The sender ID '{raw_sender}' is written in lowercase or "
                        f"uses look-alike characters to impersonate '{entry['brand_name']}'. "
                        "Genuine TRAI-registered senders always appear in capital letters. "
                        "This is a strong sign that someone is trying to fake the sender identity."
                    ),
                    latency_ms=round(latency_ms, 3),
                    raw_sender=raw_sender,
                    normalised_sender=normalised,
                )

            # ── Enrich details with extracted entities from message body ──
            entities = extract_entities(req.content)
            entity_parts = []
            if entities["phone_numbers"]:
                entity_parts.append(
                    "phone number(s) found: " + ", ".join(entities["phone_numbers"])
                )
            if entities["currency_amounts"]:
                entity_parts.append(
                    "amount(s) mentioned: ₹" + ", ₹".join(entities["currency_amounts"])
                )
            entity_note = (
                " The message also contains " + " and ".join(entity_parts) + "."
                if entity_parts else ""
            )

            # Fully verified TRAI DLT sender.
            flags.append("VERIFIED_TRAI_DLT_SENDER_HEADER")
            if is_govt:
                flags.append("GOVERNMENT_EMERGENCY_WHITELISTED")
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.OFFICIAL_TRAI_HEADER,
                risk_score=_clamp_score(5.0),
                brand_claimed=entry["brand_name"],
                is_spoofed_header=False,
                flags=flags,
                details=(
                    f"The sender '{normalised}' is an officially registered TRAI DLT "
                    f"sender ID for '{entry['brand_name']}' "
                    f"(category: {entry['category']}). "
                    "This sender is legitimate and verified by India's telecom regulator."
                    + entity_note
                ),
                latency_ms=round(latency_ms, 3),
                raw_sender=raw_sender,
                normalised_sender=normalised,
            )

        # ── Fuzzy lookalike: check if character substitutions reveal a spoofed code ──
        spoofed_entity = _fuzzy_entity_code_lookup(entity_code)
        if spoofed_entity:
            spoofed_entry = _REGISTRY[spoofed_entity]
            flags.append("FUZZY_LOOKALIKE_ENTITY_CODE")
            flags.append("UNVERIFIED_LOOKALIKE_HEADER")
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.LOOKALIKE_HEADER,
                risk_score=_clamp_score(88.0),
                is_spoofed_header=True,
                brand_claimed=spoofed_entry.get("brand_name"),
                flags=flags,
                details=(
                    f"The sender ID '{normalised}' looks almost identical to the "
                    f"official '{spoofed_entry['brand_name']}' sender ID, but uses "
                    "trick characters (e.g. the digit '1' instead of the letter 'I', "
                    "or '0' instead of 'O') to disguise itself. "
                    "This is a known fraud technique to impersonate a trusted brand."
                ),
                latency_ms=round(latency_ms, 3),
                raw_sender=raw_sender,
                normalised_sender=normalised,
            )

        # ── Check operator prefix: valid TRAI operator but unregistered entity ──
        if prefix_valid and operator_prefix in _VALID_OPERATOR_PREFIXES:
            flags.append("VALID_OPERATOR_PREFIX_BUT_UNKNOWN_ENTITY")
        elif not prefix_valid and "UNREGISTERED_TRAI_CIRCLE_PREFIX" not in flags:
            # Prefix lookup above already added this flag if needed
            flags.append("UNREGISTERED_TRAI_CIRCLE_PREFIX")
        flags.append("UNREGISTERED_TRAI_FORMAT_HEADER")
        # Falls through to lookalike detection below with elevated risk.

    # ------------------------------------------------------------------
    # Step 2.5: TRAI-Like Header With Digit Substitutions (Fuzzy Spoof)
    # ------------------------------------------------------------------
    # Catches headers like 'VM-SB1INB' (digit '1' for 'I') that match the
    # TRAI structural format (XX-XXXXXX) but contain digits in the entity
    # code — not caught by the strict all-alpha _TRAI_HEADER_RE above.
    trai_like_match = _TRAI_LIKE_HEADER_RE.match(normalised)
    if trai_like_match and not trai_match:  # only if NOT already handled above
        operator_prefix_like = trai_like_match.group(1)
        entity_code_like = trai_like_match.group(2)
        spoofed_entity_like = _fuzzy_entity_code_lookup(entity_code_like)
        if spoofed_entity_like:
            spoofed_entry_like = _REGISTRY[spoofed_entity_like]
            flags.append("FUZZY_LOOKALIKE_ENTITY_CODE")
            flags.append("UNVERIFIED_LOOKALIKE_HEADER")
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.LOOKALIKE_HEADER,
                risk_score=_clamp_score(88.0),
                is_spoofed_header=True,
                brand_claimed=spoofed_entry_like.get("brand_name"),
                flags=flags,
                details=(
                    f"The sender ID '{normalised}' uses digits in place of letters "
                    f"(e.g. '1' instead of 'I') to closely mimic the real "
                    f"'{spoofed_entry_like['brand_name']}' sender ID. "
                    "This is a fraud technique designed to trick people into trusting "
                    "a fake sender."
                ),
                latency_ms=round(latency_ms, 3),
                raw_sender=raw_sender,
                normalised_sender=normalised,
            )

    # ------------------------------------------------------------------
    # Step 3: Personal GSM Bank Impersonation Detection
    # ------------------------------------------------------------------
    if _INDIAN_GSM_RE.match(normalised):
        brand = _detect_official_keyword(req.content)
        if brand:
            flags.append("COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM")
            flags.append("MISSING_TRAI_OFFICIAL_HEADER")
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.PERSONAL_GSM,
                risk_score=_clamp_score(85.0),
                brand_claimed=brand,
                is_spoofed_header=False,
                flags=flags,
                details=(
                    f"This message is sent from a personal mobile number ({normalised}) "
                    f"but claims to be from '{brand}'. "
                    "In India, all banks and government agencies are required by TRAI "
                    "to send messages using a registered letter-based sender ID (like VM-SBIINB), "
                    "never from a personal 10-digit phone number. "
                    "This is a strong indicator of fraud."
                ),
                latency_ms=round(latency_ms, 3),
                raw_sender=raw_sender,
                normalised_sender=normalised,
            )

        # Plain personal GSM number with no suspicious content.
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        return SenderAgentResult(
            status=AgentStatusEnum.SUCCESS,
            sender_category=SenderCategoryEnum.PERSONAL_GSM,
            risk_score=_clamp_score(40.0),
            flags=flags,
            details=(
                f"Sender is a personal Indian mobile number ({normalised}). "
                "No claims of being a bank or government agency were found in this message, "
                "but be cautious — legitimate businesses do not usually contact you from "
                "personal phone numbers."
            ),
            latency_ms=round(latency_ms, 3),
            raw_sender=raw_sender,
            normalised_sender=normalised,
        )

    # ------------------------------------------------------------------
    # Step 4: Lookalike / Spoofed Header Detection
    # ------------------------------------------------------------------
    if _LOOKALIKE_HEADER_RE.match(normalised):
        if is_lc_spoof:
            flags.append("LOWERCASE_SPOOFED_HEADER")
        if has_homoglyphs:
            flags.append("HOMOGLYPH_SPOOFED_HEADER")
        flags.append("UNVERIFIED_LOOKALIKE_HEADER")
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        return SenderAgentResult(
            status=AgentStatusEnum.SUCCESS,
            sender_category=SenderCategoryEnum.LOOKALIKE_HEADER,
            risk_score=_clamp_score(75.0),
            is_spoofed_header=True,
            flags=flags,
            details=(
                f"The sender ID '{normalised}' looks like it is pretending to be a "
                "well-known brand, but it is not found in India's official TRAI sender "
                "registry and does not follow the proper registered format. "
                "Do not trust or respond to this message."
            ),
            latency_ms=round(latency_ms, 3),
            raw_sender=raw_sender,
            normalised_sender=normalised,
        )

    # ------------------------------------------------------------------
    # Step 5: Fallback — Unrecognised sender format
    # ------------------------------------------------------------------
    latency_ms = (time.perf_counter() - t_start) * 1000.0
    return SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        sender_category=SenderCategoryEnum.UNKNOWN,
        risk_score=_clamp_score(30.0),
        flags=flags,
        details=(
            f"The sender '{normalised}' does not match any recognised pattern — "
            "not a registered TRAI sender ID, not a standard phone number. "
            "Exercise caution before acting on this message."
        ),
        latency_ms=round(latency_ms, 3),
        raw_sender=raw_sender,
        normalised_sender=normalised,
    )
