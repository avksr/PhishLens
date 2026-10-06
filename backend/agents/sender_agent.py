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

import asyncio
import json
import re
import time
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from shared.models import (
    AgentStatusEnum,
    ScanRequest,
    SenderAgentResult,
    SenderCategoryEnum,
)
from agents.email_agent import analyze_email, parse_raw_eml
from agents.phone_osint import (
    resolve_phone_osint,
    resolve_phone_osint_sync,
    batch_resolve_phones_osint,
)

# ---------------------------------------------------------------------------
# Optional phonenumbers Import with Graceful Fallback
# ---------------------------------------------------------------------------
try:
    import phonenumbers
    _HAS_PHONENUMBERS = True
except ImportError:
    _HAS_PHONENUMBERS = False

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

# TRAI 140-series promotional telemarketing numbers (e.g. 140XXXXXXX)
_TRAI_140_RE = re.compile(r"^(?:\+91|91)?(140\d{7})$")

# TRAI 160-series transactional / service numbers (e.g. 160XXXXXXX)
_TRAI_160_RE = re.compile(r"^(?:\+91|91)?(160\d{7})$")

# Toll-free 1800 series
_TOLL_FREE_RE = re.compile(r"^(?:\+91|91)?(1800\d{6,7})$")


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
    ("electricity meter", "Electricity Provider"),
    ("Electricity meter", "Electricity Provider"),
    ("electricity supply will be disconnected", "Electricity Provider"),
    ("bijli", "Electricity Provider"),
    ("MSEDCL", "MSEDCL (Maharashtra Electricity)"),
    ("BESCOM", "BESCOM (Bangalore Electricity)"),
    ("TNEB", "TNEB (Tamil Nadu Electricity)"),
    ("UPPCL", "UPPCL (Uttar Pradesh Electricity)"),
    ("DISCOM", "Electricity DISCOM"),
    ("India Post", "India Post"),
    ("Speed Post", "India Post"),
    ("BlueDart", "BlueDart Express"),
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
    "UPPCLS",  # UPPCL (Uttar Pradesh Power Corporation)
    "DISCOM",  # Generic DISCOM (Electricity Distribution Companies)
    "IPPOST",  # India Post
    "BLDART",  # BlueDart Express (registered courier partner)
    "DELHIV",  # Delhivery Courier
    "NDRFIN",  # National Disaster Response Force (NDRF)
    "POLICN",  # National Police DLT (NCRB / MHA)
    "CYBERC",  # I4C National Cyber Crime Reporting Portal
    "DOTIND",  # Department of Telecommunications (Sanchar Saathi)
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


# ---------------------------------------------------------------------------
# Telecom Circle Branch Mismatch Detector (AVNI)
# ---------------------------------------------------------------------------
# Maps key Indian cities and regional locations to their canonical telecom circle
_CITY_TO_CIRCLE: Dict[str, str] = {
    # Karnataka
    "bangalore": "Karnataka", "bengaluru": "Karnataka", "mysore": "Karnataka", "mysuru": "Karnataka",
    "hubli": "Karnataka", "mangalore": "Karnataka", "mangaluru": "Karnataka", "belgaum": "Karnataka",
    # Maharashtra / Mumbai
    "mumbai": "Mumbai", "bombay": "Mumbai", "nariman point": "Mumbai", "bandra": "Mumbai",
    "andheri": "Mumbai", "thane": "Maharashtra", "pune": "Maharashtra", "nagpur": "Maharashtra",
    "nashik": "Maharashtra", "aurangabad": "Maharashtra", "navi mumbai": "Mumbai",
    # Delhi NCR
    "delhi": "Delhi", "new delhi": "Delhi", "noida": "Delhi", "gurgaon": "Delhi", "gurugram": "Delhi",
    "connaught place": "Delhi", "faridabad": "Delhi", "ghaziabad": "Delhi",
    # West Bengal / Kolkata
    "kolkata": "Kolkata", "calcutta": "Kolkata", "howrah": "West Bengal", "salt lake": "Kolkata",
    "siliguri": "West Bengal", "asansol": "West Bengal", "durgapur": "West Bengal",
    # Tamil Nadu / Chennai
    "chennai": "Tamil Nadu", "madras": "Tamil Nadu", "coimbatore": "Tamil Nadu", "madurai": "Tamil Nadu",
    "trichy": "Tamil Nadu", "tiruchirappalli": "Tamil Nadu", "salem": "Tamil Nadu",
    # Andhra Pradesh & Telangana
    "hyderabad": "Andhra Pradesh", "secunderabad": "Andhra Pradesh", "cyberabad": "Andhra Pradesh",
    "visakhapatnam": "Andhra Pradesh", "vizag": "Andhra Pradesh", "vijayawada": "Andhra Pradesh",
    "guntur": "Andhra Pradesh", "tirupati": "Andhra Pradesh",
    # Gujarat
    "ahmedabad": "Gujarat", "surat": "Gujarat", "vadodara": "Gujarat", "baroda": "Gujarat",
    "rajkot": "Gujarat", "gandhinagar": "Gujarat", "bhavnagar": "Gujarat",
    # Uttar Pradesh
    "lucknow": "Uttar Pradesh", "kanpur": "Uttar Pradesh", "varanasi": "Uttar Pradesh",
    "agra": "Uttar Pradesh", "prayagraj": "Uttar Pradesh", "allahabad": "Uttar Pradesh",
    "meerut": "Uttar Pradesh", "bareilly": "Uttar Pradesh", "aligarh": "Uttar Pradesh",
    # Bihar & Jharkhand
    "patna": "Bihar", "gaya": "Bihar", "muzaffarpur": "Bihar", "bhagalpur": "Bihar",
    "ranchi": "Bihar", "jamshedpur": "Bihar", "dhanbad": "Bihar",
    # Rajasthan
    "jaipur": "Rajasthan", "jodhpur": "Rajasthan", "udaipur": "Rajasthan", "kota": "Rajasthan",
    "bikaner": "Rajasthan", "ajmer": "Rajasthan",
    # Punjab & Haryana
    "chandigarh": "Punjab", "ludhiana": "Punjab", "amritsar": "Punjab", "jalandhar": "Punjab",
    "patiala": "Punjab", "panipat": "Haryana", "ambala": "Haryana", "karnal": "Haryana",
    # Madhya Pradesh
    "bhopal": "Madhya Pradesh", "indore": "Madhya Pradesh", "jabalpur": "Madhya Pradesh",
    "gwalior": "Madhya Pradesh", "ujjain": "Madhya Pradesh",
    # Kerala
    "kochi": "Kerala", "cochin": "Kerala", "thiruvananthapuram": "Kerala", "trivandrum": "Kerala",
    "kozhikode": "Kerala", "calicut": "Kerala", "thrissur": "Kerala", "kollam": "Kerala",
    # North East / Assam
    "guwahati": "Assam", "shillong": "North East", "imphal": "North East", "agartala": "North East",
    "aizawl": "North East", "dimapur": "North East", "kohima": "North East",
    # Odisha
    "bhubaneswar": "Odisha", "cuttack": "Odisha", "rourkela": "Odisha",
    # Jammu & Kashmir
    "srinagar": "Jammu & Kashmir", "jammu": "Jammu & Kashmir",
    # Goa
    "panaji": "Goa", "goa": "Goa", "margao": "Goa",
}

_BRANCH_CONTEXT_RE = re.compile(
    r"(?:(?:branch|branch\s*office|branch:?)\s*(?:at\s*|in\s*|of\s*|:\s*)?([A-Za-z\s]+?)(?=[.,\n\r;]|$|\b(?:call|ph|contact|ifsc|account|ac|update|kyc|manager|desk)\b))"
    r"|(?:([A-Za-z\s]+?)\s+(?:branch|banch|branch\s*office))",
    re.IGNORECASE,
)


def detect_telecom_circle_branch_mismatch(operator_prefix: str, content: str) -> Optional[Dict[str, Any]]:
    """
    Compare 2-letter operator prefix in TRAI circle prefix registry against
    regional bank branches claimed in text.
    
    If the operator prefix is circle-restricted (e.g. TA for MTNL Delhi/Mumbai,
    KL for Kerala, NE for North East) but the message body claims a branch in an
    unrelated geographic circle (e.g. Bangalore, Lucknow, Kolkata), this flags a
    critical telecom circle route contradiction.
    """
    prefix_upper = operator_prefix.upper().strip()
    entry = _CIRCLE_VALID_PREFIXES.get(prefix_upper)
    if not entry:
        return None

    allowed_circles = entry.get("circles", [])
    # Pan-India operator prefixes (Airtel AX, Vi VM, Jio JK) have All India license
    if "All India" in allowed_circles:
        return None

    # Search for regional location or branch mentions in content
    claimed_location = None
    claimed_circle = None
    content_lower = content.lower()

    # Pass 1: explicit branch context pattern
    for match in _BRANCH_CONTEXT_RE.finditer(content):
        candidate_phrase = (match.group(1) or match.group(2) or "").strip().lower()
        for city, circle in _CITY_TO_CIRCLE.items():
            if city in candidate_phrase:
                claimed_location = city
                claimed_circle = circle
                break
        if claimed_circle:
            break

    # Pass 2: check direct mentions of cities if banking/official keyword present
    if not claimed_circle:
        has_bank = any(kw.lower() in content_lower for kw, _ in _BANKING_KEYWORDS) or "branch" in content_lower
        if has_bank:
            for city, circle in _CITY_TO_CIRCLE.items():
                # Check for whole-word boundary
                if re.search(rf"\b{re.escape(city)}\b", content_lower):
                    claimed_location = city
                    claimed_circle = circle
                    break

    if not claimed_circle or not claimed_location:
        return None

    # Check circle compatibility
    def _circle_matches(allowed: List[str], target: str) -> bool:
        target_lower = target.lower()
        for c in allowed:
            c_lower = c.lower()
            if target_lower in c_lower or c_lower in target_lower:
                return True
            # Cross-handle Kolkata/West Bengal, Mumbai/Maharashtra, UP East/West
            if ("kolkata" in target_lower and "west bengal" in c_lower) or ("west bengal" in target_lower and "kolkata" in c_lower):
                return True
            if ("mumbai" in target_lower and "maharashtra" in c_lower) or ("maharashtra" in target_lower and "mumbai" in c_lower):
                return True
            if ("uttar pradesh" in target_lower and "uttar pradesh" in c_lower):
                return True
        return False

    if not _circle_matches(allowed_circles, claimed_circle):
        operator_name = entry.get("operator_name", prefix_upper)
        allowed_str = ", ".join(allowed_circles)
        details = (
            f"Telecom circle mismatch detected: Sender header uses operator prefix '{prefix_upper}' "
            f"({operator_name}), which is authorized only for [{allowed_str}], "
            f"but message claims a regional bank branch in '{claimed_location.title()}' ({claimed_circle}). "
            "Scammers frequently use mismatched regional routes or leaked telecom headers from distant circles "
            "to impersonate local bank branches."
        )
        return {
            "mismatch": True,
            "operator_prefix": prefix_upper,
            "operator_name": operator_name,
            "allowed_circles": allowed_circles,
            "claimed_location": claimed_location.title(),
            "claimed_circle": claimed_circle,
            "details": details,
        }

    return None


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


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _find_near_miss_entity_code(entity_code: str) -> Optional[Tuple[str, int]]:
    """
    Search _ALL_ENTITY_CODES for a near-miss code with Levenshtein distance 1 or 2.
    Catches spoofed headers like 'VM-SBIINM' (1 edit from 'VM-SBIINB') or
    'AX-HDFCBX' (1 edit from 'AX-HDFCBK').
    Returns (closest_registered_code, distance) if found, else None.
    """
    best_match: Optional[str] = None
    min_dist = 99
    for registered_code in _ALL_ENTITY_CODES:
        dist = _levenshtein_distance(entity_code, registered_code)
        if 0 < dist <= 2 and dist < min_dist:
            min_dist = dist
            best_match = registered_code
    if best_match:
        return best_match, min_dist
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
# Indian phone number: optional +91/91 country prefix with optional space/dash,
# then exactly 10 digits starting with 6–9.  The PRD FR-2 canonical pattern is:
#   (?:\+?91[\s\-]?)?([6-9]\d{9})\b
# We allow an optional trailing word-boundary to prevent partial matches.
_ENTITY_PHONE_RE = re.compile(
    r"(?:\+?91[\s\-]?)?([6-9]\d{9})\b"
)

# TRAI DLT header: exactly 2 uppercase letters, a hyphen, 6 uppercase letters.
# PRD FR-2 canonical pattern: \b([A-Z]{2})-([A-Z]{6})\b
_ENTITY_TRAI_HEADER_RE = re.compile(r"\b([A-Z]{2}-[A-Z]{6})\b")

# Currency amounts: Rs / INR / ₹ followed by optional space, then a number
# (supports commas, decimals, e.g. Rs 1,499 / INR 20000 / ₹2.50).
# PRD FR-2 canonical pattern: (?:Rs\.?\s*|INR\s*|₹\s*)([\d,]+(?:\.\d{1,2})?)
_ENTITY_CURRENCY_RE = re.compile(
    r"(?:Rs\.?\s*|INR\s*|\u20b9\s*)([\d,]+(?:\.\d{1,2})?)",
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
        sender_phone_candidates = _extract_all_phone_candidates(raw_sender)
        if len(sender_phone_candidates) > 1:
            return await analyze_sender_multi(req)
        normalised = _sanitise_sender(raw_sender)
    else:
        # Check if multiple phone numbers exist in the message body
        candidates = _extract_all_phone_candidates(req.content)
        if len(candidates) > 1:
            return await analyze_sender_multi(req)
        elif len(candidates) == 1:
            raw_sender = candidates[0]
            normalised = candidates[0]
        else:
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

    # ── Email / Message Analysis Check ──
    is_email_input = bool(
        (req.channel and req.channel.value == "email")
        or (raw_sender and "@" in raw_sender)
        or (req.metadata and ("headers" in req.metadata or "email_headers" in req.metadata))
        or re.search(r"^(?:from|subject|reply-to):", req.content, re.IGNORECASE | re.MULTILINE)
    )
    if is_email_input:
        email_res = analyze_email(req)
        if email_res.get("is_email"):
            category = (
                SenderCategoryEnum.LOOKALIKE_HEADER
                if email_res.get("display_name_spoofed") or email_res.get("has_reply_to_mismatch")
                else (SenderCategoryEnum.OFFICIAL_TRAI_HEADER if email_res.get("risk_score", 0) <= 20 else SenderCategoryEnum.UNKNOWN)
            )
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=category,
                risk_score=_clamp_score(email_res["risk_score"]),
                is_spoofed_header=bool(email_res.get("display_name_spoofed") or email_res.get("has_reply_to_mismatch")),
                flags=email_res.get("flags", []),
                details=email_res.get("details", ""),
                latency_ms=round(latency_ms, 3),
                raw_sender=raw_sender or email_res.get("from_header"),
                normalised_sender=email_res.get("from_domain"),
                email_analysis=email_res,
                provider="EMAIL_ANALYZER_ENGINE",
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

        # ── Telecom Circle Branch Mismatch Detector (AVNI) ──────────────
        circle_mismatch = detect_telecom_circle_branch_mismatch(operator_prefix, req.content)
        if circle_mismatch:
            flags.append("TELECOM_CIRCLE_BRANCH_MISMATCH")
            flags.append("REGIONAL_BRANCH_OPERATOR_CONTRADICTION")
            flags.append("UNVERIFIED_LOOKALIKE_HEADER")
            entry = _REGISTRY.get(entity_code)
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.LOOKALIKE_HEADER,
                risk_score=_clamp_score(88.0),
                is_spoofed_header=True,
                brand_claimed=entry.get("brand_name") if entry else circle_mismatch.get("claimed_location"),
                flags=flags,
                details=circle_mismatch["details"],
                latency_ms=round(latency_ms, 3),
                raw_sender=raw_sender,
                normalised_sender=normalised,
                provider="TRAI_DLT_REGISTRY",
            )

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

        # ── Operator / Circle Mismatch: entity is registered, but NOT with this operator prefix ──
        if entry and not pair_valid:
            flags.append("TRAI_OPERATOR_ENTITY_PREFIX_MISMATCH")
            flags.append("UNAUTHORIZED_OPERATOR_FOR_ENTITY")
            flags.append("UNVERIFIED_LOOKALIKE_HEADER")
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.LOOKALIKE_HEADER,
                risk_score=_clamp_score(78.0),
                is_spoofed_header=True,
                brand_claimed=entry.get("brand_name"),
                flags=flags,
                details=(
                    f"The sender ID '{normalised}' claims to represent '{entry['brand_name']}', "
                    f"but operator prefix '{operator_prefix}' is NOT authorized for entity code '{entity_code}'. "
                    f"Authorized prefixes for '{entry['brand_name']}' are: {', '.join(entry.get('operator_prefixes', []))}. "
                    "This indicates an operator route mismatch or spoofing attempt."
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

        # ── Dynamic Levenshtein Near-Miss Header Spoofing (e.g. VM-SBIINM mimicking VM-SBIINB) ──
        near_miss = _find_near_miss_entity_code(entity_code)
        if near_miss:
            near_code, dist = near_miss
            near_entry = _REGISTRY[near_code]
            flags.append("CRITICAL_NEAR_MISS_HEADER_SPOOF")
            flags.append("UNVERIFIED_LOOKALIKE_HEADER")
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.LOOKALIKE_HEADER,
                risk_score=_clamp_score(88.0),
                is_spoofed_header=True,
                brand_claimed=near_entry.get("brand_name"),
                flags=flags,
                details=(
                    f"The sender ID '{normalised}' differs by only {dist} letter(s) from "
                    f"the official '{near_entry['brand_name']}' header ({near_code}). "
                    "Scammers register near-miss alphabetic headers to deceive recipients "
                    "into trusting a spoofed sender."
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
    # Step 3: Phone Number Classification (TRAI 140, 160, GSM, Toll-Free)
    # ------------------------------------------------------------------
    # ── Check TRAI 140-series promotional telemarketing ──
    m140 = _TRAI_140_RE.match(normalised)
    if m140:
        clean_num = m140.group(1)
        phone_type = "PROMOTIONAL_140"
        brand = _detect_official_keyword(req.content)
        is_scam_pattern = bool(
            brand or re.search(r"\b(kyc|blocked|suspended|otp|urgent|verify|electricity|bill|pan|aadhaar|debit|credit|account)\b", req.content, re.I)
        )
        if is_scam_pattern:
            flags.append("PROMOTIONAL_140_FINANCIAL_SCAM")
            flags.append("TRAI_140_REGULATORY_VIOLATION")
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.PERSONAL_GSM,
                risk_score=_clamp_score(90.0),
                phone_type=phone_type,
                brand_claimed=brand,
                flags=flags,
                details=(
                    f"Sender '{clean_num}' is a TRAI 140-series promotional telemarketing number. "
                    "Under TRAI regulations, 140-series numbers are strictly prohibited from transmitting "
                    "banking, KYC, account suspension, or financial transaction requests. "
                    "This message is a confirmed regulatory violation and high-probability scam."
                ),
                latency_ms=round(latency_ms, 3),
                raw_sender=raw_sender,
                normalised_sender=clean_num,
            )
        else:
            flags.append("PROMOTIONAL_140_SERIES")
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.PERSONAL_GSM,
                risk_score=_clamp_score(35.0),
                phone_type=phone_type,
                flags=flags,
                details=f"Sender '{clean_num}' is a TRAI 140-series commercial marketing number.",
                latency_ms=round(latency_ms, 3),
                raw_sender=raw_sender,
                normalised_sender=clean_num,
            )

    # ── Check TRAI 160-series transactional / service ──
    m160 = _TRAI_160_RE.match(normalised)
    if m160:
        clean_num = m160.group(1)
        phone_type = "SERVICE_160"
        flags.append("TRAI_160_SERVICE_SERIES")
        flags.append("VERIFIED_TRANSACTIONAL_SENDER")
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        return SenderAgentResult(
            status=AgentStatusEnum.SUCCESS,
            sender_category=SenderCategoryEnum.OFFICIAL_TRAI_HEADER,
            risk_score=_clamp_score(10.0),
            phone_type=phone_type,
            flags=flags,
            details=(
                f"Sender '{clean_num}' originates from TRAI's official 160-series, "
                "which is mandated for legitimate transactional and service communication."
            ),
            latency_ms=round(latency_ms, 3),
            raw_sender=raw_sender,
            normalised_sender=clean_num,
        )

    # ── Check Toll-free 1800 ──
    m_tf = _TOLL_FREE_RE.match(normalised)
    if m_tf:
        clean_num = m_tf.group(1)
        phone_type = "TOLL_FREE"
        flags.append("TOLL_FREE_SERIES")
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        return SenderAgentResult(
            status=AgentStatusEnum.SUCCESS,
            sender_category=SenderCategoryEnum.OFFICIAL_TRAI_HEADER,
            risk_score=_clamp_score(15.0),
            phone_type=phone_type,
            flags=flags,
            details=f"Sender '{clean_num}' is a verified toll-free helpline number.",
            latency_ms=round(latency_ms, 3),
            raw_sender=raw_sender,
            normalised_sender=clean_num,
        )

    # ── Check Standard Indian GSM Mobile ──
    if _INDIAN_GSM_RE.match(normalised):
        phone_type = "MOBILE"
        # Validate format using phonenumbers if present
        if _HAS_PHONENUMBERS:
            try:
                p_parsed = phonenumbers.parse(normalised, "IN")
                if not phonenumbers.is_valid_number(p_parsed):
                    flags.append("INVALID_PHONE_NUMBER_FORMAT")
            except Exception:
                pass

        brand = _detect_official_keyword(req.content)
        # Query Truecaller / OSINT registry
        osint = resolve_phone_osint_sync(normalised, claimed_brand=brand)
        has_osint_spam = osint.get("spam_score", 0.0) >= 60.0 or osint.get("spam_reports", 0) >= 10
        if has_osint_spam:
            flags.append("TRUECALLER_SCAM_REPORTED")
            flags.append("OSINT_HIGH_SPAM_SCORE")
            if osint.get("entity_mismatch"):
                flags.append("OSINT_CALLER_NAME_ENTITY_MISMATCH")
            if "CHAKSHU_REPORTED" in osint.get("badges", []):
                flags.append("CHAKSHU_SUSPECTED_FRAUD")

        if brand:
            flags.append("COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM")
            flags.append("MISSING_TRAI_OFFICIAL_HEADER")
            # Mask the phone number for citizen-friendly display: show prefix + XXX
            masked_number = (
                "+91-" + normalised[:5] + "XXXXX"
                if len(normalised) == 10
                else normalised
            )
            base_score = 85.0
            if has_osint_spam:
                base_score = max(base_score, float(osint["spam_score"]))
            osint_note = ""
            if has_osint_spam:
                osint_note = (
                    f" Truecaller/OSINT intelligence flags this number as '{osint['caller_name']}' "
                    f"with {osint['spam_reports']} community reports (Category: {osint['spam_category']}, "
                    f"Carrier: {osint['carrier']}, Circle: {osint['circle']})."
                )
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return SenderAgentResult(
                status=AgentStatusEnum.SUCCESS,
                sender_category=SenderCategoryEnum.PERSONAL_GSM,
                risk_score=_clamp_score(base_score),
                phone_type=phone_type,
                brand_claimed=brand,
                is_spoofed_header=False,
                flags=flags,
                details=(
                    f"Sender is a personal 10-digit mobile number ({masked_number}) "
                    f"claiming to represent '{brand}'. "
                    "In India, all banks and government agencies are required by TRAI "
                    "to send messages using a registered alphabetic sender ID (e.g. VM-SBIINB), "
                    "never from a personal mobile phone number. "
                    "Receiving such a message from a private number is a strong warning sign of fraud — "
                    "do not click any links or call back the number."
                    + osint_note
                ),
                latency_ms=round(latency_ms, 3),
                raw_sender=raw_sender,
                normalised_sender=normalised,
                provider="TRUECALLER_OSINT_REGISTRY" if has_osint_spam else "TRAI_DLT_REGISTRY",
            )

        # Plain personal GSM number with no suspicious content.
        base_score = 40.0
        osint_note = ""
        if has_osint_spam:
            base_score = max(base_score, float(osint["spam_score"]))
            osint_note = (
                f" Truecaller/OSINT intelligence flags this number as '{osint['caller_name']}' "
                f"with {osint['spam_reports']} community spam reports (Category: {osint['spam_category']}, "
                f"Carrier: {osint['carrier']}, Circle: {osint['circle']})."
            )
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        return SenderAgentResult(
            status=AgentStatusEnum.SUCCESS,
            sender_category=SenderCategoryEnum.PERSONAL_GSM,
            risk_score=_clamp_score(base_score),
            phone_type=phone_type,
            flags=flags,
            details=(
                f"Sender is a personal Indian mobile number ({normalised}). "
                "No claims of being a bank or government agency were found in this message, "
                "but be cautious — legitimate businesses do not usually contact you from "
                "personal phone numbers."
                + osint_note
            ),
            latency_ms=round(latency_ms, 3),
            raw_sender=raw_sender,
            normalised_sender=normalised,
            provider="TRUECALLER_OSINT_REGISTRY" if has_osint_spam else "TRAI_DLT_REGISTRY",
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


# ---------------------------------------------------------------------------
# Multi-Phone Parallel Analysis (AVNI — Sprint 2)
# ---------------------------------------------------------------------------

# Maximum concurrent phone sub-analyses to avoid runaway fan-out.
_MAX_PARALLEL_PHONES: int = 8

# Regex for extracting ALL Indian phone-like tokens from free-form text.
# Matches standalone 10-digit GSM, 140 promotional, 160 service, and 1800 toll-free,
# with optional country-code prefix (+91 / 91) and common separators (space, dash, dot).
_ALL_PHONES_RE = re.compile(
    r"(?<!\d)(?:\+91[\s\-\.]?|91[\s\-\.]?)?((?:[6-9]\d{2}[\s\-\.]?\d{3}[\s\-\.]?\d{4})|(?:140\d{7})|(?:160\d{7})|(?:1800[\s\-\.]?\d{3}[\s\-\.]?\d{3,4}))(?!\d)",
    re.ASCII,
)


def _is_valid_phone_candidate(phone: str) -> bool:
    """Check if candidate is a valid Indian GSM, 140 promo, 160 service, or 1800 toll-free."""
    return bool(
        _INDIAN_GSM_RE.match(phone)
        or _TRAI_140_RE.match(phone)
        or _TRAI_160_RE.match(phone)
        or _TOLL_FREE_RE.match(phone)
    )


def _extract_all_phone_candidates(text: str) -> List[str]:
    """
    Extract every distinct Indian phone number candidate from *text*.

    - Strips country-code prefix (+91 / 91).
    - Removes internal separators (space, dash, dot).
    - Deduplicates while preserving order of first occurrence.
    - Validates candidate against GSM, 140, 160, and 1800 patterns.

    Returns up to ``_MAX_PARALLEL_PHONES`` unique numbers.
    """
    seen: set = set()
    results: List[str] = []
    for match in _ALL_PHONES_RE.finditer(text):
        raw = match.group(1).replace(" ", "").replace("-", "").replace(".", "")
        cleaned = _strip_country_code(raw)
        if _is_valid_phone_candidate(cleaned) and cleaned not in seen:
            seen.add(cleaned)
            results.append(cleaned)
            if len(results) >= _MAX_PARALLEL_PHONES:
                break
    return results


async def _analyse_phone_candidate(
    base_req: ScanRequest,
    phone: str,
    t_start: float,
) -> Dict[str, Any]:
    """
    Run ``analyze_sender`` and Truecaller/OSINT resolution concurrently for a single
    phone candidate derived from the message body. Returns a serialisable summary dict, never raises.
    """
    synthetic_req = ScanRequest(
        content=base_req.content,
        sender=phone,
        channel=base_req.channel,
        metadata=base_req.metadata or {},
    )
    try:
        sender_task = analyze_sender(synthetic_req)
        osint_task = resolve_phone_osint(phone, claimed_brand=_detect_official_keyword(base_req.content))
        result, osint = await asyncio.gather(sender_task, osint_task)

        c_flags = list(result.flags)
        c_risk = result.risk_score
        c_details = result.details

        if osint.get("spam_score", 0.0) >= 60.0 or osint.get("spam_reports", 0) >= 10:
            if "TRUECALLER_SCAM_REPORTED" not in c_flags:
                c_flags.append("TRUECALLER_SCAM_REPORTED")
            if "OSINT_HIGH_SPAM_SCORE" not in c_flags:
                c_flags.append("OSINT_HIGH_SPAM_SCORE")
            if osint.get("entity_mismatch") and "OSINT_CALLER_NAME_ENTITY_MISMATCH" not in c_flags:
                c_flags.append("OSINT_CALLER_NAME_ENTITY_MISMATCH")
            if "CHAKSHU_REPORTED" in osint.get("badges", []) and "CHAKSHU_SUSPECTED_FRAUD" not in c_flags:
                c_flags.append("CHAKSHU_SUSPECTED_FRAUD")
            c_risk = max(c_risk, float(osint["spam_score"]), 88.0)
            osint_summary = (
                f"[Truecaller/OSINT: '{osint['caller_name']}', {osint['spam_reports']} reports, "
                f"category: {osint['spam_category']}, circle: {osint['circle']}, carrier: {osint['carrier']}] "
            )
            if osint_summary not in c_details:
                c_details = osint_summary + c_details

        return {
            "phone": phone,
            "risk_score": c_risk,
            "sender_category": result.sender_category.value,
            "flags": c_flags,
            "details": c_details,
            "phone_type": result.phone_type,
            "brand_claimed": result.brand_claimed,
            "is_spoofed_header": result.is_spoofed_header,
            "latency_ms": result.latency_ms,
            "osint": osint,
        }
    except Exception as exc:  # noqa: BLE001 — fail-safe
        return {
            "phone": phone,
            "risk_score": 0.0,
            "sender_category": SenderCategoryEnum.UNKNOWN.value,
            "flags": ["ANALYSIS_ERROR"],
            "details": str(exc),
            "phone_type": None,
            "brand_claimed": None,
            "is_spoofed_header": False,
            "latency_ms": round((time.perf_counter() - t_start) * 1000.0, 3),
            "osint": None,
        }


async def analyze_sender_multi(req: ScanRequest) -> SenderAgentResult:
    """
    Multi-phone parallel sender analysis via Truecaller & OSINT registry (AVNI).

    Behaviour
    ---------
    1. If ``req.sender`` is already provided *and* is a single phone / header,
       fall through to the standard ``analyze_sender`` path.
    2. Otherwise, extract ALL distinct Indian phone numbers found in the
       message body and dispatch them **concurrently** via ``asyncio.gather``
       through the Truecaller / OSINT phone reputation registry.
    3. The sub-result with the **highest risk_score** is returned as the
       primary ``SenderAgentResult``.
    4. All sub-results and OSINT records (for UI accordion / evidence panels)
       are embedded in ``email_analysis["multi_phone_results"]`` and
       ``email_analysis["osint_registry_matches"]``.

    Parameters
    ----------
    req : ScanRequest

    Returns
    -------
    SenderAgentResult
        Primary result (highest-risk phone). Never raises.
    """
    t_start = time.perf_counter()

    # ── Fast path / multi-sender extraction ──────────────────────────────
    if req.sender:
        sender_candidates = _extract_all_phone_candidates(req.sender)
        if len(sender_candidates) > 1:
            candidates = sender_candidates
        else:
            return await analyze_sender(req)
    else:
        # ── Extract all phone candidates from body ───────────────────────────
        candidates = _extract_all_phone_candidates(req.content)

    if not candidates:
        # No phone numbers found at all — delegate to normal path
        return await analyze_sender(req)

    if len(candidates) == 1:
        # Only one number; no need for fan-out overhead
        single_req = ScanRequest(
            content=req.content,
            sender=candidates[0],
            channel=req.channel,
            metadata=req.metadata or {},
        )
        return await analyze_sender(single_req)

    # ── Parallel analysis of all candidates ─────────────────────────────
    tasks = [_analyse_phone_candidate(req, phone, t_start) for phone in candidates]
    sub_results: List[Dict[str, Any]] = list(await asyncio.gather(*tasks, return_exceptions=False))

    # ── Pick the highest-risk result as primary ──────────────────────────
    best = max(sub_results, key=lambda r: r.get("risk_score", 0.0))
    total_latency_ms = round((time.perf_counter() - t_start) * 1000.0, 3)

    # Build a SenderAgentResult from the best sub-result.
    primary_result = SenderAgentResult(
        status=AgentStatusEnum.SUCCESS,
        sender_category=SenderCategoryEnum(best["sender_category"]),
        risk_score=float(best["risk_score"]),
        flags=best["flags"],
        details=(
            f"[Multi-phone scan — {len(candidates)} numbers resolved via Truecaller/OSINT] "
            + best["details"]
        ),
        phone_type=best.get("phone_type"),
        brand_claimed=best.get("brand_claimed"),
        is_spoofed_header=bool(best.get("is_spoofed_header")),
        raw_sender=best["phone"],
        normalised_sender=best["phone"],
        latency_ms=total_latency_ms,
        provider="TRUECALLER_OSINT_REGISTRY",
        # Embed all sub-results for UI panels (reuses email_analysis slot)
        email_analysis={
            "multi_phone_results": sub_results,
            "phone_count": len(candidates),
            "highest_risk_phone": best["phone"],
            "osint_registry_matches": [r.get("osint") for r in sub_results if r.get("osint")],
        },
    )

    return primary_result
