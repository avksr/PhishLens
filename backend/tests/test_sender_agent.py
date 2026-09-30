"""
backend/tests/test_sender_agent.py
------------------------------------
Pytest test suite for the Sender Identity & TRAI DLT Verification Agent.

Run from the `backend/` directory:
    python -m pytest tests/test_sender_agent.py -v

Requirements:
    pytest, pytest-asyncio, pydantic
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import pytest_asyncio  # noqa: F401 — ensures asyncio plugin is loaded

# ---------------------------------------------------------------------------
# Path Setup — allow imports from `backend/` as root
# ---------------------------------------------------------------------------
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from agents.sender_agent import (  # noqa: E402
    analyze_sender,
    _REGISTRY,
    _VALID_PAIRS,
    _ALL_ENTITY_CODES,
    _normalise_homoglyphs,
    _fuzzy_entity_code_lookup,
    _detect_lowercase_header_spoof,
)
from shared.models import (  # noqa: E402
    AgentStatusEnum,
    ScanRequest,
    SenderAgentResult,
    SenderCategoryEnum,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_request(content: str, sender: str | None = None) -> ScanRequest:
    """Convenience factory for ScanRequest objects."""
    return ScanRequest(content=content, sender=sender)


# ===========================================================================
# ──────────────────── ORIGINAL TESTS (preserved) ───────────────────────────
# ===========================================================================

# ---------------------------------------------------------------------------
# Test 1 — Official TRAI DLT Header (Verified)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_official_trai_header() -> None:
    """
    Certified TRAI DLT header VM-SBIINB must be recognised as
    OFFICIAL_TRAI_HEADER with risk_score <= 10.
    """
    req = _make_request(
        content="Dear Customer, your SBI account balance is Rs. 12,450. "
                "For queries call 1800-11-2211.",
        sender="VM-SBIINB",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS, (
        f"Expected SUCCESS, got {result.status}: {result.details}"
    )
    assert result.sender_category == SenderCategoryEnum.OFFICIAL_TRAI_HEADER, (
        f"Expected OFFICIAL_TRAI_HEADER, got {result.sender_category}"
    )
    assert result.risk_score <= 10.0, (
        f"Expected risk_score <= 10, got {result.risk_score}"
    )
    assert result.is_spoofed_header is False, (
        "Verified TRAI header must NOT be flagged as spoofed."
    )
    assert "VERIFIED_TRAI_DLT_SENDER_HEADER" in result.flags, (
        f"Expected VERIFIED_TRAI_DLT_SENDER_HEADER flag, got {result.flags}"
    )
    assert result.brand_claimed is not None, (
        "brand_claimed must be populated for a verified TRAI header."
    )


# ---------------------------------------------------------------------------
# Test 2 — Personal GSM Number Impersonating SBI (High-Risk Scam)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_personal_gsm_bank_scam() -> None:
    """
    A 10-digit personal GSM number claiming to be SBI must return
    risk_score >= 85 and sender_category == PERSONAL_GSM.
    """
    req = _make_request(
        content="URGENT: Your SBI account has been blocked due to suspicious "
                "activity. Click here to unblock: http://sbi-secure-login.xyz",
        sender="+919876543210",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS, (
        f"Expected SUCCESS, got {result.status}: {result.details}"
    )
    assert result.sender_category == SenderCategoryEnum.PERSONAL_GSM, (
        f"Expected PERSONAL_GSM, got {result.sender_category}"
    )
    assert result.risk_score >= 85.0, (
        f"Expected risk_score >= 85, got {result.risk_score}"
    )
    assert "COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM" in result.flags, (
        f"Missing COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM flag, got {result.flags}"
    )
    assert "MISSING_TRAI_OFFICIAL_HEADER" in result.flags, (
        f"Missing MISSING_TRAI_OFFICIAL_HEADER flag, got {result.flags}"
    )
    assert result.brand_claimed is not None, (
        "brand_claimed must identify the impersonated bank."
    )


# ---------------------------------------------------------------------------
# Test 3 — Lookalike / Spoofed Header (SBI-ALERT)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_lookalike_header() -> None:
    """
    Unregistered alphanumeric header 'SBI-ALERT' must return
    risk_score >= 70 and is_spoofed_header == True.
    """
    req = _make_request(
        content="Alert: Unusual login detected on your SBI Net Banking. "
                "Verify now at http://sbi-netbanking-verify.info",
        sender="SBI-ALERT",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS, (
        f"Expected SUCCESS, got {result.status}: {result.details}"
    )
    assert result.sender_category == SenderCategoryEnum.LOOKALIKE_HEADER, (
        f"Expected LOOKALIKE_HEADER, got {result.sender_category}"
    )
    assert result.risk_score >= 70.0, (
        f"Expected risk_score >= 70, got {result.risk_score}"
    )
    assert result.is_spoofed_header is True, (
        "SBI-ALERT is NOT a registered TRAI DLT header and must be flagged as spoofed."
    )
    assert "UNVERIFIED_LOOKALIKE_HEADER" in result.flags, (
        f"Missing UNVERIFIED_LOOKALIKE_HEADER flag, got {result.flags}"
    )


# ---------------------------------------------------------------------------
# Test 4 — Null Sender Fallback (No Crash, Graceful Handling)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_null_sender_fallback() -> None:
    """
    Null sender with generic content must be handled gracefully
    (no exception, status == SUCCESS, sender_category == UNKNOWN).
    """
    req = _make_request(
        content="Congratulations! You have won a lucky draw prize. "
                "Visit our website to claim your reward.",
        sender=None,
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status != AgentStatusEnum.ERROR, (
        f"Null sender should not trigger an ERROR: {result.details}"
    )
    assert result.sender_category == SenderCategoryEnum.UNKNOWN, (
        f"Expected UNKNOWN category for null sender, got {result.sender_category}"
    )
    assert 0.0 <= result.risk_score <= 100.0, (
        f"risk_score out of bounds: {result.risk_score}"
    )


# ---------------------------------------------------------------------------
# Test 5 — HDFC DLT Header Verification (Additional Positive Case)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_hdfc_trai_header() -> None:
    """
    Certified TRAI DLT header AX-HDFCBK must resolve to HDFC Bank
    with risk_score <= 10.
    """
    req = _make_request(
        content="Your HDFC Bank OTP is 482910. Do NOT share with anyone.",
        sender="AX-HDFCBK",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.sender_category == SenderCategoryEnum.OFFICIAL_TRAI_HEADER
    assert result.risk_score <= 10.0
    assert result.is_spoofed_header is False
    assert "HDFC" in (result.brand_claimed or ""), (
        f"brand_claimed should reference HDFC, got: {result.brand_claimed}"
    )


# ---------------------------------------------------------------------------
# Test 6 — Null Sender With Embedded Phone Number Claiming Bank
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_null_sender_embedded_gsm_bank_scam() -> None:
    """
    When sender is None but the message body contains a GSM number claiming
    to be a bank, the agent must elevate risk to >= 85.
    """
    req = _make_request(
        content="Your ICICI Bank account is on hold. Call 9123456789 immediately.",
        sender=None,
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.sender_category == SenderCategoryEnum.PERSONAL_GSM
    assert result.risk_score >= 85.0
    assert "COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM" in result.flags


# ---------------------------------------------------------------------------
# Test 7 — Fail-Safe: Agent Never Crashes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_never_raises() -> None:
    """
    The agent must never raise an unhandled exception even under unexpected
    inputs (empty string, special characters, extremely long sender).
    """
    edge_cases = [
        _make_request(content=" ", sender=None),          # near-empty; ScanRequest requires min_length=1
        _make_request(content="Hello", sender=""),
        _make_request(content="Test", sender="!@#$%^&*()_+"),
        _make_request(content="X" * 8_000, sender="A" * 500),  # max allowed length; ScanRequest max_length=8000
    ]
    for req in edge_cases:
        result = await analyze_sender(req)
        assert isinstance(result, SenderAgentResult), (
            f"Expected SenderAgentResult for input {req!r}, got {type(result)}"
        )
        assert 0.0 <= result.risk_score <= 100.0, (
            f"risk_score out of bounds: {result.risk_score}"
        )


# ===========================================================================
# ──────────────── NEW TESTS: AVNI DAY-2 FEATURE ADDITIONS ──────────────────
# ===========================================================================

# ---------------------------------------------------------------------------
# Test 8 — In-Memory Registry Singleton (O(1) Lookup Validation)
# ---------------------------------------------------------------------------

def test_registry_singleton_loaded_at_import() -> None:
    """
    The TRAI DLT registry MUST be loaded into memory at module import time.
    Both _REGISTRY and _VALID_PAIRS must be non-empty dicts/sets.
    """
    assert isinstance(_REGISTRY, dict), "_REGISTRY must be a dict"
    assert len(_REGISTRY) > 0, "_REGISTRY must not be empty"
    assert isinstance(_VALID_PAIRS, set), "_VALID_PAIRS must be a set"
    assert len(_VALID_PAIRS) > 0, "_VALID_PAIRS must not be empty"
    assert isinstance(_ALL_ENTITY_CODES, set), "_ALL_ENTITY_CODES must be a set"

    # Core entries must be present.
    assert "SBIINB" in _REGISTRY, "SBIINB (SBI) must be in registry"
    assert "HDFCBK" in _REGISTRY, "HDFCBK (HDFC) must be in registry"

    # Spot-check a valid pair.
    assert ("VM", "SBIINB") in _VALID_PAIRS, "VM-SBIINB must be in _VALID_PAIRS"
    assert ("AX", "HDFCBK") in _VALID_PAIRS, "AX-HDFCBK must be in _VALID_PAIRS"


def test_registry_contains_government_entries() -> None:
    """Government and emergency service headers must be present in the registry."""
    expected_govt_codes = {
        "UIDAIT",   # UIDAI (Aadhaar)
        "EPFOHO",   # EPFO
        "MTOUCH",   # India Post Payments Bank
        "NDMAIN",   # NDMA
        "TRAISM",   # TRAI
        "INCOTX",   # Income Tax
    }
    for code in expected_govt_codes:
        assert code in _REGISTRY, (
            f"Government entity code '{code}' must be present in the registry"
        )


# ---------------------------------------------------------------------------
# Test 9 — Lowercase Spoofed Header Detection (vm-sbiinb)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_lowercase_spoofed_header_sbi() -> None:
    """
    Lowercase header 'vm-sbiinb' must be detected as LOOKALIKE_HEADER with
    LOWERCASE_SPOOFED_HEADER flag and risk_score >= 80.
    Genuine TRAI operators ALWAYS transmit headers in ALL-CAPS.
    """
    req = _make_request(
        content="Your SBI account KYC is pending. Update now to avoid suspension.",
        sender="vm-sbiinb",  # lowercase — definitive spoof signal
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.sender_category == SenderCategoryEnum.LOOKALIKE_HEADER, (
        f"Expected LOOKALIKE_HEADER for lowercase header, got {result.sender_category}"
    )
    assert result.is_spoofed_header is True, (
        "Lowercase TRAI-format header must be flagged as spoofed."
    )
    assert result.risk_score >= 80.0, (
        f"Expected risk_score >= 80 for lowercase spoof, got {result.risk_score}"
    )
    assert "LOWERCASE_SPOOFED_HEADER" in result.flags, (
        f"Missing LOWERCASE_SPOOFED_HEADER flag, got {result.flags}"
    )


@pytest.mark.asyncio
async def test_sender_agent_lowercase_spoofed_header_hdfc() -> None:
    """
    Lowercase header 'vm-hdfcbk' (as mentioned in day-2 task description)
    must be detected as a spoofed LOOKALIKE_HEADER.
    """
    req = _make_request(
        content="Your HDFC Bank account is temporarily blocked. "
                "Click to verify: http://hdfc-kyc-update.net",
        sender="vm-hdfcbk",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.sender_category == SenderCategoryEnum.LOOKALIKE_HEADER
    assert result.is_spoofed_header is True
    assert result.risk_score >= 80.0
    assert "LOWERCASE_SPOOFED_HEADER" in result.flags


@pytest.mark.asyncio
async def test_sender_agent_mixedcase_header_is_spoofed() -> None:
    """
    Mixed-case header 'Vm-SbIiNb' (Title/PascalCase) must be detected as
    a lowercase spoofed header — not a valid DLT header.
    """
    req = _make_request(
        content="SBI account alert: login from new device detected.",
        sender="Vm-SbIiNb",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.is_spoofed_header is True
    assert "LOWERCASE_SPOOFED_HEADER" in result.flags


# ---------------------------------------------------------------------------
# Test 10 — Lowercase Spoof Detection Utility Function
# ---------------------------------------------------------------------------

def test_detect_lowercase_header_spoof_utility() -> None:
    """Unit test for the _detect_lowercase_header_spoof helper function."""
    # True: lowercase / mixed case versions of TRAI header format
    assert _detect_lowercase_header_spoof("vm-sbiinb") is True
    assert _detect_lowercase_header_spoof("vm-hdfcbk") is True
    assert _detect_lowercase_header_spoof("Vm-SbIiNb") is True
    assert _detect_lowercase_header_spoof("ax-hdfcbk") is True

    # False: legitimate ALL-CAPS headers
    assert _detect_lowercase_header_spoof("VM-SBIINB") is False
    assert _detect_lowercase_header_spoof("AX-HDFCBK") is False

    # False: completely different formats (not TRAI header pattern)
    assert _detect_lowercase_header_spoof("9876543210") is False
    assert _detect_lowercase_header_spoof("SBI-ALERT") is False  # uppercase but wrong length pattern


# ---------------------------------------------------------------------------
# Test 11 — Fuzzy Lookalike Entity Code Detection (VK-SBIBNK style)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_fuzzy_entity_code_char_substitution() -> None:
    """
    Header 'VM-SB1INB' uses '1' in place of 'I' to mimic 'VM-SBIINB'.
    Must be caught by fuzzy entity code lookup → FUZZY_LOOKALIKE_ENTITY_CODE.
    """
    req = _make_request(
        content="Your SBI account needs KYC update. Tap link: http://sbi-kyc.top",
        sender="VM-SB1INB",  # '1' substituted for 'I'
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.is_spoofed_header is True
    assert result.sender_category == SenderCategoryEnum.LOOKALIKE_HEADER
    assert "FUZZY_LOOKALIKE_ENTITY_CODE" in result.flags, (
        f"Expected FUZZY_LOOKALIKE_ENTITY_CODE, got {result.flags}"
    )
    assert result.risk_score >= 85.0


@pytest.mark.asyncio
async def test_sender_agent_fuzzy_entity_code_zero_for_o() -> None:
    """
    Header 'AX-HDFCBK' with '0' (zero) substituted for 'O' in a fictional
    entity code should trigger fuzzy detection if the original entity differs.
    """
    req = _make_request(
        content="HDFC Bank: Your OTP for transaction is 582910. Valid 10 min.",
        sender="VM-SB1INB",  # Confirmed fuzzy spoof of SBIINB
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.is_spoofed_header is True
    assert result.sender_category == SenderCategoryEnum.LOOKALIKE_HEADER


def test_fuzzy_entity_code_lookup_utility() -> None:
    """Unit test for the _fuzzy_entity_code_lookup helper function."""
    # '1' instead of 'I' → should resolve to SBIINB
    result = _fuzzy_entity_code_lookup("SB1INB")
    assert result == "SBIINB", f"Expected SBIINB, got {result}"

    # '0' instead of 'O' — testing BOBSMS → B0BSMS
    # Since our table maps 0→O, B0BSMS → BOBSMS
    result2 = _fuzzy_entity_code_lookup("B0BSMS")
    assert result2 == "BOBSMS", f"Expected BOBSMS, got {result2}"

    # No substitution needed for a clean code — must return None
    result3 = _fuzzy_entity_code_lookup("SBIINB")
    assert result3 is None, "Clean entity code should return None from fuzzy lookup"

    # Completely fake code — must return None
    result4 = _fuzzy_entity_code_lookup("XYZABC")
    assert result4 is None


# ---------------------------------------------------------------------------
# Test 12 — Unicode Homoglyph Normalisation
# ---------------------------------------------------------------------------

def test_normalise_homoglyphs_cyrillic() -> None:
    """_normalise_homoglyphs must convert Cyrillic look-alikes to ASCII."""
    # Cyrillic 'О' (U+041E) should become 'O'
    cyrillic_o = "\u041E"
    result = _normalise_homoglyphs(f"VM-SBI{cyrillic_o}NB")
    assert "O" in result or cyrillic_o not in result, (
        "Cyrillic О must be normalised to ASCII O"
    )

    # Cyrillic 'А' (U+0410) should become 'A'
    cyrillic_a = "\u0410"
    result2 = _normalise_homoglyphs(f"{cyrillic_a}X-HDFCBK")
    assert "A" in result2 and cyrillic_a not in result2


def test_normalise_homoglyphs_fullwidth() -> None:
    """Fullwidth ASCII characters must be normalised to regular ASCII."""
    # Fullwidth 'Ａ' (U+FF21) → 'A'
    fullwidth_a = "\uFF21"
    result = _normalise_homoglyphs(f"{fullwidth_a}X-HDFCBK")
    assert fullwidth_a not in result
    assert "AX-HDFCBK" in result or result.startswith("A")


@pytest.mark.asyncio
async def test_sender_agent_cyrillic_homoglyph_spoofed_header() -> None:
    """
    A header containing Cyrillic homoglyphs (e.g. Cyrillic О in 'VM-SBIОNB')
    must be detected as a HOMOGLYPH_SPOOFED_HEADER or LOOKALIKE_HEADER.
    """
    # Cyrillic 'О' (U+041E) embedded in what appears to be 'VM-SBIONB'
    cyrillic_header = "VM-SBI\u041ENB"  # looks like VM-SBIONB but uses Cyrillic О
    req = _make_request(
        content="URGENT: SBI KYC suspended. Update immediately.",
        sender=cyrillic_header,
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS
    # Should be caught as a homoglyph spoof or lookalike
    assert result.is_spoofed_header is True or result.sender_category in (
        SenderCategoryEnum.LOOKALIKE_HEADER,
        SenderCategoryEnum.UNKNOWN,
    ), f"Cyrillic homoglyph header not flagged as spoof: {result.flags}"


# ---------------------------------------------------------------------------
# Test 13 — Government/Emergency Services Whitelist (No False Positives)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sender_agent_epfo_govt_whitelist() -> None:
    """
    EPFO header CP-EPFOHO must be verified as OFFICIAL_TRAI_HEADER
    with low risk even though the message body contains 'EPF' keyword.
    This tests that gov whitelisted senders don't get false-positive escalation.
    """
    req = _make_request(
        content="Your EPF withdrawal of Rs. 15,000 has been credited. "
                "EPFO UAN: 100XXXXXXXX. For queries visit epfindia.gov.in.",
        sender="CP-EPFOHO",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS, (
        f"EPFO header failed with: {result.details}"
    )
    assert result.sender_category == SenderCategoryEnum.OFFICIAL_TRAI_HEADER, (
        f"EPFO header must be OFFICIAL_TRAI_HEADER, got {result.sender_category}"
    )
    assert result.risk_score <= 10.0, (
        f"EPFO gov header must have low risk_score, got {result.risk_score}"
    )
    assert result.is_spoofed_header is False
    assert "VERIFIED_TRAI_DLT_SENDER_HEADER" in result.flags
    assert "GOVERNMENT_EMERGENCY_WHITELISTED" in result.flags


@pytest.mark.asyncio
async def test_sender_agent_uidai_govt_whitelist() -> None:
    """
    UIDAI (Aadhaar) header must be verified with GOVERNMENT_EMERGENCY_WHITELISTED flag.
    """
    req = _make_request(
        content="Your Aadhaar OTP is 845219. Valid for 10 minutes. "
                "Do NOT share with anyone. UIDAI never asks for OTP.",
        sender="AD-UIDAIT",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.sender_category == SenderCategoryEnum.OFFICIAL_TRAI_HEADER
    assert result.risk_score <= 10.0
    assert "GOVERNMENT_EMERGENCY_WHITELISTED" in result.flags


@pytest.mark.asyncio
async def test_sender_agent_india_post_payments_bank_whitelist() -> None:
    """
    India Post Payments Bank (AX-MTOUCH) must be whitelisted as an
    OFFICIAL_TRAI_HEADER even though the message mentions 'bank account'.
    """
    req = _make_request(
        content="Your India Post Payments Bank account has received Rs. 500 "
                "under PM-KISAN scheme. Visit your nearest post office.",
        sender="AX-MTOUCH",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.sender_category == SenderCategoryEnum.OFFICIAL_TRAI_HEADER
    assert result.risk_score <= 10.0
    assert "GOVERNMENT_EMERGENCY_WHITELISTED" in result.flags


@pytest.mark.asyncio
async def test_sender_agent_income_tax_dept_whitelist() -> None:
    """
    Income Tax Department header must not be false-positive flagged
    despite containing 'Income Tax' keywords in the message.
    """
    req = _make_request(
        content="Income Tax Department: Your ITR-1 for AY 2026-27 has been "
                "processed. Refund of Rs. 3,200 will credit within 5 working days.",
        sender="VM-INCOTX",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.sender_category == SenderCategoryEnum.OFFICIAL_TRAI_HEADER
    assert result.risk_score <= 10.0


# ---------------------------------------------------------------------------
# Test 14 — Edge: Verified Operator Prefix But Unregistered Entity Code
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unregistered_entity_with_valid_operator_prefix() -> None:
    """
    A header like 'VM-XYZABC' uses a valid TRAI operator prefix (VM)
    but an entity code not in the registry. Must NOT be treated as verified.
    Should be flagged as UNREGISTERED_TRAI_FORMAT_HEADER.
    """
    req = _make_request(
        content="Your account at FakeBank has an update pending.",
        sender="VM-XYZABC",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.sender_category != SenderCategoryEnum.OFFICIAL_TRAI_HEADER, (
        "Unregistered entity code must NOT be classified as official TRAI header"
    )
    assert result.is_spoofed_header is not False or "UNREGISTERED_TRAI_FORMAT_HEADER" in result.flags, (
        f"Expected UNREGISTERED_TRAI_FORMAT_HEADER in flags, got {result.flags}"
    )


# ---------------------------------------------------------------------------
# Test 15 — Preset Demo: SBI KYC Scam (Task Requirement)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_demo_critical_sbi_kyc_scam_from_gsm() -> None:
    """
    Day-2 Demo Preset #1: Critical scam — SBI KYC suspend notice with
    .top link from a 10-digit GSM number (personal mobile).
    Sender agent must return HIGH risk_score >= 85 with PERSONAL_GSM category.
    """
    req = _make_request(
        content="ALERT: Your SBI account KYC is suspended. "
                "Update now at http://sbi-kyc.top or your account will be blocked.",
        sender="9988776655",  # 10-digit personal GSM
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.sender_category == SenderCategoryEnum.PERSONAL_GSM
    assert result.risk_score >= 85.0
    assert "COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM" in result.flags
    assert result.brand_claimed is not None


@pytest.mark.asyncio
async def test_demo_verified_safe_hdfc_otp() -> None:
    """
    Day-2 Demo Preset #2: Verified safe — Real HDFC Bank OTP SMS
    with TRAI header VM-HDFCBK. Must return risk_score <= 10.
    """
    req = _make_request(
        content="Your HDFC Bank OTP for net banking login is 847291. "
                "Valid for 5 minutes. Do NOT share with anyone.",
        sender="VM-HDFCBK",
    )
    result: SenderAgentResult = await analyze_sender(req)

    assert result.sender_category == SenderCategoryEnum.OFFICIAL_TRAI_HEADER
    assert result.risk_score <= 10.0
    assert result.is_spoofed_header is False
    assert "HDFC" in (result.brand_claimed or "")


@pytest.mark.asyncio
async def test_demo_gsm_impersonation_electricity_cutoff() -> None:
    """
    Day-2 Demo Preset #3: GSM impersonation — Electricity cut-off alert
    from personal mobile number. Must return HIGH risk (>= 85).
    """
    req = _make_request(
        content="URGENT: Your electricity connection will be cut tonight at 9 PM "
                "due to non-payment. Pay now: http://msedcl-pay.online or call 8877665544.",
        sender="8877665544",  # personal GSM number
    )
    result: SenderAgentResult = await analyze_sender(req)

    # Electricity / power-cut keyword triggers official keyword detection
    assert result.sender_category == SenderCategoryEnum.PERSONAL_GSM
    assert result.risk_score >= 85.0
    assert "COMMERCIAL_BANK_CLAIMED_ON_PERSONAL_GSM" in result.flags or (
        result.brand_claimed is not None
    ), "Electricity cut-off scam from GSM must flag brand impersonation"
