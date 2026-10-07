"""
Tests for Atharv's URL Agent upgrades:
  1. Browser Extension URL Check API (POST /api/v1/url/check)
  2. Hex / Octal / Decimal IP Defanging
  3. Claimed Brand Context Passing

Author: Atharv (URL Agent team)
"""

from __future__ import annotations

import asyncio
import sys
import os
import pytest

# Ensure the backend package is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.url_agent import (
    _defang_ip_host,
    _check_ip_obfuscation,
    _check_claimed_brand_mismatch,
    _check_typosquatting,
    _score_to_risk_tier,
    analyze_url_fast,
    analyze_url,
    domain_cache_clear,
)
from shared.models import ScanRequest


# ──────────────────────────────────────────────
# Fixture: clear domain cache before each test
# ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clear_cache():
    domain_cache_clear()
    yield
    domain_cache_clear()


# ═══════════════════════════════════════════════
# Feature 2: Hex / Octal / Decimal IP Defanging
# ═══════════════════════════════════════════════

class TestIPDefanging:
    """Test _defang_ip_host and _check_ip_obfuscation for various IP encodings."""

    def test_decimal_integer_ip(self):
        """http://2130706433 should decode to 127.0.0.1."""
        ip, flags = _defang_ip_host("2130706433")
        assert ip == "127.0.0.1"
        assert "IP_DECIMAL_ENCODED" in flags

    def test_hex_integer_ip(self):
        """http://0x7f000001 should decode to 127.0.0.1."""
        ip, flags = _defang_ip_host("0x7f000001")
        assert ip == "127.0.0.1"
        assert "IP_HEX_ENCODED" in flags

    def test_dotted_hex_ip(self):
        """http://0x7f.0x0.0x0.0x1 should decode to 127.0.0.1."""
        ip, flags = _defang_ip_host("0x7f.0x0.0x0.0x1")
        assert ip == "127.0.0.1"
        assert "IP_DOTTED_HEX" in flags

    def test_dotted_octal_ip(self):
        """http://0177.0.0.01 should decode to 127.0.0.1."""
        ip, flags = _defang_ip_host("0177.0.0.01")
        assert ip == "127.0.0.1"
        assert "IP_DOTTED_OCTAL" in flags

    def test_mixed_hex_octal_ip(self):
        """http://0x7f.0.0.01 should decode with mixed encoding flag."""
        ip, flags = _defang_ip_host("0x7f.0.0.01")
        assert ip is not None
        assert any("HEX" in f or "OCTAL" in f or "MIXED" in f for f in flags)

    def test_normal_ip_no_obfuscation(self):
        """Normal dotted-decimal IP should NOT be flagged as obfuscated."""
        ip, flags = _defang_ip_host("192.168.1.1")
        assert ip is None
        assert flags == []

    def test_normal_domain_no_obfuscation(self):
        """Normal domain names should NOT be flagged."""
        ip, flags = _defang_ip_host("example.com")
        assert ip is None
        assert flags == []

    def test_empty_host(self):
        """Empty host should return None."""
        ip, flags = _defang_ip_host("")
        assert ip is None
        assert flags == []

    def test_hex_integer_with_port(self):
        """Hex IP with port should still decode."""
        ip, flags = _defang_ip_host("0x7f000001:8080")
        assert ip == "127.0.0.1"
        assert "IP_HEX_ENCODED" in flags

    def test_check_ip_obfuscation_full_url(self):
        """Full URL with decimal IP should be caught."""
        decoded_ip, delta, flags = _check_ip_obfuscation("http://2130706433/phish")
        assert decoded_ip == "127.0.0.1"
        assert delta > 0
        assert any("IP_DECIMAL_ENCODED" in f for f in flags)
        assert any("DECODED_IP:" in f for f in flags)

    def test_check_ip_obfuscation_hex_url(self):
        """Full URL with hex IP should be caught."""
        decoded_ip, delta, flags = _check_ip_obfuscation("http://0x7f000001/login")
        assert decoded_ip == "127.0.0.1"
        assert delta > 0

    def test_private_ip_lower_risk(self):
        """Private IPs should have lower risk delta than public IPs."""
        # 127.0.0.1 is private/loopback
        _, priv_delta, _ = _check_ip_obfuscation("http://2130706433")
        # 8.8.8.8 = 134744072
        _, pub_delta, _ = _check_ip_obfuscation("http://134744072")
        assert priv_delta < pub_delta

    def test_no_obfuscation_normal_url(self):
        """Normal domain URL should not trigger IP obfuscation."""
        decoded_ip, delta, flags = _check_ip_obfuscation("https://www.google.com")
        assert decoded_ip is None
        assert delta == 0.0
        assert flags == []

    def test_dotted_hex_public_ip(self):
        """Dotted hex encoding of a public IP (e.g., 8.8.8.8)."""
        ip, flags = _defang_ip_host("0x08.0x08.0x08.0x08")
        assert ip == "8.8.8.8"
        assert "IP_DOTTED_HEX" in flags

    def test_octal_public_ip(self):
        """Octal encoding of 10.0.0.1."""
        ip, flags = _defang_ip_host("012.0.0.01")
        assert ip == "10.0.0.1"
        assert "IP_DOTTED_OCTAL" in flags

    def test_large_decimal_ip(self):
        """Max valid IPv4 as decimal integer: 4294967295 = 255.255.255.255."""
        ip, flags = _defang_ip_host("4294967295")
        assert ip == "255.255.255.255"
        assert "IP_DECIMAL_ENCODED" in flags


# ═══════════════════════════════════════════════
# Feature 3: Claimed Brand Context Passing
# ═══════════════════════════════════════════════

class TestClaimedBrandContext:
    """Test _check_claimed_brand_mismatch and _check_typosquatting with claimed_brand."""

    def test_claimed_sbi_unofficial_domain(self):
        """Claimed 'State Bank of India' with non-official domain should flag."""
        mismatch, delta, flags = _check_claimed_brand_mismatch(
            registered_domain="sbi-kyc-verify.top",
            domain_label="sbi-kyc-verify",
            claimed_brand="State Bank of India",
        )
        assert mismatch is True
        assert delta > 0
        assert "CLAIMED_BRAND_MISMATCH" in flags

    def test_claimed_sbi_official_domain(self):
        """Claimed 'State Bank of India' with official domain should NOT flag."""
        mismatch, delta, flags = _check_claimed_brand_mismatch(
            registered_domain="sbi.co.in",
            domain_label="sbi",
            claimed_brand="State Bank of India",
        )
        assert mismatch is False
        assert delta == 0.0

    def test_claimed_hdfc_unofficial(self):
        """Claimed 'HDFC Bank' with phishing domain should flag."""
        mismatch, delta, flags = _check_claimed_brand_mismatch(
            registered_domain="hdfc-update.xyz",
            domain_label="hdfc-update",
            claimed_brand="HDFC Bank",
        )
        assert mismatch is True
        assert "CLAIMED_BRAND_MISMATCH" in flags

    def test_claimed_unknown_brand(self):
        """Unknown brand should not flag (can't verify)."""
        mismatch, delta, flags = _check_claimed_brand_mismatch(
            registered_domain="random-site.com",
            domain_label="random-site",
            claimed_brand="XYZ Unknown Corp",
        )
        assert mismatch is False
        assert delta == 0.0

    def test_no_claimed_brand(self):
        """None claimed_brand should not flag."""
        mismatch, delta, flags = _check_claimed_brand_mismatch(
            registered_domain="anything.com",
            domain_label="anything",
            claimed_brand=None,
        )
        assert mismatch is False

    def test_typosquatting_with_claimed_brand_context(self):
        """Typosquatting check with claimed_brand should detect impersonation."""
        is_typo, brand, delta, flags = _check_typosquatting(
            domain_label="random-domain",
            registered_domain="random-domain.xyz",
            claimed_brand="State Bank of India",
        )
        assert is_typo is True
        assert brand is not None
        assert "CLAIMED_BRAND_CONTEXT" in flags

    def test_typosquatting_claimed_brand_official_domain(self):
        """Official domain with claimed brand should NOT flag as typosquatting."""
        is_typo, brand, delta, flags = _check_typosquatting(
            domain_label="sbi",
            registered_domain="sbi.co.in",
            claimed_brand="sbi",
        )
        assert is_typo is False


# ═══════════════════════════════════════════════
# Feature 1: Fast URL Check (analyze_url_fast)
# ═══════════════════════════════════════════════

class TestAnalyzeUrlFast:
    """Test the sub-50ms analyze_url_fast function."""

    @pytest.mark.asyncio
    async def test_basic_safe_url(self):
        """A well-known safe domain should return SAFE tier."""
        result = await analyze_url_fast("https://www.google.com")
        assert result["risk_score"] == 0.0
        assert result["risk_tier"] == "SAFE"
        assert result["latency_ms"] < 100  # generous ceiling

    @pytest.mark.asyncio
    async def test_high_risk_tld(self):
        """A .top domain should get a HIGH_RISK_TLD flag."""
        result = await analyze_url_fast("https://example.top")
        assert result["risk_score"] > 0
        assert "HIGH_RISK_TLD" in result["flags"]

    @pytest.mark.asyncio
    async def test_typosquatting_detection(self):
        """sbi-kyc-verify.top should be detected as typosquatting."""
        result = await analyze_url_fast("https://sbi-kyc-verify.top")
        assert result["is_typosquatting"] is True
        assert result["target_brand"] is not None
        assert result["risk_tier"] in ("HIGH_RISK", "CRITICAL")

    @pytest.mark.asyncio
    async def test_ip_obfuscation_in_fast(self):
        """Hex IP URL should be caught in the fast endpoint."""
        result = await analyze_url_fast("http://0x7f000001/phishing")
        assert result["is_ip_obfuscated"] is True
        assert result["decoded_ip"] == "127.0.0.1"
        assert result["risk_score"] > 0

    @pytest.mark.asyncio
    async def test_claimed_brand_in_fast(self):
        """Claimed brand mismatch should elevate risk in fast mode."""
        result = await analyze_url_fast(
            "https://random-site.xyz",
            claimed_brand="State Bank of India",
        )
        assert result["risk_score"] > 0
        # Should have either typosquatting or claimed brand mismatch
        has_brand_flag = any(
            "CLAIMED_BRAND" in f or "TYPOSQUATTING" in f
            for f in result["flags"]
        )
        assert has_brand_flag

    @pytest.mark.asyncio
    async def test_url_without_scheme(self):
        """URL without http:// prefix should be auto-prefixed."""
        result = await analyze_url_fast("sbi-kyc.top")
        assert result["url"].startswith("https://")

    @pytest.mark.asyncio
    async def test_response_structure(self):
        """Response should contain all required fields."""
        result = await analyze_url_fast("https://example.com")
        required_keys = {
            "url", "risk_score", "risk_tier", "domain",
            "is_typosquatting", "is_ip_obfuscated", "flags",
            "cached", "latency_ms",
        }
        assert required_keys.issubset(result.keys())


# ═══════════════════════════════════════════════
# analyze_url with claimed_brand
# ═══════════════════════════════════════════════

class TestAnalyzeUrlWithClaimedBrand:
    """Test the full analyze_url function with claimed_brand parameter."""

    @pytest.mark.asyncio
    async def test_analyze_url_with_claimed_brand(self):
        """Passing claimed_brand into the full pipeline should affect scoring."""
        req = ScanRequest(
            content="Update your KYC at https://sbi-verify.top",
            extracted_url="https://sbi-verify.top",
        )
        result = await analyze_url(req, claimed_brand="State Bank of India")
        assert result.risk_score > 0
        assert result.is_typosquatting is True

    @pytest.mark.asyncio
    async def test_analyze_url_no_claimed_brand_backward_compat(self):
        """Existing calls without claimed_brand should still work."""
        req = ScanRequest(
            content="Check this link: https://www.google.com",
            extracted_url="https://www.google.com",
        )
        result = await analyze_url(req)
        assert result.status.value in ("SUCCESS", "SKIPPED")

    @pytest.mark.asyncio
    async def test_analyze_url_ip_obfuscation_integrated(self):
        """IP obfuscation should be flagged in the full pipeline."""
        req = ScanRequest(
            content="Visit http://0x7f000001/verify",
            extracted_url="http://0x7f000001/verify",
        )
        result = await analyze_url(req)
        has_ip_flag = any("IP_" in f for f in result.flags)
        assert has_ip_flag
        assert result.risk_score > 0


# ═══════════════════════════════════════════════
# Risk Tier Mapping
# ═══════════════════════════════════════════════

class TestScoreToRiskTier:
    """Test the _score_to_risk_tier helper."""

    def test_safe_tier(self):
        assert _score_to_risk_tier(0) == "SAFE"
        assert _score_to_risk_tier(24) == "SAFE"

    def test_caution_tier(self):
        assert _score_to_risk_tier(25) == "CAUTION"
        assert _score_to_risk_tier(49) == "CAUTION"

    def test_high_risk_tier(self):
        assert _score_to_risk_tier(50) == "HIGH_RISK"
        assert _score_to_risk_tier(77) == "HIGH_RISK"

    def test_critical_tier(self):
        assert _score_to_risk_tier(78) == "CRITICAL"
        assert _score_to_risk_tier(100) == "CRITICAL"
