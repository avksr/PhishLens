"""
backend.tests.test_extraction — Unit tests for shared extraction utilities.

Covers:
  - UPI VPA extraction vs email address discrimination (prevent false positives)
  - Phone number extraction using phonenumbers library (IN region)
  - URL extraction from text including defanged variants (hxxp, [.], [://], [dot])
"""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _BACKEND_DIR.parent
for _p in (str(_BACKEND_DIR), str(_PROJECT_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from shared.extraction import (
        extract_vpas,
        extract_phone_numbers,
        extract_urls,
        refang_url,
    )
except ImportError:
    from backend.shared.extraction import (
        extract_vpas,
        extract_phone_numbers,
        extract_urls,
        refang_url,
    )


# ──────────────────────────────────────────────
# 1. UPI VPA Extraction & Email Discrimination Tests
# ──────────────────────────────────────────────

class TestVpaExtraction:
    """Tests verifying UPI VPA extraction and non-matching of ordinary emails."""

    def test_extract_valid_bank_vpas(self):
        text = "Please pay Rs. 500 to rahul@oksbi or backup to account99@okaxis."
        vpas = extract_vpas(text)
        assert "rahul@oksbi" in vpas
        assert "account99@okaxis" in vpas
        assert len(vpas) == 2

    def test_extract_fintech_and_wallet_vpas(self):
        text = "Send payments to merchant.store@paytm or helpdesk@phonepe or user123@ybl."
        vpas = extract_vpas(text)
        assert "merchant.store@paytm" in vpas
        assert "helpdesk@phonepe" in vpas
        assert "user123@ybl" in vpas
        assert len(vpas) == 3

    def test_does_not_match_regular_email_addresses(self):
        """Standard email addresses (gmail, yahoo, outlook, corporate) must NOT be matched."""
        text = (
            "Contact our support at support@gmail.com, admin@yahoo.co.in, "
            "help@microsoft.com, info@company.org or sales@domain.in."
        )
        vpas = extract_vpas(text)
        assert vpas == [], f"Expected no VPAs, but got: {vpas}"

    def test_mixed_text_with_both_vpa_and_emails(self):
        """When text contains both emails and VPAs, only valid VPAs must be extracted."""
        text = (
            "From: notifications@sbi.co.in. Dear Customer, pay bill to "
            "sbi.bills@sbi or contact support@sbi.co.in."
        )
        vpas = extract_vpas(text)
        assert vpas == ["sbi.bills@sbi"]

    def test_case_insensitivity_and_normalization(self):
        text = "Transfer money to USER@OKAXIS or Test.Name@PAYTM."
        vpas = extract_vpas(text)
        assert len(vpas) == 2
        # Preserves format with lowercased handle
        assert "USER@okaxis" in vpas or "user@okaxis" in [v.lower() for v in vpas]
        assert "Test.Name@paytm" in vpas or "test.name@paytm" in [v.lower() for v in vpas]

    def test_deduplication(self):
        text = "Pay to scammer@paytm. Repeat: scammer@paytm. Thank you."
        vpas = extract_vpas(text)
        assert len(vpas) == 1
        assert vpas[0].lower() == "scammer@paytm"

    def test_empty_or_whitespace_text(self):
        assert extract_vpas("") == []
        assert extract_vpas("   ") == []


# ──────────────────────────────────────────────
# 2. Phone Number Extraction Tests (phonenumbers IN)
# ──────────────────────────────────────────────

class TestPhoneNumberExtraction:
    """Tests phone number extraction with IN country code defaults."""

    def test_extract_international_format_indian_number(self):
        text = "Urgent: Call our verification center at +919876543210 immediately."
        numbers = extract_phone_numbers(text, region="IN")
        assert "+919876543210" in numbers

    def test_extract_national_10_digit_indian_mobile(self):
        text = "Electricity disconnection alert. Call helpline 9876543210 now."
        numbers = extract_phone_numbers(text, region="IN")
        assert "+919876543210" in numbers

    def test_extract_formatted_indian_number(self):
        text = "Contact toll free +91-98765-43210 for KYC renewal."
        numbers = extract_phone_numbers(text, region="IN")
        assert "+919876543210" in numbers

    def test_ignores_non_phone_numbers(self):
        text = "The invoice code is 12345 and ticket ID is 998877."
        numbers = extract_phone_numbers(text, region="IN")
        assert numbers == []

    def test_empty_text_returns_empty(self):
        assert extract_phone_numbers("") == []


# ──────────────────────────────────────────────
# 3. URL Extraction & Defanging Tests
# ──────────────────────────────────────────────

class TestUrlExtractionAndRefanging:
    """Tests URL extraction from raw OCR/PDF text, including refanging."""

    def test_refang_url_hxxps_and_brackets(self):
        assert refang_url("hxxps://evil[.]com/login") == "https://evil.com/login"
        assert refang_url("hxxp://phish[dot]org/update") == "http://phish.org/update"
        assert refang_url("hxxps[://]bank-secure[.]xyz") == "https://bank-secure.xyz"

    def test_extract_standard_urls(self):
        text = "Please check https://onlinesbi.sbi/portal or http://example.com/test"
        urls = extract_urls(text)
        assert "https://onlinesbi.sbi/portal" in urls
        assert "http://example.com/test" in urls

    def test_extract_defanged_urls_from_ocr_text(self):
        text = "Phishing alert reported link: hxxps://sbi-kyc-update[.]com/login"
        urls = extract_urls(text, include_defanged=True)
        assert "https://sbi-kyc-update.com/login" in urls

    def test_extract_defanged_colon_slash_slash(self):
        text = "Defanged threat: hxxps[://]secure-login[.]net/verify"
        urls = extract_urls(text, include_defanged=True)
        assert any("https://secure-login.net/verify" in u for u in urls)

    def test_extract_strips_trailing_punctuation(self):
        text = "Visit https://legit-site.com/home. Also check https://another-site.com/,"
        urls = extract_urls(text)
        assert "https://legit-site.com/home" in urls
        assert "https://another-site.com/" in urls

    def test_empty_text_returns_empty(self):
        assert extract_urls("") == []
