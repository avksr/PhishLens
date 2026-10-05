"""
backend.tests.test_document_agent — Unit tests for the Document Intelligence Agent.

Covers:
  - Aadhaar number extraction and Verhoeff checksum validation
  - PAN format validation ([A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z])
  - PDF metadata analysis and suspicious editor fingerprinting
  - Font mismatch detection across multiple font families
  - Comprehensive scenario tests:
      1. Forged PDF (Canva editor, invalid Aadhaar, defanged phishing link)
      2. Clean PDF (official Adobe Acrobat creator, valid Aadhaar, valid PAN)
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
import pypdf

_BACKEND_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _BACKEND_DIR.parent
for _p in (str(_BACKEND_DIR), str(_PROJECT_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from agents.document_agent import (
        validate_verhoeff,
        extract_aadhaar_numbers,
        extract_pan_numbers,
        analyze_pdf_metadata,
        analyze_document,
        analyze_document_model,
    )
except ImportError:
    from backend.agents.document_agent import (
        validate_verhoeff,
        extract_aadhaar_numbers,
        extract_pan_numbers,
        analyze_pdf_metadata,
        analyze_document,
        analyze_document_model,
    )

try:
    from shared.models import DocumentAgentResult, AgentStatusEnum
except ImportError:
    from backend.shared.models import DocumentAgentResult, AgentStatusEnum


# ──────────────────────────────────────────────
# PDF Generator Helper
# ──────────────────────────────────────────────

def _create_synthetic_pdf(
    creator: str = "Adobe Acrobat Pro",
    producer: str = "Adobe PDF Library 15.0",
    fonts: list[str] | None = None,
    text: str = "",
) -> bytes:
    """Generate in-memory PDF bytes with custom metadata and fonts for testing."""
    writer = pypdf.PdfWriter()
    page = writer.add_blank_page(width=300, height=300)

    # Attach fonts to /Resources/Font if requested
    if fonts:
        font_dict = pypdf.generic.DictionaryObject()
        for i, font_name in enumerate(fonts):
            font_entry = pypdf.generic.DictionaryObject({
                pypdf.generic.NameObject("/Type"): pypdf.generic.NameObject("/Font"),
                pypdf.generic.NameObject("/Subtype"): pypdf.generic.NameObject("/Type1"),
                pypdf.generic.NameObject("/BaseFont"): pypdf.generic.NameObject(f"/{font_name}"),
            })
            font_dict[pypdf.generic.NameObject(f"/F{i+1}")] = font_entry

        page_resources = pypdf.generic.DictionaryObject({
            pypdf.generic.NameObject("/Font"): font_dict,
        })
        page[pypdf.generic.NameObject("/Resources")] = page_resources

    # Metadata
    meta = {
        "/Creator": creator,
        "/Producer": producer,
        "/Title": "Document Verification",
    }
    writer.add_metadata(meta)

    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


# ──────────────────────────────────────────────
# 1. Verhoeff & Aadhaar Validation Tests
# ──────────────────────────────────────────────

class TestAadhaarValidation:
    """Tests UIDAI Verhoeff checksum algorithm and Aadhaar regex extraction."""

    def test_verhoeff_valid_checksum(self):
        # 2345 6789 0124 has valid Verhoeff check digit (4)
        assert validate_verhoeff("234567890124") is True

    def test_verhoeff_invalid_checksum(self):
        # Corrupted check digit (5 instead of 4)
        assert validate_verhoeff("234567890125") is False

    def test_extract_valid_aadhaar_from_text(self):
        text = "Identity Document: Aadhaar No: 2345 6789 0124 presented for verification."
        results = extract_aadhaar_numbers(text)
        assert len(results) == 1
        assert results[0]["normalised"] == "234567890124"
        assert results[0]["verhoeff_valid"] is True

    def test_extract_forged_aadhaar_fails_checksum(self):
        text = "Forged identity card with fabricated Aadhaar: 2345 6789 0125"
        results = extract_aadhaar_numbers(text)
        assert len(results) == 1
        assert results[0]["normalised"] == "234567890125"
        assert results[0]["verhoeff_valid"] is False

    def test_ignores_invalid_aadhaar_starting_with_0_or_1(self):
        text = "Codes: 0123 4567 8901 and 1234 5678 9012 are not valid Aadhaar."
        results = extract_aadhaar_numbers(text)
        assert len(results) == 0

    def test_ignores_repetitive_digits(self):
        text = "Dummy test account: 9999 9999 9999"
        results = extract_aadhaar_numbers(text)
        assert len(results) == 0


# ──────────────────────────────────────────────
# 2. PAN Format Validation Tests
# ──────────────────────────────────────────────

class TestPanValidation:
    """Tests Income Tax Department PAN card format verification."""

    def test_valid_individual_pan(self):
        # 4th letter 'P' indicates Individual
        text = "Taxpayer PAN number is ABCPD1234E for annual filing."
        pans = extract_pan_numbers(text)
        assert len(pans) == 1
        assert pans[0]["number"] == "ABCPD1234E"
        assert pans[0]["format_valid"] is True

    def test_valid_company_pan(self):
        # 4th letter 'C' indicates Company
        text = "Corporate entity PAN: AABCA1234F registered."
        pans = extract_pan_numbers(text)
        assert len(pans) == 1
        assert pans[0]["number"] == "AABCA1234F"

    def test_invalid_pan_wrong_fourth_character(self):
        # 'X' is not a valid 4th letter in Indian PAN
        text = "Fake PAN: ABCXD1234E submitted."
        pans = extract_pan_numbers(text)
        assert len(pans) == 0

    def test_invalid_pan_wrong_digit_count(self):
        text = "Malformed PANs: ABCPD123E and ABCPD12345E are wrong."
        pans = extract_pan_numbers(text)
        assert len(pans) == 0


# ──────────────────────────────────────────────
# 3. PDF Metadata & Editor Fingerprinting Tests
# ──────────────────────────────────────────────

class TestPdfMetadataAnalysis:
    """Tests detection of suspicious online PDF editors and font mismatches."""

    def test_detects_canva_editor(self):
        pdf_bytes = _create_synthetic_pdf(creator="Canva Online Editor", producer="Canva")
        meta = analyze_pdf_metadata(pdf_bytes)
        assert meta["is_suspicious_editor"] is True
        assert "canva" in meta["creator"].lower()

    def test_detects_ilovepdf_editor(self):
        pdf_bytes = _create_synthetic_pdf(creator="iLovePDF", producer="iLovePDF")
        meta = analyze_pdf_metadata(pdf_bytes)
        assert meta["is_suspicious_editor"] is True

    def test_legitimate_adobe_creator_not_suspicious(self):
        pdf_bytes = _create_synthetic_pdf(
            creator="Adobe InDesign 18.0",
            producer="Adobe PDF Library 15.0",
        )
        meta = analyze_pdf_metadata(pdf_bytes)
        assert meta["is_suspicious_editor"] is False

    def test_font_mismatch_detected_when_multiple_families(self):
        # 3 different font families: Arial, TimesNewRoman, Courier
        fonts = ["Arial-Bold", "TimesNewRoman-Regular", "Courier-Bold"]
        pdf_bytes = _create_synthetic_pdf(fonts=fonts)
        meta = analyze_pdf_metadata(pdf_bytes)
        assert meta["font_count"] == 3
        assert meta["has_font_mismatch"] is True

    def test_single_font_family_not_flagged(self):
        # 2 styles of the SAME family: Helvetica-Regular, Helvetica-Bold
        fonts = ["Helvetica-Regular", "Helvetica-Bold"]
        pdf_bytes = _create_synthetic_pdf(fonts=fonts)
        meta = analyze_pdf_metadata(pdf_bytes)
        assert meta["has_font_mismatch"] is False


# ──────────────────────────────────────────────
# 4. End-to-End Scenarios: 1 Forged + 1 Clean PDF
# ──────────────────────────────────────────────

class TestDocumentScenarios:
    """End-to-end tests for 1 forged PDF vs 1 clean PDF document."""

    def test_forged_pdf_scenario(self):
        """
        Scenario 1: Forged PDF
        - Created with Canva online tool
        - Contains an invalid Aadhaar checksum
        - Contains a defanged phishing link (hxxps://evil-gov[.]in/download)
        - Must be flagged with high risk score (>= 50)
        """
        forged_pdf = _create_synthetic_pdf(
            creator="Canva Editor v2",
            producer="Canva PDF Exporter",
            fonts=["Arial-Regular", "TimesNewRoman-Bold", "ComicSans-Regular"],
        )
        text = (
            "URGENT VERIFICATION NOTICE: Aadhaar: 2345 6789 0125 is suspended. "
            "Update details immediately at hxxps://fake-uidai[.]org/verify"
        )

        result = analyze_document(text=text, pdf_bytes=forged_pdf)

        assert result["risk_score"] >= 50.0
        assert any("SUSPICIOUS_PDF_EDITOR" in f for f in result["flags"])
        assert any("INVALID_AADHAAR_CHECKSUM" in f for f in result["flags"])
        assert any("FONT_MISMATCH" in f for f in result["flags"])
        assert "https://fake-uidai.org/verify" in result["extracted_urls"]

    def test_clean_pdf_scenario(self):
        """
        Scenario 2: Clean PDF
        - Created with Adobe Acrobat
        - Contains valid Aadhaar (2345 6789 0124) and valid PAN (ABCPD1234E)
        - Consistent fonts
        - Must have risk_score == 0.0 and no flags
        """
        clean_pdf = _create_synthetic_pdf(
            creator="Adobe Acrobat Pro 2023",
            producer="Adobe PDF Library 16.0",
            fonts=["Helvetica-Regular", "Helvetica-Bold"],
        )
        text = (
            "Official Bank Account Statement: "
            "Aadhaar Number: 2345 6789 0124, PAN: ABCPD1234E. Account in good standing."
        )

        result = analyze_document(text=text, pdf_bytes=clean_pdf)

        assert result["risk_score"] == 0.0
        assert result["flags"] == []
        assert len(result["aadhaar_numbers"]) == 1
        assert result["aadhaar_numbers"][0]["verhoeff_valid"] is True
        assert len(result["pan_numbers"]) == 1
        assert result["pan_numbers"][0]["format_valid"] is True

    def test_document_model_wrapper(self):
        """Verify typed DocumentAgentResult return model."""
        clean_pdf = _create_synthetic_pdf(creator="LaTeX with hyperref")
        model = analyze_document_model(text="PAN: ABCPD1234E", pdf_bytes=clean_pdf)

        assert isinstance(model, DocumentAgentResult)
        assert model.status == AgentStatusEnum.SUCCESS
        assert model.risk_score == 0.0
        assert len(model.pan_numbers) == 1
