"""
backend.agents.document_agent — Document Intelligence Agent for PhishLens.

Analyses PDF documents and extracted text for forgery signals:

1. **PDF metadata extraction** — creator, producer, modification dates
2. **Editor software fingerprinting** — flags suspicious online editors
3. **Font mismatch detection** — multiple font families = forgery signal
4. **Aadhaar validation** — 12-digit number with Verhoeff checksum
5. **PAN format validation** — ``[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]``

Author: Atharv (URL Agent team)
"""

from __future__ import annotations

import io
import logging
import re
import time
from typing import Any, Dict, List, Optional

try:
    from shared.models import AgentStatusEnum, DocumentAgentResult
    from shared.extraction import extract_urls
except ImportError:
    from backend.shared.models import AgentStatusEnum, DocumentAgentResult
    from backend.shared.extraction import extract_urls

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Verhoeff Algorithm for Aadhaar validation
# ──────────────────────────────────────────────

# Multiplication table
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

# Permutation table
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

# Inverse table
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff(number: str) -> bool:
    """
    Validate a number string using the Verhoeff checksum algorithm.

    The Verhoeff algorithm is used by UIDAI to validate Aadhaar numbers.
    The last digit of the 12-digit Aadhaar number is the check digit.

    Returns ``True`` if the checksum is valid.
    """
    c = 0
    digits = [int(d) for d in reversed(number)]
    for i, digit in enumerate(digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][digit]]
    return c == 0


# ──────────────────────────────────────────────
# Aadhaar & PAN extraction
# ──────────────────────────────────────────────

# Aadhaar: 12 digits, optionally separated by spaces (XXXX XXXX XXXX)
_AADHAAR_REGEX = re.compile(
    r"\b(\d{4}\s?\d{4}\s?\d{4})\b"
)

# PAN: 5 letters + 4 digits + 1 letter, e.g. ABCPD1234E
# 4th char must be one of: A B C F G H J L P T
_PAN_REGEX = re.compile(
    r"\b([A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z])\b"
)

# Suspicious PDF editor software (online tools, free converters)
_SUSPICIOUS_EDITORS = frozenset({
    "canva", "smallpdf", "ilovepdf", "pdf2go",
    "sejda", "sodapdf", "pdfcandy", "pdfescape",
    "dochub", "pdffiller", "cleverpdf", "pdfzorro",
    "online2pdf", "combinepdf", "foxyutils",
    "camscanner", "adobe scan",
    # Generic indicators
    "fpdf", "tcpdf", "wkhtmltopdf",
})


def extract_aadhaar_numbers(text: str) -> List[Dict[str, Any]]:
    """
    Extract Aadhaar-format numbers from *text* and validate checksums.

    Returns a list of dicts: ``{"number": "XXXX XXXX XXXX",
    "normalised": "XXXXXXXXXXXX", "verhoeff_valid": True/False}``.
    """
    if not text:
        return []

    results: List[Dict[str, Any]] = []
    seen: set[str] = set()

    for match in _AADHAAR_REGEX.finditer(text):
        raw = match.group(1)
        normalised = raw.replace(" ", "")

        # Basic sanity: must be exactly 12 digits
        if len(normalised) != 12 or not normalised.isdigit():
            continue

        # Skip all-same-digit sequences (e.g. 000000000000)
        if len(set(normalised)) == 1:
            continue

        # Aadhaar cannot start with 0 or 1
        if normalised[0] in ("0", "1"):
            continue

        if normalised not in seen:
            seen.add(normalised)
            results.append({
                "number": raw,
                "normalised": normalised,
                "verhoeff_valid": validate_verhoeff(normalised),
            })

    return results


def extract_pan_numbers(text: str) -> List[Dict[str, Any]]:
    """
    Extract PAN-format strings from *text* and validate format.

    Returns a list of dicts: ``{"number": "ABCPD1234E",
    "format_valid": True}``.
    """
    if not text:
        return []

    results: List[Dict[str, Any]] = []
    seen: set[str] = set()

    for match in _PAN_REGEX.finditer(text):
        pan = match.group(1)
        if pan not in seen:
            seen.add(pan)
            results.append({
                "number": pan,
                "format_valid": True,
            })

    return results


# ──────────────────────────────────────────────
# PDF analysis
# ──────────────────────────────────────────────

def analyze_pdf_metadata(
    pdf_bytes: bytes,
) -> Dict[str, Any]:
    """
    Extract and analyse metadata from a PDF document.

    Returns a dict with:
      - ``metadata``: raw PDF metadata fields
      - ``creator``: the Creator field (software used)
      - ``producer``: the Producer field
      - ``is_suspicious_editor``: True if creator/producer matches known
        suspicious editors
      - ``fonts``: list of font names found
      - ``font_count``: number of distinct fonts
      - ``has_font_mismatch``: True if > 2 distinct font families
      - ``page_count``: number of pages
    """
    try:
        from pypdf import PdfReader  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("pypdf not installed — skipping PDF analysis")
        return {"error": "pypdf not installed"}

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
    except Exception as exc:
        logger.warning("Failed to parse PDF: %s", exc)
        return {"error": str(exc)}

    # ── Metadata ──
    meta = reader.metadata or {}
    raw_meta: Dict[str, Any] = {}
    for key in ("/Author", "/Creator", "/Producer", "/Title",
                "/Subject", "/CreationDate", "/ModDate"):
        val = meta.get(key)
        if val:
            raw_meta[key.lstrip("/")] = str(val)

    creator = str(meta.get("/Creator", "") or "").strip()
    producer = str(meta.get("/Producer", "") or "").strip()

    # ── Suspicious editor check ──
    combined = (creator + " " + producer).lower()
    is_suspicious = any(
        editor in combined for editor in _SUSPICIOUS_EDITORS
    )

    # ── Font extraction ──
    fonts: set[str] = set()
    try:
        for page in reader.pages:
            resources = page.get("/Resources")
            if resources and "/Font" in resources:
                font_dict = resources["/Font"]
                if hasattr(font_dict, "keys"):
                    for font_key in font_dict.keys():
                        font_obj = font_dict[font_key]
                        if hasattr(font_obj, "get"):
                            base_font = font_obj.get("/BaseFont")
                            if base_font:
                                fonts.add(str(base_font).lstrip("/"))
    except Exception:
        pass  # font extraction is best-effort

    # ── Font family grouping ──
    # Group by font family (strip Bold/Italic/Regular suffixes)
    families: set[str] = set()
    for font_name in fonts:
        # Remove common suffixes
        family = re.sub(
            r"[-,](Bold|Italic|Regular|Light|Medium|Semibold|Thin|Black|"
            r"BoldItalic|ExtraBold|ExtraLight|Condensed|Oblique).*$",
            "",
            font_name,
            flags=re.IGNORECASE,
        )
        families.add(family)

    # More than 2 distinct font families in a single doc is suspicious
    has_font_mismatch = len(families) > 2

    # ── Text and link extraction from pages ──
    extracted_text_chunks: List[str] = []
    pdf_urls: List[str] = []
    try:
        for page in reader.pages:
            try:
                t = page.extract_text()
                if t:
                    extracted_text_chunks.append(t)
            except Exception:
                pass

            try:
                annots = page.get("/Annots")
                if annots:
                    for a_ref in annots:
                        a_obj = a_ref.get_object() if hasattr(a_ref, "get_object") else a_ref
                        if hasattr(a_obj, "get"):
                            action = a_obj.get("/A")
                            if hasattr(action, "get"):
                                uri = action.get("/URI")
                                if uri and str(uri) not in pdf_urls:
                                    pdf_urls.append(str(uri))
            except Exception:
                pass
    except Exception:
        pass

    pdf_text = "\n".join(extracted_text_chunks)
    # Also extract URLs from PDF text
    for u in extract_urls(pdf_text, include_defanged=True):
        if u not in pdf_urls:
            pdf_urls.append(u)

    return {
        "metadata": raw_meta,
        "creator": creator,
        "producer": producer,
        "is_suspicious_editor": is_suspicious,
        "fonts": sorted(fonts),
        "font_families": sorted(families),
        "font_count": len(fonts),
        "has_font_mismatch": has_font_mismatch,
        "page_count": len(reader.pages),
        "extracted_text": pdf_text,
        "extracted_urls": pdf_urls,
    }


# ──────────────────────────────────────────────
# Full document analysis pipeline
# ──────────────────────────────────────────────

def analyze_document(
    text: str,
    pdf_bytes: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    Run full document analysis on extracted text and optional PDF bytes.

    Combines:
      - Aadhaar / PAN extraction and validation
      - PDF metadata analysis (if *pdf_bytes* provided)
      - Risk scoring based on detected signals

    Returns a comprehensive result dict.
    """
    start = time.perf_counter()

    flags: List[str] = []
    risk_score = 0.0

    # ── Text aggregation from PDF if provided ──
    combined_text = text or ""
    pdf_result: Optional[Dict[str, Any]] = None
    if pdf_bytes:
        pdf_result = analyze_pdf_metadata(pdf_bytes)
        pdf_text = pdf_result.get("extracted_text", "")
        if pdf_text:
            combined_text = f"{combined_text} {pdf_text}".strip()

        if pdf_result.get("is_suspicious_editor"):
            risk_score += 25.0
            flags.append(
                f"SUSPICIOUS_PDF_EDITOR ({pdf_result.get('creator', 'unknown')})"
            )

        if pdf_result.get("has_font_mismatch"):
            risk_score += 20.0
            flags.append(
                f"FONT_MISMATCH ({pdf_result.get('font_count', 0)} fonts, "
                f"{len(pdf_result.get('font_families', []))} families)"
            )

    # ── Aadhaar extraction ──
    aadhaar_results = extract_aadhaar_numbers(combined_text)
    invalid_aadhaar = [a for a in aadhaar_results if not a["verhoeff_valid"]]
    if invalid_aadhaar:
        risk_score += 30.0
        flags.append(f"INVALID_AADHAAR_CHECKSUM ({len(invalid_aadhaar)} found)")

    # ── PAN extraction ──
    pan_results = extract_pan_numbers(combined_text)

    # ── URL extraction (including defanged URLs) ──
    extracted_urls = extract_urls(combined_text, include_defanged=True)
    if pdf_result and "extracted_urls" in pdf_result:
        for u in pdf_result["extracted_urls"]:
            if u not in extracted_urls:
                extracted_urls.append(u)

    # ── Clamp score ──
    risk_score = max(0.0, min(100.0, risk_score))

    elapsed = (time.perf_counter() - start) * 1000

    return {
        "status": AgentStatusEnum.SUCCESS.value if hasattr(AgentStatusEnum, "SUCCESS") else "SUCCESS",
        "risk_score": round(risk_score, 2),
        "flags": flags,
        "aadhaar_numbers": aadhaar_results,
        "pan_numbers": pan_results,
        "extracted_urls": extracted_urls,
        "pdf_analysis": pdf_result,
        "latency_ms": round(elapsed, 2),
    }


def analyze_document_model(
    text: str,
    pdf_bytes: Optional[bytes] = None,
) -> DocumentAgentResult:
    """Convenience wrapper returning a typed DocumentAgentResult Pydantic model."""
    res = analyze_document(text=text, pdf_bytes=pdf_bytes)
    return DocumentAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=res["risk_score"],
        flags=res["flags"],
        aadhaar_numbers=res["aadhaar_numbers"],
        pan_numbers=res["pan_numbers"],
        extracted_urls=res["extracted_urls"],
        pdf_analysis=res.get("pdf_analysis"),
        details=f"Analysed document; {len(res['flags'])} flag(s) raised",
        latency_ms=res["latency_ms"],
    )
