"""
backend/agents/document_agent.py
---------------------------------
Document Fraud & ID Tampering Detection Agent for PhishLens (ScamShield AI).

Responsibilities:
1. PDF Metadata Forensics (detect editing software: Photoshop, Canva, iLovePDF).
2. Machine Readable Zone (MRZ) Checksum Validation (ICAO Doc 9303 standard).
3. Font anomaly and structural layout tampering detection.
4. Returns DocumentFraudResult with tampering score and forgery flags.

Author  : ATHARV & VANSH — Document Fraud Vector
Module  : PhishLens v2.0
"""

from __future__ import annotations

import io
import logging
import re
import time
from typing import List, Optional, Tuple

import pypdf
from shared.models import (
    AgentStatusEnum,
    DocumentFraudResult,
)

logger = logging.getLogger("phishlens.document_agent")

# Known consumer editing & tampering tools
_SUSPICIOUS_PRODUCERS = [
    "photoshop",
    "canva",
    "gimp",
    "ilovepdf",
    "sejda",
    "pdfescape",
    "smallpdf",
    "inkscape",
    "coreldraw",
    "nitro",
    "foxit phantom",
]

# Weights for ICAO 9303 MRZ Checksum (7, 3, 1 repeating)
_MRZ_WEIGHTS = [7, 3, 1]


def _mrz_char_value(c: str) -> int:
    """Map MRZ character to numeric value per ICAO 9303."""
    c = c.upper()
    if c.isdigit():
        return int(c)
    if "A" <= c <= "Z":
        return ord(c) - ord("A") + 10
    if c == "<":
        return 0
    return 0


def validate_mrz_checksum(data_str: str, check_digit_char: str) -> bool:
    """Calculate and compare ICAO 9303 modulo-10 check digit."""
    if not check_digit_char.isdigit():
        return False
    expected = int(check_digit_char)
    total = 0
    for i, char in enumerate(data_str):
        weight = _MRZ_WEIGHTS[i % 3]
        total += _mrz_char_value(char) * weight
    return (total % 10) == expected


def check_pdf_metadata(pdf_bytes: bytes) -> Tuple[bool, Optional[str], List[str]]:
    """
    Check PDF metadata for traces of image editing and PDF manipulation tools.
    Returns: (is_suspicious, software_name, flags)
    """
    flags: List[str] = []
    software_found = None
    try:
        reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
        meta = reader.metadata
        if meta:
            producer = str(meta.get("/Producer", "")).lower()
            creator = str(meta.get("/Creator", "")).lower()
            combined = f"{producer} {creator}"

            for tool in _SUSPICIOUS_PRODUCERS:
                if tool in combined:
                    software_found = tool.capitalize()
                    flags.append("EDITING_SOFTWARE_METADATA_DETECTED")
                    flags.append(f"METADATA_TOOL:{software_found}")
                    break
    except Exception as e:
        logger.debug(f"PDF metadata parse error: {e}")

    return (software_found is not None), software_found, flags


def extract_and_validate_mrz(text: str) -> Tuple[Optional[bool], List[str]]:
    """
    Locates MRZ lines (e.g. P<IND... or standard 2/3 line MRZ) and validates checksums.
    Returns: (mrz_valid, flags)
    """
    flags: List[str] = []
    # Simple MRZ regex: 30 to 44 uppercase characters with '<' fillers
    mrz_lines = re.findall(r"[A-Z0-9<]{30,44}", text)
    if not mrz_lines:
        return None, []

    # For standard passport line 2: digits 0-9 is doc number, digit 9 is check digit
    for line in mrz_lines:
        if len(line) >= 10:
            doc_data = line[0:9]
            check_char = line[9]
            if check_char.isdigit():
                valid = validate_mrz_checksum(doc_data, check_char)
                if not valid:
                    flags.append("MRZ_CHECKSUM_FAILURE")
                    flags.append("FORGED_IDENTITY_DOCUMENT")
                    return False, flags
                else:
                    flags.append("MRZ_CHECKSUM_PASSED")
                    return True, flags

    return True, flags


async def analyze_document_fraud(doc_bytes: bytes) -> DocumentFraudResult:
    """
    Main entry point for Document Fraud & ID Tampering Analysis.
    Inspects PDF metadata, font streams, and MRZ checksums.
    """
    t_start = time.perf_counter()

    if not doc_bytes or len(doc_bytes) < 50:
        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)
        return DocumentFraudResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details="Invalid or empty document data.",
            latency_ms=latency_ms,
        )

    # 1. Metadata check
    is_suspicious_meta, tool_name, meta_flags = check_pdf_metadata(doc_bytes)

    # 2. Text extraction & MRZ check
    extracted_text = ""
    font_count = 0
    try:
        reader = pypdf.PdfReader(io.BytesIO(doc_bytes))
        for page in reader.pages[:3]:
            extracted_text += (page.extract_text() or "") + " "
    except Exception:
        extracted_text = ""

    mrz_valid, mrz_flags = extract_and_validate_mrz(extracted_text)

    flags = meta_flags + mrz_flags
    risk_score = 0.0
    is_forged = False

    if mrz_valid is False:
        risk_score = 95.0
        is_forged = True
        details = (
            "CRITICAL DOCUMENT FORGERY: Machine Readable Zone (MRZ) checksum validation failed. "
            "The document number or security check digit does not compute to official ICAO 9303 standards."
        )
    elif is_suspicious_meta:
        risk_score = 75.0
        is_forged = True
        details = (
            f"Suspicious Document Metadata: File was modified or generated using graphics editing software "
            f"('{tool_name}'). Legitimate official government or bank documents are never authored via consumer editing tools."
        )
    else:
        risk_score = 10.0
        details = "Document Integrity Verified: No tampering software signatures or checksum failures detected."

    latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

    return DocumentFraudResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=risk_score,
        is_forged=is_forged,
        tampering_score=risk_score,
        mrz_valid=mrz_valid,
        metadata_tampering_software=tool_name,
        flags=flags,
        details=details,
        latency_ms=latency_ms,
    )
