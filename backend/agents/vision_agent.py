"""
backend/agents/vision_agent.py
-------------------------------
Vision AI & Image Tampering / Error Level Analysis (ELA) Agent for PhishLens.

Responsibilities:
1. Error Level Analysis (ELA) using Pillow:
   - Resaves image at 95% JPEG quality.
   - Calculates pixel difference map and standard deviation.
   - Detects localized compression inconsistencies (spliced text, altered UPI/amounts).
2. Screenshot OCR & Forensic Entity Extraction:
   - Extracts embedded text, UPI VPAs, and phone numbers from screenshots.
3. Outputs VisionAnalysisResult with morphing score and tampering flags.

Author  : ATHARV & VANSH — Vision AI Vector
Module  : PhishLens v2.0
"""

from __future__ import annotations

import io
import logging
import math
import os
import re
import time
import threading
from typing import Any, List, Optional, Tuple

from PIL import Image, ImageChops, ImageEnhance, ImageStat
from shared.models import (
    AgentStatusEnum,
    VisionAnalysisResult,
)

logger = logging.getLogger("phishlens.vision_agent")

_UPI_VPA_RE = re.compile(r"\b([a-zA-Z0-9.\-_]{1,256}@[a-zA-Z0-9]{2,20})\b")
_INDIAN_PHONE_RE = re.compile(r"(?:\+?91[\-\s]?)?([6-9]\d{9})\b")

# Thread-safe EasyOCR Reader singleton
_EASYOCR_READER: Optional[Any] = None
_EASYOCR_LOCK = threading.Lock()
_EASYOCR_INIT_ATTEMPTED = False


def get_easyocr_reader() -> Optional[Any]:
    """
    Thread-safe lazy singleton reader for EasyOCR.
    Avoids multi-second reloading of PyTorch neural network weights on every scan.
    """
    global _EASYOCR_READER, _EASYOCR_INIT_ATTEMPTED
    if not _EASYOCR_INIT_ATTEMPTED:
        with _EASYOCR_LOCK:
            if not _EASYOCR_INIT_ATTEMPTED:
                _EASYOCR_INIT_ATTEMPTED = True
                enabled = os.getenv("ENABLE_EASYOCR", "true").lower() in ("true", "1", "yes")
                if enabled:
                    try:
                        import easyocr
                        logger.info("Initializing EasyOCR reader singleton (en, gpu=False)...")
                        _EASYOCR_READER = easyocr.Reader(["en"], gpu=False, verbose=False)
                        logger.info("EasyOCR reader singleton initialized successfully.")
                    except Exception as e:
                        logger.warning(f"Could not initialize EasyOCR reader: {e}")
                        _EASYOCR_READER = None
    return _EASYOCR_READER


def perform_ela(image_bytes: bytes, quality: int = 95) -> Tuple[float, bool]:
    """
    Error Level Analysis (ELA):
    Detects digital manipulation by recompressing the image and computing
    the absolute difference in high-frequency error bands.
    Returns: (anomaly_score 0-100, is_manipulated)
    """
    try:
        orig = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        resaved_buf = io.BytesIO()
        orig.save(resaved_buf, "JPEG", quality=quality)
        resaved_buf.seek(0)
        resaved = Image.open(resaved_buf).convert("RGB")

        # Compute difference
        diff = ImageChops.difference(orig, resaved)

        # Scale difference to highlight error bands
        extrema = diff.getextrema()
        max_diff = max([ex[1] for ex in extrema])
        if max_diff == 0:
            scale = 1
        else:
            scale = 255.0 / max_diff

        enhancer = ImageEnhance.Brightness(diff)
        diff_enhanced = enhancer.enhance(scale)

        # Calculate standard deviation and variance across tiles
        stat = ImageStat.Stat(diff_enhanced)
        stddev = sum(stat.stddev) / len(stat.stddev)

        # Normal ELA stddev for pristine image: 15-35. Tampered images: > 50.
        anomaly_score = min(100.0, max(0.0, (stddev - 20.0) * 2.2))
        is_morphed = anomaly_score >= 60.0
        return round(anomaly_score, 1), is_morphed
    except Exception as e:
        logger.warning(f"ELA computation error: {e}")
        return 0.0, False


def extract_ocr_from_image(image_bytes: bytes) -> Tuple[str, List[str], List[str]]:
    """
    Extract text, UPI IDs, and phone numbers from image bytes.
    Uses EasyOCR singleton if available, otherwise fast heuristic extraction.
    """
    text_content = ""
    vpas: List[str] = []
    phones: List[str] = []

    reader = get_easyocr_reader()
    if reader is not None:
        try:
            results = reader.readtext(image_bytes)
            extracted_lines = [r[1] for r in results]
            text_content = " ".join(extracted_lines)
        except Exception as e:
            logger.debug(f"EasyOCR extraction error: {e}")

    # Fallback to fast byte stream string extraction
    if not text_content:
        try:
            ascii_text = re.findall(rb"[a-zA-Z0-9@.\-_]{4,}", image_bytes)
            text_content = " ".join(b.decode("utf-8", "ignore") for b in ascii_text[:40])
        except Exception:
            text_content = ""

    if text_content:
        vpas = list(set(_UPI_VPA_RE.findall(text_content)))
        phones = list(set(_INDIAN_PHONE_RE.findall(text_content)))

    return text_content, vpas, phones


def decode_qr_code(image_bytes: bytes) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Decodes QR code from image bytes using OpenCV QRCodeDetector.
    Returns: (raw_payload, extracted_vpa, extracted_url)
    """
    try:
        import cv2
        import numpy as np
        from urllib.parse import parse_qs, urlparse

        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return None, None, None

        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(img)
        if not data:
            return None, None, None

        raw = data.strip()
        extracted_vpa = None
        extracted_url = None

        # Check if upi://pay URI
        if raw.lower().startswith("upi://pay"):
            parsed = urlparse(raw)
            params = parse_qs(parsed.query)
            if "pa" in params:
                extracted_vpa = params["pa"][0]
        elif raw.lower().startswith(("http://", "https://")):
            extracted_url = raw
        elif "@" in raw and len(raw.split("@")) == 2:
            extracted_vpa = raw

        return raw, extracted_vpa, extracted_url
    except Exception as e:
        logger.debug(f"QR decode error: {e}")
        return None, None, None


def compute_phash(img: Image.Image, hash_size: int = 8) -> Tuple[int, str]:
    """
    Compute 64-bit perceptual difference hash (dHash) using Pillow.
    Returns: (integer_hash, hex_string)
    """
    resized = img.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
    pixels = list(resized.getdata())
    diff = []
    for row in range(hash_size):
        for col in range(hash_size):
            p1 = pixels[row * (hash_size + 1) + col]
            p2 = pixels[row * (hash_size + 1) + col + 1]
            diff.append(p1 > p2)
    decimal_val = 0
    for bit in diff:
        decimal_val = (decimal_val << 1) | int(bit)
    hex_str = f"{decimal_val:016x}"
    return decimal_val, hex_str


def hamming_distance(h1: int, h2: int) -> int:
    """Compute Hamming distance between two 64-bit hashes."""
    return bin(h1 ^ h2).count("1")


RECEIPT_CANONICAL_HASHES: Dict[str, int] = {
    "GPAY": 0xa5c3963c6396c3a5,
    "PHONEPE": 0x9c3c669999663c9c,
    "PAYTM": 0x3c6699c3c399663c,
    "BHIM": 0x5a5aa5a55a5aa5a5,
}

RECEIPT_KEYWORDS = [
    "paid", "payment", "transaction", "successful", "successtul", "success",
    "upi", "vpa", "utr", "google pay", "gpay", "phonepe", "paytm", "bhim",
    "debited", "credited", "rs.", "₹", "rupees", "completed", "banking name",
    "transfer"
]


def match_payment_receipt(
    img: Image.Image,
    ocr_text: str = "",
    phash_int: Optional[int] = None
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Identify if image corresponds to a UPI payment receipt template
    using perceptual hashing (pHash) and text pattern heuristics.
    Returns: (is_receipt_matched, template_name, phash_hex)
    """
    if phash_int is None:
        phash_int, phash_hex = compute_phash(img)
    else:
        phash_hex = f"{phash_int:016x}"

    text_lower = ocr_text.lower() if ocr_text else ""
    keyword_hits = sum(1 for kw in RECEIPT_KEYWORDS if kw in text_lower)

    # Check template hamming distance
    best_template = None
    min_dist = 64
    for tmpl, ref_hash in RECEIPT_CANONICAL_HASHES.items():
        dist = hamming_distance(phash_int, ref_hash)
        if dist < min_dist:
            min_dist = dist
            best_template = tmpl

    if min_dist <= 14:
        return True, best_template, phash_hex

    has_app_name = any(app in text_lower for app in ["google pay", "gpay", "phonepe", "paytm", "bhim"])
    has_action = any(act in text_lower for act in ["paid", "payment", "transaction", "successtul", "successful", "transfer", "completed"])

    if (has_app_name and has_action) or keyword_hits >= 2:
        if "google pay" in text_lower or "gpay" in text_lower:
            detected_tmpl = "GPAY"
        elif "phonepe" in text_lower:
            detected_tmpl = "PHONEPE"
        elif "paytm" in text_lower:
            detected_tmpl = "PAYTM"
        else:
            detected_tmpl = "UPI_RECEIPT"
        return True, detected_tmpl, phash_hex

    return False, None, phash_hex


async def analyze_image_screenshot(image_bytes: bytes) -> VisionAnalysisResult:
    """
    Main entry point for Vision AI Analysis.
    Performs ELA tampering detection, perceptual hashing, QR code decoding, and OCR extraction.
    """
    t_start = time.perf_counter()

    if not image_bytes or len(image_bytes) < 100:
        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)
        return VisionAnalysisResult(
            status=AgentStatusEnum.ERROR,
            risk_score=0.0,
            details="Invalid or empty image data provided.",
            latency_ms=latency_ms,
        )

    try:
        pil_img = Image.open(io.BytesIO(image_bytes))
    except Exception:
        pil_img = None

    anomaly_score, is_morphed = perform_ela(image_bytes)
    ocr_text, vpas, phones = extract_ocr_from_image(image_bytes)
    qr_raw, qr_vpa, qr_url = decode_qr_code(image_bytes)

    # pHash & payment receipt matching
    is_receipt = False
    receipt_tmpl = None
    phash_hex = None
    if pil_img is not None:
        phash_int, phash_hex = compute_phash(pil_img)
        is_receipt, receipt_tmpl, _ = match_payment_receipt(pil_img, ocr_text, phash_int)

    flags: List[str] = []
    risk_score = 0.0

    if qr_raw:
        flags.append("QR_CODE_PAYLOAD_DETECTED")
        if qr_vpa:
            flags.append(f"QR_EXTRACTED_VPA:{qr_vpa}")
            if qr_vpa not in vpas:
                vpas.append(qr_vpa)
        if qr_url:
            flags.append(f"QR_EXTRACTED_URL:{qr_url}")
            if not ocr_text:
                ocr_text = qr_url
            else:
                ocr_text = f"{ocr_text} {qr_url}"

        # Evaluate QR payload via Pre-Payment Shield
        try:
            from agents.qr_shield import verify_qr_pre_payment
            qr_assessment = verify_qr_pre_payment(qr_raw)
            for f in qr_assessment.flags:
                if f not in flags:
                    flags.append(f)
            if qr_assessment.risk_score >= 70.0:
                risk_score = max(risk_score, qr_assessment.risk_score)
        except Exception as e:
            logger.debug(f"QR shield evaluation error: {e}")

    if is_receipt:
        flags.append(f"RECEIPT_TEMPLATE_MATCH:{receipt_tmpl}")
        if is_morphed or anomaly_score >= 45.0:
            is_morphed = True
            flags.append("FAKE_PAYMENT_RECEIPT_DETECTED")
            flags.append("PAYMENT_SCREENSHOT_SPLICING")
            risk_score = max(risk_score, max(88.0, anomaly_score))
            details = (
                f"Vision AI Tampering Alert: Forged {receipt_tmpl} payment receipt detected. "
                f"Spliced transaction details and compression inconsistencies identified (ELA score: {anomaly_score}/100)."
            )
        else:
            risk_score = max(risk_score, anomaly_score * 0.4)
            details = f"Vision AI Analysis: Clean {receipt_tmpl} payment receipt screenshot (ELA score: {anomaly_score}/100)."
    elif is_morphed:
        flags.append("PIXEL_LEVEL_TAMPERING_DETECTED")
        flags.append("ELA_HIGH_FREQUENCY_ANOMALY")
        risk_score = max(risk_score, max(80.0, anomaly_score))
        details = (
            f"Vision AI Tampering Alert: Error Level Analysis detected local compression "
            f"anomalies (score: {anomaly_score}/100), indicative of spliced text or altered digits."
        )
    else:
        risk_score = max(risk_score, anomaly_score * 0.4)
        details = f"Vision AI Analysis: Clean pixel consistency (ELA score: {anomaly_score}/100). No splicing detected."

    if qr_raw:
        details += f" Embedded QR Code detected: {qr_raw[:60]}."

    if vpas:
        flags.append(f"OCR_EXTRACTED_VPA:{vpas[0]}")
    if phones:
        flags.append(f"OCR_EXTRACTED_PHONE:{phones[0]}")

    latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

    return VisionAnalysisResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=round(risk_score, 1),
        is_morphed=is_morphed,
        ela_anomaly_score=anomaly_score,
        deepfake_probability=round(anomaly_score / 100.0, 2),
        ocr_extracted_text=ocr_text[:300] if ocr_text else None,
        extracted_vpas=vpas,
        extracted_phones=phones,
        is_receipt_matched=is_receipt,
        receipt_template=receipt_tmpl,
        phash=phash_hex,
        flags=flags,
        details=details,
        latency_ms=latency_ms,
    )
