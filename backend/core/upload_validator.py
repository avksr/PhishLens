# ============================================================
# OWNER: VANSH
# FILE: backend/core/upload_validator.py
# PURPOSE: Upload Hardening: Magic-Byte Signature Verification
#          and Strict File Size Enforcement (GIGW 3.0 / CERT-In)
# ============================================================

import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("phishlens.upload_validator")

# Default max file upload size: 5MB
DEFAULT_MAX_SIZE_MB = 5.0

# Supported binary magic byte signatures
MAGIC_SIGNATURES = {
    "pdf": [b"%PDF"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpeg": [b"\xff\xd8\xff"],
    "webp": [b"RIFF"],  # With "WEBP" at byte 8
}


class UploadValidationError(Exception):
    """Base error for upload validation failure."""
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class UploadSizeExceededError(UploadValidationError):
    def __init__(self, message: str):
        super().__init__(message, status_code=413)


class InvalidFileSignatureError(UploadValidationError):
    def __init__(self, message: str):
        super().__init__(message, status_code=400)


def get_max_upload_size_bytes() -> int:
    """Read max upload size from MAX_UPLOAD_SIZE_MB, defaulting to 5MB."""
    try:
        mb = float(os.getenv("MAX_UPLOAD_SIZE_MB", str(DEFAULT_MAX_SIZE_MB)))
        return int(mb * 1024 * 1024)
    except Exception:
        return int(DEFAULT_MAX_SIZE_MB * 1024 * 1024)


def detect_file_type(content: bytes) -> Optional[Dict[str, str]]:
    """
    Examine the header magic bytes of raw file content.
    Returns dict with file_type ('pdf' | 'image') and mime_type, or None if unrecognized.
    """
    if not content or len(content) < 4:
        return None

    # 1. PDF Check
    if content.startswith(b"%PDF"):
        return {"file_type": "pdf", "mime_type": "application/pdf"}

    # 2. PNG Check
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return {"file_type": "image", "mime_type": "image/png"}

    # 3. JPEG Check
    if content.startswith(b"\xff\xd8\xff"):
        return {"file_type": "image", "mime_type": "image/jpeg"}

    # 4. WebP Check
    if content.startswith(b"RIFF") and len(content) >= 12 and content[8:12] == b"WEBP":
        return {"file_type": "image", "mime_type": "image/webp"}

    return None


def validate_upload_bytes(content: bytes, filename: Optional[str] = None) -> Dict[str, Any]:
    """
    Validates file payload before OCR or PDF parsing:
    1. Enforces strict size limit (< 5MB by default)
    2. Enforces magic-byte check (prevents extension spoofing / polyglots)
    """
    max_bytes = get_max_upload_size_bytes()
    size_bytes = len(content)

    # 1. Size limit check
    if size_bytes > max_bytes:
        max_mb = round(max_bytes / (1024 * 1024), 2)
        actual_mb = round(size_bytes / (1024 * 1024), 2)
        logger.warning(f"Rejected oversized upload: {actual_mb}MB exceeds limit of {max_mb}MB")
        raise UploadSizeExceededError(
            f"File size exceeds maximum allowed limit ({actual_mb}MB > {max_mb}MB). "
            f"Please compress or upload files under {max_mb}MB."
        )

    # 2. Magic-byte verification
    detected = detect_file_type(content)
    if not detected:
        logger.warning(f"Rejected upload with invalid magic bytes (filename='{filename}')")
        raise InvalidFileSignatureError(
            "Security validation failed: File signature (magic bytes) does not match a valid PDF or Image. "
            "Executable and polyglot files are strictly rejected."
        )

    return {
        "status": "VALID",
        "file_type": detected["file_type"],
        "mime_type": detected["mime_type"],
        "size_bytes": size_bytes,
        "filename": filename or "upload"
    }
