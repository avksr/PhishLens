# ============================================================
# OWNER: VANSH
# FILE: backend/core/db_logger.py
# PURPOSE: Async SQLite Audit Logger with GIGW 3.0 Zero PII Leakage & Privacy Hardening
# ============================================================

import os
import re
import sqlite3
import asyncio
import hashlib
import logging
from typing import Optional, Dict, Any, List

try:
    import aiosqlite
    HAS_AIOSQLITE = True
except ImportError:
    HAS_AIOSQLITE = False

from shared.models import ScanResponse, ScanRequest

logger = logging.getLogger("phishlens.db_logger")

DB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(DB_DIR, "phishlens_audit.db")

# Regex patterns for GIGW 3.0 PII Sanitization
# 1. Indian 10-digit mobile number: e.g., +919876543210 or 9876543210 -> +91-987***210
PHONE_WITH_CC_RE = re.compile(r'(?:\+?91[\-\s]?)?([6-9]\d{2})\d{4}(\d{3})\b')

# 2. OTP numbers: e.g. "OTP 123456" -> "OTP ***", "code 654321" -> "code ***", "OTP is 112233"
OTP_CONTEXT_RE = re.compile(
    r'\b(otp|code|pin|verification\s+code)(?:\s+is\s+|[\s:]+)(\d{4,8})\b',
    re.IGNORECASE
)
OTP_STANDALONE_RE = re.compile(r'\b(?<!\w)(\d{4,6})(?!\w)\b')

# 3. Credit/Debit Card numbers: e.g. "ending 8812" -> "ending ****", 16-digit cards
CARD_ENDING_RE = re.compile(r'\b(ending\s+in\s+|ending\s+)(\d{4})\b', re.IGNORECASE)
CARD_16_RE = re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b')


def is_production_mode() -> bool:
    """
    Check if the service is running in production mode.
    Reads ENVIRONMENT, APP_ENV, PHISHLENS_ENV, ENV, or PRODUCTION.
    """
    env = (
        os.getenv("ENVIRONMENT")
        or os.getenv("APP_ENV")
        or os.getenv("PHISHLENS_ENV")
        or os.getenv("ENV")
        or ""
    ).strip().lower()
    return env in ("production", "prod") or os.getenv("PRODUCTION", "").strip().lower() in ("1", "true", "yes")


def mask_phone_number(sender: Optional[str]) -> str:
    """Mask Indian phone numbers to format +91-987***210."""
    if not sender:
        return "UNKNOWN"
    cleaned = re.sub(r'[\s\-]', '', sender)
    m = re.search(r'(?:\+?91)?([6-9]\d{2})\d{4}(\d{3})$', cleaned)
    if m:
        return f"+91-{m.group(1)}***{m.group(2)}"
    return sender


def mask_pii(text: Optional[str]) -> str:
    """
    GIGW 3.0 Zero PII Leakage Function:
    - Automatically scrubs Indian mobile numbers (+91-987***210)
    - Automatically scrubs OTP numbers (***)
    - Automatically scrubs card numbers (ending ****)
    """
    if not text:
        return ""

    result = str(text)

    # 1. Mask card endings and 16-digit card numbers
    result = CARD_ENDING_RE.sub(r'\1****', result)
    result = CARD_16_RE.sub(r'****-****-****-****', result)

    # 2. Mask contextual OTP numbers: "OTP 123456" -> "OTP ***"
    result = OTP_CONTEXT_RE.sub(r'\1 ***', result)

    # 3. Mask Indian 10-digit mobile numbers: e.g. 9876543210 -> +91-987***210
    result = PHONE_WITH_CC_RE.sub(r'+91-\1***\2', result)

    return result


def _ensure_schema(conn: sqlite3.Connection):
    """Ensure scan_audit table exists and has input_hash column."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_audit (
            scan_id TEXT PRIMARY KEY,
            timestamp TEXT,
            input_hash TEXT,
            sender_masked TEXT,
            content_masked TEXT,
            overall_risk_score INTEGER,
            risk_tier TEXT,
            action_required TEXT,
            verdict TEXT,
            latency_ms REAL
        )
    """)
    cursor = conn.execute("PRAGMA table_info(scan_audit)")
    columns = [row[1] for row in cursor.fetchall()]
    if "input_hash" not in columns:
        conn.execute("ALTER TABLE scan_audit ADD COLUMN input_hash TEXT")
    conn.commit()


async def init_db():
    """Ensure scan_audit table exists using aiosqlite or sqlite3."""
    if HAS_AIOSQLITE:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS scan_audit (
                    scan_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    input_hash TEXT,
                    sender_masked TEXT,
                    content_masked TEXT,
                    overall_risk_score INTEGER,
                    risk_tier TEXT,
                    action_required TEXT,
                    verdict TEXT,
                    latency_ms REAL
                )
            """)
            cursor = await db.execute("PRAGMA table_info(scan_audit)")
            rows = await cursor.fetchall()
            columns = [r[1] for r in rows]
            if "input_hash" not in columns:
                await db.execute("ALTER TABLE scan_audit ADD COLUMN input_hash TEXT")
            await db.commit()
    else:
        loop = asyncio.get_running_loop()

        def _sync_init():
            with sqlite3.connect(DB_PATH) as conn:
                _ensure_schema(conn)

        await loop.run_in_executor(None, _sync_init)


# Initialize schema immediately on module load
try:
    with sqlite3.connect(DB_PATH) as _conn:
        _ensure_schema(_conn)
except Exception as e:
    logger.warning(f"Could not initialize DB schema: {e}")


async def log_scan_audit(resp: ScanResponse, req: ScanRequest):
    """
    Asynchronously write PII-sanitized scan audit record to SQLite database.
    Computes SHA-256 input_hash and enforces zero raw text storage in production mode (FR-10 & §9).
    """
    try:
        # Audit Privacy Hardening (FR-10 & §9): Compute SHA-256 hash of content
        input_hash = hashlib.sha256(req.content.encode("utf-8")).hexdigest()

        sender_masked = mask_phone_number(req.sender) if req.sender else "UNKNOWN"

        # Verify no raw text is stored when in production mode
        if is_production_mode():
            content_masked = None
        else:
            content_masked = mask_pii(req.content)

        risk_tier_val = resp.risk_tier.value if hasattr(resp.risk_tier, "value") else str(resp.risk_tier)
        action_val = resp.action_required.value if hasattr(resp.action_required, "value") else str(resp.action_required)

        query = """
        INSERT OR REPLACE INTO scan_audit (
            scan_id, timestamp, input_hash, sender_masked, content_masked,
            overall_risk_score, risk_tier, action_required, verdict, latency_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            resp.scan_id,
            resp.timestamp,
            input_hash,
            sender_masked,
            content_masked,
            resp.overall_risk_score,
            risk_tier_val,
            action_val,
            resp.verdict,
            resp.processing_time_ms
        )

        if HAS_AIOSQLITE:
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute(query, params)
                await db.commit()
        else:
            loop = asyncio.get_running_loop()

            def _insert():
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute(query, params)
                    conn.commit()

            await loop.run_in_executor(None, _insert)

    except Exception as exc:
        logger.error(f"Error logging scan to SQLite: {exc}", exc_info=True)


async def get_recent_scans(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Retrieve recent PII-sanitized audit records for evaluator inspection.
    """
    limit = max(1, min(limit, 50))
    query = """
    SELECT scan_id, timestamp, input_hash, sender_masked, content_masked,
           overall_risk_score, risk_tier, action_required, verdict, latency_ms
    FROM scan_audit
    ORDER BY timestamp DESC
    LIMIT ?
    """
    try:
        if HAS_AIOSQLITE:
            async with aiosqlite.connect(DB_PATH) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(query, (limit,)) as cursor:
                    rows = await cursor.fetchall()
                    return [dict(row) for row in rows]
        else:
            loop = asyncio.get_running_loop()

            def _fetch():
                with sqlite3.connect(DB_PATH) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    cursor.execute(query, (limit,))
                    return [dict(row) for row in cursor.fetchall()]

            return await loop.run_in_executor(None, _fetch)
    except Exception as exc:
        logger.error(f"Error reading scan audits from SQLite: {exc}", exc_info=True)
        return []


async def get_scan_audit(scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves full execution status and audit record for a given scan_id from SQLite (US-5).
    Yields briefly if the record was just dispatched to SQLite to prevent race conditions.
    """
    query = """
    SELECT scan_id, timestamp, input_hash, sender_masked, content_masked,
           overall_risk_score, risk_tier, action_required, verdict, latency_ms
    FROM scan_audit WHERE scan_id = ?
    """
    for attempt in range(2):
        if HAS_AIOSQLITE:
            async with aiosqlite.connect(DB_PATH) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(query, (scan_id,)) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        data = dict(row)
                        data["status"] = "COMPLETED"
                        return data
        else:
            loop = asyncio.get_running_loop()

            def _fetch():
                with sqlite3.connect(DB_PATH) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    cursor.execute(query, (scan_id,))
                    row = cursor.fetchone()
                    if row:
                        data = dict(row)
                        data["status"] = "COMPLETED"
                        return data
                    return None

            result = await loop.run_in_executor(None, _fetch)
            if result:
                return result

        if attempt == 0:
            await asyncio.sleep(0.05)

    return None


def verify_audit_privacy(record: Optional[Dict[str, Any]], raw_content: str) -> bool:
    """
    Verifies that raw content is not stored in the audit record when in production mode (FR-10 & §9).
    """
    if not record:
        return True
    content_stored = record.get("content_masked")
    if content_stored is None:
        return True
    if raw_content and raw_content in content_stored:
        return False
    return True
