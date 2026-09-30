# ============================================================
# OWNER: VANSH
# FILE: backend/core/db_logger.py
# PURPOSE: Async SQLite Audit Logger with GIGW 3.0 Zero PII Leakage
# ============================================================

import os
import re
import sqlite3
import asyncio
import logging
from typing import Optional

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

# 2. OTP numbers: e.g. "OTP 123456" -> "OTP ***", "code 654321" -> "code ***"
OTP_CONTEXT_RE = re.compile(r'\b(otp|code|pin|verification\s+code)[\s:]+(\d{4,8})\b', re.IGNORECASE)
OTP_STANDALONE_RE = re.compile(r'\b(?<!\w)(\d{4,6})(?!\w)\b')

# 3. Credit/Debit Card numbers: e.g. "ending 8812" -> "ending ****", 16-digit cards
CARD_ENDING_RE = re.compile(r'\b(ending\s+in\s+|ending\s+)(\d{4})\b', re.IGNORECASE)
CARD_16_RE = re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b')


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


async def init_db():
    """Ensure scan_audit table exists using aiosqlite or sqlite3."""
    sql = """
    CREATE TABLE IF NOT EXISTS scan_audit (
        scan_id TEXT PRIMARY KEY,
        timestamp TEXT,
        sender_masked TEXT,
        content_masked TEXT,
        overall_risk_score INTEGER,
        risk_tier TEXT,
        action_required TEXT,
        verdict TEXT,
        latency_ms REAL
    )
    """
    if HAS_AIOSQLITE:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(sql)
            await db.commit()
    else:
        loop = asyncio.get_running_loop()

        def _sync_init():
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(sql)
                conn.commit()
        await loop.run_in_executor(None, _sync_init)


# Initialize schema immediately on module load
try:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_audit (
                scan_id TEXT PRIMARY KEY,
                timestamp TEXT,
                sender_masked TEXT,
                content_masked TEXT,
                overall_risk_score INTEGER,
                risk_tier TEXT,
                action_required TEXT,
                verdict TEXT,
                latency_ms REAL
            )
        """)
        conn.commit()
except Exception as e:
    logger.warning(f"Could not initialize DB schema: {e}")


async def log_scan_audit(resp: ScanResponse, req: ScanRequest):
    """
    Asynchronously write PII-sanitized scan audit record to SQLite database.
    """
    try:
        sender_masked = mask_phone_number(req.sender) if req.sender else "UNKNOWN"
        content_masked = mask_pii(req.content)
        risk_tier_val = resp.risk_tier.value if hasattr(resp.risk_tier, "value") else str(resp.risk_tier)
        action_val = resp.action_required.value if hasattr(resp.action_required, "value") else str(resp.action_required)

        query = """
        INSERT OR REPLACE INTO scan_audit (
            scan_id, timestamp, sender_masked, content_masked,
            overall_risk_score, risk_tier, action_required, verdict, latency_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            resp.scan_id,
            resp.timestamp,
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


async def get_recent_scans(limit: int = 10) -> list[dict]:
    """
    Retrieve recent PII-sanitized audit records for evaluator inspection.
    """
    limit = max(1, min(limit, 50))
    query = """
    SELECT scan_id, timestamp, sender_masked, content_masked,
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
