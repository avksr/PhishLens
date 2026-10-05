# ============================================================
# OWNER: VANSH
# FILE: backend/core/db_logger.py
# PURPOSE: Async Dual-Engine Audit & Crowdsourced Scam Database
#          Supports Supabase Postgres (scans, reports, audit) with
#          automatic SQLite fallback. Zero PII leakage (GIGW 3.0).
# ============================================================

import os
import re
import uuid
import sqlite3
import asyncio
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

try:
    import aiosqlite
    HAS_AIOSQLITE = True
except ImportError:
    HAS_AIOSQLITE = False

try:
    import psycopg2
    from psycopg2 import sql
    from psycopg2.extras import RealDictCursor
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

from shared.models import ScanResponse, ScanRequest

logger = logging.getLogger("phishlens.db_logger")

DB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(DB_DIR, "phishlens_audit.db")

# Regex patterns for GIGW 3.0 PII Sanitization
PHONE_WITH_CC_RE = re.compile(r'(?:\+?91[\-\s]?)?([6-9]\d{2})\d{4}(\d{3})\b')
OTP_CONTEXT_RE = re.compile(
    r'\b(otp|code|pin|verification\s+code)(?:\s+is\s+|[\s:]+)(\d{4,8})\b',
    re.IGNORECASE
)
CARD_ENDING_RE = re.compile(r'\b(ending\s+in\s+|ending\s+)(\d{4})\b', re.IGNORECASE)
CARD_16_RE = re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b')


def get_postgres_url() -> Optional[str]:
    """Retrieve Postgres / Supabase URL if configured and non-empty."""
    url = (
        os.getenv("DATABASE_URL")
        or os.getenv("SUPABASE_DB_URL")
        or ""
    ).strip()
    if url.startswith("postgresql://") or url.startswith("postgres://"):
        return url
    return None


def is_production_mode() -> bool:
    """Check if the service is running in production mode."""
    prod_mode = os.getenv("PRODUCTION_MODE", "").strip().lower()
    if prod_mode in ("true", "1", "yes"):
        return True
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
    result = CARD_ENDING_RE.sub(r'\1****', result)
    result = CARD_16_RE.sub(r'****-****-****-****', result)
    result = OTP_CONTEXT_RE.sub(r'\1 ***', result)
    result = PHONE_WITH_CC_RE.sub(r'+91-\1***\2', result)
    return result


# ─────────────────────────────────────────────────────────────
# Database Schema Definitions (Dual Engine: Supabase / SQLite)
# ─────────────────────────────────────────────────────────────

def _ensure_sqlite_schema(conn: sqlite3.Connection):
    """Create scan_audit and reports tables with unique constraints and migration checks."""
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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            reporter_hash TEXT NOT NULL,
            target TEXT NOT NULL,
            type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            details TEXT,
            status TEXT DEFAULT 'ACTIVE',
            UNIQUE(reporter_hash, target)
        )
    """)
    cursor = conn.execute("PRAGMA table_info(scan_audit)")
    columns = [row[1] for row in cursor.fetchall()]
    if "input_hash" not in columns:
        conn.execute("ALTER TABLE scan_audit ADD COLUMN input_hash TEXT")
    conn.commit()


# Backward compatibility alias
_ensure_schema = _ensure_sqlite_schema


def _ensure_postgres_schema(pg_conn):
    """Ensure Postgres scan_audit and reports tables exist."""
    with pg_conn.cursor() as cur:
        cur.execute("""
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
            );
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                reporter_hash TEXT NOT NULL,
                target TEXT NOT NULL,
                type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT,
                status TEXT DEFAULT 'ACTIVE',
                UNIQUE(reporter_hash, target)
            );
        """)
        pg_conn.commit()


async def init_db():
    """Initialize DB schema on startup using Supabase Postgres or fallback SQLite."""
    pg_url = get_postgres_url()
    if pg_url and HAS_PSYCOPG2:
        try:
            loop = asyncio.get_running_loop()

            def _init_pg():
                with psycopg2.connect(pg_url) as conn:
                    _ensure_postgres_schema(conn)

            await loop.run_in_executor(None, _init_pg)
            logger.info("Database initialized with Supabase Postgres engine.")
            return
        except Exception as e:
            logger.warning(f"Could not connect to Supabase Postgres ({e}). Falling back to SQLite.")

    # SQLite Fallback
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
            await db.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY,
                    reporter_hash TEXT NOT NULL,
                    target TEXT NOT NULL,
                    type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT,
                    status TEXT DEFAULT 'ACTIVE',
                    UNIQUE(reporter_hash, target)
                )
            """)
            await db.commit()
    else:
        loop = asyncio.get_running_loop()

        def _sync_init():
            with sqlite3.connect(DB_PATH) as conn:
                _ensure_sqlite_schema(conn)

        await loop.run_in_executor(None, _sync_init)


# Module-level immediate initialization
try:
    with sqlite3.connect(DB_PATH) as _conn:
        _ensure_sqlite_schema(_conn)
except Exception as e:
    logger.warning(f"Could not initialize local SQLite schema on load: {e}")


# ─────────────────────────────────────────────────────────────
# Audit Log Methods (FR-10, §9, US-5)
# ─────────────────────────────────────────────────────────────

async def log_scan_audit(resp: ScanResponse, req: ScanRequest):
    """
    Asynchronously write PII-sanitized scan audit record to database.
    Computes SHA-256 input_hash and enforces zero raw text storage in production mode.
    """
    try:
        input_hash = hashlib.sha256(req.content.encode("utf-8")).hexdigest()
        sender_masked = mask_phone_number(req.sender) if req.sender else "UNKNOWN"

        if is_production_mode():
            content_masked = ""
        else:
            content_masked = mask_pii(req.content)

        risk_tier_val = resp.risk_tier.value if hasattr(resp.risk_tier, "value") else str(resp.risk_tier)
        action_val = resp.action_required.value if hasattr(resp.action_required, "value") else str(resp.action_required)

        query = """
        INSERT INTO scan_audit
        (scan_id, timestamp, input_hash, sender_masked, content_masked, overall_risk_score, risk_tier, action_required, verdict, latency_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            resp.verdict or "",
            resp.processing_time_ms
        )

        pg_url = get_postgres_url()
        if pg_url and HAS_PSYCOPG2:
            try:
                loop = asyncio.get_running_loop()

                def _pg_insert():
                    with psycopg2.connect(pg_url) as conn:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO scan_audit
                                (scan_id, timestamp, input_hash, sender_masked, content_masked, overall_risk_score, risk_tier, action_required, verdict, latency_ms)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                ON CONFLICT (scan_id) DO NOTHING
                            """, params)
                            conn.commit()

                await loop.run_in_executor(None, _pg_insert)
                return
            except Exception as pg_err:
                logger.warning(f"Supabase Postgres insert failed ({pg_err}), falling back to SQLite.")

        # SQLite Fallback
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
        logger.error(f"Error logging scan audit: {exc}", exc_info=True)


async def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full audit record for a given scan_id (US-5)."""
    query = """
    SELECT scan_id, timestamp, input_hash, sender_masked, content_masked,
           overall_risk_score, risk_tier, action_required, verdict, latency_ms
    FROM scan_audit WHERE scan_id = ?
    """
    for attempt in range(2):
        pg_url = get_postgres_url()
        if pg_url and HAS_PSYCOPG2:
            try:
                loop = asyncio.get_running_loop()

                def _pg_fetch():
                    with psycopg2.connect(pg_url) as conn:
                        with conn.cursor(cursor_factory=RealDictCursor) as cur:
                            cur.execute(
                                "SELECT * FROM scan_audit WHERE scan_id = %s",
                                (scan_id,)
                            )
                            row = cur.fetchone()
                            if row:
                                data = dict(row)
                                data["status"] = "COMPLETED"
                                return data
                    return None

                res = await loop.run_in_executor(None, _pg_fetch)
                if res:
                    return res
            except Exception as e:
                logger.debug(f"Postgres scan lookup fallback: {e}")

        # SQLite query
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


async def get_recent_scans(limit: int = 10) -> List[Dict[str, Any]]:
    """Retrieve recent PII-sanitized audit records."""
    limit = max(1, min(limit, 50))
    query = """
    SELECT scan_id, timestamp, input_hash, sender_masked, content_masked,
           overall_risk_score, risk_tier, action_required, verdict, latency_ms
    FROM scan_audit
    ORDER BY timestamp DESC
    LIMIT ?
    """
    try:
        pg_url = get_postgres_url()
        if pg_url and HAS_PSYCOPG2:
            try:
                loop = asyncio.get_running_loop()

                def _pg_fetch():
                    with psycopg2.connect(pg_url) as conn:
                        with conn.cursor(cursor_factory=RealDictCursor) as cur:
                            cur.execute(
                                "SELECT * FROM scan_audit ORDER BY timestamp DESC LIMIT %s",
                                (limit,)
                            )
                            return [dict(r) for r in cur.fetchall()]

                return await loop.run_in_executor(None, _pg_fetch)
            except Exception:
                pass

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
        logger.error(f"Error reading scan audits: {exc}", exc_info=True)
        return []


# Backward compatibility alias
get_scan_audit = get_scan_by_id


# ─────────────────────────────────────────────────────────────
# Crowdsourced Reports Table Methods (One report per reporter per target)
# ─────────────────────────────────────────────────────────────

async def add_crowdsourced_report(
    reporter_hash: Optional[str] = None,
    target: Optional[str] = None,
    report_type: Optional[str] = None,
    details: Optional[str] = None,
    *,
    target_handle: Optional[str] = None,
    target_type: Optional[str] = None,
    scam_category: Optional[str] = None,
    claimed_name: Optional[str] = None,
    reported_by: Optional[str] = None,
) -> Any:
    """
    Add a new scam report to the reports table.
    Enforces UNIQUE(reporter_hash, target): exactly one report per reporter per target.
    Supports both standard API call and legacy keyword signature.
    """
    is_legacy = target_handle is not None and target is None
    clean_target = (target or target_handle or "").strip().lower()
    clean_type = (report_type or target_type or scam_category or "scam").strip().lower()
    eff_reporter = reporter_hash or reported_by or "COMMUNITY_USER"
    report_id = f"rep_{uuid.uuid4().hex[:12]}"
    now_ts = datetime.now(timezone.utc).isoformat()

    full_details = details or ""
    if claimed_name:
        full_details = f"[Claimed: {claimed_name}] {full_details}".strip()

    record = {
        "id": report_id,
        "reporter_hash": eff_reporter,
        "target": clean_target,
        "type": clean_type,
        "timestamp": now_ts,
        "details": full_details,
        "status": "ACTIVE"
    }

    # Try Postgres if configured
    pg_url = get_postgres_url()
    if pg_url and HAS_PSYCOPG2:
        try:
            loop = asyncio.get_running_loop()

            def _pg_add():
                with psycopg2.connect(pg_url) as conn:
                    with conn.cursor(cursor_factory=RealDictCursor) as cur:
                        try:
                            cur.execute("""
                                INSERT INTO reports (id, reporter_hash, target, type, timestamp, details, status)
                                VALUES (%s, %s, %s, %s, %s, %s, %s)
                            """, (
                                record["id"], record["reporter_hash"], record["target"],
                                record["type"], record["timestamp"], record["details"], record["status"]
                            ))
                            conn.commit()
                            return True, "REPORT_CREATED"
                        except psycopg2.IntegrityError:
                            conn.rollback()
                            return False, "ALREADY_REPORTED"

            is_created, msg = await loop.run_in_executor(None, _pg_add)
            if is_legacy:
                return is_created
            return is_created, msg, record
        except Exception as e:
            logger.debug(f"Postgres report insert fallback: {e}")

    # SQLite Implementation
    if HAS_AIOSQLITE:
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute("""
                    INSERT INTO reports (id, reporter_hash, target, type, timestamp, details, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    record["id"], record["reporter_hash"], record["target"],
                    record["type"], record["timestamp"], record["details"], record["status"]
                ))
                await db.commit()
                if is_legacy:
                    return True
                return True, "REPORT_CREATED", record
        except sqlite3.IntegrityError:
            if is_legacy:
                return False
            return False, "ALREADY_REPORTED", record
        except Exception as e:
            logger.error(f"Failed to insert report into SQLite: {e}")
            if is_legacy:
                return False
            return False, "DATABASE_ERROR", record
    else:
        loop = asyncio.get_running_loop()

        def _sync_add():
            try:
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute("""
                        INSERT INTO reports (id, reporter_hash, target, type, timestamp, details, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        record["id"], record["reporter_hash"], record["target"],
                        record["type"], record["timestamp"], record["details"], record["status"]
                    ))
                    conn.commit()
                    return True, "REPORT_CREATED"
            except sqlite3.IntegrityError:
                return False, "ALREADY_REPORTED"
            except Exception:
                return False, "DATABASE_ERROR"

        is_created, msg = await loop.run_in_executor(None, _sync_add)
        if is_legacy:
            return is_created
        return is_created, msg, record


async def get_reports_by_target(target: str) -> List[Dict[str, Any]]:
    """Retrieve all crowdsourced reports matching target for OSINT agent."""
    clean_target = target.strip().lower()
    query = "SELECT * FROM reports WHERE target = ? ORDER BY timestamp DESC"

    pg_url = get_postgres_url()
    if pg_url and HAS_PSYCOPG2:
        try:
            loop = asyncio.get_running_loop()

            def _pg_get():
                with psycopg2.connect(pg_url) as conn:
                    with conn.cursor(cursor_factory=RealDictCursor) as cur:
                        cur.execute("SELECT * FROM reports WHERE target = %s ORDER BY timestamp DESC", (clean_target,))
                        return [dict(r) for r in cur.fetchall()]

            return await loop.run_in_executor(None, _pg_get)
        except Exception:
            pass

    if HAS_AIOSQLITE:
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(query, (clean_target,)) as cursor:
                    rows = await cursor.fetchall()
                    return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error fetching target reports: {e}")
            return []
    else:
        loop = asyncio.get_running_loop()

        def _fetch():
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute(query, (clean_target,))
                return [dict(r) for r in cur.fetchall()]

        return await loop.run_in_executor(None, _fetch)


# Backward compatibility alias
get_crowdsourced_reports = get_reports_by_target


async def get_recent_reports(limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieve most recent community scam reports."""
    limit = max(1, min(limit, 100))
    query = "SELECT id, target, type, timestamp, details, status FROM reports ORDER BY timestamp DESC LIMIT ?"

    if HAS_AIOSQLITE:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, (limit,)) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]
    else:
        loop = asyncio.get_running_loop()

        def _fetch():
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute(query, (limit,))
                return [dict(r) for r in cur.fetchall()]

        return await loop.run_in_executor(None, _fetch)


def verify_audit_privacy(record: Optional[Dict[str, Any]], raw_content: str) -> bool:
    """Verifies that raw content is not stored in the audit record when in production mode."""
    if not record:
        return True
    content_stored = record.get("content_masked")
    if content_stored is None or content_stored == "":
        return True
    if raw_content and raw_content in content_stored:
        return False
    return True
