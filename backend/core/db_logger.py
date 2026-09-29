# ============================================================
# OWNER: VANSH
# FILE: backend/core/db_logger.py
# PURPOSE: SQLite Audit Logger with GIGW 3.0 Zero-Trust PII Masking
# ============================================================

import os
import re
import json
import sqlite3
import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from shared.models import ScanResponse, ScanRequest

logger = logging.getLogger("phishlens.db_logger")

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "audit_scans.db")

PHONE_PATTERN = re.compile(r'(\+?91[\-\s]?)?([6-9]\d{5})(\d{4})\b')
OTP_PATTERN = re.compile(r'\b(?<!\w)(\d{4,6})(?!\w)\b')


def mask_phone_number(sender: Optional[str]) -> str:
    """Mask 10-digit Indian mobile numbers preserving only last 4 digits."""
    if not sender:
        return "UNKNOWN"
    cleaned = re.sub(r'[\s\-]', '', sender)
    if re.search(r'[6-9]\d{9}$', cleaned):
        last4 = cleaned[-4:]
        return f"+91-XXXXX-{last4}"
    return sender


def mask_pii_content(content: str) -> str:
    """Scrub OTPs, passwords, and personal phone numbers from text payload."""
    if not content:
        return ""
    # Scrub 10-digit phones
    scrubbed = re.sub(r'\b[6-9]\d{9}\b', '[REDACTED_PHONE]', content)
    # Scrub 4 to 6-digit standalone codes/pins
    scrubbed = OTP_PATTERN.sub('[REDACTED_CREDENTIAL]', scrubbed)
    return scrubbed


class AuditLogger:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db_sync()

    def _init_db_sync(self):
        """Create audit log schema if not already present."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS scan_logs (
                        scan_id TEXT PRIMARY KEY,
                        timestamp TEXT,
                        channel TEXT,
                        masked_sender TEXT,
                        masked_content TEXT,
                        overall_risk_score INTEGER,
                        risk_tier TEXT,
                        action_required TEXT,
                        verdict TEXT,
                        recommendation TEXT,
                        processing_time_ms REAL,
                        audit_trail_json TEXT
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize SQLite database at {self.db_path}: {e}")

    async def log_scan(self, response: ScanResponse, raw_req: ScanRequest):
        """Asynchronously record PII-sanitized scan event."""
        masked_sender = mask_phone_number(raw_req.sender)
        masked_content = mask_pii_content(raw_req.content)
        audit_trail_json = json.dumps(response.audit_trail.model_dump())

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            self._insert_log_sync,
            response.scan_id,
            response.timestamp,
            raw_req.channel.value if hasattr(raw_req.channel, "value") else str(raw_req.channel),
            masked_sender,
            masked_content,
            response.overall_risk_score,
            response.risk_tier.value,
            response.action_required.value,
            response.verdict,
            response.recommendation,
            response.processing_time_ms,
            audit_trail_json
        )

    def _insert_log_sync(
        self, scan_id, timestamp, channel, masked_sender, masked_content,
        score, tier, action, verdict, recommendation, latency, audit_json
    ):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_logs (
                    scan_id, timestamp, channel, masked_sender, masked_content,
                    overall_risk_score, risk_tier, action_required, verdict,
                    recommendation, processing_time_ms, audit_trail_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id, timestamp, channel, masked_sender, masked_content,
                    score, tier, action, verdict, recommendation, latency, audit_json
                )
            )
            conn.commit()

    async def get_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent scans for audit dashboard."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._get_recent_logs_sync, limit)

    def _get_recent_logs_sync(self, limit: int) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM scan_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "scan_id": r["scan_id"],
                    "timestamp": r["timestamp"],
                    "channel": r["channel"],
                    "masked_sender": r["masked_sender"],
                    "masked_content": r["masked_content"],
                    "overall_risk_score": r["overall_risk_score"],
                    "risk_tier": r["risk_tier"],
                    "action_required": r["action_required"],
                    "verdict": r["verdict"],
                    "recommendation": r["recommendation"],
                    "processing_time_ms": r["processing_time_ms"],
                    "audit_trail": json.loads(r["audit_trail_json"] or "{}")
                })
            return results


audit_logger = AuditLogger()
