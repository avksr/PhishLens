"""
backend/agents/osint_agent.py
------------------------------
Parallel OSINT Past History Search Agent for PhishLens (ScamShield AI).

Dual-Path Architecture:
- Path A (Internal): Checks PhishLens Crowdsourced DB (reported by others).
- Path B (External): Web scrapes public consumer complaint forums, Reddit, Twitter
  using DuckDuckGo / Google Custom Search JSON API with BeautifulSoup4.

Author  : ATHARV & AVNI — Threat Intelligence & Identity Forensics
Module  : PhishLens v2.0
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx
from bs4 import BeautifulSoup
from shared.models import (
    AgentStatusEnum,
    OsintHistoryResult,
    OsintReportItem,
    ScanRequest,
)

logger = logging.getLogger("phishlens.osint_agent")

_SCAM_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "crowdsourced_scams.json"
_UPI_VPA_RE = re.compile(r"\b([a-zA-Z0-9.\-_]{1,256}@[a-zA-Z0-9]{2,20})\b")
_INDIAN_PHONE_RE = re.compile(r"(?:\+?91[\-\s]?)?([6-9]\d{9})\b")


def _load_crowdsource_db() -> Dict[str, dict]:
    """Load internal crowdsourced scam database."""
    if _SCAM_DB_PATH.exists():
        try:
            with open(_SCAM_DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Error reading crowdsourced scam DB: {e}")
    return {}


def _extract_query_targets(req: ScanRequest) -> List[str]:
    """Extract candidate UPI handles and phone numbers for OSINT intelligence lookup."""
    corpus = f"{req.content} {req.sender or ''}"
    targets = []

    # 1. Check for UPI handles
    vpas = _UPI_VPA_RE.findall(corpus)
    for vpa in vpas:
        targets.append(vpa.lower().strip())

    # 2. Check for phone numbers
    phones = _INDIAN_PHONE_RE.findall(corpus)
    for p in phones:
        targets.append(f"+91{p.strip()}")

    # Sender itself if GSM phone
    if req.sender:
        cleaned_sender = re.sub(r"[\s\-]", "", req.sender)
        m = re.search(r"(?:\+?91)?([6-9]\d{9})$", cleaned_sender)
        if m:
            full_p = f"+91{m.group(1)}"
            if full_p not in targets:
                targets.append(full_p)

    return targets


async def _search_internal_db(target: str) -> Optional[dict]:
    """Path A: Search internal PhishLens crowdsourced scam database."""
    db = _load_crowdsource_db()
    upis = db.get("scam_upis", {})
    phones = db.get("scam_phones", {})

    target_clean = target.lower().strip()
    if target_clean in upis:
        return upis[target_clean]

    # Normalize phone match (+91 vs 10 digits)
    phone_digits = re.sub(r"\D", "", target_clean)
    if len(phone_digits) >= 10:
        ten_digit = phone_digits[-10:]
        for p_key, p_val in phones.items():
            if ten_digit in re.sub(r"\D", "", p_key):
                return p_val

    return None


_EXTERNAL_FORUM_UNAVAILABLE = False


def _is_offline() -> bool:
    """Check if external network requests should be bypassed."""
    return (
        os.getenv("OSINT_OFFLINE", "").lower() in ("1", "true", "yes")
        or os.getenv("PHISHLENS_OFFLINE", "").lower() in ("1", "true", "yes")
    )


async def _scrape_external_forums(target: str) -> Tuple[int, List[str]]:
    """
    Path B: Zero-cost public scraping via DuckDuckGo HTML search.
    Searches for consumer complaints and scam alerts related to target.
    Returns: (mention_count, [extracted_snippets])
    """
    global _EXTERNAL_FORUM_UNAVAILABLE
    if _is_offline() or _EXTERNAL_FORUM_UNAVAILABLE:
        return 0, []

    # If target is already known locally, return fast
    query = f'"{target}" (scam OR fraud OR complaint OR OLX)'
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        )
    }

    try:
        timeout_cfg = httpx.Timeout(0.4, connect=0.2)
        async with httpx.AsyncClient(timeout=timeout_cfg, follow_redirects=True) as client:
            res = await client.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                headers=headers,
            )
            if res.status_code == 200:
                soup = BeautifulSoup(res.text, "html.parser")
                snippets = []
                for result in soup.find_all("a", class_="result__snippet"):
                    text = result.get_text(strip=True)
                    if any(w in text.lower() for w in ["scam", "fraud", "complaint", "fake", "stolen", "police", "olx"]):
                        snippets.append(text)
                return len(snippets), snippets[:3]
    except (httpx.ConnectTimeout, httpx.ConnectError, httpx.ReadTimeout) as e:
        logger.debug(f"External forum scrape unavailable or timed out ({type(e).__name__}); tripping circuit breaker.")
        _EXTERNAL_FORUM_UNAVAILABLE = True
    except Exception as e:
        logger.debug(f"External forum scrape error for {target}: {e}")

    return 0, []


async def analyze_osint(req: ScanRequest) -> OsintHistoryResult:
    """
    Main entry point for Parallel OSINT Past History Search Agent.
    Runs Path A (Internal Crowdsource) & Path B (External Forum Scraping) concurrently.
    """
    t_start = time.perf_counter()
    targets = _extract_query_targets(req)

    if not targets:
        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)
        return OsintHistoryResult(
            status=AgentStatusEnum.SKIPPED,
            risk_score=0.0,
            query_target=None,
            total_complaints=0,
            internal_reports_count=0,
            external_forum_mentions=0,
            risk_level="CLEAN",
            details="No UPI ID or phone number found for OSINT past history lookup.",
            latency_ms=latency_ms,
        )

    # Analyze primary target (worst case / first)
    primary_target = targets[0]
    internal_record = await _search_internal_db(primary_target)

    # Run Path B external scrape if not offline and not already known locally
    if internal_record or _is_offline() or _EXTERNAL_FORUM_UNAVAILABLE:
        external_count, snippets = 0, []
    else:
        external_count, snippets = await _scrape_external_forums(primary_target)

    reports: List[OsintReportItem] = []
    flags: List[str] = []
    total_complaints = 0
    proof_snippet = None

    if internal_record:
        count = internal_record.get("complaint_count", 1)
        total_complaints += count
        category = internal_record.get("scam_category", "GENERAL_FRAUD")
        proof = internal_record.get("proof_summary", f"Flagged {count} times by PhishLens community.")
        proof_snippet = proof
        flags.append("CROWDSOURCED_SCAM_FLAGGED")
        flags.append(f"CATEGORY_{category}")

        reports.append(
            OsintReportItem(
                source="PhishLens Crowdsource DB",
                scam_category=category,
                details=proof,
                frequency_flagged=count,
                date_reported=internal_record.get("last_reported"),
            )
        )

    if external_count > 0:
        total_complaints += external_count
        flags.append("EXTERNAL_FORUM_COMPLAINTS_FOUND")
        for s in snippets:
            reports.append(
                OsintReportItem(
                    source="Public Forums / Web Scraping",
                    scam_category="PUBLIC_COMPLAINT",
                    details=s[:160] + "..." if len(s) > 160 else s,
                    frequency_flagged=1,
                )
            )
        if not proof_snippet:
            proof_snippet = f"Warning: {external_count} past complaints/scam reports found on public forums."

    # Compute OSINT risk score
    if total_complaints >= 5:
        risk_score = 95.0
        risk_level = "KNOWN_SCAMMER"
        flags.append("REPEAT_OFFENDER_SCAMMER")
    elif total_complaints >= 1:
        risk_score = 80.0
        risk_level = "HIGH_RISK"
    elif external_count > 0:
        risk_score = 65.0
        risk_level = "SUSPICIOUS"
    else:
        risk_score = 0.0
        risk_level = "CLEAN"

    if total_complaints > 0:
        details_str = (
            f"OSINT Investigation for '{primary_target}': {total_complaints} prior incident(s) flagged. "
            f"{proof_snippet or ''}"
        )
    else:
        details_str = f"OSINT Investigation for '{primary_target}': Clean history. No prior scam complaints found in crowdsourced databases."

    latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

    return OsintHistoryResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=risk_score,
        query_target=primary_target,
        total_complaints=total_complaints,
        internal_reports_count=internal_record.get("complaint_count", 0) if internal_record else 0,
        external_forum_mentions=external_count,
        risk_level=risk_level,
        proof_snippet=proof_snippet,
        reports=reports,
        flags=flags,
        details=details_str,
        latency_ms=latency_ms,
    )
