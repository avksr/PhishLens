# ============================================================
# OWNER: VANSH & ATHARV
# FILE: backend/agents/osint_agent.py
# PURPOSE: Parallel OSINT Past History Search Agent for PhishLens
#          Multi-Source Intelligence:
#          - Path 1: Internal DB (crowdsourced_scams.json + reports table)
#          - Path 2: Brave Search API (with ProviderBudget & TTL cache)
#          - Path 3: Reddit API / Search (with ProviderBudget & TTL cache)
#          - Path 4: DuckDuckGo scraping (behind flag, OFF by default)
# ============================================================

from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import httpx

try:
    from bs4 import BeautifulSoup
    HAS_BEAUTIFULSOUP = True
except ImportError:
    BeautifulSoup = None
    HAS_BEAUTIFULSOUP = False

try:
    from shared.models import (
        AgentStatusEnum,
        OsintHistoryResult,
        OsintReportItem,
        ScanRequest,
    )
    from core.provider_budget import provider_budget
    from core.db_logger import get_reports_by_target
except ImportError:
    from backend.shared.models import (
        AgentStatusEnum,
        OsintHistoryResult,
        OsintReportItem,
        ScanRequest,
    )
    from backend.core.provider_budget import provider_budget
    from backend.core.db_logger import get_reports_by_target

logger = logging.getLogger("phishlens.osint_agent")

_SCAM_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "crowdsourced_scams.json"
_UPI_VPA_RE = re.compile(r"\b([a-zA-Z0-9.\-_]{1,256}@[a-zA-Z0-9]{2,20})\b")
_INDIAN_PHONE_RE = re.compile(r"(?:\+?91[\-\s]?)?([6-9]\d{9})\b")


def _load_crowdsource_db() -> Dict[str, dict]:
    """Load internal static crowdsourced scam database."""
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
        t = vpa.lower().strip()
        if t not in targets:
            targets.append(t)

    # 2. Check for phone numbers
    phones = _INDIAN_PHONE_RE.findall(corpus)
    for p in phones:
        t = f"+91{p.strip()}"
        if t not in targets:
            targets.append(t)

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
    """
    Path 1: Search internal PhishLens static DB + dynamic community reports table.
    """
    target_clean = target.lower().strip()

    # 1. Check static crowdsourced scam DB
    db = _load_crowdsource_db()
    upis = db.get("scam_upis", {})
    phones = db.get("scam_phones", {})

    if target_clean in upis:
        return upis[target_clean]

    # Phone number match
    phone_digits = re.sub(r"\D", "", target_clean)
    if len(phone_digits) >= 10:
        ten_digit = phone_digits[-10:]
        for p_key, p_val in phones.items():
            if ten_digit in re.sub(r"\D", "", p_key):
                return p_val

    # 2. Check dynamic database reports table
    try:
        dynamic_reports = await get_reports_by_target(target_clean)
        if dynamic_reports:
            count = len(dynamic_reports)
            latest = dynamic_reports[0]
            return {
                "scam_category": f"COMMUNITY_REPORTED_{latest.get('type', 'SCAM').upper()}",
                "complaint_count": count,
                "proof_summary": f"Reported {count} time(s) by PhishLens verified community reporters.",
                "last_reported": latest.get("timestamp"),
            }
    except Exception as e:
        logger.debug(f"Error querying dynamic reports table for {target}: {e}")

    return None


def is_ddg_scraping_enabled() -> bool:
    """DuckDuckGo scraping is OFF by default and requires explicit opt-in flag."""
    return os.getenv("ENABLE_DDG_SCRAPING", "false").strip().lower() in ("true", "1", "yes")


def _is_offline() -> bool:
    """Check if external network requests should be bypassed."""
    return (
        os.getenv("OSINT_OFFLINE", "").lower() in ("1", "true", "yes")
        or os.getenv("PHISHLENS_OFFLINE", "").lower() in ("1", "true", "yes")
    )


async def _search_brave_api(target: str) -> Tuple[int, List[str]]:
    """
    Path 2: Brave Search API with rate counter & TTL cache.
    Cache hits NEVER consume quota.
    """
    if _is_offline():
        return 0, []

    brave_key = (os.getenv("BRAVE_API_KEY") or os.getenv("BRAVE_SEARCH_API_KEY") or "").strip()
    if not brave_key:
        return 0, []

    # Check TTL cache first (cache hits do NOT consume quota)
    cached = provider_budget.get_cached("brave_search", target)
    if cached is not None:
        return cached

    # Check provider budget limit
    if not provider_budget.acquire("brave_search"):
        logger.warning(f"[OSINT] Brave Search rate limit reached. Skipping API call for {target}.")
        return 0, []

    query = f'"{target}" (scam OR fraud OR cyber crime OR complaint)'
    url = "https://api.search.brave.com/res/v1/web/search"
    headers = {
        "Accept": "application/json",
        "X-Subscription-Token": brave_key,
        "User-Agent": "PhishLens-ScamShield/1.0"
    }

    try:
        timeout_cfg = httpx.Timeout(1.2, connect=0.5)
        async with httpx.AsyncClient(timeout=timeout_cfg) as client:
            res = await client.get(url, params={"q": query, "count": 5}, headers=headers)
            if res.status_code == 200:
                data = res.json()
                results = data.get("web", {}).get("results", [])
                snippets = []
                for r in results:
                    desc = r.get("description", "")
                    if any(w in desc.lower() for w in ["scam", "fraud", "complaint", "fake", "stolen", "cyber"]):
                        snippets.append(desc)
                result_tuple = (len(snippets), snippets[:3])
                provider_budget.set_cached("brave_search", target, result_tuple, ttl=600)
                return result_tuple
    except Exception as exc:
        logger.debug(f"[OSINT] Brave Search error for {target}: {exc}")

    return 0, []


async def _search_reddit_api(target: str) -> Tuple[int, List[str]]:
    """
    Path 3: Reddit API Search with rate counter & TTL cache.
    Searches r/Scams, r/india for community fraud mentions.
    """
    if _is_offline():
        return 0, []

    cached = provider_budget.get_cached("reddit", target)
    if cached is not None:
        return cached

    if not provider_budget.acquire("reddit"):
        logger.warning(f"[OSINT] Reddit API rate limit reached. Skipping for {target}.")
        return 0, []

    query = f'"{target}" scam'
    url = "https://www.reddit.com/search.json"
    headers = {
        "User-Agent": os.getenv("REDDIT_USER_AGENT", "PhishLens:v1.0 (by /u/scamshield_bot)")
    }

    try:
        timeout_cfg = httpx.Timeout(1.0, connect=0.5)
        async with httpx.AsyncClient(timeout=timeout_cfg, follow_redirects=True) as client:
            res = await client.get(url, params={"q": query, "limit": 4, "sort": "relevance"}, headers=headers)
            if res.status_code == 200:
                data = res.json()
                children = data.get("data", {}).get("children", [])
                snippets = []
                for item in children:
                    post = item.get("data", {})
                    title = post.get("title", "")
                    selftext = post.get("selftext", "")
                    combined = f"{title}: {selftext[:120]}"
                    if any(w in combined.lower() for w in ["scam", "fraud", "fake", "police", "warning"]):
                        snippets.append(combined)
                result_tuple = (len(snippets), snippets[:3])
                provider_budget.set_cached("reddit", target, result_tuple, ttl=600)
                return result_tuple
    except Exception as exc:
        logger.debug(f"[OSINT] Reddit search error for {target}: {exc}")

    return 0, []


async def _scrape_duckduckgo_fallback(target: str) -> Tuple[int, List[str]]:
    """
    Path 4: DuckDuckGo HTML scraping — strictly behind ENABLE_DDG_SCRAPING flag, OFF by default.
    """
    if not is_ddg_scraping_enabled() or _is_offline() or not HAS_BEAUTIFULSOUP:
        return 0, []

    query = f'"{target}" (scam OR fraud OR complaint OR OLX)'
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        )
    }

    try:
        timeout_cfg = httpx.Timeout(0.6, connect=0.3)
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
    except Exception as e:
        logger.debug(f"[OSINT] DDG scrape error for {target}: {e}")

    return 0, []


async def analyze_osint(req: ScanRequest) -> OsintHistoryResult:
    """
    Main entry point for Parallel OSINT Past History Search Agent.
    Executes multi-source intelligence gathering:
    1. Internal DB (static crowdsource + dynamic reports table)
    2. Brave Search API (quota controlled)
    3. Reddit API Search (quota controlled)
    4. Optional DuckDuckGo scraping (flag guarded, OFF by default)
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

    primary_target = targets[0]

    # Path 1: Check internal DB
    internal_record = await _search_internal_db(primary_target)

    # Path 2 & 3: External intelligence (Brave Search & Reddit API)
    brave_count, brave_snippets = await _search_brave_api(primary_target)
    reddit_count, reddit_snippets = await _search_reddit_api(primary_target)

    # Path 4: Optional DDG scraping if enabled
    ddg_count, ddg_snippets = await _scrape_duckduckgo_fallback(primary_target)

    external_count = brave_count + reddit_count + ddg_count
    all_external_snippets = brave_snippets + reddit_snippets + ddg_snippets

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

    if brave_count > 0:
        flags.append("BRAVE_SEARCH_SCAM_INTEL_FOUND")
        for s in brave_snippets:
            reports.append(
                OsintReportItem(
                    source="Brave Search Intelligence",
                    scam_category="PUBLIC_SEARCH_COMPLAINT",
                    details=s[:160] + "..." if len(s) > 160 else s,
                    frequency_flagged=1,
                )
            )

    if reddit_count > 0:
        flags.append("REDDIT_COMMUNITY_SCAM_ALERTS_FOUND")
        for s in reddit_snippets:
            reports.append(
                OsintReportItem(
                    source="Reddit Fraud Subreddits",
                    scam_category="COMMUNITY_ALERT",
                    details=s[:160] + "..." if len(s) > 160 else s,
                    frequency_flagged=1,
                )
            )

    if ddg_count > 0:
        flags.append("EXTERNAL_FORUM_COMPLAINTS_FOUND")
        for s in ddg_snippets:
            reports.append(
                OsintReportItem(
                    source="Public Forum Web Scraping",
                    scam_category="PUBLIC_COMPLAINT",
                    details=s[:160] + "..." if len(s) > 160 else s,
                    frequency_flagged=1,
                )
            )

    total_complaints += external_count
    if external_count > 0 and not proof_snippet:
        proof_snippet = f"Warning: {external_count} past complaints/scam reports found across Brave/Reddit forums."

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
            f"OSINT Investigation for '{primary_target}': {total_complaints} prior incident(s) flagged across "
            f"internal DB and web intelligence. {proof_snippet or ''}"
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
