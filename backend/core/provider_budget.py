# ============================================================
# OWNER: VANSH
# FILE: backend/core/provider_budget.py
# PURPOSE: Provider Budget & Quota Controller with Per-Provider
#          Sliding-Window Rate Counters and TTL Cache (FR-8 / §9)
# ============================================================

import os
import time
import logging
from typing import Any, Dict, Optional, Tuple, Callable
from collections import deque
import threading

logger = logging.getLogger("phishlens.provider_budget")

# Default per-minute limits per external provider
DEFAULT_LIMITS: Dict[str, int] = {
    "groq": 30,
    "gemini": 15,
    "brave_search": 20,
    "reddit": 30,
    "virustotal": 4,
    "google_safe_browsing": 60,
    "otx": 30,
}


class ProviderBudgetManager:
    """
    Thread-safe provider budget controller with:
    1. Sliding-window rate counters per provider.
    2. In-memory TTL cache where cache hits NEVER use quota.
    3. Live quota metrics for evaluators and monitoring.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # provider -> deque of timestamps of calls in the current window
        self._call_history: Dict[str, deque] = {}
        # (provider, key) -> (cached_value, expiry_timestamp)
        self._cache: Dict[Tuple[str, str], Tuple[Any, float]] = {}
        # Metrics: provider -> count
        self._cache_hits: Dict[str, int] = {}
        self._quota_used: Dict[str, int] = {}
        self._window_seconds: float = 60.0

    def get_limit(self, provider: str) -> int:
        """Read provider limit from env (e.g. PROVIDER_GROQ_LIMIT) or fallback default."""
        env_var = f"PROVIDER_{provider.upper()}_LIMIT"
        env_val = os.getenv(env_var)
        if env_val and env_val.isdigit():
            return int(env_val)
        return DEFAULT_LIMITS.get(provider.lower(), 30)

    def _purge_old_calls(self, provider: str, now: float) -> None:
        """Purge timestamps older than sliding window."""
        history = self._call_history.setdefault(provider, deque())
        cutoff = now - self._window_seconds
        while history and history[0] < cutoff:
            history.popleft()

    def get_cached(self, provider: str, cache_key: str) -> Optional[Any]:
        """
        Retrieve value from TTL cache.
        CRITICAL: Cache hits NEVER consume quota or increment rate counters.
        """
        now = time.time()
        cache_tuple_key = (provider.lower(), cache_key)
        with self._lock:
            if cache_tuple_key in self._cache:
                val, expiry = self._cache[cache_tuple_key]
                if now < expiry:
                    self._cache_hits[provider] = self._cache_hits.get(provider, 0) + 1
                    logger.debug(f"[ProviderBudget] Cache HIT for provider='{provider}', key='{cache_key}' (quota preserved).")
                    return val
                else:
                    # Expired
                    del self._cache[cache_tuple_key]
        return None

    def set_cached(self, provider: str, cache_key: str, value: Any, ttl: int = 300) -> None:
        """Store value in TTL cache with specified time-to-live in seconds."""
        expiry = time.time() + max(1, ttl)
        cache_tuple_key = (provider.lower(), cache_key)
        with self._lock:
            self._cache[cache_tuple_key] = (value, expiry)

    def can_call(self, provider: str) -> bool:
        """Check if provider has available quota in the current sliding window."""
        now = time.time()
        provider_key = provider.lower()
        limit = self.get_limit(provider_key)
        with self._lock:
            self._purge_old_calls(provider_key, now)
            return len(self._call_history.get(provider_key, deque())) < limit

    def acquire(self, provider: str) -> bool:
        """
        Attempt to acquire 1 call quota from provider.
        Returns True if quota granted, False if rate limit exceeded.
        """
        now = time.time()
        provider_key = provider.lower()
        limit = self.get_limit(provider_key)
        with self._lock:
            self._purge_old_calls(provider_key, now)
            history = self._call_history.setdefault(provider_key, deque())
            if len(history) < limit:
                history.append(now)
                self._quota_used[provider_key] = self._quota_used.get(provider_key, 0) + 1
                return True
            else:
                logger.warning(
                    f"[ProviderBudget] Quota EXCEEDED for provider='{provider}' "
                    f"({len(history)}/{limit} calls in {self._window_seconds}s window)."
                )
                return False

    def reset(self) -> None:
        """Reset counters and cache (used in unit testing)."""
        with self._lock:
            self._call_history.clear()
            self._cache.clear()
            self._cache_hits.clear()
            self._quota_used.clear()

    def get_status(self) -> Dict[str, Dict[str, Any]]:
        """Return diagnostic metrics for evaluators and health checks."""
        now = time.time()
        status: Dict[str, Dict[str, Any]] = {}
        with self._lock:
            for provider, default_lim in DEFAULT_LIMITS.items():
                self._purge_old_calls(provider, now)
                used = len(self._call_history.get(provider, deque()))
                limit = self.get_limit(provider)
                status[provider] = {
                    "limit_per_minute": limit,
                    "active_window_usage": used,
                    "quota_remaining": max(0, limit - used),
                    "total_quota_consumed": self._quota_used.get(provider, 0),
                    "cache_hits_saved": self._cache_hits.get(provider, 0),
                }
        return status


# Global Singleton
provider_budget = ProviderBudgetManager()
