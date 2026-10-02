# ============================================================
# OWNER: VANSH
# FILE: backend/core/limiter.py
# PURPOSE: Configurable Rate Limiting Controller (PRD §8 & §9)
# ============================================================

import os
from slowapi import Limiter
from slowapi.util import get_remote_address


def get_rate_limit() -> str:
    """
    Read rate limit from RATE_LIMIT_PER_MINUTE environment variable,
    defaulting to '30/minute'. Formats raw integer strings e.g. '30' to '30/minute'.
    """
    limit_val = os.getenv("RATE_LIMIT_PER_MINUTE", "30/minute").strip()
    if limit_val.isdigit():
        return f"{limit_val}/minute"
    if "/" not in limit_val:
        return f"{limit_val}/minute"
    return limit_val


limiter = Limiter(key_func=get_remote_address, default_limits=[get_rate_limit])
