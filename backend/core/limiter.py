# ============================================================
# OWNER: VANSH
# FILE: backend/core/limiter.py
# PURPOSE: GIGW 3.0 DDoS / Rate Limiting Controller (30 req/min)
# ============================================================

from slowapi import Limiter
from slowapi.util import get_remote_address

# Enforce 30 requests/minute per client IP for GIGW 3.0 / DDoS compliance
limiter = Limiter(key_func=get_remote_address, default_limits=["30/minute"])
