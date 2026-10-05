# ============================================================
# OWNER: VANSH
# FILE: backend/main.py
# PURPOSE: FastAPI Application Entrypoint with GIGW 3.0 Compliance,
#          Startup Agent Key Verification, SlowAPI Rate Limiting,
#          and Fail-Secure Zero Information Leakage Error Shielding.
# ============================================================

import os
import logging
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exceptions import RequestValidationError
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from core.limiter import limiter, get_rate_limit
from core.agent_registry import agent_registry
from core.db_logger import init_db
from api.routes import router as api_router

logger = logging.getLogger("phishlens.api")

FRONTEND_HTML = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html"))

# Configurable Rate Limiting (PRD §8 & §9)
RATE_LIMIT_PER_MINUTE = get_rate_limit()

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Evaluate environment keys and initialize database schema
    agent_registry.evaluate_environment()
    try:
        await init_db()
    except Exception as e:
        logger.warning(f"Startup DB init non-fatal warning: {e}")
    yield

app = FastAPI(
    title="PhishLens API (ScamShield AI)",
    description="Real-Time Explainable Multi-Vector Scam Interception Engine",
    version="2.0.0",
    lifespan=lifespan
)


# GIGW 3.0 & CERT-In Zero Information Leakage Exception Handler:
# Ensures raw stack traces and server-side file paths are never exposed to the client.
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Allow explicit HTTPExceptions (400, 404, 409, 413, 429) and ValidationErrors to pass through
    if isinstance(exc, (StarletteHTTPException, RateLimitExceeded, RequestValidationError)):
        raise exc

    logger.error(f"Unhandled server error on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "code": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred during request processing. Please try again later.",
            "path": request.url.path
        }
    )


# Register slowapi state, handler, and middleware
app.state.limiter = limiter
app.state.rate_limit = RATE_LIMIT_PER_MINUTE
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(api_router)

from shared.models import ScanRequest, ScanResponse
from core.orchestrator import run_pipeline


@app.post("/api/scan", response_model=ScanResponse, tags=["Compatibility"], include_in_schema=False)
async def scan_compat(req: ScanRequest) -> ScanResponse:
    """Compatibility alias for /api/scan -> /api/v1/scan"""
    return await run_pipeline(req)


@app.get("/health", tags=["Compatibility"])
def health_root():
    """Top-level health check endpoint"""
    return {"status": "HEALTHY", "service": "PhishLens ScamShield API", "version": "2.0.0"}


@app.get("/")
@app.get("/demo")
def root():
    if os.path.exists(FRONTEND_HTML):
        return FileResponse(FRONTEND_HTML)
    return {
        "name": "PhishLens API",
        "description": "Pre-Transaction Scam Interception Engine",
        "docs_url": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
