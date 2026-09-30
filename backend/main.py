import os
import logging
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from core.limiter import limiter
from api.routes import router as api_router

logger = logging.getLogger("phishlens.api")

FRONTEND_HTML = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html"))

app = FastAPI(
    title="PhishLens API (ScamShield AI)",
    description="Real-Time Explainable Multi-Vector Scam Interception Engine",
    version="1.0.0"
)


# GIGW 3.0 & CERT-In Zero Information Leakage Exception Handler:
# Ensures raw stack traces and server-side file paths are never exposed to the client.
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled server error on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred during request processing. Please try again later.",
            "path": request.url.path
        }
    )


# Register slowapi state, handler, and middleware
app.state.limiter = limiter
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
