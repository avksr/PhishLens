import os
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from api.routes import router as api_router

FRONTEND_HTML = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html"))

app = FastAPI(
    title="PhishLens API (ScamShield AI)",
    description="Real-Time Explainable Multi-Vector Scam Interception Engine",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
