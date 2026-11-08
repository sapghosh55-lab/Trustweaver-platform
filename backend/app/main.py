"""TrustWeaver Platform API entry point."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.router import api_router
from app.api.routes import routes

app = FastAPI(
    title="Hackmatrix / TrustWeaver Platform API",
    description="Backend API for Hackmatrix / TrustWeaver Security & Digital Trust Platform",
    version="0.1.0",
)

# Configure CORS middleware to allow frontend connections
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Expose /scan both at root /scan and under /api/scan
app.include_router(routes)
app.include_router(routes, prefix="/api")
app.include_router(api_router, prefix="/api")


@app.get("/", tags=["Root"])
@app.head("/", include_in_schema=False)
async def root():
    """Root status endpoint to verify backend service health and available routes."""
    return {
        "status": "online",
        "service": "TrustWeaver Platform API",
        "version": "0.1.0",
        "health": "/health",
        "docs": "/docs",
        "endpoints": {
            "scan": "POST /scan",
            "recent_scans": "GET /scans/recent",
            "health": "GET /health",
            "docs": "GET /docs",
        },
    }


@app.get("/health", tags=["Health"])
@app.head("/health", include_in_schema=False)
async def health_check():
    return {"status": "ok", "service": "hackmatrix-backend"}
