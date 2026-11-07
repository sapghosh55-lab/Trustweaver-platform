from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.router import api_router
from app.api.routes import routes

app = FastAPI(
    title="Hackmatrix / TrustWeaver Platform API",
    description="Backend API for Hackmatrix / TrustWeaver Security & Digital Trust Platform",
    version="0.1.0",
)

# Enable CORS for frontend and browser extensions
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


@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "ok", "service": "hackmatrix-backend"}
