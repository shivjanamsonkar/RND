"""
FastAPI application entry-point.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from app.api.analyze import router as analyze_router
from app.api.reports import router as reports_router
from app.api.webhook import router as webhook_router

app = FastAPI(
    title="Code Security Analysis Platform",
    description=(
        "Submit source code and receive detailed security findings with "
        "OWASP-aligned severity ratings and remediation guidance."
    ),
    version="1.0.0",
    contact={"name": "Security Team"},
    license_info={"name": "MIT"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router, tags=["Analysis"])
app.include_router(reports_router, tags=["Reports"])
app.include_router(webhook_router, tags=["CI/CD"])

# Serve the frontend static files if the directory exists
_FRONTEND = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")
if os.path.isdir(_FRONTEND):
    app.mount("/static", StaticFiles(directory=os.path.join(_FRONTEND, "static")), name="static")

    @app.get("/", include_in_schema=False)
    def serve_index():
        return FileResponse(os.path.join(_FRONTEND, "index.html"))

    @app.get("/report", include_in_schema=False)
    def serve_report():
        return FileResponse(os.path.join(_FRONTEND, "report.html"))
