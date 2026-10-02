"""
main.py — FastAPI application entry point.

Startup note:
  Base.metadata.create_all(bind=engine) is used for MVP convenience — it creates tables
  that don't exist yet without touching existing ones. This is IDEMPOTENT but does NOT
  handle schema migrations (column additions, renames, type changes).

  Before production or any schema-changing deploy, switch to Alembic:
    alembic init alembic
    alembic revision --autogenerate -m "initial"
    alembic upgrade head
  and REMOVE the create_all call below.
"""

import sys
import logging
import models  # noqa: F401 — imports all ORM classes so they register on Base.metadata

from config import settings
from database import Base, engine
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import api_keys, auth, findings, guard, health, reports, scans, targets, usage

logger = logging.getLogger("sentinelloop.main")

_api_key = settings.OPENAI_API_KEY
_is_placeholder = (
    not _api_key or 
    _api_key.startswith("sk-replace") or 
    _api_key.startswith("sk-test") or 
    _api_key == "change-me"
)
_is_gemini = bool(_api_key and _api_key.startswith("AIzaSy"))

if _is_placeholder:
    sys.stderr.write(
        "\n" + "="*80 + "\n"
        "⚠️  WARNING: OPENAI_API_KEY IS A PLACEHOLDER!\n"
        "👉 LLM judge layer is using the OFFLINE HEURISTIC fallback, NOT real GPT-4o-mini calls.\n"
        "👉 Set a valid production key in .env to enable real LLM security audits.\n"
        + "="*80 + "\n\n"
    )
    sys.stderr.flush()
    logger.warning("OPENAI_API_KEY is a placeholder — LLM judge layer is using offline heuristic, NOT real GPT-4o-mini calls.")
elif _is_gemini:
    sys.stderr.write(
        "\n" + "="*80 + "\n"
        "🚀 INFO: GOOGLE GEMINI API KEY DETECTED!\n"
        "👉 LLM judge layer will route calls to models/gemini-2.5-flash via compatibility layer.\n"
        + "="*80 + "\n\n"
    )
    sys.stderr.flush()
    logger.info("Google Gemini API key detected — Routing LLM judge requests to models/gemini-2.5-flash.")

# Create all tables on startup (idempotent — safe to run every start in MVP)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SentinelLoop",
    description=(
        "Automated AI red-teaming platform. "
        "Attack your LLM chatbot, get code-level fixes, auto-retest after redeploy."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers under /api/v1
app.include_router(health.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
app.include_router(targets.router, prefix="/api/v1")
app.include_router(api_keys.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")
app.include_router(guard.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")
app.include_router(usage.router, prefix="/api/v1")


@app.get("/", tags=["root"])
def root():
    return {
        "name": "SentinelLoop",
        "version": "0.1.0",
        "status": "running",
        "docs": "/docs",
        "health": "/api/v1/health",
    }
