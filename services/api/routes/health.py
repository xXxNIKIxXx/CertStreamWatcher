"""Health / readiness endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from ..models import HealthResponse

router = APIRouter(tags=["Health"])


def _get_db():
    from ..main import db
    return db


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns service health and dependency status.",
)
async def health():
    db = _get_db()
    db_status = "up" if db.available else "down"
    overall = "healthy" if db.available else "degraded"
    return HealthResponse(status=overall, database=db_status)


@router.get(
    "/ready",
    summary="Readiness probe",
    description="Returns 200 when the service is ready to accept traffic.",
)
async def readiness():
    db = _get_db()
    if not db.available:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=503,
            content={"status": "not ready", "database": "down"},
        )
    return {"status": "ready"}
