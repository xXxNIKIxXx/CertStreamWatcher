"""FastAPI application factory and entry point for the CertStream API.

Swagger UI:   http://localhost:8080/docs
ReDoc:         http://localhost:8080/redoc
OpenAPI JSON:  http://localhost:8080/openapi.json
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from .config import get_logger
from .database import DatabasePool
from .metrics import ApiMetrics

logger = get_logger("CertStreamAPI")

# ---------------------------------------------------------------------------
# Module-level singletons (available to route modules via import)
# ---------------------------------------------------------------------------
metrics = ApiMetrics()
db = DatabasePool(metrics=metrics)


# ---------------------------------------------------------------------------
# Lifespan (startup / shutdown)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Connect to ClickHouse on startup, close on shutdown."""
    await db.connect()
    logger.info("API service started")
    yield
    await db.close()
    logger.info("API service stopped")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(
        title="CertStream Watcher API",
        description=(
            "REST API for querying Certificate Transparency log data "
            "collected by CertStream Watcher.\n\n"
            "**Features:** full-text search, fingerprint lookup, analytics, "
            "pagination, and Prometheus metrics."
        ),
        version="1.0.0",
        docs_url="/docs",       # Swagger UI
        redoc_url="/redoc",     # ReDoc
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # -- CORS (allow dashboards / frontends on other origins) --------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -- Request instrumentation middleware --------------------------------
    @app.middleware("http")
    async def prometheus_middleware(request: Request, call_next):
        method = request.method
        path = request.url.path

        # Skip metrics endpoint to avoid self-referencing noise
        if path == "/metrics":
            return await call_next(request)

        metrics.http_requests_in_progress.labels(method=method, endpoint=path).inc()
        start = time.monotonic()

        response: Response = await call_next(request)

        elapsed = time.monotonic() - start
        status = str(response.status_code)

        metrics.http_request_duration.labels(method=method, endpoint=path).observe(elapsed)
        metrics.http_requests_total.labels(method=method, endpoint=path, status=status).inc()
        metrics.http_requests_in_progress.labels(method=method, endpoint=path).dec()

        content_length = response.headers.get("content-length")
        if content_length:
            metrics.http_response_size.labels(method=method, endpoint=path).observe(
                int(content_length)
            )

        return response

    # -- Register routers --------------------------------------------------
    from .routes.certificates import router as certs_router
    from .routes.stats import router as stats_router
    from .routes.health import router as health_router

    app.include_router(certs_router, prefix="/api/v1")
    app.include_router(stats_router, prefix="/api/v1")
    app.include_router(health_router, prefix="/api/v1")

    # -- Root redirect to docs ---------------------------------------------
    @app.get("/", include_in_schema=False)
    async def root():
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/docs")

    return app


# Build the app instance (used by uvicorn and __main__)
app = create_app()
