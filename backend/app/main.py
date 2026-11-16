"""
Application entrypoint.

This module wires together config, logging, middleware, exception handling,
and routers. It intentionally contains no business logic — that lives in
services/ and repositories/. main.py's only job is composition.
"""
import logging
import time
import uuid

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from slowapi.errors import RateLimitExceeded

from app.core.config import get_settings
from app.core.logging_config import configure_logging
from app.core.rate_limit import limiter
from app.api.v1 import auth as auth_routes
from app.api.v1 import scans as scan_routes
from app.api.v1 import enrichment as enrichment_routes
from app.api.v1 import risk as risk_routes
from app.api.v1 import assets as asset_routes
from app.api.v1 import vulnerabilities as vulnerability_routes
from app.api.v1 import remediation as remediation_routes
from app.api.v1 import dashboard as dashboard_routes
from app.api.v1 import reports as report_routes
from app.api.v1 import notifications as notification_routes

settings = get_settings()
configure_logging()
logger = logging.getLogger("triageiq")

from contextlib import asynccontextmanager

from app.scheduler.runner import start_scheduler, shutdown_scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Scheduler starts with the app and stops cleanly on shutdown — not
    # started at import time, which would fire it even during tests that
    # merely import app.main without meaning to run background jobs.
    start_scheduler()
    yield
    shutdown_scheduler()


app = FastAPI(
    lifespan=lifespan,
    title=settings.APP_NAME,
    description="Risk-based vulnerability prioritization engine — CVSS + EPSS + CISA KEV composite scoring.",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"error": {"message": "Too many requests, slow down.", "status_code": 429}},
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    """
    Attaches a request ID to every request/response and logs timing.
    A request ID is essential in production: when a user reports 'it broke',
    this is what lets you grep logs across services for that exact call.
    """
    request_id = str(uuid.uuid4())
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    logger.info(
        f"{request.method} {request.url.path} -> {response.status_code} ({duration_ms}ms)",
        extra={"context": {"request_id": request_id, "duration_ms": duration_ms}},
    )
    return response


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """
    Uniform error envelope. Real API consumers (and our own React frontend)
    should never have to guess the shape of an error response.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"message": exc.detail, "status_code": exc.status_code}},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": {"message": "Internal server error", "status_code": 500}},
    )


@app.get("/api/health", tags=["system"])
def health_check():
    """
    Liveness/readiness probe. Kept dependency-free (no DB call) so it
    answers instantly even if the DB is degraded — orchestrators (k8s,
    Docker healthcheck) use this to decide whether to restart the container.
    """
    return {"status": "ok", "service": settings.APP_NAME, "env": settings.APP_ENV}


app.include_router(auth_routes.router, prefix=settings.API_V1_PREFIX)
app.include_router(scan_routes.router, prefix=settings.API_V1_PREFIX)
app.include_router(enrichment_routes.router, prefix=settings.API_V1_PREFIX)
app.include_router(risk_routes.router, prefix=settings.API_V1_PREFIX)
app.include_router(asset_routes.router, prefix=settings.API_V1_PREFIX)
app.include_router(vulnerability_routes.router, prefix=settings.API_V1_PREFIX)
app.include_router(remediation_routes.router, prefix=settings.API_V1_PREFIX)
app.include_router(dashboard_routes.router, prefix=settings.API_V1_PREFIX)
app.include_router(report_routes.router, prefix=settings.API_V1_PREFIX)
app.include_router(notification_routes.router, prefix=settings.API_V1_PREFIX)
