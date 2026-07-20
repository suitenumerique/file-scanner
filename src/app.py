import hmac
import io
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, File, HTTPException, Query, Response, UploadFile
from fastapi.responses import PlainTextResponse
from fastapi.security import APIKeyHeader
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, HttpUrl

from config import get_settings
from metrics import refresh_signatures
from scanner import get_scanner, resolve_scanners, run_scanners, validate_registry
from ssrf import SSRFValidationError
from tasks import scan_task
from validation import assert_scannable
from version import __version__

settings = get_settings()
logger = logging.getLogger("file-scanner")
logging.basicConfig(level=logging.DEBUG if settings.debug else logging.INFO)

# --- Auth ---

API_KEYS: dict[str, str] = {}
for raw_entry in settings.api_keys.split(","):
    entry = raw_entry.strip()
    if ":" in entry:
        name, key = entry.split(":", 1)
        API_KEYS[key] = name

if not API_KEYS:
    logger.warning(
        "No API keys configured — every request will return 401. "
        "Set API_KEYS as a comma-separated list of name:key pairs."
    )

api_key_header = APIKeyHeader(name="X-API-Key")


def verify_auth(key: Annotated[str, Depends(api_key_header)]) -> str:
    # Constant-time comparison against every configured key so a timing side
    # channel can't be used to recover a valid key byte by byte.
    if key:
        for candidate, service in API_KEYS.items():
            if hmac.compare_digest(key, candidate):
                return service
    raise HTTPException(status_code=401, detail="Invalid API key")


# --- Helpers / models ---


def _split(raw: str | None) -> list[str] | None:
    """Split a comma-separated query value into a clean list (None if empty)."""
    if not raw:
        return None
    return [s.strip() for s in raw.split(",") if s.strip()] or None


def _resolve(
    categories: list[str] | None = None, scanners: list[str] | None = None
) -> list[str]:
    """Resolve ``categories`` union ``scanners``, mapping a bad selection to 400."""
    try:
        return resolve_scanners(categories, scanners)
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from exc


class ScanAsyncRequest(BaseModel):
    url: HttpUrl
    filename: str | None = None
    webhook_url: str | None = None
    metadata: dict | None = None
    # Category and/or scanner selectors; both union. Omit both to use
    # DEFAULT_CATEGORIES.
    categories: list[str] | None = None
    scanners: list[str] | None = None


# --- App ---


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Fail fast at boot if the category/scanner configuration is inconsistent.
    validate_registry()
    yield


app = FastAPI(title="File Scanner", version=__version__, lifespan=lifespan)


# The dramatiq-redis-streams queue dashboard is destructive; the same
# `uvicorn app:app` serves it at WORKER_DASHBOARD_PATH, but only when a password
# is configured — otherwise it stays absent (fail-safe, and tests / installs
# without the broker package skip it). It rides the public web tier behind its
# own Basic-auth + IP-allowlist guard (dashboard.py); restrict it further at the
# ingress in production.
def _mount_dashboard() -> None:
    # Normalise to a leading-slash, no-trailing-slash mount path.
    path = "/" + (settings.worker_dashboard_path.strip().strip("/") or "dashboard")
    if not settings.worker_dashboard_password:
        logger.info(
            "Dashboard disabled; set WORKER_DASHBOARD_PASSWORD to serve it at %s.",
            path,
        )
        return
    try:
        from uvicorn.middleware.wsgi import WSGIMiddleware

        from dashboard import create_app as build_dashboard

        wsgi = build_dashboard(prefix=path)
    except Exception:
        logger.exception("Dashboard could not be mounted")
        return
    app.mount(path, WSGIMiddleware(wsgi))
    logger.info("Dashboard mounted at %s (Basic auth + IP allowlist).", path)


_mount_dashboard()


@app.get("/metrics")
def metrics():
    """Prometheus exposition: default process metrics, scan counters, and the
    signature-freshness gauges (refreshed lazily here)."""
    try:
        refresh_signatures(resolve_scanners(), get_scanner)
    except ValueError:
        pass
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/", response_class=PlainTextResponse)
@app.get("/check", response_class=PlainTextResponse)
def healthcheck():
    # Healthy when every default scanner is reachable.
    try:
        names = resolve_scanners()
        ok = all(get_scanner(name).ping() for name in names)
    except (ValueError, RuntimeError) as exc:
        logger.error(f"healthcheck failed: {exc}")
        ok = False
    if ok:
        return PlainTextResponse("Service OK", status_code=200)
    return PlainTextResponse("Service Unavailable", status_code=503)


@app.post("/api/v1.0/scan")
def scan(
    file: UploadFile = File(...),
    username: str = Depends(verify_auth),
    categories: Annotated[
        str | None,
        Query(
            description="Comma-separated categories (e.g. malware,nsfw); "
            "defaults to DEFAULT_CATEGORIES."
        ),
    ] = None,
    scanners: Annotated[
        str | None,
        Query(description="Comma-separated scanner names; unions with categories."),
    ] = None,
):
    """Scan an uploaded file; returns per-category aggregates + a per-scanner report."""
    names = _resolve(_split(categories), _split(scanners))

    file.file.seek(0, 2)
    size = file.file.tell()
    file.file.seek(0)
    if size > settings.max_upload_size:
        raise HTTPException(413, detail="File Too Large")

    # Read once (bounded by max_upload_size) so each scanner gets its own handle
    # and they can run in parallel.
    data = file.file.read()
    logger.info(f"Scanning {file.filename} for {username} with {names}")
    report = run_scanners(names, lambda: io.BytesIO(data), api_client=username)
    if report.all_errored:
        # Every scanner failed to run — says nothing about the file.
        raise HTTPException(503, detail="scan temporarily unavailable")
    return report.as_dict()


@app.post("/api/v1.0/scan-async", status_code=202)
@app.post("/v2/scan-async", status_code=202, deprecated=True)  # alias used by transfers
def scan_async(
    body: ScanAsyncRequest,
    username: str = Depends(verify_auth),
):
    """Queue an asynchronous scan. Stateless: nothing is persisted — the result
    is delivered exclusively via the (mandatory) ``webhook_url`` callback, so a
    caller that can't receive webhooks must use the synchronous
    ``/api/v1.0/scan``.
    """
    names = _resolve(body.categories, body.scanners)

    url_str = str(body.url)
    try:
        assert_scannable(url_str, body.webhook_url)
    except SSRFValidationError as exc:
        raise HTTPException(400, detail=str(exc)) from exc

    if not body.webhook_url:
        raise HTTPException(422, detail="webhook_url is required for async scans")

    # The job id is a correlation handle echoed back in the webhook payload.
    # Today the service is stateless (webhook-only delivery), but nothing here
    # precludes a future API persisting the job and letting callers poll it by id.
    job_id = str(uuid.uuid4())
    scan_task.send(
        job_id, url_str, names, body.filename, body.webhook_url, body.metadata, username
    )

    logger.info(f"Async scan job {job_id} created by {username} for {url_str}")
    return {"job_id": job_id, "status": "pending"}
