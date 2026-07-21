import hmac
import io
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field, HttpUrl, field_validator

import encryption
import jwt_auth
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

if not jwt_auth.enabled_incoming():
    logger.warning(
        "No JWT issuer keys configured — every request will return 401. "
        "Set JWT_ISSUER_KEYS (iss:pubkey pairs of caller Ed25519 public keys)."
    )


async def _authenticate(request: Request, *, bind_body: bool) -> str:
    """Authenticate a request via its EdDSA **Bearer JWT** and return the caller
    identity (its ``iss``, used as the metrics ``api_client`` label). The token is
    verified against the caller's configured public key and **bound to this
    request** — its method + target, plus the body hash when ``bind_body`` (the
    async endpoint, so the ``url``/``webhook_url`` can't be swapped). The sync
    upload's file bytes are never hashed (``bind_body`` is False there)."""
    authz = request.headers.get("Authorization") or ""
    if not authz.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    try:
        payload = jwt_auth.decode(authz[7:].strip())
        method, htu = jwt_auth.request_target(
            request.method, request.url.path, request.url.query
        )
        body = await request.body() if bind_body else None
        jwt_auth.check_binding(
            payload, method=method, htu=htu, body=body, require_body=bind_body
        )
    except jwt_auth.JWTError as exc:
        raise HTTPException(401, detail=f"Invalid token: {exc}") from exc
    return payload["iss"]


async def auth_sync(request: Request) -> str:
    """Auth for the sync upload endpoint — binds method + target, not file bytes."""
    return await _authenticate(request, bind_body=False)


async def auth_async(request: Request) -> str:
    """Auth for the async endpoint — also binds the JSON body (so the token
    covers the ``url`` and ``webhook_url`` the caller authorised)."""
    return await _authenticate(request, bind_body=True)


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


class ScanEncryption(BaseModel):
    """Decryption material for a client-encrypted source. Without it a scanner
    sees opaque bytes and reports them clean, so an encrypting caller must send
    it. Not persisted in the service or echoed to the webhook, but note the key
    does transit the broker in the task message (see docs/client-encryption.md).
    """

    # Wire-format identifier; omit for the default. Unknown schemes are rejected.
    scheme: str = encryption.SCHEME
    # URL-safe base64 AES-256 key (43 chars unpadded, 44 padded).
    key: str = Field(min_length=43, max_length=44, pattern=r"^[A-Za-z0-9_-]+={0,2}$")
    # Plaintext bytes per crypto chunk; each stored chunk is this + 28 bytes
    # (12-byte IV + 16-byte GCM tag), the last one shorter. Bounded both ways
    # (ceiling: worker memory; floor: chunk-count CPU) by the configurable
    # ENCRYPTION_MIN/MAX_CHUNK_SIZE.
    chunk_size: int = Field(
        ge=settings.encryption_min_chunk_size, le=settings.encryption_max_chunk_size
    )
    # AAD prefix: each chunk is bound to f"{file_id}:{part}:{parts}".
    file_id: str = Field(min_length=1, max_length=255)
    # Total number of chunks; bound into every chunk's AAD to defeat trailing
    # truncation.
    parts: int = Field(ge=0)

    @field_validator("scheme")
    @classmethod
    def _known_scheme(cls, value: str) -> str:
        if value not in encryption.SCHEMES:
            raise ValueError(
                f"unknown scheme {value!r}; supported: {sorted(encryption.SCHEMES)}"
            )
        return value


class ScanAsyncRequest(BaseModel):
    url: HttpUrl
    filename: str | None = None
    webhook_url: str | None = None
    metadata: dict | None = None
    # Category and/or scanner selectors; both union. Omit both to use
    # DEFAULT_CATEGORIES.
    categories: list[str] | None = None
    scanners: list[str] | None = None
    # Present when the source is client-encrypted: decrypt before scanning.
    encryption: ScanEncryption | None = None


# --- App ---


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Fail fast at boot if the category/scanner configuration is inconsistent.
    validate_registry()
    if not settings.prometheus_api_key:
        logger.warning(
            "PROMETHEUS_API_KEY is not set — /metrics is unauthenticated and its "
            "api_client label exposes caller identities. Set it, or isolate "
            "/metrics at the network layer."
        )
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


def verify_prometheus(request: Request) -> None:
    """Bearer-token gate for /metrics (the PROMETHEUS_API_KEY convention from
    suitenumerique/messages). Open when the key is unset — only safe if the
    endpoint is isolated at the network layer, and note the scan metrics carry an
    ``api_client`` label (caller identities + volumes)."""
    key = settings.prometheus_api_key
    if not key:
        return
    if not hmac.compare_digest(
        request.headers.get("Authorization") or "", f"Bearer {key}"
    ):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.get("/metrics")
def metrics(_: None = Depends(verify_prometheus)):
    """Prometheus exposition: default process metrics, scan counters, and the
    signature-freshness gauges (refreshed lazily here)."""
    try:
        refresh_signatures(resolve_scanners(), get_scanner)
    except ValueError:
        pass
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/.well-known/jwks.json")
def jwks():
    """Our webhook-signing public key(s) as a JWK Set, derived from
    JWT_SIGNING_KEY at boot. Public by design; empty when no signing key is set.
    Receivers fetch this to verify signed webhook callbacks."""
    return jwt_auth.jwks()


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
    username: str = Depends(auth_sync),
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
def scan_async(
    body: ScanAsyncRequest,
    username: str = Depends(auth_async),
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
        job_id,
        url_str,
        names,
        body.filename,
        body.webhook_url,
        body.metadata,
        username,
        body.encryption.model_dump() if body.encryption else None,
    )

    logger.info(
        f"Async scan job {job_id} created by {username} for {url_str} "
        f"(encrypted={body.encryption is not None})"
    )
    return {"job_id": job_id, "status": "pending"}
