import ipaddress
import logging
import socket
import timeit
import uuid
from typing import Annotated, Optional
from urllib.parse import urlparse

import clamd
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, HttpUrl

import clamav_versions as versions
from config import get_settings
from tasks import celery_app, scan_task
from version import __version__

settings = get_settings()
logger = logging.getLogger("CLAMAV-REST")
logging.basicConfig(level=logging.DEBUG if settings.debug else logging.INFO)


# --- Celery ---

celery_app.conf.update(
    task_serializer="json",
    result_backend=None,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,
)

# --- ClamD ---

if settings.clamd_socket:
    cd = clamd.ClamdUnixSocket(path=settings.clamd_socket)
else:
    cd = clamd.ClamdNetworkSocket(host=settings.clamd_host, port=settings.clamd_port)

# --- Auth ---

API_KEYS: dict[str, str] = {}
for entry in settings.api_keys.split(","):
    entry = entry.strip()
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
    service = API_KEYS.get(key)
    if not service:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return service


# --- Pydantic models ---

class ScanResult(BaseModel):
    malware: bool
    reason: Optional[str]
    time: float


class ScanAsyncRequest(BaseModel):
    url: HttpUrl
    filename: Optional[str] = None
    webhook_url: Optional[str] = None
    metadata: Optional[dict] = None


# --- Helpers ---

def _resolves_to_public_only(hostname: str) -> bool:
    """Reject hostnames whose A/AAAA records point at non-public ranges.

    Defense against SSRF: a caller-supplied URL must not let the worker reach
    loopback, link-local, or RFC1918 space (e.g. cloud metadata endpoints).
    Unresolvable hostnames are allowed through so the download surfaces a
    clear network error instead of a misleading 400.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return True
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
    return True


def _validate_url(url: str):
    parsed = urlparse(url)
    if not parsed.hostname:
        raise HTTPException(400, detail="invalid URL")

    if settings.allowed_url_hosts:
        hosts = [h.strip() for h in settings.allowed_url_hosts.split(",") if h.strip()]
        if hosts and parsed.hostname not in hosts:
            raise HTTPException(400, detail=f"host {parsed.hostname} not allowed")

    if not settings.testing and not _resolves_to_public_only(parsed.hostname):
        raise HTTPException(
            400, detail=f"host {parsed.hostname} resolves to a non-public address"
        )


# --- App ---

app = FastAPI(title="ClamAV Service", version=__version__)


@app.get("/", response_class=PlainTextResponse)
@app.get("/check", response_class=PlainTextResponse)
def healthcheck():
    try:
        if cd.ping() == "PONG":
            return PlainTextResponse("Service OK", status_code=200)
    except clamd.ConnectionError as e:
        logger.error(f"clamd.ConnectionError: {e}")
    except Exception as e:
        logger.error(f"Failed to ping clamd: {e}")
    return PlainTextResponse("Service Unavailable", status_code=503)


@app.get("/check_version")
def check_version():
    response = {"service": __version__}
    try:
        local = versions.get_local_version_number(cd)
        remote = versions.get_remote_version_number(settings.clamav_txt_uri)
    except versions.VersionError as e:
        return JSONResponse({"service": __version__, "error": str(e)}, status_code=500)
    response["clamd-actual"] = local
    response["clamd-required"] = remote
    response["outdated"] = local != remote
    return JSONResponse(response, status_code=500 if local != remote else 200)


@app.post("/v2/scan")
def scan_v2(
    file: UploadFile = File(...),
    username: str = Depends(verify_auth),
):
    file.file.seek(0, 2)
    size = file.file.tell()
    file.file.seek(0)
    if size > settings.max_upload_size:
        raise HTTPException(413, detail="File Too Large")

    logger.info(f"Starting scan for {username} of {file.filename}")
    start = timeit.default_timer()
    try:
        result = cd.instream(file.file)
        status, reason = result["stream"]
    except Exception:
        logger.exception(f"scan failed for {file.filename}")
        raise HTTPException(500, detail="scan failed")
    elapsed = timeit.default_timer() - start
    return ScanResult(malware=status != "OK", reason=reason if status != "OK" else None, time=elapsed)


@app.post("/v2/scan-async", status_code=202)
def scan_async(
    body: ScanAsyncRequest,
    username: str = Depends(verify_auth),
):
    """Queue an asynchronous scan. Stateless: nothing is persisted — the result
    is delivered exclusively via the (mandatory) ``webhook_url`` callback, so a
    caller that can't receive webhooks must use the synchronous ``/v2/scan``.
    """
    url_str = str(body.url)
    _validate_url(url_str)

    if not body.webhook_url:
        raise HTTPException(422, detail="webhook_url is required for async scans")

    # The job id is just a correlation handle echoed back in the webhook
    # payload; it is not a key to any stored record.
    job_id = str(uuid.uuid4())
    scan_task.delay(
        job_id, url_str, body.filename, body.webhook_url, body.metadata
    )

    logger.info(f"Async scan job {job_id} created by {username} for {url_str}")
    return {"job_id": job_id, "status": "pending"}
