import logging
import timeit
from typing import Annotated, Optional
from urllib.parse import urlparse

import clamd
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, HttpUrl

import clamav_versions as versions
from config import get_settings
from database import SessionLocal
from models import ScanJob
from tasks import celery_app, scan_url_task
from version import __version__

settings = get_settings()
logger = logging.getLogger("CLAMAV-REST")
logging.basicConfig(level=logging.DEBUG if settings.debug else logging.INFO)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


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
    if size > settings.max_content_length:
        raise HTTPException(413, detail="File Too Large")

    logger.info(f"Starting scan for {username} of {file.filename}")
    start = timeit.default_timer()
    try:
        result = cd.instream(file.file)
        status, reason = result["stream"]
    except Exception as e:
        raise HTTPException(500, detail=str(e))
    elapsed = timeit.default_timer() - start
    return ScanResult(malware=status != "OK", reason=reason if status != "OK" else None, time=elapsed)



@app.post("/v2/scan-async", status_code=202)
def scan_async(
    body: ScanAsyncRequest,
    username: str = Depends(verify_auth),
    db=Depends(get_db),
):
    url_str = str(body.url)
    parsed = urlparse(url_str)

    if settings.allowed_url_hosts:
        hosts = [h.strip() for h in settings.allowed_url_hosts.split(",") if h.strip()]
        if hosts and parsed.hostname not in hosts:
            raise HTTPException(400, detail=f"host {parsed.hostname} not allowed")

    job = ScanJob(
        url=url_str,
        filename=body.filename,
        webhook_url=body.webhook_url,
        metadata_=body.metadata,
        requested_by=username,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    scan_url_task.delay(job.id)

    logger.info(f"Async scan job {job.id} created by {username} for {url_str}")
    return job.to_dict()


@app.get("/v2/jobs/{job_id}")
def get_job(
    job_id: str,
    username: str = Depends(verify_auth),
    db=Depends(get_db),
):
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(404, detail="job not found")
    return job.to_dict()
