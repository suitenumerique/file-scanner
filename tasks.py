import logging
import timeit
from datetime import datetime, timezone

import clamd
import requests as http_requests
from celery import Celery

from config import get_settings
from database import SessionLocal
from models import ScanJob

logger = logging.getLogger("CLAMAV-REST")

settings = get_settings()
celery_app = Celery("clamav_tasks", broker=settings.celery_broker_url)

if settings.clamd_socket:
    _cd = clamd.ClamdUnixSocket(path=settings.clamd_socket)
else:
    _cd = clamd.ClamdNetworkSocket(host=settings.clamd_host, port=settings.clamd_port)


@celery_app.task(bind=True, max_retries=2, default_retry_delay=30)
def scan_url_task(self, job_id):
    db = SessionLocal()
    try:
        job = db.get(ScanJob, job_id)
        if not job:
            logger.error(f"Job {job_id} not found")
            return

        job.status = "downloading"
        job.started_at = datetime.now(timezone.utc)
        db.commit()

        response = http_requests.get(job.url, stream=True, timeout=settings.url_download_timeout)
        response.raise_for_status()

        job.status = "scanning"
        db.commit()

        start_time = timeit.default_timer()
        result = _cd.instream(response.raw)
        elapsed = timeit.default_timer() - start_time

        status, reason = result["stream"]
        job.status = "done"
        job.malware = status != "OK"
        job.reason = reason if status != "OK" else None
        job.scan_duration = elapsed
        job.completed_at = datetime.now(timezone.utc)
        db.commit()

        logger.info(f"Async scan job {job_id} complete. Malware: {job.malware}, Time: {elapsed:.3f}s")

    except http_requests.RequestException as exc:
        job.status = "error"
        job.error = f"download_failed: {exc}"
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.error(f"Job {job_id} download failed: {exc}")

    except clamd.ConnectionError as exc:
        job.status = "error"
        job.error = f"scan_failed: {exc}"
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.error(f"Job {job_id} scan failed: {exc}")
        raise self.retry(exc=exc)

    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.error(f"Job {job_id} unexpected error: {exc}")
        raise self.retry(exc=exc)

    finally:
        db.close()
