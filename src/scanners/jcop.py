"""Scanner backend for JCOP — "Je Clique Ou Pas" (https://jecliqueoupas.cyber.gouv.fr),
the malware-analysis API from cyber.gouv.fr.

Modelled on the reference implementation in suitenumerique/django-lasuite
(``lasuite/malware_detection/backends/jcop.py``), which drives the same API from
Django/Celery. There, each poll is a separate retried task; here we collapse
submit-then-poll into a single blocking :meth:`scan` — fine for the dramatiq
worker (long tasks are expected), and usable synchronously too, bounded by
``JCOP_SUBMIT_TIMEOUT``.

The API (``X-Auth-Token`` auth; ``JCOP_BASE_URL`` ends in ``/api/v1``):

* ``GET  {base}/results/{key}`` → ``404`` unknown · ``401`` bad key ·
  ``200 {done, is_malware, error_code, error}``.
* ``POST {base}/submit`` (multipart ``file``) → ``200 {id}``; poll ``results/{id}``.

We check ``results/{sha256}`` first (free cache hit / dedup) before submitting.
"""

import hashlib
import logging
import time
from http import HTTPStatus

import requests

from config import get_settings
from scanner import Scanner, ScannerError, Verdict, clean, malware, unscannable

logger = logging.getLogger("file-scanner")

settings = get_settings()

# JCOP error_code for a file too large to analyse (mirrors the 413 the Drive
# callback special-cases).
_TOO_LARGE_CODE = 413


class JcopScanner(Scanner):
    category = "malware"

    def __init__(
        self,
        base_url=None,
        api_key=None,
        result_timeout=None,
        submit_timeout=None,
        poll_interval=None,
    ):
        self.base_url = (base_url or settings.jcop_base_url).rstrip("/")
        self.api_key = api_key or settings.jcop_api_key
        self.result_timeout = (
            result_timeout
            if result_timeout is not None
            else settings.jcop_result_timeout
        )
        self.submit_timeout = (
            submit_timeout
            if submit_timeout is not None
            else settings.jcop_submit_timeout
        )
        self.poll_interval = (
            poll_interval if poll_interval is not None else settings.jcop_poll_interval
        )
        if not self.base_url or not self.api_key:
            raise RuntimeError("JCOP backend requires JCOP_BASE_URL and JCOP_API_KEY")

    @property
    def _headers(self):
        return {"X-Auth-Token": self.api_key, "Accept": "application/json"}

    def ping(self) -> bool:
        # JCOP has no health route; any HTTP answer to a results lookup means the
        # service is reachable (404/401 included), a 5xx or no answer means not.
        try:
            r = requests.get(
                f"{self.base_url}/results/{'0' * 64}",
                headers=self._headers,
                timeout=self.result_timeout,
            )
        except requests.RequestException:
            return False
        return r.status_code < HTTPStatus.INTERNAL_SERVER_ERROR

    def scan(self, fileobj) -> Verdict:
        file_hash = hashlib.file_digest(fileobj, "sha256").hexdigest()
        fileobj.seek(0)
        content = self._analyse(file_hash, fileobj)
        return self._verdict(content)

    # --- HTTP helpers (any RequestException → transient ScannerError) ---

    def _get_result(self, key):
        try:
            return requests.get(
                f"{self.base_url}/results/{key}",
                headers=self._headers,
                timeout=self.result_timeout,
            )
        except requests.RequestException as exc:
            raise ScannerError(f"JCOP results request failed: {exc}") from exc

    def _submit(self, fileobj, deadline) -> str:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ScannerError("JCOP budget exhausted before submit")
        try:
            r = requests.post(
                f"{self.base_url}/submit",
                headers=self._headers,
                files={"file": ("file", fileobj)},
                timeout=(30, remaining),
            )
        except requests.RequestException as exc:
            raise ScannerError(f"JCOP submit failed: {exc}") from exc
        if r.status_code == HTTPStatus.OK:
            return r.json()["id"]
        if r.status_code == HTTPStatus.UNAUTHORIZED:
            raise ScannerError("JCOP submit rejected: invalid API key")
        raise ScannerError(f"JCOP submit failed: HTTP {r.status_code}")

    def _analyse(self, file_hash, fileobj) -> dict:
        # One deadline for the whole submit + poll flow, so total wall time stays
        # within submit_timeout (rather than resetting the clock after submit).
        deadline = time.monotonic() + self.submit_timeout
        # Cache check by content hash before spending a submit.
        r = self._get_result(file_hash)
        if r.status_code == HTTPStatus.OK:
            content = r.json()
            if content.get("done"):
                return content
            poll_key = file_hash
        elif r.status_code == HTTPStatus.NOT_FOUND:
            poll_key = self._submit(fileobj, deadline)
        elif r.status_code == HTTPStatus.UNAUTHORIZED:
            raise ScannerError("JCOP rejected the request: invalid API key")
        else:
            raise ScannerError(f"JCOP results lookup failed: HTTP {r.status_code}")

        # Poll until the analysis is done or the shared budget is spent.
        while time.monotonic() < deadline:
            time.sleep(self.poll_interval)
            r = self._get_result(poll_key)
            if r.status_code == HTTPStatus.OK:
                content = r.json()
                if content.get("done"):
                    return content
            elif r.status_code == HTTPStatus.UNAUTHORIZED:
                raise ScannerError("JCOP rejected the request: invalid API key")
            # 404 / not-done / other → keep polling until the deadline.
        raise ScannerError(
            f"JCOP analysis did not complete within {self.submit_timeout}s"
        )

    @staticmethod
    def _verdict(content: dict) -> Verdict:
        is_malware = content.get("is_malware")
        if is_malware is True:
            return malware(content.get("error") or "malware")
        if is_malware is False:
            return clean()
        # done but no clear verdict: JCOP couldn't classify the file.
        if content.get("error_code") == _TOO_LARGE_CODE:
            return unscannable("TOO-LARGE")
        return unscannable("UNSCANNABLE")
