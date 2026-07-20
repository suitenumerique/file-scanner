"""Scanner backend for exav (https://github.com/sylvinus/exav).

exav speaks the clamd wire protocol but adds the ``EXINSTREAM`` verb: it streams
a file exactly like ``INSTREAM`` and replies with one line of structured JSON
stating the verdict class outright (``clean`` / ``malware`` / ``unscannable`` /
``error``) plus the signature and, for a detection inside a container, the inner
member's path (``location``). So this backend parses JSON rather than guessing a
verdict from a reason string, and surfaces a ``location`` the clamav backend
can't. exav requires ``EXINSTREAM`` — pointing ``EXAV_HOSTS`` at a daemon without
it (e.g. stock clamd) makes scans error.

It has its own daemon pool (``EXAV_HOSTS``, ``host:port,...``, balanced per scan)
so clamav and exav can run in parallel against separate daemons. ``PING`` /
``VERSION`` use the standard clamd path; exav manages its own database reloads and
its ``VERSION`` isn't the ClamAV freshness format, so it reports no signature
version.
"""

import json
import random
import struct

import clamd

from config import get_settings
from scanner import ScannerError, Verdict, VersionInfo, clean, unscannable
from scanners.clamav import ClamavScanner, parse_hosts

settings = get_settings()

# Stream chunk size for EXINSTREAM (mirrors the clamd client's INSTREAM).
_STREAM_CHUNK = 1024


class _ExavClient(clamd.ClamdNetworkSocket):
    """A clamd network client plus exav's ``EXINSTREAM`` verb (JSON reply).

    Reuses the clamd client's connection setup and command/response framing, so
    ``PING`` / ``VERSION`` keep working; only the scan reply differs.
    """

    def exinstream(self, fileobj) -> str:
        """Stream ``fileobj`` over EXINSTREAM (INSTREAM framing) and return the
        raw JSON reply line."""
        self._init_socket()
        try:
            self._send_command("EXINSTREAM")
            chunk = fileobj.read(_STREAM_CHUNK)
            while chunk:
                self.clamd_socket.sendall(struct.pack(b"!L", len(chunk)) + chunk)
                chunk = fileobj.read(_STREAM_CHUNK)
            self.clamd_socket.sendall(struct.pack(b"!L", 0))
            return self._recv_response()
        finally:
            self._close_socket()


class ExavScanner(ClamavScanner):
    def __init__(self):
        if not settings.exav_hosts:
            raise RuntimeError("exav backend requires EXAV_HOSTS (host:port,...)")

    def _endpoints(self):
        return None, parse_hosts(settings.exav_hosts)

    def _client(self) -> _ExavClient:
        # exav uses a TCP host pool (no unix socket); pick one at random per scan.
        _, hosts = self._endpoints()
        host, port = random.choice(hosts)  # noqa: S311 — load balancing, not crypto
        return _ExavClient(host=host, port=port, timeout=settings.clamav_timeout)

    def scan(self, fileobj) -> Verdict:
        try:
            raw = self._client().exinstream(fileobj)
        except (clamd.ConnectionError, OSError) as exc:
            # Unreachable, or a daemon without EXINSTREAM that drops the connection.
            raise ScannerError(f"exav scan failed: {exc}") from exc
        return self._parse_verdict(raw)

    @staticmethod
    def _parse_verdict(raw: str) -> Verdict:
        """Map an ``EXINSTREAM`` JSON reply to a :class:`Verdict`."""
        if raw.startswith("UNKNOWN COMMAND"):
            raise ScannerError("exav does not support EXINSTREAM (upgrade the daemon)")
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ScannerError(f"exav returned a non-JSON reply: {raw[:80]!r}") from exc
        verdict = data.get("verdict")
        if verdict == "clean":
            return clean()
        if verdict == "malware":
            return Verdict(
                "malware", data.get("signature"), location=data.get("location")
            )
        if verdict == "unscannable":
            # exav states the class outright — no tag-vs-sentence guessing.
            return unscannable(data.get("tag") or "UNSCANNABLE")
        if verdict == "error":
            # A transient/infra failure — retryable.
            raise ScannerError(
                f"exav scan error: {data.get('message') or 'unspecified'}"
            )
        raise ScannerError(f"exav returned an unknown verdict: {verdict!r}")

    def version(self) -> VersionInfo | None:
        return None
