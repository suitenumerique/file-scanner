"""ClamAV scanner backend (the clamd wire protocol).

Connects to ``CLAMAV_SOCKET`` (a Unix socket, if set) or the ``CLAMAV_HOSTS`` pool
(``host:port,...``); with several hosts one is picked at random per scan for
client-side balancing (the task-level retry fails over to another). All clamd/ClamAV
specifics — connection, INSTREAM, and verdict classification — live here; the
exav backend (``exav.py``) subclasses this one.

An ``ERROR`` reply means the file was not fully scanned, so it is never clean: a
transient infrastructure reason (out of memory, disk full, a runtime limit)
retries, anything else is a ``partial`` verdict. The exav backend extends this
via :meth:`ClamavScanner._error_verdict` to recognise its structured error tags.
"""

import calendar
import functools
import logging
import random
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import clamd

from config import get_settings
from scanner import (
    Scanner,
    ScannerError,
    Verdict,
    clean,
    malware,
    partial,
)

logger = logging.getLogger("file-scanner")
settings = get_settings()

# How long a VERSION probe (the /metrics signature-database gauges) may take per
# daemon. clamd answers it from memory, so a slower daemon is one in trouble.
_PROBE_TIMEOUT = 2.0


def parse_hosts(raw: str) -> list[tuple[str, int]]:
    """Parse a ``host:port,host2:port2`` list; port defaults to 3310."""
    hosts = []
    for raw_entry in raw.split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        host, _, port = entry.partition(":")
        hosts.append((host, int(port) if port else 3310))
    return hosts


# Raw clamd/OS error fragments that are genuinely transient infrastructure
# problems (out of memory, hit a runtime limit, disk full) — a retry may help.
_TRANSIENT_HINTS = ("allocate", "time limit", "timeout", "no space")


# clamd's "signature" for a limit it hit, when AlertExceedsMax is on:
# Heuristics.Limits.Exceeded.<MaxScanTime|MaxFileSize|MaxScanSize|...>.
_LIMIT_ALERT_PREFIX = "Heuristics.Limits.Exceeded"


def _is_transient(reason) -> bool:
    return any(h in (reason or "").lower() for h in _TRANSIENT_HINTS)


@dataclass(frozen=True)
class DatabaseInfo:
    """The signature database a clamd daemon has loaded."""

    version: int | None  # daily database version; None when none is loaded
    built: float | None  # its build time (Unix); None when unreadable


def parse_database_info(version_text: str) -> DatabaseInfo:
    """``'ClamAV 1.4.3/27000/Mon Nov 10 08:23:01 2026'`` → (27000, build time).

    clamd prints the build time with ``ctime()``, in its own timezone — UTC in
    the official image — so it is read as UTC: a few hours of skew don't matter
    to a freshness alert counted in days. A daemon without a database answers
    just ``'ClamAV 1.4.3'``; an out-of-range time, ``'invalid timestamp'``.
    """
    parts = version_text.strip().split("/", 2)
    if len(parts) < 3:
        return DatabaseInfo(None, None)
    try:
        version = int(parts[1])
    except ValueError:
        version = None
    try:
        built = float(
            calendar.timegm(time.strptime(parts[2].strip(), "%a %b %d %H:%M:%S %Y"))
        )
    except ValueError:
        built = None
    return DatabaseInfo(version, built)


class ClamavScanner(Scanner):
    category = "malware"

    def _endpoints(self):
        """Return ``(socket_path, hosts)`` for this backend — override in
        subclasses. Exactly one is set; the socket takes precedence."""
        if settings.clamav_socket:
            return settings.clamav_socket, None
        return None, parse_hosts(settings.clamav_hosts)

    def _client(self):
        """Build a fresh clamd client, picking a random host from the pool so a
        host list balances per scan (socket takes precedence)."""
        socket_path, hosts = self._endpoints()
        timeout = settings.clamav_timeout
        if socket_path:
            return clamd.ClamdUnixSocket(path=socket_path, timeout=timeout)
        host, port = random.choice(hosts)  # noqa: S311 — load balancing, not crypto
        return clamd.ClamdNetworkSocket(host=host, port=port, timeout=timeout)

    def ping(self) -> bool:
        try:
            return self._client().ping() == "PONG"
        except Exception:
            return False

    # Named in every failure a stream over clamd's StreamMaxLength (default
    # 100M) can produce, so the operator reads a deployment limit rather than
    # a flaky daemon. All stay transient: the scan passes once it is raised.
    _LIMIT_HINT = (
        "a file above clamd's StreamMaxLength? (raise CLAMD_CONF_StreamMaxLength "
        "/ MaxFileSize / MaxScanSize past MAX_URL_SIZE)"
    )

    def scan(self, fileobj) -> Verdict:
        try:
            result = self._client().instream(fileobj)
        except clamd.ConnectionError as exc:
            # The daemon is down — or it closed the socket after the stream
            # was sent, which the client reports as a read error.
            raise ScannerError(
                f"clamd connection failed: {exc} — daemon unreachable, or "
                f"{self._LIMIT_HINT}"
            ) from exc
        except (BrokenPipeError, ConnectionResetError, clamd.BufferTooLongError) as exc:
            # clamd answered "INSTREAM size limit exceeded" (BufferTooLongError)
            # or closed the socket mid-stream and the client died on send().
            raise ScannerError(
                f"clamd closed the stream mid-scan: {self._LIMIT_HINT}: {exc}"
            ) from exc
        if not result:
            # clamd closed the connection without a reply: the client returns
            # nothing rather than raising.
            raise ScannerError(f"clamd sent no reply: {self._LIMIT_HINT}")
        status, reason = result["stream"]

        if status == "OK":
            return clean()
        if status == "ERROR":
            # An ERROR means the file was NOT fully scanned — never clean.
            return self._error_verdict(reason)
        if (reason or "").startswith(_LIMIT_ALERT_PREFIX):
            # With AlertExceedsMax on, clamd reports a scan it had to stop
            # (MaxScanTime, MaxFileSize, MaxScanSize, MaxRecursion, ...) as a
            # FOUND named after the limit. That is a file it could not fully
            # examine, not a detection.
            return partial("LIMITS-EXCEEDED")
        # FOUND (or any other non-OK verdict) → a detection.
        return malware(reason)

    def _error_verdict(self, reason) -> Verdict:
        """Map a clamd ``ERROR`` reply to a verdict. The file was not fully
        scanned, so it is never clean: a transient infrastructure reason (OOM,
        disk, runtime limit) retries; anything else is a partial verdict.
        Subclasses override to recognise structured error tags (see exav).
        """
        if _is_transient(reason):
            raise ScannerError(f"scan error: {reason}")
        return partial("UNSCANNABLE")

    def database_info(self) -> dict[str, DatabaseInfo | None]:
        """The database every daemon of the pool has loaded, keyed ``host:port``
        (or the socket path); None for a daemon that didn't answer.

        Unlike a scan, which picks one host at random, this asks each one, in
        parallel: a stale daemon must not hide behind its peers."""
        socket_path, hosts = self._endpoints()
        if socket_path:
            targets = {
                socket_path: functools.partial(
                    clamd.ClamdUnixSocket, path=socket_path, timeout=_PROBE_TIMEOUT
                )
            }
        else:
            targets = {
                f"{host}:{port}": functools.partial(
                    clamd.ClamdNetworkSocket,
                    host=host,
                    port=port,
                    timeout=_PROBE_TIMEOUT,
                )
                for host, port in hosts
            }

        def _probe(item):
            """One daemon's DatabaseInfo, or None if it didn't answer."""
            daemon, make_client = item
            try:
                return parse_database_info(make_client().version())
            except Exception as exc:
                logger.warning("clamd %s did not answer VERSION: %s", daemon, exc)
                return None

        with ThreadPoolExecutor(max_workers=len(targets)) as pool:
            return dict(zip(targets, pool.map(_probe, targets.items()), strict=True))
