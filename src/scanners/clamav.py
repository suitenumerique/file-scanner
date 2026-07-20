"""ClamAV scanner backend (the clamd wire protocol).

Connects to ``CLAMAV_SOCKET`` or ``CLAMAV_HOST:CLAMAV_PORT``; if ``CLAMAV_HOSTS`` is
set (``host:port,...``) a host is picked at random per scan for client-side
balancing (the task-level retry fails over to another). All clamd/ClamAV
specifics — connection, INSTREAM, and verdict classification — live here; the
exav backend (``exav.py``) subclasses this one.

An ``ERROR`` reply means the file was not fully scanned, so it is never clean: a
transient infrastructure reason (out of memory, disk full, a runtime limit)
retries, anything else is an ``unscannable`` file. The exav backend extends this
via :meth:`ClamavScanner._error_verdict` to recognise its structured error tags.
"""

import random

import clamd
import dns.resolver

from config import get_settings
from scanner import (
    Scanner,
    ScannerError,
    Verdict,
    VersionInfo,
    clean,
    malware,
    unscannable,
)

settings = get_settings()


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


def _is_transient(reason) -> bool:
    return any(h in (reason or "").lower() for h in _TRANSIENT_HINTS)


def parse_local_version(version_text: str) -> str:
    """'ClamAV 0.100.3/25480/Fri Jun 14 ...' -> '25480'."""
    return version_text.split("/")[1]


def parse_remote_version(version_text: str) -> str:
    """'0.103.1:59:26120:1616678940:...' -> '26120'."""
    return version_text.split(":")[2]


def _remote_version_text(uri: str) -> str:
    answers = dns.resolver.resolve(uri, "TXT")
    version = "unknown"
    for data in answers:
        for txt in data.strings:
            version = txt.decode("utf-8")
    return version


class ClamavScanner(Scanner):
    category = "malware"

    def _endpoints(self):
        """Return ``(socket_path, hosts)`` for this backend — override in
        subclasses. Exactly one is set."""
        if settings.clamav_hosts:
            return None, parse_hosts(settings.clamav_hosts)
        if settings.clamav_socket:
            return settings.clamav_socket, None
        return None, [(settings.clamav_host, settings.clamav_port)]

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

    def scan(self, fileobj) -> Verdict:
        try:
            result = self._client().instream(fileobj)
        except clamd.ConnectionError as exc:
            raise ScannerError(f"scanner unreachable: {exc}") from exc
        status, reason = result["stream"]

        if status == "OK":
            return clean()
        if status == "ERROR":
            # An ERROR means the file was NOT fully scanned — never clean.
            return self._error_verdict(reason)
        # FOUND (or any other non-OK verdict) → a detection.
        return malware(reason)

    def _error_verdict(self, reason) -> Verdict:
        """Map a clamd ``ERROR`` reply to a verdict. The file was not fully
        scanned, so it is never clean: a transient infrastructure reason (OOM,
        disk, runtime limit) retries; anything else is an unscannable file.
        Subclasses override to recognise structured error tags (see exav).
        """
        if _is_transient(reason):
            raise ScannerError(f"scan error: {reason}")
        return unscannable("UNSCANNABLE")

    def version(self) -> VersionInfo:
        try:
            local = parse_local_version(self._client().version())
            remote = parse_remote_version(_remote_version_text(settings.clamav_txt_uri))
        except Exception as exc:
            raise ScannerError(f"version check failed: {exc}") from exc
        return VersionInfo(actual=local, required=remote, outdated=local != remote)
