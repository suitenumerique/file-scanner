"""Scanner backend for exav (https://github.com/sylvinus/exav).

exav is a memory-safe Rust reimplementation of the clamd wire protocol that
loads the same ClamAV signature databases, so it reuses most of
:class:`~scanners.clamav.ClamavScanner` — INSTREAM and the OK/FOUND handling.
What is exav-specific lives here: its ``ERROR`` replies carry a *structured tag*
(``LIMITS-EXCEEDED`` / ``UNSCANNABLE`` / ``PASSWORD-PROTECTED``, and future
codes) rather than a raw clamd sentence, so it overrides
:meth:`_error_verdict` to surface the recognised tag as the ``unscannable``
reason. Stock ClamAV never emits these, which is why the clamav base stays
unaware of them.

It has its own daemon pool (``EXAV_HOSTS``, ``host:port,...``, balanced per scan)
so clamav and exav can run **in parallel** against separate daemons. exav's
``VERSION`` string isn't the ClamAV freshness format and it manages its own
database reloads, so it reports no signature version.
"""

from config import get_settings
from scanner import Verdict, VersionInfo, unscannable
from scanners.clamav import ClamavScanner, _is_transient, parse_hosts

settings = get_settings()


def unscannable_tag(reason):
    """Return the exav 'not fully scanned' tag for an ERROR reason, else None.

    Recognises the known tags AND any future exav code (a bare upper-case token
    is returned verbatim). A structured tag is a single upper-case token, e.g.
    LIMITS-EXCEEDED — a raw clamd/OS error is a mixed-case sentence with spaces,
    so it never qualifies. A bare token that is actually a transient infra signal
    (``TIMEOUT``) returns None so it is retried, not treated as a permanent file
    error.
    """
    if not reason:
        return None
    token = reason.strip()
    if " " in token or not token.isupper():
        return None
    if _is_transient(token):
        return None
    return token


class ExavScanner(ClamavScanner):
    def __init__(self):
        if not settings.exav_hosts:
            raise RuntimeError("exav backend requires EXAV_HOSTS (host:port,...)")

    def _endpoints(self):
        return None, parse_hosts(settings.exav_hosts)

    def _error_verdict(self, reason) -> Verdict:
        """Surface a recognised exav structured tag verbatim; otherwise fall back
        to the generic clamd handling (transient retry vs. plain unscannable)."""
        tag = unscannable_tag(reason)
        if tag:
            return unscannable(tag)
        return super()._error_verdict(reason)

    def version(self) -> VersionInfo | None:
        return None
