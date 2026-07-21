"""Guarded dramatiq-redis-streams queue dashboard.

The upstream dashboard (``dramatiq_redis_streams.dashboard.DashboardApp``, a WSGI
app) exposes **destructive, unauthenticated** endpoints — flush, remove, requeue.
:func:`create_app` returns it wrapped by :class:`Guard`, a thin WSGI middleware
that enforces

* **HTTP Basic auth** — the ``WORKER_DASHBOARD_PASSWORD`` is the secret; with none
  set the guard fail-closes (and the app doesn't even mount it). The username is
  ignored unless ``WORKER_DASHBOARD_USER`` is set.
* an optional **IP allowlist** (``WORKER_DASHBOARD_ALLOWED_IPS``, IPs/CIDRs). By
  default it checks the direct peer (``REMOTE_ADDR``); set
  ``WORKER_DASHBOARD_FORWARDED_IP_HEADER`` (e.g. ``X-Forwarded-For``) to trust a
  proxy's client-IP header instead.

The web app mounts this at ``WORKER_DASHBOARD_PATH`` (default ``/dashboard``, see
``app.py``), so a single ``uvicorn app:app`` serves both the API and — when a
password is configured — the dashboard. Because it rides on the public web tier,
restrict it with the IP allowlist and/or a reverse proxy.
"""

import base64
import binascii
import hmac
import ipaddress
import logging

from config import get_settings

logger = logging.getLogger("file-scanner")
settings = get_settings()


def _allowed_networks() -> list:
    """Parse ``WORKER_DASHBOARD_ALLOWED_IPS`` into networks (per call, for tests)."""
    nets = []
    for raw in settings.worker_dashboard_allowed_ips.split(","):
        entry = raw.strip()
        if entry:
            nets.append(ipaddress.ip_network(entry, strict=False))
    return nets


def client_ip(environ) -> str | None:
    """The client IP for the allowlist check.

    If ``WORKER_DASHBOARD_FORWARDED_IP_HEADER`` names a header (e.g.
    ``X-Forwarded-For``), its leftmost value is used — trust it only behind a
    proxy that overwrites the header. Otherwise the direct peer (``REMOTE_ADDR``).
    """
    header = settings.worker_dashboard_forwarded_ip_header.strip()
    if header:
        # WSGI exposes request headers as HTTP_<UPPER_SNAKE>.
        value = environ.get("HTTP_" + header.upper().replace("-", "_"))
        if value:
            return value.split(",")[0].strip()
    return environ.get("REMOTE_ADDR")


def ip_allowed(host: str | None) -> bool:
    """True if ``host`` is in the allowlist — or if no allowlist is configured."""
    nets = _allowed_networks()
    if not nets:
        return True
    try:
        ip = ipaddress.ip_address(host or "")
    except ValueError:
        return False
    return any(ip in net for net in nets)


def authorized(auth_header: str | None) -> bool:
    """Validate an HTTP Basic ``Authorization`` header in constant time.

    Fail-closed: returns False when no ``WORKER_DASHBOARD_PASSWORD`` is configured,
    so the destructive dashboard is never served unauthenticated.
    """
    if not settings.worker_dashboard_password:
        return False
    if not auth_header or not auth_header.startswith("Basic "):
        return False
    try:
        user, _, password = base64.b64decode(auth_header[6:]).decode().partition(":")
    except (binascii.Error, UnicodeDecodeError):
        return False
    # The password is the secret (constant-time compare). The username is only
    # enforced when WORKER_DASHBOARD_USER is set; empty accepts any username.
    ok_password = hmac.compare_digest(password, settings.worker_dashboard_password)
    expected_user = settings.worker_dashboard_user
    ok_user = not expected_user or hmac.compare_digest(user, expected_user)
    return ok_user and ok_password


def _deny(start_response, status: str, message: str, headers=None) -> list:
    body = message.encode()
    resp_headers = [
        ("Content-Type", "text/plain; charset=utf-8"),
        ("Content-Length", str(len(body))),
        *(headers or []),
    ]
    start_response(status, resp_headers)
    return [body]


class Guard:
    """WSGI middleware: IP allowlist + Basic auth in front of the (destructive)
    dashboard app."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        peer = client_ip(environ)
        if not ip_allowed(peer):
            logger.warning("dashboard: blocked request from %s", peer)
            return _deny(start_response, "403 Forbidden", "Forbidden\n")
        if not authorized(environ.get("HTTP_AUTHORIZATION")):
            return _deny(
                start_response,
                "401 Unauthorized",
                "Unauthorized\n",
                [("WWW-Authenticate", 'Basic realm="dashboard"')],
            )
        return self.app(environ, start_response)


def create_app(prefix: str = ""):
    """Build the guarded dashboard **WSGI** app.

    ``prefix`` is the mount path (so the dashboard's own links resolve) — the web
    app passes ``/dashboard``. The heavy imports are lazy so this module (and its
    guard helpers) can be imported without the ``dramatiq_redis_streams`` package
    or a live broker present.
    """
    from dramatiq_redis_streams.dashboard import DashboardApp

    from broker import broker

    return Guard(DashboardApp(broker, prefix=prefix))
