"""Shared scan-request policy: positive host allowlist + SSRF guard.

Enforced at BOTH boundaries — the web layer (fast rejection) and the worker
(the real fetch, defense in depth) — so a request that reaches the queue by any
path is still checked before the service dials out.
"""

from urllib.parse import urlparse

from config import get_settings
from ssrf import SSRFValidationError, validate_hostname

settings = get_settings()


def host_allowed(hostname: str) -> bool:
    """False when ``ALLOWED_URL_HOSTS`` is set and ``hostname`` isn't on it.

    Hostnames are case-insensitive, so both sides are lower-cased before matching
    (as ``ssrf.py`` does).
    """
    if not settings.allowed_url_hosts:
        return True
    raw = settings.allowed_url_hosts.split(",")
    hosts = [h.strip().lower() for h in raw if h.strip()]
    return not hosts or (hostname or "").lower() in hosts


def assert_scannable(url: str, webhook_url: str | None = None) -> None:
    """Raise ``SSRFValidationError`` unless ``url`` (and ``webhook_url``) are safe.

    Applies the positive allowlist always, and the SSRF hostname guard unless
    ``settings.testing`` is set (the guard is inert in the test/CI profiles; the
    worker's ``SSRFSafeSession`` still pins/validates at connection time).
    """
    parsed = urlparse(url)
    if not parsed.hostname:
        raise SSRFValidationError("invalid url (missing hostname)")
    if not host_allowed(parsed.hostname):
        raise SSRFValidationError(f"host {parsed.hostname} not allowed")

    if settings.testing:
        return

    validate_hostname(parsed.hostname)
    if webhook_url:
        webhook_host = urlparse(webhook_url).hostname
        if not webhook_host:
            raise SSRFValidationError("invalid webhook_url (missing hostname)")
        validate_hostname(webhook_host)
