"""Server-Side Request Forgery (SSRF) protections.

Vendored, with minimal changes, from suitenumerique/messages
(``src/backend/core/services/ssrf.py``) so improvements can be rebased from
upstream. The only local edits are:

* the operator allowlist is read from this project's ``config.get_settings()``
  (``SSRF_ALLOWED_HOSTS``) instead of Django settings;
* no other behavioural change.

It provides a hostname/IP validator plus an HTTP session with IP pinning that
follows redirects manually, re-validating every hop — defeating DNS-rebinding
(TOCTOU) and redirect-to-internal SSRF.
"""

import ipaddress
import socket
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter

from config import get_settings

CLOUD_METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254"})

MAX_REDIRECTS = 5
REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})


class SSRFValidationError(Exception):
    """Raised when a URL or hostname fails SSRF validation."""


def _allowed_hosts() -> set[str]:
    """Operator SSRF allowlist, parsed from ``SSRF_ALLOWED_HOSTS``."""
    raw = get_settings().ssrf_allowed_hosts or ""
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def is_allowlisted_host(hostname: str) -> bool:
    """Return True if ``hostname`` is on the operator SSRF allowlist.

    ``SSRF_ALLOWED_HOSTS`` holds exact, case-insensitive hostnames that a
    deployment trusts even though they resolve to a private/internal address
    (e.g. app-to-app traffic on a PaaS internal overlay, or the object store an
    async scan downloads from). Matching a host here bypasses the ``_check_ip``
    range checks — so keep the list narrow.
    """
    if not hostname:
        return False
    return hostname.lower() in _allowed_hosts()


def _check_ip(ip_addr: ipaddress._BaseAddress, hostname: str) -> None:
    # Check specific categories before is_private: in Python's ipaddress
    # module, loopback/link-local/etc. are subsets of is_private, so checking
    # is_private first would mask the more informative error.
    if str(ip_addr) in CLOUD_METADATA_IPS:
        raise SSRFValidationError(f"{hostname} resolves to cloud metadata endpoint")
    if ip_addr.is_loopback:
        raise SSRFValidationError(f"{hostname} resolves to loopback address")
    if ip_addr.is_link_local:
        raise SSRFValidationError(f"{hostname} resolves to link-local address")
    if ip_addr.is_multicast:
        raise SSRFValidationError(f"{hostname} resolves to multicast address")
    if ip_addr.is_reserved:
        raise SSRFValidationError(f"{hostname} resolves to reserved address")
    if ip_addr.is_private:
        raise SSRFValidationError(f"{hostname} resolves to private IP address")
    # Catch-all for anything not globally routable that the specific checks
    # above miss — notably shared address space / CGNAT (100.64.0.0/10), which
    # is neither is_private nor is_reserved in Python's ipaddress module.
    if not ip_addr.is_global:
        raise SSRFValidationError(f"{hostname} resolves to non-global address")


def assert_public_ip(ip: str, hostname: str = "") -> None:
    """Raise ``SSRFValidationError`` unless ``ip`` is a public address."""
    try:
        ip_addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise SSRFValidationError(f"Invalid IP address {ip!r}") from exc
    _check_ip(ip_addr, hostname or ip)


def validate_hostname(hostname: str, *, allow_ip_literal: bool = False) -> list[str]:
    """Resolve hostname and reject private/internal/metadata addresses.

    Args:
        hostname: A hostname or, when allow_ip_literal=True, an IP literal.
        allow_ip_literal: If False (default), IP literals are rejected outright —
            legitimate services use domain names. If True, public IP literals
            are accepted.

    Returns:
        List of validated IP addresses the hostname resolves to.

    Raises:
        SSRFValidationError: If the hostname/IP resolves to a blocked address.
    """
    if not hostname:
        raise SSRFValidationError("Invalid hostname (missing)")

    # An operator-trusted host skips the IP-range checks below, but we still
    # resolve it: callers (IP-pinning session) need a concrete IP, and a name
    # that doesn't resolve should still fail rather than silently pass.
    allowlisted = is_allowlisted_host(hostname)

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None

    if ip is not None:
        if not allow_ip_literal:
            raise SSRFValidationError(
                "IP addresses are not allowed (domain name required)"
            )
        if not allowlisted:
            _check_ip(ip, hostname)
        return [str(ip)]

    try:
        addr_info = socket.getaddrinfo(
            hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise SSRFValidationError("Unable to resolve hostname") from exc

    valid_ips: list[str] = []
    for _, _, _, _, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            ip_addr = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise SSRFValidationError("Invalid IP address in DNS response") from exc
        if not allowlisted:
            _check_ip(ip_addr, hostname)
        valid_ips.append(ip_str)

    if not valid_ips:
        raise SSRFValidationError("No valid IP addresses found")

    return valid_ips


class SSRFProtectedAdapter(HTTPAdapter):
    """HTTPAdapter that pins the connection to a pre-validated IP.

    Prevents TOCTOU DNS rebinding by:
    1. Connecting to the IP address that was validated (no re-resolving DNS).
    2. Verifying TLS certificates against the original hostname (for HTTPS).
    3. Setting the Host header correctly for virtual hosting.
    """

    def __init__(
        self,
        dest_ip: str,
        dest_port: int,
        original_hostname: str,
        original_scheme: str,
        **kwargs,
    ):
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.original_hostname = original_hostname
        self.original_scheme = original_scheme
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        if self.original_scheme == "https":
            pool_kwargs["assert_hostname"] = self.original_hostname
            pool_kwargs["server_hostname"] = self.original_hostname
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

    def send(
        self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None
    ):
        parsed = urlparse(request.url)

        if ":" in self.dest_ip:
            ip_netloc = f"[{self.dest_ip}]:{self.dest_port}"
        else:
            ip_netloc = f"{self.dest_ip}:{self.dest_port}"

        request.url = urlunparse(
            (
                parsed.scheme,
                ip_netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )

        if parsed.port and parsed.port not in (80, 443):
            request.headers["Host"] = f"{self.original_hostname}:{parsed.port}"
        else:
            request.headers["Host"] = self.original_hostname

        return super().send(
            request,
            stream=stream,
            timeout=timeout,
            verify=verify,
            cert=cert,
            proxies=proxies,
        )


class SSRFSafeSession:
    """HTTP Session with built-in SSRF protection.

    1. Validates URL scheme (only http/https allowed).
    2. Blocks direct IP addresses (legitimate services use domain names).
    3. Resolves hostnames and blocks private/internal IPs.
    4. Pins resolved IPs to prevent DNS rebinding attacks (TOCTOU).

    Usage:
        try:
            response = SSRFSafeSession().get("https://example.com/f.pdf", timeout=10)
        except SSRFValidationError:
            # URL was blocked for security reasons
            pass
    """

    def _validate_and_unpack(self, url: str) -> tuple[str, str, str, int]:
        """Validate a URL and return (validated_ip, hostname, scheme, port)."""
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise SSRFValidationError("Invalid URL scheme (only http/https allowed)")
        if not parsed.hostname:
            raise SSRFValidationError("Invalid URL (missing hostname)")

        valid_ips = validate_hostname(parsed.hostname, allow_ip_literal=False)

        if parsed.port:
            port = parsed.port
        elif parsed.scheme == "http":
            port = 80
        else:
            port = 443

        return valid_ips[0], parsed.hostname, parsed.scheme, port

    def _pinned_session(self, url: str) -> tuple[requests.Session, str]:
        """Return an SSRF-pinned Session bound to ``url``'s validated IP."""
        validated_ip, hostname, scheme, port = self._validate_and_unpack(url)
        session = requests.Session()
        adapter = SSRFProtectedAdapter(
            dest_ip=validated_ip,
            dest_port=port,
            original_hostname=hostname,
            original_scheme=scheme,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session, hostname

    def _request_with_redirects(
        self, method: str, url: str, timeout: int, **kwargs
    ) -> requests.Response:
        """Issue ``method`` to ``url``, following redirects manually with
        per-hop SSRF validation.

        Each Location URL is re-validated and re-pinned from scratch, so an
        attacker-controlled server cannot redirect to an internal address on a
        later hop. The HTTP method and body are preserved across hops. An
        HTTPS→HTTP downgrade is refused.
        """
        kwargs.pop("allow_redirects", None)

        current_url = url
        for _ in range(MAX_REDIRECTS + 1):
            session, _ = self._pinned_session(current_url)

            response = getattr(session, method)(
                current_url, timeout=timeout, allow_redirects=False, **kwargs
            )

            if response.status_code not in REDIRECT_STATUS_CODES:
                return response

            location = response.headers.get("Location")
            if not location:
                return response

            next_url = urljoin(current_url, location)
            if (
                urlparse(current_url).scheme == "https"
                and urlparse(next_url).scheme == "http"
            ):
                response.close()
                raise SSRFValidationError(
                    "Refusing to follow HTTPS→HTTP redirect downgrade"
                )
            response.close()
            current_url = next_url

        raise SSRFValidationError(f"Too many redirects (max {MAX_REDIRECTS})")

    def get(self, url: str, timeout: int, **kwargs) -> requests.Response:
        """Perform a safe HTTP GET with per-hop SSRF validation on redirects."""
        return self._request_with_redirects("get", url, timeout, **kwargs)

    def post(self, url: str, timeout: int, **kwargs) -> requests.Response:
        """Perform a safe HTTP POST with per-hop SSRF validation on redirects."""
        return self._request_with_redirects("post", url, timeout, **kwargs)
