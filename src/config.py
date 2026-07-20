"""Application configuration.

Every knob is a field on :class:`Settings`, documented inline below with its
environment variable (in parentheses) and units. ``APP_CONFIG`` selects a
profile from ``CONFIGS``: ``config.ProductionConfig`` (default) reads everything
from the environment; the ``Test`` / ``Ci`` / ``Local`` profiles are static and
run "eager" (no Redis / worker). Get the active settings via
:func:`get_settings`.
"""

import os
from dataclasses import dataclass


def _int_env(name: str, default: int) -> int:
    """Read an integer env var, falling back to ``default`` when unset/empty."""
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc


@dataclass
class Settings:
    # --- Runtime profile ---
    # Verbose (DEBUG) logging when true.
    debug: bool = False
    # Test/CI mode: relaxes a few guards that need real infrastructure — the
    # request-time SSRF check is skipped (the worker still enforces it) and tasks
    # may run eagerly. NEVER enable in production.
    testing: bool = False

    # --- Authentication ---
    # Accepted API keys as a comma-separated list of ``name:key`` pairs; ``name``
    # identifies the caller in logs. Empty = every request is rejected. (API_KEYS)
    api_keys: str = ""

    # --- Web server ---
    host: str = "0.0.0.0"  # interface uvicorn binds to
    port: int = 8090  # web server port (PORT)

    # --- Metrics ---
    # If set, GET /metrics requires `Authorization: Bearer <key>` (constant-time
    # compare; Prometheus sends it via bearer_token / authorization). Matches the
    # PROMETHEUS_API_KEY convention in suitenumerique/messages. Empty (default)
    # leaves /metrics open — ONLY safe when the endpoint is isolated at the network
    # layer (private port, mTLS mesh, kube-rbac-proxy). The scan metrics carry an
    # api_client label (caller identities + volumes), so set this on any
    # deployment where /metrics is reachable from an untrusted network.
    # (PROMETHEUS_API_KEY)
    prometheus_api_key: str = ""

    # --- Scanner selection ---
    # JSON map of category -> [scanner names]: which categories (axes of
    # judgment, e.g. "malware" / "nsfw") exist on this deployment and which
    # engines compose each. Its keys are the categories a `?categories=` request
    # can select; a `?scanners=` request names engines directly. Public engine
    # names are the products: "clamav" / "exav" (the clamd wire protocol) and
    # "jcop" (the cyber.gouv.fr HTTP service). (DEFAULT_SCANNERS)
    default_scanners: str = '{"malware": ["clamav"]}'
    # Comma-separated categories run when a request names neither `categories`
    # nor `scanners`. Every entry must be a key of DEFAULT_SCANNERS.
    # (DEFAULT_CATEGORIES)
    default_categories: str = "malware"

    # --- clamav backend ---
    # DNS TXT record queried for the latest published signature database version,
    # exposed as the freshness gauge on /metrics. (CLAMAV_TXT_URI)
    clamav_txt_uri: str = "current.cvd.clamav.net"
    clamav_host: str = "localhost"  # single daemon hostname (CLAMAV_HOST)
    clamav_port: int = 3310  # single daemon TCP port (CLAMAV_PORT)
    # Socket timeout (s) for a clamd connection, so an unreachable/hung daemon
    # fails the scan instead of blocking a worker forever. Generous by default to
    # not trip on a legitimately slow scan of a large file. (CLAMAV_TIMEOUT)
    clamav_timeout: int = 300
    # Unix socket path; when set it takes precedence over host/port. (CLAMAV_SOCKET)
    clamav_socket: str = ""
    # Optional client-side balancing: a comma-separated list of ``host:port``
    # (port defaults to 3310). When set, a host is picked at random per scan and
    # the task-level retry fails over to another — no external load balancer
    # needed. Overrides the single host/socket above. (CLAMAV_HOSTS)
    clamav_hosts: str = ""

    # --- exav backend (its own daemon pool; can run alongside clamav) ---
    # Comma-separated ``host:port`` list for the exav pool (balanced per scan like
    # CLAMAV_HOSTS). Required to use the exav scanner. (EXAV_HOSTS)
    exav_hosts: str = ""

    # --- jcop backend ("Je Clique Ou Pas", cyber.gouv.fr) ---
    jcop_base_url: str = ""  # API base, includes the /api/v1 path (JCOP_BASE_URL)
    jcop_api_key: str = ""  # X-Auth-Token value (JCOP_API_KEY)
    jcop_result_timeout: int = 30  # per-request timeout (s) for a results GET
    jcop_submit_timeout: int = 600  # total budget (s) for submit + polling
    jcop_poll_interval: int = 5  # delay (s) between result polls

    # --- Size & time limits ---
    # Max size of a direct upload to /api/v1.0/scan; larger → 413. (MAX_UPLOAD_SIZE)
    max_upload_size: int = 100 * 1024 * 1024  # 100 MiB
    # Max size of a file fetched by /v2/scan-async; enforced against both
    # Content-Length and the bytes actually streamed. (MAX_URL_SIZE)
    max_url_size: int = 2 * 1024 * 1024 * 1024  # 2 GiB
    # Scratch directory the async worker downloads a file into before streaming
    # it to the scanner (INSTREAM). Transient — each file is deleted right after
    # the scan — and NOT shared with the scanner daemon, so any writable path
    # works. (SCAN_DIR)
    scan_dir: str = os.environ.get("SCAN_DIR", "/tmp/file-scanner")
    # Per-read (socket) timeout on the async download — caps time between chunks,
    # not the whole transfer. (URL_DOWNLOAD_TIMEOUT)
    url_download_timeout: int = 30  # seconds
    # Total wall-clock budget for one async download, so a server that dribbles
    # bytes just under the per-read timeout can't tie up a worker.
    # (DOWNLOAD_MAX_SECONDS)
    download_max_seconds: int = 300  # seconds

    # --- Host policy (async scans) ---
    # Positive restriction: if set, ONLY these hostnames may be submitted to
    # /v2/scan-async (comma-separated). Empty = any host, still subject to
    # the SSRF guard below. (ALLOWED_URL_HOSTS)
    allowed_url_hosts: str = ""
    # SSRF allowlist: hostnames trusted to resolve to a private/internal address
    # (e.g. internal object storage, the webhook callback host). Comma-separated;
    # keep it narrow. (SSRF_ALLOWED_HOSTS)
    ssrf_allowed_hosts: str = ""

    # --- Webhook delivery (async result callback) ---
    webhook_timeout: int = 10  # per-attempt timeout (s) (WEBHOOK_TIMEOUT)
    webhook_max_attempts: int = 3  # attempts before giving up (WEBHOOK_MAX_ATTEMPTS)

    # --- Queue dashboard (dramatiq-redis-streams) ---
    # The dashboard exposes DESTRUCTIVE, unauthenticated endpoints upstream. The
    # web app mounts it (behind a Basic-auth + IP-allowlist guard, see
    # dashboard.py) at worker_dashboard_path, but ONLY when a password is set —
    # empty password => not mounted (fail-safe).
    # Optional: if set, the Basic-auth username must also match. Empty (default)
    # accepts ANY username — the password is the secret. (WORKER_DASHBOARD_USER)
    worker_dashboard_user: str = ""
    # (WORKER_DASHBOARD_PASSWORD) — required to serve; empty ⇒ not mounted.
    worker_dashboard_password: str = ""
    # Path the dashboard is mounted at on the web app. (WORKER_DASHBOARD_PATH)
    worker_dashboard_path: str = "/dashboard"
    # Optional peer-IP allowlist (comma-separated IPs/CIDRs); empty = any IP
    # (still password-gated). By default this checks the direct peer.
    # (WORKER_DASHBOARD_ALLOWED_IPS)
    worker_dashboard_allowed_ips: str = ""
    # If set, trust this request header for the client IP in the allowlist check
    # (e.g. "X-Forwarded-For"); its leftmost entry is used. Empty ⇒ use the
    # direct peer (REMOTE_ADDR). Only set this behind a proxy that overwrites the
    # header — it is otherwise client-spoofable.
    # (WORKER_DASHBOARD_FORWARDED_IP_HEADER)
    worker_dashboard_forwarded_ip_header: str = ""

    # --- Background tasks (dramatiq) ---
    # Eager mode: run tasks synchronously, in-process, with an in-memory stub
    # broker — no Redis and no worker needed. On for the test/CI/local profiles.
    worker_eager: bool = False
    # Redis URL for the dramatiq-redis-streams broker (async scans). (WORKER_BROKER_URL)
    worker_broker_url: str = "redis://localhost:6379/0"
    # Redis key prefix for the streams broker; set a distinct value to isolate
    # multiple deployments sharing one Redis. (WORKER_QUEUE_NAMESPACE)
    worker_queue_namespace: str = "file-scanner"


TEST_API_KEY = "test-key-not-for-production"


def _production() -> Settings:
    """Production settings, fully driven by environment variables."""
    return Settings(
        port=_int_env("PORT", 8090),
        prometheus_api_key=os.environ.get("PROMETHEUS_API_KEY", ""),
        api_keys=os.environ.get("API_KEYS", ""),
        default_scanners=os.environ.get("DEFAULT_SCANNERS", '{"malware": ["clamav"]}'),
        default_categories=os.environ.get("DEFAULT_CATEGORIES", "malware"),
        clamav_txt_uri=os.environ.get("CLAMAV_TXT_URI", "current.cvd.clamav.net"),
        clamav_socket=os.environ.get("CLAMAV_SOCKET", ""),
        clamav_host=os.environ.get("CLAMAV_HOST", "clamav"),
        clamav_port=_int_env("CLAMAV_PORT", 3310),
        clamav_timeout=_int_env("CLAMAV_TIMEOUT", 300),
        clamav_hosts=os.environ.get("CLAMAV_HOSTS", ""),
        exav_hosts=os.environ.get("EXAV_HOSTS", ""),
        jcop_base_url=os.environ.get("JCOP_BASE_URL", ""),
        jcop_api_key=os.environ.get("JCOP_API_KEY", ""),
        jcop_result_timeout=_int_env("JCOP_RESULT_TIMEOUT", 30),
        jcop_submit_timeout=_int_env("JCOP_SUBMIT_TIMEOUT", 600),
        jcop_poll_interval=_int_env("JCOP_POLL_INTERVAL", 5),
        worker_broker_url=os.environ.get(
            "WORKER_BROKER_URL", "redis://localhost:6379/0"
        ),
        worker_queue_namespace=os.environ.get("WORKER_QUEUE_NAMESPACE", "file-scanner"),
        worker_dashboard_user=os.environ.get("WORKER_DASHBOARD_USER", ""),
        worker_dashboard_password=os.environ.get("WORKER_DASHBOARD_PASSWORD", ""),
        worker_dashboard_path=os.environ.get("WORKER_DASHBOARD_PATH", "/dashboard"),
        worker_dashboard_allowed_ips=os.environ.get("WORKER_DASHBOARD_ALLOWED_IPS", ""),
        worker_dashboard_forwarded_ip_header=os.environ.get(
            "WORKER_DASHBOARD_FORWARDED_IP_HEADER", ""
        ),
        scan_dir=os.environ.get("SCAN_DIR", "/tmp/file-scanner"),
        max_upload_size=_int_env("MAX_UPLOAD_SIZE", 100 * 1024 * 1024),
        max_url_size=_int_env("MAX_URL_SIZE", 2 * 1024 * 1024 * 1024),
        url_download_timeout=_int_env("URL_DOWNLOAD_TIMEOUT", 30),
        download_max_seconds=_int_env("DOWNLOAD_MAX_SECONDS", 300),
        allowed_url_hosts=os.environ.get("ALLOWED_URL_HOSTS", ""),
        ssrf_allowed_hosts=os.environ.get("SSRF_ALLOWED_HOSTS", ""),
        webhook_timeout=_int_env("WEBHOOK_TIMEOUT", 10),
        webhook_max_attempts=_int_env("WEBHOOK_MAX_ATTEMPTS", 3),
    )


CONFIGS = {
    "config.ProductionConfig": _production(),
    "config.TestConfig": Settings(
        debug=True,
        testing=True,
        worker_eager=True,
        clamav_host="clamav",
        # Optional: point the exav backend at a running exav daemon to exercise
        # the exav integration tests (they skip when it's unset/unreachable).
        exav_hosts=os.environ.get("EXAV_HOSTS", ""),
        max_upload_size=4999999,
        max_url_size=4999999,
        api_keys=f"drive:{TEST_API_KEY}",
    ),
    "config.CiConfig": Settings(
        debug=True,
        testing=True,
        worker_eager=True,
        clamav_host="localhost",
        exav_hosts=os.environ.get("EXAV_HOSTS", ""),
        max_upload_size=4999999,
        max_url_size=4999999,
        api_keys=f"drive:{TEST_API_KEY}",
    ),
    "config.LocalConfig": Settings(
        debug=True,
        testing=True,
        worker_eager=True,
        clamav_host="localhost",
        max_upload_size=4999999,
        max_url_size=4999999,
        api_keys=f"drive:{TEST_API_KEY}",
    ),
}


def get_settings() -> Settings:
    config_name = os.environ.get("APP_CONFIG", "config.ProductionConfig")
    try:
        return CONFIGS[config_name]
    except KeyError as exc:
        raise RuntimeError(
            f"Unknown APP_CONFIG {config_name!r}; expected one of {list(CONFIGS)}"
        ) from exc
