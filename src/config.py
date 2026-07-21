"""Application configuration (pydantic-settings).

Every knob is a field on :class:`Settings` with its default — the **single**
source of truth. In production (``config.ProductionConfig``) each field is read
from the environment variable of the same name (upper-cased), falling back to the
field default; nothing is restated. ``APP_CONFIG`` selects a profile from
``CONFIGS``; the ``Test`` / ``Ci`` / ``Local`` profiles **ignore the ambient
environment** (so tests are deterministic regardless of what the container
injects) and run "eager" (no Redis / worker). Get the active settings via
:func:`get_settings`.
"""

import os

from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

# These change safety-relevant behaviour (``testing`` relaxes the request-time
# SSRF guard; ``worker_eager`` bypasses the real broker), so they are set ONLY by
# the profile class and never read from the ambient environment — not even in
# production, where an accidental ``TESTING=true`` must not take effect.
_PROFILE_ONLY = frozenset({"testing", "worker_eager"})


class _DropEnvKeys:
    """Wrap the env settings source to hide a few field names from it."""

    def __init__(self, source: PydanticBaseSettingsSource, drop: frozenset[str]):
        self._source, self._drop = source, drop

    def __call__(self) -> dict:
        return {k: v for k, v in self._source().items() if k not in self._drop}


class Settings(BaseSettings):
    """Production settings — every field read from its upper-cased env var."""

    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore")

    # --- Runtime profile ---
    # Verbose (DEBUG) logging when true.
    debug: bool = False
    # Test/CI mode: relaxes a few guards that need real infrastructure — the
    # request-time SSRF check is skipped (the worker still enforces it) and tasks
    # may run eagerly. Set only by a profile; NEVER enable in production.
    testing: bool = False

    # --- Web server ---
    host: str = "0.0.0.0"  # interface uvicorn binds to (HOST)
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

    # --- JWT authentication (both directions; EdDSA / Ed25519) ---
    # OUTGOING: base64url of our raw 32-byte Ed25519 private seed, used to sign
    # webhook callbacks. The public half is DERIVED at boot and served at
    # /.well-known/jwks.json — never stored separately (a fixed private key
    # yields a fixed public key). Empty ⇒ webhooks are sent unsigned and the
    # JWKS is empty. (JWT_SIGNING_KEY)
    jwt_signing_key: str = ""
    # Key id advertised in the JWKS + webhook token headers so receivers can
    # match keys across a rotation. (JWT_SIGNING_KID)
    jwt_signing_kid: str = ""
    # The `iss` we stamp on outgoing webhook tokens (our service identity).
    # (JWT_ISSUER)
    jwt_issuer: str = "file-scanner"
    # INCOMING: caller public keys, inline as `iss:pubkey,iss2:pubkey2` (each the
    # base64url raw 32-byte Ed25519 public key). The token's `iss` selects the
    # key and identifies the caller in logs + the `api_client` metric. Empty ⇒ no
    # caller can authenticate (every request is rejected). (JWT_ISSUER_KEYS)
    jwt_issuer_keys: str = ""
    # Expected `aud` on incoming tokens (this service's identity). (JWT_AUDIENCE)
    jwt_audience: str = "file-scanner"
    # Hard cap on an incoming token's lifetime (`exp - iat`), seconds — bounds the
    # replay window of a captured token. Also the TTL of the tokens we mint for
    # webhooks. (JWT_MAX_AGE)
    jwt_max_age: int = 300
    # Clock-skew leeway (seconds) applied to exp/iat/nbf. (JWT_LEEWAY)
    jwt_leeway: int = 60

    # --- Size & time limits ---
    # Max size of a direct upload to /api/v1.0/scan; larger → 413. (MAX_UPLOAD_SIZE)
    max_upload_size: int = 100 * 1024 * 1024  # 100 MiB
    # Max size of a file fetched by /api/v1.0/scan-async; enforced against both
    # Content-Length and the bytes actually streamed. (MAX_URL_SIZE)
    max_url_size: int = 2 * 1024 * 1024 * 1024  # 2 GiB
    # Scratch directory the async worker downloads a file into before streaming
    # it to the scanner (INSTREAM) — it holds the download, not the scan (which
    # happens over the socket). Transient (each file is deleted right after the
    # scan) and NOT shared with the scanner daemon, so any writable path works.
    # (DOWNLOAD_DIR)
    download_dir: str = "/tmp/file-scanner"
    # Per-read (socket) timeout on the async download — caps time between chunks,
    # not the whole transfer. (URL_DOWNLOAD_TIMEOUT)
    url_download_timeout: int = 30  # seconds
    # Total wall-clock budget for one async download, so a server that dribbles
    # bytes just under the per-read timeout can't tie up a worker.
    # (DOWNLOAD_MAX_SECONDS)
    download_max_seconds: int = 300  # seconds

    # --- Client-encryption chunking (see docs/client-encryption.md) ---
    # Bounds the caller-declared `chunk_size` (plaintext bytes per AES-GCM chunk).
    # Floor: a tiny chunk_size inflates the chunk count into a per-chunk CPU cost
    # (millions of tiny GCM decrypts). Ceiling: the worker buffers one whole chunk
    # in RAM before decrypting, so this caps per-decryption memory (x worker
    # concurrency) — raise it knowingly. A caller aligning crypto chunks to S3
    # multipart parts wants chunk_size >= the S3 5 MiB minimum, so the 50 MiB
    # ceiling comfortably covers typical part sizes.
    # (ENCRYPTION_MIN_CHUNK_SIZE)
    encryption_min_chunk_size: int = 4096  # 4 KiB
    # (ENCRYPTION_MAX_CHUNK_SIZE)
    encryption_max_chunk_size: int = 50 * 1024 * 1024  # 50 MiB

    # --- Host policy (async scans) ---
    # Positive restriction: if set, ONLY these hostnames may be submitted to
    # /api/v1.0/scan-async (comma-separated). Empty = any host, still subject to
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
    # broker — no Redis and no worker needed. Set only by a profile.
    worker_eager: bool = False
    # Redis URL for the dramatiq-redis-streams broker (async scans). Supports
    # TLS + auth, e.g. rediss://:password@host:6379/0. (WORKER_BROKER_URL)
    worker_broker_url: str = "redis://localhost:6379/0"
    # Redis key prefix for the streams broker; set a distinct value to isolate
    # multiple deployments sharing one Redis. (WORKER_QUEUE_NAMESPACE)
    worker_queue_namespace: str = "file-scanner"

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        # Same precedence as the default (init > env > dotenv > secrets), but the
        # env source can't set the profile-only flags.
        return (
            init_settings,
            _DropEnvKeys(env_settings, _PROFILE_ONLY),
            dotenv_settings,
            file_secret_settings,
        )


class _StaticSettings(Settings):
    """Base for the non-production profiles: values come only from field defaults
    and explicit overrides — the ambient environment is ignored entirely, so the
    test suite is deterministic no matter what the container/compose injects."""

    @classmethod
    def settings_customise_sources(cls, settings_cls, init_settings, **_):
        return (init_settings,)


class TestConfig(_StaticSettings):
    debug: bool = True
    testing: bool = True
    worker_eager: bool = True
    clamav_host: str = "clamav"
    max_upload_size: int = 4999999
    max_url_size: int = 4999999
    # Opt-in: point the exav backend at a running daemon to exercise the exav
    # integration tests (they skip when unset/unreachable). Read from the env
    # directly since this profile otherwise ignores it.
    exav_hosts: str = os.environ.get("EXAV_HOSTS", "")


class CiConfig(_StaticSettings):
    debug: bool = True
    testing: bool = True
    worker_eager: bool = True
    clamav_host: str = "localhost"
    max_upload_size: int = 4999999
    max_url_size: int = 4999999
    exav_hosts: str = os.environ.get("EXAV_HOSTS", "")


class LocalConfig(_StaticSettings):
    debug: bool = True
    testing: bool = True
    worker_eager: bool = True
    clamav_host: str = "localhost"
    max_upload_size: int = 4999999
    max_url_size: int = 4999999


# Built once at import (a singleton per profile, shared across modules).
CONFIGS = {
    "config.ProductionConfig": Settings(),
    "config.TestConfig": TestConfig(),
    "config.CiConfig": CiConfig(),
    "config.LocalConfig": LocalConfig(),
}


def get_settings() -> Settings:
    config_name = os.environ.get("APP_CONFIG", "config.ProductionConfig")
    try:
        return CONFIGS[config_name]
    except KeyError as exc:
        raise RuntimeError(
            f"Unknown APP_CONFIG {config_name!r}; expected one of {list(CONFIGS)}"
        ) from exc
