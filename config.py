import os
from dataclasses import dataclass


@dataclass
class Settings:
    debug: bool = False
    testing: bool = False
    api_keys: str = ""
    clamav_txt_uri: str = "current.cvd.clamav.net"
    clamd_host: str = "localhost"
    clamd_port: int = 3310
    clamd_socket: str = ""
    host: str = "0.0.0.0"
    port: int = int(os.environ.get("PORT", "8090"))
    max_upload_size: int = 100 * 1024 * 1024       # 100 Mo — upload direct
    max_url_size: int = 2 * 1024 * 1024 * 1024     # 2 Go — scan par URL
    celery_broker_url: str = "redis://localhost:6379/0"
    scan_dir: str = os.environ.get("SCAN_DIR", "/tmp/clamav-scan")
    url_download_timeout: int = 30
    allowed_url_hosts: str = ""
    webhook_timeout: int = 10        # per-attempt timeout for webhook delivery
    webhook_max_attempts: int = 3    # total delivery attempts before giving up


TEST_API_KEY = "test-key-not-for-production"

CONFIGS = {
    "config.ProductionConfig": Settings(
        clamd_socket=os.environ.get("CLAMD_SOCKET", "/app/run/clamd.sock"),
        clamd_host=os.environ.get("CLAMD_HOST", "clamav"),
        celery_broker_url=os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0"),
        api_keys=os.environ.get("API_KEYS", ""),
        allowed_url_hosts=os.environ.get("ALLOWED_URL_HOSTS", ""),
    ),
    "config.TestConfig": Settings(
        debug=True,
        testing=True,
        clamd_host="clamd",
        max_upload_size=4999999,
        max_url_size=4999999,
        celery_broker_url=os.environ.get("CELERY_BROKER_URL", "redis://clamav_redis:6379/0"),
        api_keys=f"drive:{TEST_API_KEY}",
    ),
    "config.CiConfig": Settings(
        debug=True,
        testing=True,
        clamd_host="localhost",
        max_upload_size=4999999,
        max_url_size=4999999,
        celery_broker_url="memory://",
        api_keys=f"drive:{TEST_API_KEY}",
    ),
    "config.LocalConfig": Settings(
        debug=True,
        testing=True,
        clamd_host="localhost",
        max_upload_size=4999999,
        max_url_size=4999999,
        celery_broker_url="memory://",
        api_keys=f"drive:{TEST_API_KEY}",
    ),
}


def get_settings() -> Settings:
    config_name = os.environ.get("APP_CONFIG", "config.ProductionConfig")
    try:
        return CONFIGS[config_name]
    except KeyError:
        raise RuntimeError(
            f"Unknown APP_CONFIG {config_name!r}; expected one of {list(CONFIGS)}"
        )
