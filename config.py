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
    max_content_length: int = 1 * 1024 * 1024 * 1024
    database_url: str = "postgresql://clamav:clamav@localhost:5432/clamav"
    celery_broker_url: str = "redis://localhost:6379/0"
    url_download_timeout: int = 30
    allowed_url_hosts: str = ""


TEST_API_KEY = "test-key-not-for-production"

CONFIGS = {
    "config.ProductionConfig": Settings(
        clamd_socket=os.environ.get("CLAMD_SOCKET", "/app/run/clamd.sock"),
        clamd_host=os.environ.get("CLAMD_HOST", "clamav"),
        database_url=os.environ.get("DATABASE_URL", "postgresql://clamav:clamav@localhost:5432/clamav"),
        celery_broker_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        api_keys=os.environ.get("API_KEYS", ""),
        allowed_url_hosts=os.environ.get("ALLOWED_URL_HOSTS", ""),
    ),
    "config.TestConfig": Settings(
        debug=True,
        testing=True,
        clamd_host="clamd",
        max_content_length=4999999,
        database_url=os.environ.get("DATABASE_URL", "postgresql://clamav:clamav@db:5432/clamav"),
        celery_broker_url=os.environ.get("REDIS_URL", "redis://redis:6379/0"),
        api_keys=f"drive:{TEST_API_KEY}",
    ),
    "config.CiConfig": Settings(
        debug=True,
        testing=True,
        clamd_host="localhost",
        max_content_length=4999999,
        database_url=os.environ.get("DATABASE_URL", "sqlite:///test.db"),
        celery_broker_url="memory://",
        api_keys=f"drive:{TEST_API_KEY}",
    ),
    "config.LocalConfig": Settings(
        debug=True,
        testing=True,
        clamd_host="localhost",
        max_content_length=4999999,
        database_url=os.environ.get("DATABASE_URL", "sqlite:///test.db"),
        celery_broker_url="memory://",
        api_keys=f"drive:{TEST_API_KEY}",
    ),
}


def get_settings() -> Settings:
    config_name = os.environ.get("APP_CONFIG", "config.ProductionConfig")
    return CONFIGS.get(config_name, Settings())
