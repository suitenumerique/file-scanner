"""Prometheus metrics: the web process's metrics (HTTP, sync scans, queue
state) and the worker's multiprocess exposition."""

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from unittest import mock

from conftest import sample
from prometheus_client import CollectorRegistry, generate_latest

import metrics
import worker
import worker_metrics
from scanners.clamav import DatabaseInfo

SCAN_URL = "/api/v2.0/scan"


# --- sync scans ---


def test_sync_scan_records_scanner_report_and_size(auth_client, clamav_cd):
    clamav_cd.instream.return_value = {"stream": ("FOUND", "Eicar-Test-Signature")}
    scan = {
        "scanner": "clamav",
        "category": "malware",
        "verdict": "malware",
        "mode": "sync",
        "api_client": "dev-issuer",
    }
    report = {
        "category": "malware",
        "verdict": "malware",
        "mode": "sync",
        "api_client": "dev-issuer",
    }
    scans, reports = (
        sample("filescanner_scans_total", **scan),
        sample("filescanner_reports_total", **report),
    )
    sizes = sample("filescanner_file_size_bytes_sum", mode="sync")
    durations = sample(
        "filescanner_scan_duration_seconds_count",
        scanner="clamav",
        verdict="malware",
        mode="sync",
    )

    r = auth_client.post(SCAN_URL, files={"file": ("f.txt", b"12345")})

    assert r.status_code == 200
    assert sample("filescanner_scans_total", **scan) == scans + 1
    assert sample("filescanner_reports_total", **report) == reports + 1
    assert sample("filescanner_file_size_bytes_sum", mode="sync") == sizes + 5
    assert (
        sample(
            "filescanner_scan_duration_seconds_count",
            scanner="clamav",
            verdict="malware",
            mode="sync",
        )
        == durations + 1
    )


# --- HTTP ---


def test_http_requests_are_labelled_by_route_template(client):
    labels = {"route": "/check", "method": "GET", "status": "503"}
    before = sample("filescanner_http_requests_total", **labels)
    with mock.patch("app.resolve_scanners", side_effect=ValueError("none")):
        assert client.get("/check").status_code == 503
    assert sample("filescanner_http_requests_total", **labels) == before + 1
    assert (
        sample(
            "filescanner_http_request_duration_seconds_count",
            route="/check",
            method="GET",
        )
        >= 1
    )


def test_http_unknown_paths_and_methods_collapse(client):
    labels = {"route": "other", "method": "GET", "status": "404"}
    before = sample("filescanner_http_requests_total", **labels)
    client.get("/nope/12345")
    client.get("/nope/67890")
    assert sample("filescanner_http_requests_total", **labels) == before + 2

    labels = {"route": "/check", "method": "other", "status": "405"}
    before = sample("filescanner_http_requests_total", **labels)
    client.request("BREW", "/check")
    assert sample("filescanner_http_requests_total", **labels) == before + 1


def test_job_route_uses_the_template_not_the_id(auth_client):
    auth_client.get("/api/v2.0/jobs/some-random-id")
    text = auth_client.get("/metrics").text
    assert 'route="/api/v2.0/jobs/{job_id}"' in text
    assert "some-random-id" not in text


# --- queue state ---


class _FakePipe:
    def __init__(self, client):
        self._client, self._calls = client, []

    def __getattr__(self, name):
        def _queue(*args, **kwargs):
            self._calls.append((name, args))

        return _queue

    def execute(self, raise_on_error=True):
        return [self._client.answer(name, args) for name, args in self._calls]


class _FakeRedis:
    """Just enough of redis-py for the queue collector."""

    def __init__(self, now_ms):
        self.now_ms = now_ms
        self.reads = 0
        self.fail = False

    def smembers(self, key):
        assert key == "ns:queues"
        if self.fail:
            raise ConnectionError("redis down")
        return {b"scans", b"webhooks", b"ping.host-1"}

    def close(self):
        pass

    def pipeline(self, transaction=True):
        self.reads += 1
        return _FakePipe(self)

    def answer(self, name, args):
        key = args[0]
        if name == "xinfo_groups":
            if key == "ns:stream:webhooks":
                return Exception("no such key")
            return [
                {
                    "name": b"workers",
                    "consumers": 4,
                    "pending": 2,
                    "lag": 7,
                }
            ]
        if name == "xlen":
            return {"ns:dlq:scans": 3}.get(key, 0)
        if name == "xrange":
            if key == "ns:stream:scans":
                return [(f"{int(self.now_ms) - 90_000}-0".encode(), {b"data": b"x"})]
            return []
        if name == "zcard":
            return 5
        raise AssertionError(name)


def _collect(collector):
    registry = CollectorRegistry()
    registry.register(collector)
    return registry


def test_queue_stats():
    redis = _FakeRedis(time.time() * 1000)
    registry = _collect(metrics.QueueStatsCollector(redis, "ns", queues=["scans"]))

    def value(name, **labels):
        return registry.get_sample_value(name, labels)

    assert value("filescanner_queue_stats_success") == 1
    assert value("filescanner_queue_backlog", queue="scans") == 7
    assert value("filescanner_queue_in_flight", queue="scans") == 2
    assert value("filescanner_queue_consumers", queue="scans") == 4
    assert value("filescanner_queue_dead_letters", queue="scans") == 3
    assert 89 <= value("filescanner_queue_oldest_message_age_seconds", queue="scans")
    assert value("filescanner_queue_oldest_message_age_seconds", queue="webhooks") == 0
    assert value("filescanner_queue_delayed") == 5
    # No group yet on webhooks: its group gauges are absent, not zero.
    assert value("filescanner_queue_backlog", queue="webhooks") is None
    # The per-container healthcheck queues are not reported.
    assert "ping." not in generate_latest(registry).decode()


def test_queue_stats_are_cached_between_scrapes():
    redis = _FakeRedis(time.time() * 1000)
    registry = _collect(metrics.QueueStatsCollector(redis, "ns", ttl=60))
    generate_latest(registry)
    generate_latest(registry)
    assert redis.reads == 1


def test_cached_collector_keeps_last_snapshot_on_failure():
    calls = []

    class _Flaky(metrics._CachedCollector):
        def _snapshot(self):
            calls.append(None)
            if len(calls) > 1:
                raise RuntimeError("boom")
            return ["first"]

    collector = _Flaky(ttl=0)
    assert collector.collect() == ["first"]
    assert collector.collect() == ["first"]  # failed refresh: previous kept
    collector._ttl = 60
    assert collector.collect() == ["first"]  # failure advanced the cache time
    assert len(calls) == 2


def test_queue_stats_report_redis_failure():
    redis = _FakeRedis(time.time() * 1000)
    redis.fail = True
    registry = _collect(metrics.QueueStatsCollector(redis, "ns"))
    assert registry.get_sample_value("filescanner_queue_stats_success") == 0
    assert registry.get_sample_value("filescanner_queue_delayed") is None


def test_queue_stats_client_has_timeouts(monkeypatch):
    import app

    monkeypatch.setattr(app.settings, "worker_eager", False)
    monkeypatch.setattr(app.settings, "metrics_queue_stats", True)
    collector = app._queue_stats_collector()
    kwargs = collector._client.connection_pool.connection_kwargs
    assert kwargs["socket_timeout"] == app._QUEUE_STATS_TIMEOUT
    assert kwargs["socket_connect_timeout"] == app._QUEUE_STATS_TIMEOUT
    collector.close()

    monkeypatch.setattr(app.settings, "metrics_queue_stats", False)
    assert app._queue_stats_collector() is None


def test_queue_stats_registered_for_the_app_lifetime(monkeypatch):
    from fastapi.testclient import TestClient

    import app

    collector = metrics.QueueStatsCollector(_FakeRedis(time.time() * 1000), "ns")
    monkeypatch.setattr(app, "_queue_stats_collector", lambda: collector)
    monkeypatch.setattr(app, "_clamav_database_collector", lambda: None)
    monkeypatch.setattr(app.settings, "prometheus_api_key", "")
    for _ in range(2):  # a second start must not hit "Duplicated timeseries"
        with TestClient(app.app) as client:
            assert "filescanner_queue_delayed 5.0" in client.get("/metrics").text
        assert sample("filescanner_queue_delayed") == 0.0  # unregistered


# --- clamav signature database ---


def test_clamav_database_gauges():
    fetches = []

    def _fetch():
        fetches.append(1)
        return {
            "c1:3310": DatabaseInfo(27000, 1762156800.0),
            "c2:3310": None,
            "c3:3310": DatabaseInfo(None, None),  # up, no database loaded
        }

    registry = _collect(metrics.ClamavDatabaseCollector(_fetch, ttl=60))

    def value(name, daemon):
        return registry.get_sample_value(name, {"daemon": daemon})

    assert value("filescanner_clamav_up", "c1:3310") == 1
    assert value("filescanner_clamav_db_version", "c1:3310") == 27000
    assert value("filescanner_clamav_db_timestamp_seconds", "c1:3310") == 1762156800
    assert value("filescanner_clamav_up", "c2:3310") == 0
    assert value("filescanner_clamav_db_timestamp_seconds", "c2:3310") is None
    assert value("filescanner_clamav_up", "c3:3310") == 1
    assert value("filescanner_clamav_db_version", "c3:3310") is None
    generate_latest(registry)
    assert len(fetches) == 1  # cached between scrapes


def test_clamav_database_check_failure_is_contained():
    def _fetch():
        raise RuntimeError("boom")

    registry = _collect(metrics.ClamavDatabaseCollector(_fetch))
    assert "filescanner_clamav_up{" not in generate_latest(registry).decode()


def test_clamav_database_collector_follows_the_configuration(monkeypatch):
    import app

    assert app._clamav_database_collector() is not None  # clamav is a default
    monkeypatch.setattr(app.settings, "default_scanners", '{"malware": ["exav"]}')
    assert app._clamav_database_collector() is None


def test_clamav_database_gauges_on_the_app_metrics(monkeypatch, clamav):
    from fastapi.testclient import TestClient

    import app

    monkeypatch.setattr(app, "_queue_stats_collector", lambda: None)
    monkeypatch.setattr(app.settings, "prometheus_api_key", "")
    with (
        mock.patch.object(clamav, "database_info", return_value={"clamav:3310": None}),
        TestClient(app.app) as client,
    ):
        text = client.get("/metrics").text
    assert 'filescanner_clamav_up{daemon="clamav:3310"} 0.0' in text


# --- worker exposition ---


def test_prepare_metrics_dir_wipes_and_exports(tmp_path, monkeypatch):
    path = tmp_path / "prom"
    path.mkdir()
    (path / "counter_123.db").write_bytes(b"stale")
    monkeypatch.setattr(worker_metrics.settings, "worker_metrics_dir", str(path))
    # prepare_metrics_dir writes os.environ directly; monkeypatch restores it.
    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", "placeholder")
    monkeypatch.setenv("dramatiq_prom_db", "placeholder")

    worker.prepare_metrics_dir()

    assert list(path.iterdir()) == []
    assert os.environ["PROMETHEUS_MULTIPROC_DIR"] == str(path)
    assert os.environ["dramatiq_prom_db"] == str(path)


def test_prepare_metrics_dir_disabled(monkeypatch):
    monkeypatch.setattr(worker_metrics.settings, "worker_metrics_port", 0)
    monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)
    worker.prepare_metrics_dir()
    assert "PROMETHEUS_MULTIPROC_DIR" not in os.environ


def test_worker_metrics_auth(monkeypatch):
    monkeypatch.setattr(worker_metrics.settings, "prometheus_api_key", "")
    assert worker_metrics._authorized(None)
    monkeypatch.setattr(worker_metrics.settings, "prometheus_api_key", "s3cret")
    assert not worker_metrics._authorized(None)
    assert not worker_metrics._authorized("Bearer wrong")
    assert not worker_metrics._authorized("Bearer é")
    assert worker_metrics._authorized("Bearer s3cret")


_WORKER_SCRIPT = textwrap.dedent(
    """
    import os, sys, threading, urllib.error, urllib.request
    from http.server import ThreadingHTTPServer

    import metrics, worker_metrics

    # Two "worker processes" worth of samples: this one, plus a file written
    # under another PID, as a forked sibling would.
    metrics.DOWNLOADS.labels("ok").inc(3)
    from prometheus_client import values
    other = values.MultiProcessValue(lambda: 99999)(
        "counter", "filescanner_downloads", "filescanner_downloads_total",
        ("outcome",), ("ok",), "",
    )
    other.inc(2)

    worker_metrics.settings.prometheus_api_key = "s3cret"
    server = ThreadingHTTPServer(("127.0.0.1", 0), worker_metrics._Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/metrics"
    try:
        urllib.request.urlopen(url)
        sys.exit("no auth required")
    except urllib.error.HTTPError as exc:
        assert exc.code == 401, exc.code
    req = urllib.request.Request(url, headers={"Authorization": "Bearer s3cret"})
    print(urllib.request.urlopen(req).read().decode())
    """
)


def test_worker_endpoint_aggregates_processes(tmp_path):
    env = dict(
        os.environ,
        APP_CONFIG="config.TestConfig",
        PROMETHEUS_MULTIPROC_DIR=str(tmp_path),
        PYTHONPATH=str(Path(__file__).parent.parent / "src"),
    )
    out = subprocess.run(
        [sys.executable, "-c", _WORKER_SCRIPT],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    assert 'filescanner_downloads_total{outcome="ok"} 5.0' in out.stdout
