"""The worker healthcheck: its actor and the queue the worker consumes."""

import health
import worker


def test_ping_answers_pong():
    assert health.ping.fn() == "pong"


def test_worker_consumes_its_own_ping_queue(monkeypatch):
    monkeypatch.setenv("WORKER_QUEUES", "webhooks")
    argv = worker.build_argv()
    assert argv[argv.index("--queues") + 1 :] == ["webhooks", health.PING_QUEUE]
    assert "health" in argv
