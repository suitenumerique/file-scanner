"""Dashboard guard: HTTP Basic auth (fail-closed) + IP allowlist."""

import base64

import pytest

import dashboard as dash


def _basic(user, password):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


@pytest.fixture(autouse=True)
def _creds(monkeypatch):
    # Default posture: no enforced username (any accepted), password is the secret.
    monkeypatch.setattr(dash.settings, "worker_dashboard_user", "")
    monkeypatch.setattr(dash.settings, "worker_dashboard_password", "s3cret")
    monkeypatch.setattr(dash.settings, "worker_dashboard_allowed_ips", "")
    monkeypatch.setattr(dash.settings, "worker_dashboard_forwarded_ip_header", "")


def test_authorized_accepts_any_username_by_default():
    # No WORKER_DASHBOARD_USER set → the username is ignored; password is enough.
    assert dash.authorized(_basic("whoever", "s3cret"))
    assert dash.authorized(_basic("", "s3cret"))


def test_authorized_enforces_username_when_configured(monkeypatch):
    monkeypatch.setattr(dash.settings, "worker_dashboard_user", "ops")
    assert dash.authorized(_basic("ops", "s3cret"))
    assert not dash.authorized(_basic("nope", "s3cret"))


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Bearer token",
        "Basic not-base64!!",
        f"Basic {base64.b64encode(b'admin:wrong').decode()}",  # wrong password
    ],
)
def test_authorized_rejects(header):
    assert not dash.authorized(header)


def test_authorized_fail_closed_without_password(monkeypatch):
    # No configured password → reject everything, even matching an empty one.
    monkeypatch.setattr(dash.settings, "worker_dashboard_password", "")
    assert not dash.authorized(_basic("admin", ""))


def test_ip_allowed_when_no_allowlist():
    assert dash.ip_allowed("203.0.113.5")


def test_ip_allowlist_enforced(monkeypatch):
    monkeypatch.setattr(
        dash.settings, "worker_dashboard_allowed_ips", "10.0.0.0/8, 192.168.1.5"
    )
    assert dash.ip_allowed("10.1.2.3")
    assert dash.ip_allowed("192.168.1.5")
    assert not dash.ip_allowed("203.0.113.5")
    assert not dash.ip_allowed(None)
    assert not dash.ip_allowed("not-an-ip")


# --- client IP resolution (direct peer vs trusted forwarded header) ---


def test_client_ip_uses_peer_by_default():
    assert dash.client_ip({"REMOTE_ADDR": "10.0.0.1"}) == "10.0.0.1"


def test_client_ip_trusts_configured_header(monkeypatch):
    monkeypatch.setattr(
        dash.settings, "worker_dashboard_forwarded_ip_header", "X-Forwarded-For"
    )
    env = {"REMOTE_ADDR": "10.0.0.9", "HTTP_X_FORWARDED_FOR": "203.0.113.7, 10.0.0.9"}
    assert dash.client_ip(env) == "203.0.113.7"  # leftmost entry


def test_client_ip_falls_back_when_header_absent(monkeypatch):
    monkeypatch.setattr(
        dash.settings, "worker_dashboard_forwarded_ip_header", "X-Forwarded-For"
    )
    assert dash.client_ip({"REMOTE_ADDR": "10.0.0.9"}) == "10.0.0.9"


# --- the WSGI Guard middleware ---


def _call_guard(environ):
    """Drive dash.Guard wrapping a trivial inner WSGI app; return
    (status, headers, body, inner_reached)."""
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    reached = []

    def inner(env, sr):
        reached.append(True)
        sr("200 OK", [])
        return [b"dashboard"]

    body = b"".join(dash.Guard(inner)(environ, start_response))
    return captured["status"], captured["headers"], body, bool(reached)


def test_guard_passes_authorized_request():
    env = {"REMOTE_ADDR": "127.0.0.1", "HTTP_AUTHORIZATION": _basic("admin", "s3cret")}
    status, _, body, reached = _call_guard(env)
    assert status == "200 OK"
    assert body == b"dashboard"
    assert reached


def test_guard_rejects_missing_auth_with_challenge():
    status, headers, _, reached = _call_guard({"REMOTE_ADDR": "127.0.0.1"})
    assert status.startswith("401")
    assert any(k == "WWW-Authenticate" for k, _ in headers)
    assert not reached  # inner dashboard never reached


def test_guard_blocks_disallowed_ip_before_auth(monkeypatch):
    monkeypatch.setattr(dash.settings, "worker_dashboard_allowed_ips", "10.0.0.0/8")
    env = {
        "REMOTE_ADDR": "203.0.113.5",
        "HTTP_AUTHORIZATION": _basic("admin", "s3cret"),
    }
    status, _, _, reached = _call_guard(env)
    assert status.startswith("403")
    assert not reached


def test_guard_allowlist_uses_forwarded_header(monkeypatch):
    # Peer is the proxy (not in the allowlist), but the trusted XFF client is.
    monkeypatch.setattr(
        dash.settings, "worker_dashboard_forwarded_ip_header", "X-Forwarded-For"
    )
    monkeypatch.setattr(dash.settings, "worker_dashboard_allowed_ips", "203.0.113.0/24")
    env = {
        "REMOTE_ADDR": "10.0.0.9",
        "HTTP_X_FORWARDED_FOR": "203.0.113.7",
        "HTTP_AUTHORIZATION": _basic("admin", "s3cret"),
    }
    status, _, _, reached = _call_guard(env)
    assert status == "200 OK"
    assert reached
