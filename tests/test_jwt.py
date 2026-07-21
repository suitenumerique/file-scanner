"""JWT auth both directions: incoming Bearer verification + request binding,
issuer key sources, the JWKS endpoint, and outgoing webhook signing."""

import json
import time
from unittest import mock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import jwt_auth
import tasks


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub = jwt_auth._b64url_encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return priv, pub


def _mint(priv, *, iss="dev-issuer", aud="file-scanner", htm="POST", htu="/x", **extra):
    now = int(time.time())
    payload = {
        "iss": iss,
        "aud": aud,
        "iat": now,
        "exp": now + 300,
        "htm": htm,
        "htu": htu,
    }
    payload.update(extra)
    return jwt_auth.encode(payload, private_key=priv)


# --- pure encode/decode ---


def test_roundtrip_ok():
    priv, _ = _keypair()
    keys = {"dev-issuer": priv.public_key()}
    tok = _mint(priv)
    claims = jwt_auth.decode(tok, issuer_keys=keys, audience="file-scanner")
    assert claims["iss"] == "dev-issuer"


def test_bad_signature_rejected():
    priv, _ = _keypair()
    other, _ = _keypair()
    tok = _mint(priv)
    with pytest.raises(jwt_auth.JWTError, match="bad signature"):
        jwt_auth.decode(tok, issuer_keys={"dev-issuer": other.public_key()})


def test_unknown_issuer_rejected():
    priv, _ = _keypair()
    tok = _mint(priv, iss="ghost")
    with pytest.raises(jwt_auth.JWTError, match="unknown issuer"):
        jwt_auth.decode(tok, issuer_keys={"dev-issuer": priv.public_key()})


def test_wrong_audience_rejected():
    priv, _ = _keypair()
    tok = _mint(priv, aud="someone-else")
    with pytest.raises(jwt_auth.JWTError, match="audience"):
        jwt_auth.decode(
            tok, issuer_keys={"dev-issuer": priv.public_key()}, audience="file-scanner"
        )


def test_expired_rejected():
    priv, _ = _keypair()
    now = int(time.time())
    tok = jwt_auth.encode(
        {
            "iss": "dev-issuer",
            "aud": "file-scanner",
            "iat": now - 1000,
            "exp": now - 500,
        },
        private_key=priv,
    )
    with pytest.raises(jwt_auth.JWTError, match="expired"):
        jwt_auth.decode(tok, issuer_keys={"dev-issuer": priv.public_key()}, leeway=0)


def test_lifetime_cap_rejected():
    priv, _ = _keypair()
    now = int(time.time())
    tok = jwt_auth.encode(
        {"iss": "dev-issuer", "aud": "file-scanner", "iat": now, "exp": now + 99999},
        private_key=priv,
    )
    with pytest.raises(jwt_auth.JWTError, match="max_age"):
        jwt_auth.decode(tok, issuer_keys={"dev-issuer": priv.public_key()}, max_age=300)


def test_alg_confusion_rejected():
    # A token that claims alg:none must never be accepted.
    priv, _ = _keypair()
    header = jwt_auth._b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = jwt_auth._b64url_encode(json.dumps({"iss": "dev-issuer"}).encode())
    forged = f"{header}.{body}."
    with pytest.raises(jwt_auth.JWTError, match="alg"):
        jwt_auth.decode(forged, issuer_keys={"dev-issuer": priv.public_key()})


def test_binding_mismatch_rejected():
    priv, _ = _keypair()
    tok = _mint(priv, htm="POST", htu="/a")
    claims = jwt_auth.decode(tok, issuer_keys={"dev-issuer": priv.public_key()})
    with pytest.raises(jwt_auth.JWTError, match="htu"):
        jwt_auth.check_binding(
            claims, method="POST", htu="/b", body=None, require_body=False
        )


# --- issuer key sources ---


def test_issuer_keys_parsed_from_env(monkeypatch):
    _, pub_a = _keypair()
    _, pub_b = _keypair()
    monkeypatch.setattr(
        jwt_auth.settings, "jwt_issuer_keys", f"dev-issuer:{pub_a},transfers:{pub_b}"
    )
    loaded = jwt_auth._load_issuers()
    assert set(loaded) == {"dev-issuer", "transfers"}


# --- endpoints ---


@pytest.fixture
def caller():
    """One configured caller "dev-issuer"; yields its private key for minting tokens."""
    priv, _ = _keypair()
    with mock.patch.dict(
        jwt_auth._ISSUER_KEYS, {"dev-issuer": priv.public_key()}, clear=True
    ):
        yield priv


def test_sync_scan_with_jwt(client, caller, clamav_cd):
    clamav_cd.instream.return_value = {"stream": ("OK", None)}
    tok = _mint(caller, htu="/api/v1.0/scan")
    r = client.post(
        "/api/v1.0/scan",
        files={"file": ("f.txt", b"hello")},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 200
    assert r.json()["malware"] is False


def test_sync_scan_wrong_target_rejected(client, caller, clamav_cd):
    # A token minted for a different path can't be replayed here.
    tok = _mint(caller, htu="/api/v1.0/scan-async")
    r = client.post(
        "/api/v1.0/scan",
        files={"file": ("f.txt", b"hello")},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 401


def test_async_scan_with_jwt_body_bound(client, caller):
    body = json.dumps(
        {
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
        }
    ).encode()
    tok = _mint(caller, htu="/api/v1.0/scan-async", bh=jwt_auth.body_hash(body))
    r = client.post(
        "/api/v1.0/scan-async",
        content=body,
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
    )
    assert r.status_code == 202


def test_async_scan_body_tampered_rejected(client, caller):
    signed = json.dumps(
        {
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
        }
    ).encode()
    tok = _mint(caller, htu="/api/v1.0/scan-async", bh=jwt_auth.body_hash(signed))
    # Deliver a DIFFERENT body than the one bound in `bh` (e.g. a swapped webhook).
    tampered = json.dumps(
        {
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://attacker.example.com/av",
        }
    ).encode()
    r = client.post(
        "/api/v1.0/scan-async",
        content=tampered,
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
    )
    assert r.status_code == 401


def test_missing_credentials_rejected(client):
    r = client.post("/api/v1.0/scan", files={"file": ("f.txt", b"hello")})
    assert r.status_code == 401


# --- JWKS endpoint ---


def test_jwks_empty_when_unset(client):
    assert client.get("/.well-known/jwks.json").json() == {"keys": []}


def test_jwks_serves_derived_public_key(client):
    priv, _ = _keypair()
    with mock.patch.object(jwt_auth, "_PRIVATE_KEY", priv):
        jwk = client.get("/.well-known/jwks.json").json()["keys"][0]
    expected = jwt_auth._b64url_encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and jwk["x"] == expected


# --- outgoing webhook signing ---


def test_webhook_signed_and_verifiable():
    priv, _ = _keypair()
    captured = {}

    def _post(url, **kw):
        captured.update(url=url, data=kw["data"], headers=kw["headers"])
        resp = mock.MagicMock()
        resp.is_redirect = False
        resp.raise_for_status.return_value = None
        return resp

    with (
        mock.patch.object(jwt_auth, "_PRIVATE_KEY", priv),
        mock.patch.object(tasks._session, "post", side_effect=_post),
    ):
        tasks.deliver_webhook.fn("http://cb/av", {"job_id": "j", "malware": False})

    token = captured["headers"]["Authorization"].removeprefix("Bearer ")
    claims = jwt_auth.decode(
        token,
        issuer_keys={jwt_auth.settings.jwt_issuer: priv.public_key()},
        audience="http://cb/av",
    )
    # The signature binds the exact bytes POSTed.
    assert claims["bh"] == jwt_auth.body_hash(captured["data"])
    assert claims["htu"] == "http://cb/av"


def test_webhook_unsigned_when_no_key():
    captured = {}

    def _post(url, **kw):
        captured.update(kw["headers"])
        resp = mock.MagicMock()
        resp.is_redirect = False
        resp.raise_for_status.return_value = None
        return resp

    with (
        mock.patch.object(jwt_auth, "_PRIVATE_KEY", None),
        mock.patch.object(tasks._session, "post", side_effect=_post),
    ):
        tasks.deliver_webhook.fn("http://cb/av", {"job_id": "j"})
    assert "Authorization" not in captured
