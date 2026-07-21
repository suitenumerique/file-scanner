"""JWT authentication, both directions (EdDSA / Ed25519).

**Incoming.** Callers authenticate with a short-lived JWT in the
``Authorization: Bearer`` header. We verify it against the *caller's* public key,
looked up by the
token's ``iss`` claim (configured in ``JWT_ISSUER_KEYS``) — so this side stores
only *public* keys and a config/env leak here cannot forge caller tokens (unlike
a shared static key). The token also **binds the request** so a captured token
can't be replayed against a different call:

- ``htm`` — the HTTP method;
- ``htu`` — the request target (path + raw query). On ``/scan`` this is all we
  bind (the uploaded file bytes are deliberately *not* hashed);
- ``bh``  — base64url SHA-256 of the raw request **body**, bound on the async
  endpoint so the ``url`` and ``webhook_url`` a caller authorised can't be
  swapped. (Not the fetched file — just the JSON request.)

**Outgoing.** We sign each webhook payload with our own private key
(``JWT_SIGNING_KEY``) so a receiver can authenticate the callback and confirm
the body wasn't tampered with (``bh`` over the exact bytes we POST). Our public
key is published at ``/.well-known/jwks.json`` — **derived** from the private key
at boot, never stored separately (a fixed private key yields a fixed public key).

Tokens are signed/verified with **PyJWT** (an audited library — we don't hand-roll
JWS). The accepted algorithm is **hard-pinned to EdDSA** at ``decode`` time (never
taken from the token's own ``alg`` header), so ``alg`` confusion / ``alg:none``
downgrades are rejected. Key material stays raw Ed25519 (32-byte base64url).
"""

import base64
import hashlib
import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jwt.algorithms import OKPAlgorithm

from config import get_settings

settings = get_settings()

ALG = "EdDSA"
KEY_BYTES = 32  # Ed25519 raw key length (both private seed and public point)


class JWTError(Exception):
    """Any failure to verify a token: malformed, bad signature, expired, wrong
    audience, unknown issuer, or a request-binding mismatch. Always a 401 — the
    caller must mint a fresh, correct token; retrying the same one won't help."""


# --- base64url + key decoding ---


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _key_bytes(fragment: str) -> bytes:
    raw = _b64url_decode(fragment.strip())
    if len(raw) != KEY_BYTES:
        raise JWTError(f"Ed25519 key must be {KEY_BYTES} bytes, got {len(raw)}")
    return raw


def _load_private() -> Ed25519PrivateKey | None:
    if not settings.jwt_signing_key:
        return None
    return Ed25519PrivateKey.from_private_bytes(_key_bytes(settings.jwt_signing_key))


def _load_issuers() -> dict[str, Ed25519PublicKey]:
    """Caller ``iss -> public key`` map from ``JWT_ISSUER_KEYS`` — inline
    ``iss:pubkey,iss2:pubkey2`` (each the base64url raw 32-byte Ed25519 public
    key). The token's ``iss`` selects the key. Empty ⇒ no JWT logins.

    A malformed entry (missing ``:`` separator) raises here rather than
    being silently skipped — a typo like ``JWT_ISSUER_KEYS=drive-pubkey``
    would otherwise leave the caller absent from the map and turn every
    request into a 401 with no operational signal on why."""
    keys: dict[str, Ed25519PublicKey] = {}
    for raw_entry in settings.jwt_issuer_keys.split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            raise ValueError(
                f"JWT_ISSUER_KEYS entry {entry!r} is missing the "
                "'iss:pubkey' separator ':'."
            )
        iss, pub = entry.split(":", 1)
        keys[iss.strip()] = Ed25519PublicKey.from_public_bytes(_key_bytes(pub))
    return keys


# Loaded once at import from the configured keys. With no issuer keys, every
# request is rejected; with no signing key, webhooks are sent unsigned.
_PRIVATE_KEY = _load_private()
_ISSUER_KEYS = _load_issuers()


def enabled_incoming() -> bool:
    """True when at least one caller public key is configured (JWT logins possible)."""
    return bool(_ISSUER_KEYS)


def can_sign() -> bool:
    """True when a signing key is configured (webhooks + JWKS available)."""
    return _PRIVATE_KEY is not None


# --- encode / decode ---


def encode(payload: dict, *, private_key: Ed25519PrivateKey | None = None) -> str:
    """EdDSA-sign a compact JWS via PyJWT. Uses the configured signing key unless
    ``private_key`` is passed (tests, or a caller-side signer)."""
    key = private_key or _PRIVATE_KEY
    if key is None:
        raise JWTError("no signing key configured (JWT_SIGNING_KEY)")
    headers = {"kid": settings.jwt_signing_kid} if settings.jwt_signing_kid else None
    return jwt.encode(payload, key, algorithm=ALG, headers=headers)


def decode(
    token: str,
    *,
    issuer_keys: dict[str, Ed25519PublicKey] | None = None,
    audience: str | None = None,
    max_age: int | None = None,
    leeway: int | None = None,
) -> dict:
    """Verify a token and return its claims, or raise :class:`JWTError`.

    The issuer is read from the (still-unverified) claims only to pick its public
    key; PyJWT then verifies the signature with the algorithm **pinned to EdDSA**
    (so a token's own ``alg`` header can't downgrade it), requires ``exp``/``iat``,
    and checks ``aud`` and the time window (with ``leeway``). We add a hard cap on
    ``exp - iat`` (``max_age``) that PyJWT doesn't enforce, bounding the replay
    window of a captured token."""
    keys = _ISSUER_KEYS if issuer_keys is None else issuer_keys
    audience = settings.jwt_audience if audience is None else audience
    max_age = settings.jwt_max_age if max_age is None else max_age
    leeway = settings.jwt_leeway if leeway is None else leeway

    try:
        iss = jwt.decode(token, options={"verify_signature": False}).get("iss")
    except jwt.PyJWTError as exc:
        raise JWTError(f"malformed token: {exc}") from exc
    key = keys.get(iss)
    if key is None:
        raise JWTError(f"unknown issuer {iss!r}")

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[ALG],
            audience=audience,
            leeway=leeway,
            options={"require": ["exp", "iat"], "verify_aud": audience is not None},
        )
    except jwt.ExpiredSignatureError as exc:
        raise JWTError("token expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise JWTError(f"wrong audience; expected {audience!r}") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise JWTError(f"missing claim: {exc}") from exc
    except jwt.InvalidAlgorithmError as exc:
        raise JWTError(f"algorithm not allowed: {exc}") from exc
    except jwt.InvalidSignatureError as exc:
        raise JWTError("bad signature") from exc
    except jwt.PyJWTError as exc:
        raise JWTError(f"invalid token: {exc}") from exc

    iat, exp = claims.get("iat"), claims.get("exp")
    if max_age and isinstance(iat, (int, float)) and isinstance(exp, (int, float)):
        if exp - iat > max_age:
            raise JWTError(f"token lifetime exceeds max_age ({max_age}s)")
    return claims


# --- request binding ---


def request_target(method: str, path: str, query: str) -> tuple[str, str]:
    """The (``htm``, ``htu``) a token must carry for this request: the method and
    the exact target (path plus raw query string, if any)."""
    return method.upper(), path + (f"?{query}" if query else "")


def body_hash(raw: bytes) -> str:
    """base64url SHA-256 of the raw request/response body, for the ``bh`` claim."""
    return _b64url_encode(hashlib.sha256(raw).digest())


def check_binding(
    payload: dict, *, method: str, htu: str, body: bytes | None, require_body: bool
) -> None:
    """Reject a token whose bound method/target/body doesn't match the request."""
    if payload.get("htm") != method:
        raise JWTError("htm claim does not match request method")
    if payload.get("htu") != htu:
        raise JWTError("htu claim does not match request target")
    if require_body and payload.get("bh") != body_hash(body or b""):
        raise JWTError("bh claim does not match request body")


# --- outgoing (webhook signing) + JWKS ---


def sign_webhook(
    webhook_url: str, body: bytes, *, now: float | None = None
) -> str | None:
    """Mint a token authenticating a webhook POST, bound to the target URL and
    the exact body bytes. Returns ``None`` when no signing key is configured (the
    webhook is then sent unsigned)."""
    if not can_sign():
        return None
    issued = int(time.time() if now is None else now)
    payload = {
        "iss": settings.jwt_issuer,
        "aud": webhook_url,
        "iat": issued,
        "exp": issued + settings.jwt_max_age,
        "htm": "POST",
        "htu": webhook_url,
        "bh": body_hash(body),
    }
    return encode(payload)


def public_jwk() -> dict:
    """Our signing public key as a JWK (derived from the private key), or ``{}``."""
    if _PRIVATE_KEY is None:
        return {}
    jwk = json.loads(OKPAlgorithm.to_jwk(_PRIVATE_KEY.public_key()))
    jwk.update(use="sig", alg=ALG)
    if settings.jwt_signing_kid:
        jwk["kid"] = settings.jwt_signing_kid
    return jwk


def jwks() -> dict:
    """The JWKS document served at ``/.well-known/jwks.json`` (empty when unset)."""
    jwk = public_jwk()
    return {"keys": [jwk] if jwk else []}
