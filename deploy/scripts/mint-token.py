#!/usr/bin/env python3
"""Mint a request-bound JWT for a caller — a dev/testing helper.

Usage:
    python deploy/mint-token.py <private-key> <iss> <METHOD> <path[?query]> [body-file]

`<private-key>` is the caller's base64url raw Ed25519 key from `new-issuer.py`.
The token binds the request (`htm`/`htu`), and — for the async endpoint — the
body hash (`bh`) when a `body-file` is given. Prints just the token, so:

    TOKEN=$(python deploy/scripts/mint-token.py "$KEY" dev-issuer POST /api/v1.0/scan)

Real callers mint tokens the same way inside their own code (three lines with a
JWT lib); this script only spares the dev quick start the key-decoding boilerplate.
"""

import base64
import hashlib
import sys
import time

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

AUDIENCE = "file-scanner"  # must match the service's JWT_AUDIENCE
TTL_SECONDS = 300


def main(argv: list[str]) -> int:
    if len(argv) not in (5, 6):
        print(
            "usage: mint-token.py <private-key> <iss> <METHOD> <path[?query]>"
            " [body-file]",
            file=sys.stderr,
        )
        return 2
    private_key, iss, method, htu = argv[1:5]

    key = Ed25519PrivateKey.from_private_bytes(
        base64.urlsafe_b64decode(private_key + "==")
    )
    now = int(time.time())
    payload = {
        "iss": iss,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + TTL_SECONDS,
        "htm": method.upper(),
        "htu": htu,
    }
    if len(argv) == 6:  # async endpoint: bind the JSON request body
        with open(argv[5], "rb") as fh:
            digest = hashlib.sha256(fh.read()).digest()
        payload["bh"] = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    print(jwt.encode(payload, key, algorithm="EdDSA"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
