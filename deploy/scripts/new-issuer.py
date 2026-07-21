#!/usr/bin/env python3
"""Generate an Ed25519 keypair for a new JWT issuer (a caller of this service).

Usage:  python deploy/new-issuer.py <issuer-name>
   or:  make new-issuer NAME=<issuer-name>

Prints two things:

  1. the caller's PRIVATE key — hand it to that caller over a secure channel;
     they sign their request tokens with it (see the README quick start), and it
     is never shared with this service;
  2. the `iss:pubkey` fragment to add to this service's JWT_ISSUER_KEYS — only
     the PUBLIC key lives here, so a leak of the service config can't forge the
     caller's tokens.

Keys are the raw 32-byte Ed25519 values as unpadded URL-safe base64 — exactly
the format src/jwt_auth.py parses.
"""

import base64
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not argv[1].strip():
        print("usage: new-issuer.py <issuer-name>", file=sys.stderr)
        return 2
    iss = argv[1].strip()
    # `iss:pubkey` pairs are comma-separated in JWT_ISSUER_KEYS, so the name can
    # contain neither delimiter.
    if ":" in iss or "," in iss:
        print("issuer name must not contain ':' or ','", file=sys.stderr)
        return 2

    key = Ed25519PrivateKey.generate()
    private = _b64url(
        key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    )
    public = _b64url(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    print(f'New JWT issuer "{iss}"\n')
    print("  1. Caller's PRIVATE key (send securely; they sign tokens with it):")
    print(f"       {private}\n")
    print("  2. Add to this service's JWT_ISSUER_KEYS (comma-separate if not first):")
    print(f"       {iss}:{public}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
