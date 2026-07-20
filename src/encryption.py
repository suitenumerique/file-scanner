"""Decrypt client-encrypted sources so they can actually be scanned.

Scanned as-is, AES-256-GCM ciphertext makes a scanner report a clean file — so a
caller that encrypts must hand us the key. Layout mirrors the caller's, one
crypto chunk per stored part:

    [ IV (12 bytes) | ciphertext (N bytes) | GCM tag (16 bytes) ]

``chunk_size`` is the *plaintext* bytes per chunk. The AAD binds each chunk to
``f"{file_id}:{part_number}"`` (1-based), so reordered chunks fail
authentication instead of decrypting.
"""

import base64
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

IV_BYTES = 12
GCM_TAG_BYTES = 16
KEY_BYTES = 32  # AES-256
OVERHEAD_PER_CHUNK = IV_BYTES + GCM_TAG_BYTES

# URL-safe base64 alphabet, optional padding. The key travels in a URL fragment
# on the caller's side, so '+' and '/' are not acceptable even though they are
# valid standard base64.
_FRAGMENT_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


class DecryptionError(Exception):
    """Bad key, wrong chunking, truncated or tampered ciphertext. Never
    retryable — asking again won't change the bytes."""


def decode_key(fragment: str) -> bytes:
    """Decode the URL-safe base64 key fragment into raw AES-256 key bytes.

    Alphabet checked up front: ``urlsafe_b64decode`` silently discards junk,
    which would otherwise yield a wrong-length key.
    """
    if not _FRAGMENT_RE.match(fragment or ""):
        raise DecryptionError("key must be URL-safe base64 (A-Z a-z 0-9 - _)")
    padding = "=" * (-len(fragment) % 4)
    raw = base64.urlsafe_b64decode(fragment + padding)
    if len(raw) != KEY_BYTES:
        raise DecryptionError(f"expected a {KEY_BYTES}-byte key, got {len(raw)}")
    return raw


def decrypt_chunk(key: bytes, blob: bytes, file_id: str, part_number: int) -> bytes:
    """Decrypt one ``IV || ciphertext || tag`` chunk back to plaintext."""
    if len(blob) <= OVERHEAD_PER_CHUNK:
        raise DecryptionError(
            f"chunk {part_number} is {len(blob)} bytes, too short to hold "
            f"an IV + tag ({OVERHEAD_PER_CHUNK})"
        )
    iv = blob[:IV_BYTES]
    body = blob[IV_BYTES:]
    aad = f"{file_id}:{part_number}".encode()
    try:
        return AESGCM(key).decrypt(iv, body, aad)
    except Exception as exc:
        raise DecryptionError(
            f"chunk {part_number} failed authentication: {exc}"
        ) from exc
