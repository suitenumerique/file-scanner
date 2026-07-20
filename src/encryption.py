"""Decrypt client-encrypted sources so they can actually be scanned.

Scanned as-is, AES-256-GCM ciphertext makes a scanner report a clean file — so a
caller that encrypts must hand us the key. Layout mirrors the caller's, one
crypto chunk per stored part:

    [ IV (12 bytes) | ciphertext (N bytes) | GCM tag (16 bytes) ]

``chunk_size`` is the *plaintext* bytes per chunk. The AAD binds each chunk to
``f"{file_id}:{part}:{parts}"`` — its 1-based position **and** the total number
of chunks. Binding position defeats reordering; binding the total defeats
*trailing truncation*: dropping whole trailing chunks lands on a boundary and
would otherwise pass per-chunk authentication, but the count no longer matches.
See ``docs/client-encryption.md`` for the caller-facing contract.
"""

import base64
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Wire-format identifier. The `encryption.scheme` request field selects a
# decryptor; pinning it makes the format versioned, so it can evolve (or a second
# scheme be added) without ambiguity. Only this one ships today.
SCHEME = "aes-256-gcm-chunked-v1"
SCHEMES = frozenset({SCHEME})

IV_BYTES = 12
GCM_TAG_BYTES = 16
KEY_BYTES = 32  # AES-256
OVERHEAD_PER_CHUNK = IV_BYTES + GCM_TAG_BYTES
# Bounds on the plaintext bytes per chunk. Upper: the worker buffers one whole
# chunk in memory before decrypting, so an unbounded chunk_size forces the
# download into RAM (memory-DoS). Lower: a tiny chunk_size inflates the chunk
# count and per-chunk GCM overhead into a CPU-DoS (millions of one-byte
# decryptions), so require a sensible floor.
MIN_CHUNK_SIZE = 4096  # 4 KiB
MAX_CHUNK_SIZE = 16 * 1024 * 1024  # 16 MiB

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


def decrypt_chunk(
    key: bytes, blob: bytes, file_id: str, part_number: int, parts: int
) -> bytes:
    """Decrypt one ``IV || ciphertext || tag`` chunk back to plaintext.

    ``part_number`` (1-based) and ``parts`` (the total) are authenticated via the
    AAD, so a chunk only decrypts in its intended position within its file.
    """
    # A chunk must hold an IV + tag plus at least one ciphertext byte; empty
    # chunks are never produced (an empty plaintext slice yields no chunk).
    if len(blob) <= OVERHEAD_PER_CHUNK:
        raise DecryptionError(
            f"chunk {part_number} is {len(blob)} bytes, too short to hold "
            f"an IV + tag ({OVERHEAD_PER_CHUNK}) plus ciphertext"
        )
    iv = blob[:IV_BYTES]
    body = blob[IV_BYTES:]
    aad = f"{file_id}:{part_number}:{parts}".encode()
    try:
        return AESGCM(key).decrypt(iv, body, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            f"chunk {part_number} failed authentication "
            "(wrong key, chunking, or tampered/truncated ciphertext)"
        ) from exc
