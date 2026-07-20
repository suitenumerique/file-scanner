"""AES-256-GCM decryption: URL-safe key decoding + per-chunk authentication."""

import base64
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import encryption
from encryption import DecryptionError, decode_key, decrypt_chunk

KEY = b"\x07" * 32
FRAGMENT = base64.urlsafe_b64encode(KEY).decode().rstrip("=")


def _chunk(plaintext, key=KEY, file_id="fid", part=1):
    iv = os.urandom(encryption.IV_BYTES)
    aad = f"{file_id}:{part}".encode()
    return iv + AESGCM(key).encrypt(iv, plaintext, aad)


# --- decode_key ---


def test_decode_key_roundtrip():
    assert decode_key(FRAGMENT) == KEY


def test_decode_key_accepts_padding():
    assert decode_key(FRAGMENT + "=") == KEY


def test_decode_key_rejects_standard_base64_chars():
    # '+' and '/' are valid standard base64 but not URL-safe.
    with pytest.raises(DecryptionError):
        decode_key("+/" + "A" * 41)


@pytest.mark.parametrize("fragment", ["", None, "!!!bad!!!"])
def test_decode_key_rejects_junk(fragment):
    with pytest.raises(DecryptionError):
        decode_key(fragment)


def test_decode_key_rejects_wrong_length():
    short = base64.urlsafe_b64encode(b"\x01" * 16).decode().rstrip("=")
    with pytest.raises(DecryptionError, match="32-byte key"):
        decode_key(short)


# --- decrypt_chunk ---


def test_decrypt_chunk_roundtrip():
    assert decrypt_chunk(KEY, _chunk(b"hello world"), "fid", 1) == b"hello world"


def test_decrypt_chunk_wrong_part_fails_auth():
    # The AAD binds each chunk to its 1-based part number: a reordered chunk
    # fails authentication instead of decrypting.
    blob = _chunk(b"data", part=1)
    with pytest.raises(DecryptionError):
        decrypt_chunk(KEY, blob, "fid", 2)


def test_decrypt_chunk_wrong_file_id_fails_auth():
    blob = _chunk(b"data", file_id="fid")
    with pytest.raises(DecryptionError):
        decrypt_chunk(KEY, blob, "other", 1)


def test_decrypt_chunk_wrong_key_fails():
    with pytest.raises(DecryptionError):
        decrypt_chunk(b"\x00" * 32, _chunk(b"data"), "fid", 1)


def test_decrypt_chunk_tampered_fails():
    blob = bytearray(_chunk(b"data"))
    blob[-1] ^= 0x01  # flip a tag bit
    with pytest.raises(DecryptionError):
        decrypt_chunk(KEY, bytes(blob), "fid", 1)


@pytest.mark.parametrize("size", [0, encryption.OVERHEAD_PER_CHUNK])
def test_decrypt_chunk_too_short(size):
    with pytest.raises(DecryptionError, match="too short"):
        decrypt_chunk(KEY, b"\x00" * size, "fid", 1)
