# Client-side encryption — caller contract

If you encrypt a file before storing it, the scanner sees opaque bytes and
reports it clean. To have it scanned, encrypt in the format below and pass an
`encryption` object on `POST /api/v1.0/scan-async`; the worker decrypts to
plaintext before scanning. This page is the **caller-side spec** — implement your
encryptor to match it exactly, or decryption fails (permanently — reported as
`error_kind: "file"`, never retried).

## Scheme

This page documents scheme **`aes-256-gcm-chunked-v1`** — the default (and only
one today). Send it in `encryption.scheme`, or omit it for the default; an
unknown scheme is rejected with `422`. The tag versions the wire format so it can
evolve without ambiguity.

## Wire format

AES-256-GCM, one **chunk** per `chunk_size` bytes of *plaintext*, concatenated in
order. Each stored chunk is:

```
[ IV (12 bytes) | ciphertext (len of the plaintext slice) | GCM tag (16 bytes) ]
```

- Split the plaintext into `parts = ceil(len / chunk_size)` slices. Every slice
  is `chunk_size` bytes except the last, which is whatever remains (never empty).
- Encrypt slice number `part` (1-based) with a fresh random 12-byte **IV** and
  **additional authenticated data (AAD)** of exactly:

  ```
  f"{file_id}:{part}:{parts}"      # e.g. "abc123:2:5" — UTF-8 bytes
  ```

- Store `IV || ciphertext || tag`. Concatenate the chunks in part order.

## Request

```jsonc
{
  "url": "https://storage.example.com/presigned/ciphertext.bin",
  "webhook_url": "https://app.example.com/av-callback",
  "encryption": {
    "scheme": "aes-256-gcm-chunked-v1",  // optional; this is the default
    "key": "<url-safe base64 AES-256 key, 43 chars unpadded>",
    "chunk_size": 65536,        // PLAINTEXT bytes per chunk; 4 KiB .. 50 MiB by default
    "file_id": "abc123",        // the AAD prefix; matches what you encrypted with
    "parts": 5                  // total number of chunks
  }
}
```

The `key` is URL-safe base64 (`A–Z a–z 0–9 - _`, optional `=` padding) of the raw
32-byte key — standard base64 (`+` `/`) is rejected.

## Rules that will bite you if you get them wrong

- **AAD must be `{file_id}:{part}:{parts}` exactly.** It binds each chunk to its
  position *and* the total count. Position stops reordering; the total stops
  **trailing truncation** — dropping whole end chunks lands on a chunk boundary
  and would otherwise pass per-chunk authentication, so the service also checks
  that it decrypted exactly `parts` chunks. `parts` in the request **must** equal
  the `parts` you put in every AAD.
- **Use a unique IV per chunk.** AES-GCM is catastrophically broken if an IV is
  ever reused under the same key — reuse leaks plaintext and lets tags be forged.
  Generate a fresh CSPRNG IV for every chunk. The service cannot detect reuse.
- **`chunk_size` is the plaintext size**, not the stored size; the stored chunk
  is `chunk_size + 28` bytes (IV + tag) except the last. By default it must be
  **4 KiB – 50 MiB** (configurable per deployment via `ENCRYPTION_MIN_CHUNK_SIZE`
  / `ENCRYPTION_MAX_CHUNK_SIZE`): the worker buffers one whole chunk in memory
  (upper bound), and a tiny chunk_size would inflate the chunk count into a CPU
  cost (lower bound). Only the *uniform* `chunk_size` is bounded — the final
  chunk may be as small as one byte.
- The download size limit (`MAX_URL_SIZE`) counts **ciphertext** bytes.

## Key handling

The `key` is not persisted by the service and is never written to logs or the
webhook payload. **But** async scans are queued, so the key travels inside the
task message on the broker (Redis) until the job runs. Treat the broker as
sensitive: password it, keep it on an internal network, and avoid on-disk
persistence (RDB/AOF) for the queue. Keys are per-request and short-lived; rotate
them per file.
