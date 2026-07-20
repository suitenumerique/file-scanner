#!/usr/bin/env bash
#
# Examples against a locally running service (see the project README).
# Set API_KEY to one of the keys configured in API_KEYS (name:key pairs).
set -euo pipefail

API_KEY="${API_KEY:-test-key-not-for-production}"
BASE_URL="${BASE_URL:-http://localhost:8090}"

# --- Synchronous scan of an uploaded file -----------------------------------
#
# Runs DEFAULT_CATEGORIES; pass ?categories=malware,nsfw (deployment picks the
# engines) and/or ?scanners=clamav,exav (explicit engines) to select. The
# response has one key per category plus a per-scanner breakdown:
#   {"malware": bool, "scanners": [{"scanner", "category", "kind", ...}]}.

# The harmless EICAR test signature — reported as malware.
curl -sf -H "X-API-Key: $API_KEY" \
  -F "file=@eicar.txt" \
  "$BASE_URL/api/v1.0/scan?categories=malware"

# A password-protected archive. With exav (or clamd's ArchiveBlockEncrypted),
# the scanner's entry comes back as {"kind": "unscannable", "reason":
# "PASSWORD-PROTECTED"} — could not be fully scanned, not clean.
curl -sf -H "X-API-Key: $API_KEY" \
  -F "file=@protected.zip" \
  "$BASE_URL/api/v1.0/scan?scanners=exav"

# --- Asynchronous scan of a file fetched from a URL -------------------------
#
# The service downloads the URL itself and POSTs the report to webhook_url.
# Returns 202 {"job_id": "...", "status": "pending"}.
curl -sf -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{
        "url": "https://example.com/some/file.pdf",
        "filename": "file.pdf",
        "webhook_url": "https://your-app.example.com/av-callback",
        "scanners": ["clamav"]
      }' \
  "$BASE_URL/api/v1.0/scan-async"
