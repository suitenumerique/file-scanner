# file-scanner Helm chart

Deploys the scanning API (`app`), the dramatiq worker (`worker`), and by
default a bundled ClamAV daemon and a Redis broker. Both `app` and `worker`
are required for async scans; see [docs/deployment.md](../../../docs/deployment.md).

## Install

Released charts live on GHCR as OCI artifacts, one version per release tag
(chart `X.Y.Z` deploys image `vX.Y.Z`):

```sh
helm install file-scanner oci://ghcr.io/suitenumerique/charts/file-scanner --version 0.1.1 \
  --set config.JWT_ISSUER_KEYS="transferts:<caller base64url Ed25519 pubkey>"
```

Every pull request touching the chart publishes a pre-release,
`<version>-pr<n>.<sha>`, so it can be installed for review (the version is in
the run's summary); running the workflow by hand on a branch gives
`<version>-dev.<sha>`.

From a checkout:

```sh
helm install file-scanner deploy/helm/file-scanner \
  --set config.JWT_ISSUER_KEYS="transferts:<caller base64url Ed25519 pubkey>" \
  --set secrets.JWT_SIGNING_KEY="<base64url Ed25519 seed>" \
  --set config.JWT_SIGNING_KID=2026-09
```

`deploy/scripts/new-issuer.py` mints a caller key pair; the private half goes
to the caller (transfers: `SCAN_JWT_PRIVATE_KEY`), the public half here.
`JWT_SIGNING_KEY` is this deployment's own key — generate it once (see
[docs/deployment.md](../../../docs/deployment.md#the-services-own-key-jwt_signing_key))
and keep it in `secrets.existingSecret`.

## Values that matter

| Key | Default | Notes |
| --- | --- | --- |
| `config.*` | see `values.yaml` | Non-secret env for both processes (ConfigMap). Empty strings are omitted. |
| `secrets.*` / `secrets.existingSecret` | empty | Secret env. Use an existing Secret with the same keys in production. |
| `clamav.enabled` | `true` | Bundled clamd. Set `false` and `config.CLAMAV_HOSTS` for an external pool. |
| `clamav.conf.*` | 2200M | `StreamMaxLength` / `MaxFileSize` / `MaxScanSize` — must clear `MAX_URL_SIZE`, else big files are cut mid-stream or skipped and reported clean. |
| `clamav.persistence` | 2Gi PVC | Signature database; `Recreate` strategy because RWO. |
| `redis.enabled` | `true` | Bundled, non-persistent broker. `false` ⇒ set `secrets.WORKER_BROKER_URL`. |
| `worker.queues` | `webhooks scans` | Run a second release with `scans` / `webhooks` split to keep callbacks prompt under a backlog. |
| `worker.downloadSizeLimit` | 8Gi | emptyDir for async downloads: ≥ `MAX_URL_SIZE` × concurrent scans. |
| `clamav.tmpSizeLimit` | 8Gi | clamd spools each stream to `/tmp` before scanning. |
| `ingress`, `metrics.serviceMonitor` | disabled | Standard knobs. |

## Sizing notes

* clamd holds the whole signature set in memory (~1.5 GiB) — keep its
  `resources.limits.memory` ≥ 2 GiB.
* The worker buffers one `ENCRYPTION_MAX_CHUNK_SIZE` chunk per running scan;
  `processes × threads × chunk` bounds its memory.
* The app image is distroless: probes are HTTP (`/check`, which also pings
  clamd), there is no shell to `exec` into. Use the `:debug-nonroot` base if
  you need one.
