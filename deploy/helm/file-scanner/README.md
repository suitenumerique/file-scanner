# file-scanner Helm chart

Deploys the scanning API (`app`), the dramatiq worker (`worker`), and by
default a bundled ClamAV daemon and a Redis broker. Both `app` and `worker`
are required for async scans; see [docs/deployment.md](../../../docs/deployment.md).

## Install

Released charts live on GHCR as OCI artifacts, one version per release tag
`vX.Y.Z` (chart `X.Y.Z` deploys image `X.Y.Z`):

```sh
helm install file-scanner oci://ghcr.io/suitenumerique/charts/file-scanner --version X.Y.Z \
  --set config.JWT_ISSUER_KEYS="transferts:<caller base64url Ed25519 pubkey>"
```

Every pull request from a branch of this repository that touches the chart
publishes a pre-release, `<version>-pr<n>.<sha>`, so it can be installed for
review (the version is in the run's summary; pull requests from forks are
skipped). Running the workflow by hand publishes the `version` input, or
`<version>-dev.<sha>` when it is left empty.

From a checkout, with the deployment's own signing key in a Secret rather
than on the command line:

```sh
kubectl create secret generic file-scanner \
  --from-literal=JWT_SIGNING_KEY="<base64url Ed25519 seed>"
helm install file-scanner deploy/helm/file-scanner \
  --set config.JWT_ISSUER_KEYS="transferts:<caller base64url Ed25519 pubkey>" \
  --set secrets.existingSecret=file-scanner \
  --set config.JWT_SIGNING_KID=2026-09
```

`deploy/scripts/new-issuer.py` mints a caller key pair; the private half goes
to the caller (transfers: `SCAN_JWT_PRIVATE_KEY`), the public half here.
`JWT_SIGNING_KEY` is this deployment's own key — generate it once with
`make signing-key` (see
[docs/deployment.md](../../../docs/deployment.md#the-services-own-key-jwt_signing_key)).
`secrets.*` also accepts the values inline, which renders them into a Secret
the chart owns.

## Values that matter

| Key | Default | Notes |
| --- | --- | --- |
| `config.*` | see `values.yaml` | Non-secret env for both processes (ConfigMap). Empty strings are omitted. |
| `secrets.*` / `secrets.existingSecret` | empty | Secret env. Use an existing Secret with the same keys in production. |
| `clamav.enabled` | `true` | Bundled clamd. Set `false` and `config.CLAMAV_HOSTS` for an external pool. |
| `clamav.conf.*` | 2200M | `StreamMaxLength` / `MaxFileSize` / `MaxScanSize` — must clear `MAX_URL_SIZE`, else big files are cut mid-stream or skipped and reported clean. |
| `clamav.persistence` | 2Gi PVC | Signature database; `Recreate` strategy because RWO. |
| `exav.enabled` | `false` | Bundled [exav](https://exav.org) as a second engine; add `exav` to `config.DEFAULT_SCANNERS` (with `config.ADVISORY_SCANNERS=clamav` to let it decide past clamav's 2 GiB ceiling). |
| `exav.dbUrl` | `""` (required when enabled) | The prebuilt `.exavdb` the daemon pulls over HTTPS and polls (`exav.dbUrlAllowHttp=true` for an isolated plain-HTTP mirror; `exav.dbUrlSecret` for a URL with credentials). |
| `redis.enabled` | `true` | Bundled, non-persistent broker. `false` ⇒ set `secrets.WORKER_BROKER_URL`. |
| `worker.queues` | `webhooks scans` | Run a second release with `scans` / `webhooks` split to keep callbacks prompt under a backlog. |
| `worker.downloadSizeLimit` | 8Gi | emptyDir for async downloads: ≥ `MAX_URL_SIZE` × concurrent scans. |
| `clamav.tmpSizeLimit` | 24Gi | clamd spools each stream to `/tmp` before scanning: `StreamMaxLength` × `MaxThreads`. |
| `ingress`, `metrics.serviceMonitor` | disabled | Standard knobs. |

## Sizing notes

* clamd holds the whole signature set in memory (~1.5 GiB) — keep its
  `resources.limits.memory` ≥ 2 GiB.
* The worker buffers one `ENCRYPTION_MAX_CHUNK_SIZE` chunk per running scan;
  `processes × threads × chunk` bounds its memory.
* The app image is distroless: probes are HTTP (readiness on `/check`,
  which also pings clamd; startup and liveness on the JWKS document, so a
  clamd outage makes the pods NotReady without restarting them), there is
  no shell to `exec` into. Use the `:debug-nonroot` base if you need one.
* Every pod runs non-root with a read-only root filesystem, clamav included
  (started through the chart's own entrypoint rather than the image's
  root-only `/init`), so the chart fits a `restricted` Pod Security
  namespace. `networkPolicy.enabled` fences the bundled redis, clamd and
  exav.

## Checks

`make lint-helm` runs what the CI runs: `helm lint --strict`, renders the
three configurations we ship, and asserts that the bundled clamd and Redis
are wired into the app/worker env (and gone when disabled). Uses your local
`helm`, or a pinned `alpine/helm` container if you have none.
