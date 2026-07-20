# Scanner backends

The scanning engine is pluggable. The app and worker only ever see a normalized
`Verdict` (`clean` / `malware` / `flagged` / `unscannable`) from the `Scanner`
interface in `scanner.py`; concrete backends live in `scanners/` and are
registered by public name in `scanner._BUILDERS`. Each backend declares the
**category** (axis) it feeds. A request selects work by category and/or scanner
(`?categories=malware` and/or `?scanners=clamav,jcop`); otherwise
`DEFAULT_CATEGORIES` is used — see [categories.md](categories.md). Selected
scanners run **in parallel** (each on its own file handle); within a category
their results are combined **strictly** — clean only if every scanner scanned it
in full and found nothing.

| Name | Module | Category | Engine |
| --- | --- | --- | --- |
| `clamav` | `scanners/clamav.py` | `malware` | ClamAV over the clamd wire protocol. |
| `exav` | `scanners/exav.py` | `malware` | [exav](https://github.com/sylvinus/exav) — subclasses the clamav backend; its own daemon pool. |
| `jcop` | `scanners/jcop.py` | `malware` | [Je Clique Ou Pas](https://jecliqueoupas.cyber.gouv.fr) HTTP API. |

All shipped backends feed `malware`. A *scored* axis such as `nsfw` is fully
supported by the plumbing (`Verdict.score`, `Scanner.scored`) but no scored
backend ships yet; see [categories.md](categories.md).

## Adding a backend

Implement `scanner.Scanner` (`ping` / `scan` → `Verdict` or raise `ScannerError`;
optional `version`) in a new `scanners/<name>.py`, set its `category` (and
`scored = True` for a probabilistic axis), then add a builder to
`scanner._BUILDERS`. Nothing in `app.py` or `tasks.py` changes.

## clamav

Connects to `CLAMAV_SOCKET` or `CLAMAV_HOST:CLAMAV_PORT`. For horizontal scale,
set `CLAMAV_HOSTS="h1:3310,h2:3310,…"` — a host is picked at **random per scan**
(client-side balancing), and a connection failure becomes a transient error so
the task retry fails over to another host. No external load balancer required
(though one is still fine — point `CLAMAV_HOST` at its VIP).

## exav

[exav](https://github.com/sylvinus/exav) is a memory-safe Rust reimplementation
that loads the same ClamAV databases and speaks the same protocol, so it reuses
the whole clamav backend (INSTREAM + verdict handling). It has its **own** pool,
`EXAV_HOSTS` (required, same `host:port,…` format), so `clamav` and `exav` can
run side by side against separate daemons. Its defining property: it **never
reports a skipped file clean** — where ClamAV silently returns `OK` (e.g. a file
over ~2 GB), exav returns an `ERROR` verdict with a structured tag (see
[Extended verdicts](#extended-verdicts)). exav manages its own database reloads,
so it reports no signature-freshness metric.

> exav is experimental (alpha). Evaluate it for your risk profile.

## jcop

[JCOP — "Je Clique Ou Pas"](https://jecliqueoupas.cyber.gouv.fr) is a
malware-analysis HTTP API from cyber.gouv.fr (a gated service — you need a URL
and token). Unlike the clamd backends it is **submit-then-poll**: hash the file,
check the results cache, submit on a miss, poll until done (bounded by
`JCOP_SUBMIT_TIMEOUT`). Modelled on the reference implementation in
[suitenumerique/django-lasuite](https://github.com/suitenumerique/django-lasuite).
Because it blocks while polling it suits the async path; on the sync endpoint it
blocks the request. Configure with `JCOP_BASE_URL` / `JCOP_API_KEY` (see
[deployment.md](deployment.md#configuration)).

## Extended verdicts

exav surfaces "couldn't fully scan" outcomes as an `ERROR` verdict whose reason
is one of:

| Tag | Meaning |
| --- | --- |
| `LIMITS-EXCEEDED` | A size / ratio / recursion / scan-bytes limit stopped the scan. |
| `UNSCANNABLE` | A container was recognised but couldn't be decoded. |
| `PASSWORD-PROTECTED` | An encrypted member — actionable (re-scan with a password). |

The clamav backend (shared by exav) surfaces the tag as an `unscannable` verdict
(never clean, never malware), and treats **any future / unrecognised** bare
upper-case tag as `UNSCANNABLE` by default. A raw clamd/OS error sentence (e.g.
`Can't allocate memory`) is instead classified `transient` (retryable).
