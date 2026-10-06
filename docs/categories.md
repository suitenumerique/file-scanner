# Content categories & multi-axis verdicts

> **Status: implemented.** This is the reference for the category model — the
> request grammar (`?categories=` ∪ `?scanners=`), the multi-axis response
> (`{verdicts: {malware, nsfw, …}, scanners: […]}`), and its configuration. The one axis that
> ships is `malware` (clamav / exav / jcop); `nsfw` is documented throughout as
> the worked example of adding a *scored* axis — no scored backend ships yet.

## Motivation

Malware is a discrete threat axis (`infected` / `clean`, a signature match).
Content classifications such as **NSFW** are a *different* kind of judgment: a
graded score (`P(porn) = 0.99`), not a binary infection. Collapsing both into the
single `malware` answer would be semantically wrong, and would leave
a malware-only caller reading a number where it expects a detection. So the
model grows a
**category** axis rather than overloading `malware`.

## Verdict model

Each `ScannerResult` gains a **`category`** and an optional **`score`**:

- `category` — the axis the scanner feeds (`malware`, `nsfw`, …). A scanner
  declares its intrinsic category (clamav/exav/jcop → `malware`; a NudeNet-style
  backend → `nsfw`).
- `score` — optional float for probabilistic axes; absent for discrete ones.
- `kind` — still `clean` / `malware` / `partial` / `error`, plus `flagged`
  for a policy hit computed against a server-side threshold (so lazy callers get
  a decision without thresholding the raw score themselves).

## Response shape

`verdicts` holds the **per-category answer in the same vocabulary a scanner
uses**; the `scanners[]` array is the transparency/debug view of what actually
ran.

```jsonc
{
  "verdicts": {
    "malware": {"kind": "clean"},
    "nsfw":    {"kind": "flagged", "score": 0.99, "reason": "porn"}
  },
  "scanners": [
    {"scanner": "clamav",  "category": "malware", "kind": "clean",   "time": 0.01},
    {"scanner": "nudenet", "category": "nsfw",    "kind": "flagged",
     "score": 0.99, "reason": "porn", "time": 0.12}
  ]
}
```

Rules:

- **One vocabulary, end to end.** A verdict's `kind` is the same five words as a
  per-scanner `kind` — `clean` / `malware` / `flagged` / `partial` / `error` —
  reduced across the axis, so nothing is re-encoded between the backend that
  produced it and the caller that acts on it. The words are this service's own:
  it borrows an engine's only where that engine is what named the concept —
  `partial` is exav's `PARTIAL`, while `clean` and `malware` say what a
  protocol-level `OK` and `FOUND` only imply. See [glossary.md](glossary.md)
  for the mapping from each engine.
- **Precedence within a category:** `malware` (or `flagged`) > `error` >
  `partial` > `clean`, with a **scope** that differs by word — a detection
  counts from *any* scanner, advisory included, while not having read the whole
  file counts only from the *deciding* ones. Those two rules are the whole of
  `ScanReport.verdicts()`.
- **A verdict says why an axis has no answer**, which a bare scalar could not:
  `partial` (a property of this file — blocking it is final) against `error`
  (the engines failed — a retry may still answer). Hence their order above:
  a retry that comes back `partial` blocks the file then, whereas leading with
  `partial` would block it on what may be a passing outage.
- **Per-category score reduction:** a scored axis reports the *max* across its
  scanners (most alarming). A discrete axis has no score.
- **No score at all, never `0.0`, when nothing scored.** A score of `0.0`
  asserts "definitely not", which is a lie if no scanner covering that axis
  produced one. The key is omitted, mirroring the strict rule above ("clean
  only if it truly scanned").
- **Response keys follow the scanners that ran**, not the request — running
  `?scanners=clamav` still yields a `malware` key because clamav declares that
  category.
- **Strict aggregation within a category**: `clean` only if every deciding
  scanner in that category scanned in full and found nothing. One that could
  not (`error`, `partial`) carries its own word up to the axis.

A caller that reads only the `malware` axis is unaffected by any number of
extra axes.

## Advisory scanners

`ADVISORY_SCANNERS` (comma-separated engine names) marks engines that scan
**for information**: their detections count like any other, but a file they
could not fully examine — a size or time limit, an unreadable container — does
not stop the category from being asserted when a non-advisory engine of that
category examined it in full. An advisory engine running alone still decides.
Its results are flagged `"advisory": true` in `scanners[]`.

What it is for: running a second engine next to the one that decides —
an engine under evaluation, or clamav next to exav on files past clamav's
2 GiB ceiling, where clamav answers `LIMITS-EXCEEDED` and exav has read the
whole file. Without the role, strict aggregation makes two engines only as
capable as the more limited one.

| exav (deciding) | clamav (advisory) | verdict |
| --- | --- | --- |
| clean | clean | `clean` |
| clean | partial / error | `clean` — clamav's result is kept in `scanners[]` |
| clean | malware | `malware` — a detection always wins |
| partial | clean | `partial` — the deciding engine did not complete |
| error | clean | `error` — the job is retried |
| error | malware | `malware` — **reported, not retried** (see below) |

The last row is the one asymmetry worth stating: a detection is a positive
fact about the file that no retry can improve on, so it is reported even
though the engine meant to decide never ran. An advisory `clean` in the same
spot asserts nothing, so it does not rescue the job.

## Request grammar

Two selectors that **union** into one scanner set — no precedence:

```
effective_scanners = (scanners named in ?scanners=)
                   ∪ (⋃ DEFAULT_SCANNERS[c] for c in ?categories=)
```

- `categories` express **intent** ("give me this axis, the deployment picks
  engines"); `scanners` express **control** ("run this specific engine").
- Either selector present ⇒ the default layer is skipped (request wins; defaults
  do not merge in).
- Naming a scanner *without* its category **narrows** an axis; naming it
  *alongside* the category **adds** — the same knob does both, so no per-category
  default-subset config is needed.

| Request | Means |
| --- | --- |
| `?categories=malware` | malware axis, deployment picks engines → clamav,exav |
| `?scanners=clamav` | malware axis, but *only* clamav (narrow) |
| `?categories=malware&scanners=jcop` | the standard malware set **plus** jcop (add) |
| `?scanners=exav` | just exav (A/B a specific engine) |

## Configuration

The whole surface is two vars, and the default layer mirrors the request grammar
(a default is just a server-side canned request):

```
DEFAULT_SCANNERS = {"malware": ["clamav", "exav"], "nsfw": ["nudenet"]}
DEFAULT_CATEGORIES = "malware"
```

- **`DEFAULT_SCANNERS`** — JSON `category → [engines]`. Does double duty:
  *availability + composition* (its keys are the categories that exist;
  `?categories=nsfw` resolves to `DEFAULT_SCANNERS["nsfw"]`).
- **`DEFAULT_CATEGORIES`** — which of those keys run when a request names neither
  selector. This is why both vars exist: the map says what's *available*
  (`nsfw` configured ⇒ `?categories=nsfw` works), `DEFAULT_CATEGORIES` says
  what's *on by default* (`nsfw` available but not run unless asked). Available ≠
  default-on.

Default resolution when the request names neither selector:

```
⋃ DEFAULT_SCANNERS[c] for c in DEFAULT_CATEGORIES
```

Per-axis thresholds (for the `flagged` decision) live in config too, e.g.
`NSFW_THRESHOLD`.

### Boot validation (fail fast)

- `DEFAULT_SCANNERS` parses as a JSON object; every value is a non-empty list.
- Every engine name resolves in `scanner._BUILDERS`, and its placement matches
  the scanner's declared category (listing `clamav` under `nsfw` is a misconfig).
- Every `DEFAULT_CATEGORIES` entry is a key of `DEFAULT_SCANNERS`.

### Request-time errors (all `400`, consistent with today)

- unknown scanner name;
- unknown category (`?categories=X`, `X ∉ DEFAULT_SCANNERS`);
- empty effective scanner set.

## Migration / compatibility

- A caller sending neither selector gets `DEFAULT_CATEGORIES` ⇒ with the
  shipped default, only the `malware` axis, whatever else is configured.
- The scanner-based request (`?scanners=`) survives as-is — it's one of the two
  union paths — so no existing caller breaks.
- The response **replaced** the per-category scalars it used to carry at the top
  level (`"malware": true|false|null`, with `error_kind` / `error` beside them)
  with `verdicts`. A scalar could not say why an answer was missing, and read as
  clean when tested for truth. `scanners[]` keeps its meaning.
- **The scalars are not gone — they are v1.** `verdicts` is the `/api/v2.0/`
  response; `/api/v1.0/` still answers in the shape it always did, derived from
  the same verdict rather than computed beside it, so the two views cannot
  disagree about a file. No caller is forced to move, and no deployment has to
  be ordered around the change. What v1 cannot express is listed in
  [`src/wire.py`](../src/wire.py); the short version is that `null` stays
  overloaded there, which is why v2 exists. See
  [deployment](deployment.md#api-versions-and-upgrading).

## What ships vs. what's illustrative

Implemented: the request grammar, per-category aggregation, the config surface,
boot validation, and the `category` label on `filescanner_scans_total`. A scored
axis is fully supported by the plumbing (`Verdict.score`, `Scanner.scored`,
max-reduction, no-score-rather-than-`0.0`) but **no scored backend ships** — `nsfw` /
`nudenet` above are the worked example. Adding one is a new `scanners/<name>.py`
that sets `category`/`scored` and a builder in `_BUILDERS`; nothing else changes.

Decisions settled while implementing:

- Both `score` (raw, top-level and per-scanner) and `kind: "flagged"` (a
  decision against a server-side threshold) are surfaced — the raw score for
  callers that re-threshold, the decision for callers that don't.
- The service owns the category vocabulary (a scanner's `category` attribute);
  the `DEFAULT_SCANNERS` map must list each engine under the category it
  declares, enforced at boot.
- Sync scans are counted in the web process, async in the worker — scrape both
  or use `PROMETHEUS_MULTIPROC_DIR` (unchanged by categories).
