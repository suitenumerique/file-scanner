# Content categories & multi-axis verdicts

> **Status: implemented.** This is the reference for the category model — the
> request grammar (`?categories=` ∪ `?scanners=`), the multi-axis response
> (`{malware, nsfw, …, scanners:[…]}`), and its configuration. The one axis that
> ships is `malware` (clamav / exav / jcop); `nsfw` is documented throughout as
> the worked example of adding a *scored* axis — no scored backend ships yet.

## Motivation

Malware is a discrete threat axis (`infected` / `clean`, a signature match).
Content classifications such as **NSFW** are a *different* kind of judgment: a
graded score (`P(porn) = 0.99`), not a binary infection. Collapsing both into the
single top-level `malware` boolean would (a) be semantically wrong and (b) break
malware-only consumers — notably [transfers](https://github.com/suitenumerique/transfers),
whose webhook reads `{status, malware, reason, error_kind}`. So the model grows a
**category** axis rather than overloading `malware`.

## Verdict model

Each `ScannerResult` gains a **`category`** and an optional **`score`**:

- `category` — the axis the scanner feeds (`malware`, `nsfw`, …). A scanner
  declares its intrinsic category (clamav/exav/jcop → `malware`; a NudeNet-style
  backend → `nsfw`).
- `score` — optional float for probabilistic axes; absent for discrete ones.
- `kind` — still `clean` / `malware` / `unscannable` / `error`, plus `flagged`
  for a policy hit computed against a server-side threshold (so lazy callers get
  a decision without thresholding the raw score themselves).

## Response shape

Top-level keys are **per-category aggregates in each axis's native type**; the
`scanners[]` array is the transparency/debug view of what actually ran.

```jsonc
{
  "malware": false,        // bool  — OR across malware-category scanners
  "nsfw": 0.99,            // float — max across nsfw-category scanners, or null
  "scanners": [
    {"scanner": "clamav",  "category": "malware", "kind": "clean",   "time": 0.01},
    {"scanner": "nudenet", "category": "nsfw",    "kind": "flagged",
     "score": 0.99, "reason": "porn", "time": 0.12}
  ]
}
```

Rules:

- **Per-category reduction:** `malware` = *any* (OR); `nsfw` = *max* (most
  alarming). Each axis documents its own reduction.
- **`null`, never `0.0`, when an axis wasn't run.** A score of `0.0` asserts
  "definitely not," which is a lie if no scanner covering that axis ran (or it
  errored). Omit the key or set `null`. This mirrors the existing strict rule
  ("clean only if it truly scanned").
- **Response keys follow the scanners that ran**, not the request — running
  `?scanners=clamav` still yields a `malware` key because clamav declares that
  category.
- **Strict aggregation within a category** is unchanged: clean only if every
  scanner in that category scanned in full and found nothing.

`transfers` reads only `malware`, so it is unaffected by any number of extra
axes.

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

- `transfers` sends neither selector ⇒ `DEFAULT_CATEGORIES=malware` ⇒ exactly
  today's behavior; it only ever reads `malware`.
- The scanner-based request (`?scanners=`) survives as-is — it's one of the two
  union paths — so no existing caller breaks.
- The response gains keys (`nsfw`, `null` axes); the `malware` key and
  `scanners[]` array keep their meaning.

## What ships vs. what's illustrative

Implemented: the request grammar, per-category aggregation, the config surface,
boot validation, and the `category` label on `filescanner_scans_total`. A scored
axis is fully supported by the plumbing (`Verdict.score`, `Scanner.scored`,
max-reduction, `null`-not-`0.0`) but **no scored backend ships** — `nsfw` /
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
