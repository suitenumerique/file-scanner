# Glossary

Four vocabularies are stacked in this service, each one translating the one
below it: the **clamd wire protocol** that the daemons speak, **exav's**
extension of it, the **five words** this service normalizes everything into,
and the **objects** that carry them. Most of the confusion in the code comes
from reading a word at the wrong level — `ERROR` and `error` are not the same
thing, and a clamd `FOUND` is not always a detection.

This page is the translation table. For how the pieces are used, see
[categories.md](categories.md) (the axis model), [api.md](api.md) (what goes on
the wire) and [scanner-backends.md](scanner-backends.md) (the engines).

## 1. The clamd wire protocol

Spoken by ClamAV's `clamd` **and** by exav: a socket, text commands
(`INSTREAM` to stream and scan, `PING`, `VERSION`), and one reply line ending
in a word.

| Word | Meaning |
| --- | --- |
| `OK` | nothing found |
| `FOUND` | a detection — the line carries the signature name |
| `ERROR` | clamd could not scan |

Two properties of clamd explain much of `scanners/clamav.py`:

- **`OK` overstates its case on large files.** Past `MaxFileSize` /
  `MaxScanSize`, clamd *skips* the file and answers `OK`. Setting
  `AlertExceedsMax` makes it answer `Heuristics.Limits.Exceeded.<Limit>`
  **`FOUND`** instead — a `FOUND` that is not a detection, and the reason this
  service pattern-matches on the signature name.
- **`CLAMAV_MAX_FILE_BYTES` (2³¹−3, `scanner.py`) is libclamav's own ceiling.**
  It clamps whatever `MaxFileSize` says, and skips anything above it. That is
  why boot refuses a `MAX_UPLOAD_SIZE` / `MAX_URL_SIZE` above it while clamav
  is a deciding scanner: the combination is a silent hole.

## 2. exav's extension

exav speaks the same protocol and adds one verb, **`EXINSTREAM`**: the file is
streamed exactly as with `INSTREAM`, but the reply is a single line of JSON,
`{"v": 1, "status": …}`.

| `status` | Extra fields | Becomes |
| --- | --- | --- |
| `OK` | — | `clean` |
| `FOUND` | `signature`, `location` | `malware` |
| `PARTIAL` | `category`, `reason` | `partial` |
| `ERROR` | `reason` | `error` |

`PARTIAL` has no equivalent in clamd. Its `category` is `LIMITS-EXCEEDED`,
`UNSCANNABLE` or `PASSWORD-PROTECTED`.

The difference that matters: **exav states that a file could not be read,
where clamav has to be inferred from a reason string**. It follows that an
`ERROR` from exav is always an engine failure — the file cases have their own
status — while an `ERROR` from clamd is ambiguous and has to be classified.

`location` is exav-only too: the path of the matching member inside a
container (`report.zip/payload.exe`).

## 3. The five words

The only vocabulary that leaves this service. Every backend reply is
normalized into one of them, and the same five run from a `Verdict` up to the
per-category verdict on the wire.

| Word | Meaning | Releases the file? |
| --- | --- | --- |
| `clean` | read in full, nothing found | yes |
| `malware` | a detection; `reason` is the signature | no, final |
| `flagged` | a hit on a **scored** axis, at or above the server-side threshold — *no shipped backend produces this* | no, final |
| `partial` | **not** read in full — the **file** is why | no, final |
| `error` | **not** read in full — the **engines** are why | no, but retry |

`partial` and `error` together are `ScannerResult.incomplete`. What they share
is that no usable assertion came out; what separates them is whose fault it is,
and therefore what the caller should do next — retry an `error`, drop the file
on a `partial`.

`flagged` ships as plumbing only: no scored backend exists yet, and the
`nsfw` / `nudenet` pair in these docs is a worked example.

### The full translation table

| Input | Verdict |
| --- | --- |
| clamd `OK` | `clean` |
| clamd `FOUND`, signature starts with `Heuristics.Limits.Exceeded` | `partial("LIMITS-EXCEEDED")` |
| clamd `FOUND`, anything else | `malware(signature)` |
| clamd `ERROR`, reason matching `allocate` / `time limit` / `timeout` / `no space` | `error` |
| clamd `ERROR`, anything else | `partial("UNSCANNABLE")` |
| exav `OK` / `FOUND` / `PARTIAL` / `ERROR` | `clean` / `malware` / `partial(category)` / `error` |
| jcop, file over its size limit (its `error_code` 413) | `partial("LIMITS-EXCEEDED")` |
| jcop, any other refusal | `partial("UNSCANNABLE")` |
| daemon unreachable, socket closed mid-stream, backend crash | `error` |

### Reason tags

A `partial` verdict carries a tag in its `reason`, from a vocabulary **exav
defines** — it is the only engine that reports the case natively, so the other
two backends synthesize the same words rather than inventing their own. A
caller grouping "a limit was hit" must not have to know which engine ran.

| Tag | Meaning | Reported by |
| --- | --- | --- |
| `LIMITS-EXCEEDED` | a size, time, recursion or ratio limit was hit | exav, clamav, jcop |
| `PASSWORD-PROTECTED` | an encrypted archive | exav |
| `UNSCANNABLE` | could not be read, no further detail | exav, clamav, jcop |

`PASSWORD-PROTECTED` being exav-only is not a divergence but a capability: the
other two cannot tell that case apart and fall back to `UNSCANNABLE`.

Two consequences worth knowing:

- **The set is open.** The exav backend passes exav's `category` through
  verbatim, so a tag a future exav version introduces reaches the caller
  unchanged rather than being flattened. A caller must therefore tolerate a tag
  it does not recognize — the `kind` is what it acts on, the tag is what it
  displays or groups by.
- **clamav does not parse tags.** A clamd `ERROR` whose reason happens to read
  `PASSWORD-PROTECTED` still becomes `UNSCANNABLE`: clamd's reason strings are
  free text, and guessing a structured meaning out of them is exactly what
  `EXINSTREAM` exists to avoid.

## 4. The objects

| Object | Scope | Produced by |
| --- | --- | --- |
| `Verdict` | what **one** backend concluded | `Scanner.scan()` |
| `ScannerResult` | a `Verdict` plus `category`, `advisory`, `time` | `run_scanners()` |
| `CategoryVerdict` | **one axis**, after reducing every engine on it | `ScanReport.verdicts()` |
| `ScanReport` | **the whole scan** of one file | `run_scanners()` |

`ScannerError` is an **exception**, not a verdict: a backend raises it when the
scan could not be carried out, `run_scanners` catches it and records a
`ScannerResult` of `kind="error"`. A backend should never raise anything else;
if it does, that is a bug in the backend and it is isolated the same way.

`run_scanners` produces exactly **one** `ScanReport` per scanned file, whatever
the number of engines. `verdicts()` then reduces N scanner results into M
category verdicts, M ≤ N — with today's `DEFAULT_SCANNERS`, M is 1.

## 5. Configuration terms

- **category** (axis) — `malware`, `nsfw`, … *what* is being judged. The keys
  of `DEFAULT_SCANNERS`, and the keys of `verdicts` in the response.
- **scanner** (engine) — `clamav`, `exav`, `jcop`: *who* judges. Each declares
  the one category it feeds.
- **deciding** vs **advisory** — `ADVISORY_SCANNERS` names the engines that run
  for information: their detections count like anyone else's, their failure to
  examine the file does not. An advisory engine running alone decides anyway.
- **scored** vs **discrete** — a scored axis reduces by `max` over a float, a
  discrete one by "detected or not". Boot refuses a category that mixes them.
- **`?categories=` vs `?scanners=`** — intent ("this axis, you pick the
  engines") against control ("this engine"). They **union**; neither wins.

## 6. The job envelope is not the verdict

They travel together and answer different questions. Keeping them apart is the
whole reason the report shape looks the way it does.

| Field | Question it answers |
| --- | --- |
| `status: done \| error` | did the **job** run at all? |
| `verdicts[axis].kind` | what did the scan **conclude**? |
| `error_kind: file \| transient` | on `status: error` only: was the job's failure the file's fault or the infrastructure's? |

`status: error` covers two cases, told apart by whether the body carries a
report at all.

- **Before scanning** — the URL could not be fetched, the file was too large to
  download, decryption failed. No engine ran, so there are no `verdicts` and no
  `scanners`. `error_kind` is `file` for a file that can never be scanned and
  `transient` for anything worth retrying.
- **Every deciding engine failed** — they ran and none could answer. The report
  *is* there: the axis's verdict is `error`, and `scanners` lists each failure.
  `error_kind` is always `transient`.

So `error_kind: "file"` describes a file that was **never scanned**, while a
`partial` verdict describes one that **was** scanned and could not be read.
Collapsing the two is the mistake this vocabulary exists to prevent.

## 7. Downstream

A caller keeps its own vocabulary, and should: its states are about a file's
lifecycle, not about a scan — "scanning is disabled on this instance" or "never
submitted" are states no verdict corresponds to. What matters is that the
mapping from these five words onto those states is total and explicit, and that
anything unrecognized fails closed.

## False friends

1. **clamd `ERROR` ≠ `error`.** A clamd `ERROR` most often becomes `partial`;
   only a handful of reasons are transient enough to be an `error`.
2. **clamd `FOUND` ≠ `malware`.** A `FOUND` named `Heuristics.Limits.Exceeded`
   is a file clamd gave up on, and becomes `partial`.
3. **`malware` is three things**: a verdict word, a category name, and a
   response key. Hence `verdicts["malware"]["kind"] == "malware"`, which reads
   like a stutter but says "on the malware axis, the answer is: a detection".
4. **`partial` / `PARTIAL` / `UNSCANNABLE`** — a verdict word, an exav wire
   status, and a reason tag, in three different layers. Callers add a fourth
   with their own file state.
5. **`status` ≠ `kind`.** The first belongs to the job, the second to a verdict.
