"""API wire formats.

The scan result has two shapes on the wire, one per API version. **Both are
serialisations of the same verdict** — the engines' own words, reduced per
category by :meth:`scanner.ScanReport.verdicts` — so the two views cannot
disagree about a file. Only their vocabulary differs.

``v2`` is canonical: it is what the scanners produce, what the result store
holds, and what every internal path passes around. ``v1`` is the shape this
service spoke before verdicts existed, kept so a caller written against it
keeps working. It is produced by *downgrading* a v2 payload here — never by a
second pass over the scanner results, which is exactly how two views drift
apart.

The v1 vocabulary is narrower than the verdict it comes from, and that is the
whole reason v2 exists:

===========  ===================================  ==========================
verdict      v1 scalar                            v1 ``error_kind``
===========  ===================================  ==========================
``clean``    ``False`` (or the score, if scored)  —
``malware``  ``True``                             —
``flagged``  the score, else ``True``             —
``partial``  ``None``                             ``file`` (permanent)
``error``    ``None``                             ``transient`` (retryable)
===========  ===================================  ==========================

Two consequences a v1 caller lives with, and a v2 caller does not:

* ``None`` is overloaded. "The file could not be read" and "the engines failed"
  are the same scalar, told apart only by ``error_kind`` beside it — and that
  key is a single one for the whole response, so with several categories it
  describes only the ``malware`` axis (the one any v1 caller reads).
* ``flagged`` is reported as a detection. A v1 caller has no word for a
  content-policy hit, so on a discrete axis it arrives as ``True`` — the file is
  blocked, but labelled a virus. v2 keeps the distinction.

One case is inexact, and no shipped backend can reach it: a *scored* axis that
came back clean with no score at all is ``False`` here where the pre-verdicts
service said ``None``. Telling the two apart needs the axis's scored-ness,
which the verdict does not carry, and no scanner we ship sets it (see
``scanner.Scanner``). It is documented rather than guessed at.
"""

V1 = "v1.0"
V2 = "v2.0"

# Every version this service answers on, newest first. The path prefix is the
# contract: ``/api/v1.0/`` is frozen, ``/api/v2.0/`` is current.
PREFIXES = {"/api/v2.0/": V2, "/api/v1.0/": V1}


def of_path(path: str) -> str:
    """The wire version a request path asks for; ``V2`` for anything unprefixed."""
    for prefix, version in PREFIXES.items():
        if path.startswith(prefix):
            return version
    return V2


def _scalar(verdict: dict):
    """One category's verdict → the v1 scalar for that axis."""
    kind, score = verdict.get("kind"), verdict.get("score")
    if kind == "malware":
        return True
    if kind == "flagged":
        # A scored axis reports how sure it is; a discrete one has only the fact.
        return score if score is not None else True
    if kind == "clean":
        # A scored axis that saw nothing still reports its highest score.
        return score if score is not None else False
    # partial / error, and any word a future version adds: the axis has no
    # answer. Failing closed is the caller's job — a v1 caller must not read
    # ``None`` as clean, which is the trap v2 was built to remove.
    return None


def to_v1(payload: dict) -> dict:
    """Downgrade a canonical (v2) payload to the v1 shape.

    Returns a new dict: the per-category scalars at the top level, the
    ``scanners`` breakdown untouched, and the ``error_kind`` / ``error`` pair
    that qualifies a ``None`` on the malware axis. A payload carrying no
    ``verdicts`` — a pending seed, or a pre-scan failure that never reached a
    scanner — is already v1-shaped and passes through unchanged.

    The job envelope wins where it speaks: a pre-scan failure sets its own
    ``error_kind``, and that is more specific than anything derived here, so it
    is never overwritten.
    """
    out = {k: v for k, v in payload.items() if k != "verdicts"}
    verdicts = payload.get("verdicts")
    if not isinstance(verdicts, dict):
        return out

    for category, verdict in verdicts.items():
        if isinstance(verdict, dict):
            out[category] = _scalar(verdict)

    malware = verdicts.get("malware")
    if isinstance(malware, dict) and malware.get("kind") in ("partial", "error"):
        out.setdefault(
            "error_kind", "file" if malware["kind"] == "partial" else "transient"
        )
        if malware.get("reason"):
            out.setdefault("error", malware["reason"])
    return out


def serialize(payload: dict, version: str) -> dict:
    """``payload`` (canonical v2) in the shape ``version`` asks for, stamped with
    the version it is in.

    The stamp matters most where there is no route to infer it from: a webhook is
    a callback, and its shape was decided when the job was submitted, which may
    be before the receiver was last deployed. Without it a caller has to guess
    the shape by sniffing for keys; with it, a caller that reads a version it
    does not expect knows so for certain, and can act — acknowledge and
    re-submit the scan in the version it does speak. The key is additive, so a
    v1 caller written before it existed ignores it.
    """
    out = to_v1(payload) if version == V1 else dict(payload)
    out["api_version"] = version
    return out
