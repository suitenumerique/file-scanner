"""Backend-agnostic scanner interface and multi-scanner orchestration.

The service scans a file across one or more **categories** (axes of judgment,
e.g. ``malware`` / ``nsfw``) and reports a per-scanner breakdown plus a
per-category aggregate. Each scanner declares the category it feeds and returns a
normalized :class:`Verdict`; the app and worker never see the engine. Concrete
scanners live in ``scanners/`` and are registered by public name in
:data:`_BUILDERS` — ``clamav`` / ``exav`` (the clamd wire protocol) and ``jcop``
(an HTTP service). A future engine implements :class:`Scanner`, sets its
``category``, and adds a builder here.

A request selects work with two selectors that **union** into one scanner set:
``?categories=`` (intent — the deployment picks engines via the
``DEFAULT_SCANNERS`` map) and ``?scanners=`` (explicit engines). When it names
neither, ``DEFAULT_CATEGORIES`` is used. Within a category, results are combined
**strictly** (clean only if every scanner scanned in full and found nothing);
see :class:`ScanReport`. See ``docs/categories.md`` for the full design.
"""

import contextlib
import json
import logging
import timeit
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import metrics
from config import get_settings

logger = logging.getLogger("file-scanner")
settings = get_settings()

# libclamav's ceiling on one file, INT_MAX - 2: MaxFileSize / MaxScanSize
# above it are clamped ("File size limit set to 2147483645 bytes"), and a
# bigger file is skipped rather than scanned.
CLAMAV_MAX_FILE_BYTES = 2**31 - 3


class ScannerError(Exception):
    """A transient scanner/infrastructure failure — a retry may succeed.

    Raised by :meth:`Scanner.scan` when the scan could not be *carried out*
    (engine unreachable, out of memory, hit a runtime limit). It is distinct
    from a :class:`Verdict` of ``unscannable``, which is a permanent property of
    the file itself.
    """


@dataclass
class Verdict:
    """Normalized result of scanning one file. ``kind`` is one of:

    - ``clean``       — scanned in full, nothing detected.
    - ``malware``     — a detection; ``reason`` is the signature/rule name.
    - ``flagged``     — a content-policy hit on a *scored* axis (e.g. nsfw) whose
      ``score`` is at/above the backend's threshold; ``reason`` is a label.
    - ``unscannable`` — could NOT be fully scanned (encrypted, undecodable,
      over a limit). Permanent for this file, so never retried and never clean.
      ``reason`` is a short tag (e.g. ``PASSWORD-PROTECTED``, ``UNSCANNABLE``).

    ``score`` is the raw confidence for a scored axis (0.0-1.0), ``None`` for a
    discrete axis like malware. ``location`` is the inner path of the matched
    member within a container (e.g. ``a.zip/dir/evil.exe``) when the backend can
    report it (exav); ``None`` otherwise.
    """

    kind: str
    reason: str | None = None
    score: float | None = None
    location: str | None = None

    @property
    def malware(self) -> bool:
        return self.kind == "malware"


def clean() -> Verdict:
    return Verdict("clean")


def malware(signature: str | None) -> Verdict:
    return Verdict("malware", signature)


def unscannable(tag: str) -> Verdict:
    return Verdict("unscannable", tag)


@dataclass
class VersionInfo:
    """Signature-database freshness, when a backend can report it."""

    actual: str | None
    required: str | None
    outdated: bool


class Scanner(ABC):
    """A pluggable file scanner. Implementations live in ``scanners/``.

    ``category`` is the axis this scanner feeds (``malware``, ``nsfw``, …) — it
    determines which top-level response key the scanner's result aggregates into.
    ``scored`` is True for probabilistic axes that report a numeric ``score``
    (reduced by ``max`` across the category); False for discrete detection axes
    like malware (reduced by ``any``).
    """

    category: str = "malware"
    scored: bool = False

    @abstractmethod
    def ping(self) -> bool:
        """Return True if the scanner is reachable and healthy."""

    @abstractmethod
    def scan(self, fileobj) -> Verdict:
        """Scan a file-like object and return a :class:`Verdict`.

        Raises :class:`ScannerError` if the scan could not be carried out
        (transient — the caller may retry).
        """

    def version(self) -> VersionInfo | None:
        """Signature-freshness info, or None if the backend can't report it."""
        return None


# --- Per-scanner result + combined report ---


@dataclass
class ScannerResult:
    """One scanner's outcome for a file.

    ``kind`` is one of {clean, malware, flagged, unscannable, error}; ``error`` is a
    transient failure to *carry out* the scan (from :class:`ScannerError`).
    ``reason`` carries the signature (malware), the label (flagged), the tag
    (unscannable), or the message (error). ``category`` is the axis the scanner
    feeds and ``score`` the raw confidence for a scored axis (else ``None``).
    ``scored`` mirrors the scanner's flag so the report can pick the right
    per-category reduction. ``time`` is the scan duration in seconds.
    """

    scanner: str
    category: str
    kind: str
    reason: str | None = None
    score: float | None = None
    location: str | None = None
    time: float = 0.0
    scored: bool = False
    # Runs for information: its detection counts, its failure to examine the
    # file does not (see ADVISORY_SCANNERS).
    advisory: bool = False

    @property
    def incomplete(self) -> bool:
        """The scanner did not examine the whole file — transiently (``error``)
        or as a property of the file (``unscannable``)."""
        return self.kind in ("error", "unscannable")

    def as_dict(self) -> dict:
        d = {
            "scanner": self.scanner,
            "category": self.category,
            "kind": self.kind,
            "time": round(self.time, 4),
        }
        if self.advisory:
            d["advisory"] = True
        if self.score is not None:
            d["score"] = round(self.score, 4)
        if self.reason is not None:
            d["reason"] = self.reason
        if self.location is not None:
            d["location"] = self.location
        return d


@dataclass
class ScanReport:
    """The combined outcome of running several scanners on one file.

    The response is per-category aggregates (:meth:`categories`) plus the
    per-scanner breakdown. A discrete axis (malware) reduces by ``any`` to a
    bool; a scored axis (nsfw) reduces by ``max`` to a float, or ``None`` when
    no scanner in that axis produced a score (didn't run / errored) — never
    ``0.0``, which would falsely assert "definitely not".
    """

    results: list[ScannerResult] = field(default_factory=list)

    @property
    def malware(self) -> bool:
        """Any scanner detected malware (a detection always wins)."""
        return any(r.kind == "malware" for r in self.results)

    @property
    def all_errored(self) -> bool:
        """Every deciding scanner failed transiently — nothing that could
        assert a verdict scanned the file, whatever the advisory ones did."""
        deciding = [
            r
            for results in self._by_category().values()
            for r in self._deciding(results)
        ]
        return bool(deciding) and all(r.kind == "error" for r in deciding)

    def _by_category(self) -> dict[str, list[ScannerResult]]:
        """Results grouped by category, in first-seen order."""
        grouped: dict[str, list[ScannerResult]] = {}
        for result in self.results:
            grouped.setdefault(result.category, []).append(result)
        return grouped

    @staticmethod
    def _deciding(results: list[ScannerResult]) -> list[ScannerResult]:
        """The non-advisory results — or all of them when only advisory
        scanners ran: advisory means "defer to a deciding sibling", not
        "cannot block"."""
        return [r for r in results if not r.advisory] or results

    @property
    def unscannable(self) -> list[ScannerResult]:
        """Deciding results whose scanner could not examine the whole file for
        a reason that is a property of the file (never a transient error)."""
        blaming_the_file = []
        for results in self._by_category().values():
            detected = any(r.kind in ("malware", "flagged") for r in results)
            if detected:
                continue
            blaming_the_file += [
                r for r in self._deciding(results) if r.kind == "unscannable"
            ]
        return blaming_the_file

    def categories(self) -> dict:
        """Per-category aggregate, in first-seen order.

        A detection wins outright, from any scanner. Otherwise the deciding
        scanners (:meth:`_deciding`) must all have examined the whole file for
        the axis to be asserted: a discrete axis (malware) → ``False`` then,
        ``None`` when one of them did not complete (a transient error, or a
        file it cannot read); a scored axis → ``max`` of the available scores,
        ``None`` likewise.
        """
        aggregates: dict = {}
        for category, results in self._by_category().items():
            deciding = self._deciding(results)
            incomplete = any(r.incomplete for r in deciding)
            if any(r.scored for r in results):
                scores = [r.score for r in results if r.score is not None]
                if any(r.kind == "flagged" for r in results):
                    aggregates[category] = max(scores)
                elif incomplete:
                    aggregates[category] = None
                else:
                    aggregates[category] = max(scores) if scores else None
            elif any(r.kind == "malware" for r in results):
                aggregates[category] = True
            elif incomplete:
                aggregates[category] = None
            else:
                aggregates[category] = False
        return aggregates

    def as_dict(self) -> dict:
        report = {
            **self.categories(),
            "scanners": [r.as_dict() for r in self.results],
        }
        unscannable = self.unscannable
        deciding_error = any(r.kind == "error" for r in self.results if not r.advisory)
        if unscannable and not deciding_error:
            # The file itself is why a category is unknown: say so the way a
            # pre-scan failure does, so a caller neither trusts it nor retries.
            report["error_kind"] = "file"
            report["error"] = "not fully scanned: " + ", ".join(
                f"{r.scanner} ({r.reason})" for r in unscannable
            )
        return report


# --- Registry & orchestration ---


def _build_clamav() -> Scanner:
    from scanners.clamav import ClamavScanner

    return ClamavScanner()


def _build_exav() -> Scanner:
    from scanners.exav import ExavScanner

    return ExavScanner()


def _build_jcop() -> Scanner:
    from scanners.jcop import JcopScanner

    return JcopScanner()


# Public scanner name → builder.
_BUILDERS = {
    "clamav": _build_clamav,
    "exav": _build_exav,
    "jcop": _build_jcop,
}

_cache: dict[str, Scanner] = {}


def get_scanner(name: str) -> Scanner:
    """Return the (cached) scanner for ``name``.

    Raises ``KeyError`` for an unknown name, or ``RuntimeError`` if the backend
    exists but isn't configured (e.g. ``jcop`` without credentials).
    """
    if name not in _cache:
        # KeyError if unknown; may raise RuntimeError if unconfigured.
        _cache[name] = _BUILDERS[name]()
    return _cache[name]


def category_map() -> dict[str, list[str]]:
    """Parse the ``DEFAULT_SCANNERS`` JSON map (``{category: [scanners]}``).

    This is the deployment's composition + availability map: its keys are the
    categories a ``?categories=`` request can select. Read on each call so tests
    can monkeypatch ``settings``. Malformed JSON raises ``RuntimeError``; that is
    caught at boot by :func:`validate_registry` (fail-fast), so request paths can
    assume a well-formed map.
    """
    raw = (settings.default_scanners or "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"DEFAULT_SCANNERS must be JSON {{category: [scanners]}}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError(
            "DEFAULT_SCANNERS must be a JSON object {category: [scanners]}"
        )
    return {str(cat): list(names) for cat, names in data.items()}


def _default_categories() -> list[str]:
    return [c.strip() for c in settings.default_categories.split(",") if c.strip()]


def resolve_scanners(
    categories: list[str] | None = None, scanners: list[str] | None = None
) -> list[str]:
    """Resolve a request's ``categories`` union ``scanners`` into an ordered,
    de-duplicated scanner-name list.

    ``categories`` expand through :func:`category_map`; ``scanners`` are added
    verbatim. When the request names neither, ``DEFAULT_CATEGORIES`` is used.
    Raises ``ValueError`` (→ 400) for an empty selection, an unknown category or
    scanner, or a backend that isn't configured on this deployment.
    """
    cat_map = category_map()
    if not categories and not scanners:
        categories = _default_categories()

    names: list[str] = []
    for cat in categories or []:
        if cat not in cat_map:
            raise ValueError(f"unknown category {cat!r}; available: {sorted(cat_map)}")
        names.extend(cat_map[cat])
    names.extend(scanners or [])

    # De-dup, preserving first-seen order (a scanner may arrive via both paths).
    deduped = list(dict.fromkeys(names))
    if not deduped:
        raise ValueError(
            "no scanners selected (DEFAULT_CATEGORIES / DEFAULT_SCANNERS empty?)"
        )
    for name in deduped:
        if name not in _BUILDERS:
            raise ValueError(
                f"unknown scanner {name!r}; available: {sorted(_BUILDERS)}"
            )
        try:
            get_scanner(name)  # surface an unconfigured backend now, not mid-scan
        except RuntimeError as exc:
            raise ValueError(f"scanner {name!r} is not available: {exc}") from exc
    return deduped


def advisory_scanners() -> frozenset[str]:
    """Engine names from ``ADVISORY_SCANNERS`` (see :class:`ScannerResult`)."""
    raw = settings.advisory_scanners or ""
    return frozenset(n.strip() for n in raw.split(",") if n.strip())


def deciding_scanners(names: list[str]) -> list[str]:
    """The engines that decide a scan by ``names``: the non-advisory ones, or
    all of them when only advisory engines were named (see
    :meth:`ScanReport._deciding`)."""
    advisory = advisory_scanners()
    return [n for n in names if n not in advisory] or list(names)


def assert_size_cap_decidable(names: list[str]) -> None:
    """Refuse a selection clamav would decide on a file it cannot scan in
    full: past CLAMAV_MAX_FILE_BYTES clamd skips the file and reports it
    clean. Boot checks the default selection; this covers a request naming
    clamav alone while it is advisory. Raises ``ValueError`` (→ 400)."""
    if settings.max_url_size > CLAMAV_MAX_FILE_BYTES and "clamav" in deciding_scanners(
        names
    ):
        raise ValueError(
            f"clamav cannot decide a scan with MAX_URL_SIZE above "
            f"{CLAMAV_MAX_FILE_BYTES} bytes: name a deciding engine next to it"
        )


def validate_registry() -> None:
    """Fail-fast boot check of the category configuration (called at startup).

    Ensures ``DEFAULT_SCANNERS`` parses, every listed engine exists, is
    configured, declares the category it is listed under, and that a category
    doesn't mix scored and unscored engines (it must be a single axis type); and
    that every ``DEFAULT_CATEGORIES`` entry is a known category. Raises
    ``RuntimeError``.
    """
    cat_map = category_map()
    for cat, names in cat_map.items():
        if not names:
            raise RuntimeError(f"DEFAULT_SCANNERS[{cat!r}] is empty")
        for name in names:
            if name not in _BUILDERS:
                raise RuntimeError(
                    f"DEFAULT_SCANNERS[{cat!r}] names unknown scanner {name!r}; "
                    f"available: {sorted(_BUILDERS)}"
                )
            try:
                scanner = get_scanner(name)
            except RuntimeError as exc:
                raise RuntimeError(
                    f"scanner {name!r} in DEFAULT_SCANNERS[{cat!r}] "
                    f"is not configured: {exc}"
                ) from exc
            if scanner.category != cat:
                raise RuntimeError(
                    f"scanner {name!r} declares category {scanner.category!r} "
                    f"but is listed under {cat!r} in DEFAULT_SCANNERS"
                )
        # A category is one axis, so its engines must agree on scored-ness —
        # otherwise ScanReport.categories() can't pick a single reduction.
        if len({get_scanner(name).scored for name in names}) > 1:
            raise RuntimeError(
                f"DEFAULT_SCANNERS[{cat!r}] mixes scored and unscored scanners; "
                "a category must be a single axis type"
            )
    for cat in _default_categories():
        if cat not in cat_map:
            raise RuntimeError(
                f"DEFAULT_CATEGORIES names {cat!r}, absent from DEFAULT_SCANNERS "
                f"(configured: {sorted(cat_map)})"
            )
    for name in advisory_scanners():
        if name not in _BUILDERS:
            raise RuntimeError(
                f"ADVISORY_SCANNERS names unknown scanner {name!r}; "
                f"available: {sorted(_BUILDERS)}"
            )
    # clamd cannot scan past CLAMAV_MAX_FILE_BYTES whatever its MaxFileSize
    # says (libclamav clamps it), and skips — reports clean — what it will
    # not scan. Accepting bigger downloads with clamav deciding a category
    # is a silent hole; an advisory clamav defers to the engine that does.
    clamav_decides = any(
        "clamav" in deciding_scanners(names) for names in cat_map.values()
    )
    if settings.max_url_size > CLAMAV_MAX_FILE_BYTES and clamav_decides:
        raise RuntimeError(
            f"MAX_URL_SIZE ({settings.max_url_size}) is above what clamav can "
            f"scan ({CLAMAV_MAX_FILE_BYTES} bytes): lower it, or drop clamav "
            "from DEFAULT_SCANNERS or make it advisory (exav streams any size)"
        )


def run_scanners(names: list[str], open_file, api_client: str = "") -> ScanReport:
    """Run each named scanner **concurrently** and collect a :class:`ScanReport`.

    ``open_file`` is a callable returning a fresh readable file positioned at 0 —
    each scanner gets its own handle (so clamav and exav can stream in parallel).
    ``api_client`` is the calling service (JWT ``iss``), recorded as a metric
    label. A scanner that fails transiently becomes an ``error`` result rather
    than aborting the others. Results keep ``names`` order.
    """

    def _one(name: str) -> ScannerResult:
        scanner = get_scanner(name)
        start = timeit.default_timer()
        score = location = None
        try:
            with contextlib.closing(open_file()) as fh:
                verdict = scanner.scan(fh)
            kind, reason = verdict.kind, verdict.reason
            score, location = verdict.score, verdict.location
        except ScannerError as exc:
            kind, reason = "error", str(exc)
        except Exception as exc:
            # A backend should only ever raise ScannerError; anything else is a
            # bug in it. Isolate it as an error result so one scanner can't 500
            # the request or abort its siblings running in parallel.
            logger.exception("scanner %r crashed", name)
            kind, reason = "error", f"internal error: {exc}"
        result = ScannerResult(
            scanner=name,
            category=scanner.category,
            kind=kind,
            reason=reason,
            score=score,
            location=location,
            time=timeit.default_timer() - start,
            scored=scanner.scored,
            advisory=name in advisory_scanners(),
        )
        metrics.record(result, api_client)
        return result

    if len(names) == 1:
        return ScanReport([_one(names[0])])
    with ThreadPoolExecutor(max_workers=len(names)) as pool:
        return ScanReport(list(pool.map(_one, names)))
