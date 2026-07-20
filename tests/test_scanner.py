"""Scanner core: category/scanner resolution, report aggregation, host pools,
parallel execution, and the clamd backend's verdict translation."""

import io
from unittest import mock

import clamd
import pytest

import scanner as scanner_mod
from scanner import (
    ScannerError,
    ScannerResult,
    ScanReport,
    Verdict,
    category_map,
    resolve_scanners,
    run_scanners,
    validate_registry,
)
from scanners.clamav import (
    ClamavScanner,
    parse_hosts,
    parse_local_version,
    parse_remote_version,
)
from scanners.exav import ExavScanner, unscannable_tag


def _malware(scanner, kind, reason=None, **kw):
    """ScannerResult in the malware category (the default axis in tests)."""
    return ScannerResult(scanner, "malware", kind, reason, **kw)


def test_parse_local_version():
    assert (
        parse_local_version("ClamAV 0.100.2/12321/Fri May 31 07:57:34 2019") == "12321"
    )


def test_parse_remote_version():
    assert (
        parse_remote_version("220.101.2:58:remote:1559294940:1:63:48725:32823")
        == "remote"
    )


# --- resolve_scanners: categories union scanners ---


def test_resolve_default_uses_default_categories():
    # DEFAULT_CATEGORIES=malware, DEFAULT_SCANNERS={"malware": ["clamav"]}.
    assert resolve_scanners() == ["clamav"]


def test_resolve_by_category():
    assert resolve_scanners(categories=["malware"]) == ["clamav"]


def test_resolve_by_scanner():
    assert resolve_scanners(scanners=["clamav"]) == ["clamav"]


def test_resolve_unions_and_dedups():
    # The category expands to clamav; naming clamav again must not duplicate it.
    assert resolve_scanners(categories=["malware"], scanners=["clamav"]) == ["clamav"]


def test_resolve_rejects_unknown_category():
    with pytest.raises(ValueError, match="unknown category"):
        resolve_scanners(categories=["nsfw"])


@pytest.mark.parametrize("requested", [["bogus"], ["jcop"]])
def test_resolve_rejects_bad_scanner(requested):
    # "bogus" is unknown; "jcop" is known but unconfigured under the test config.
    with pytest.raises(ValueError):
        resolve_scanners(scanners=requested)


def test_category_map_parses_json(monkeypatch):
    monkeypatch.setattr(
        scanner_mod.settings, "default_scanners", '{"malware": ["clamav", "exav"]}'
    )
    assert category_map() == {"malware": ["clamav", "exav"]}


# --- validate_registry (boot fail-fast) ---


def test_validate_registry_ok():
    validate_registry()  # the test config is consistent


def test_validate_registry_rejects_unknown_scanner(monkeypatch):
    monkeypatch.setattr(
        scanner_mod.settings, "default_scanners", '{"malware": ["bogus"]}'
    )
    with pytest.raises(RuntimeError, match="unknown scanner"):
        validate_registry()


def test_validate_registry_rejects_category_mismatch(monkeypatch):
    # clamav declares category "malware"; listing it under "nsfw" is a misconfig.
    monkeypatch.setattr(
        scanner_mod.settings, "default_scanners", '{"nsfw": ["clamav"]}'
    )
    with pytest.raises(RuntimeError, match="declares category"):
        validate_registry()


def test_validate_registry_rejects_default_category_not_in_map(monkeypatch):
    monkeypatch.setattr(scanner_mod.settings, "default_categories", "nsfw")
    with pytest.raises(RuntimeError, match="DEFAULT_CATEGORIES"):
        validate_registry()


class _ScoredScanner:
    category = "malware"
    scored = True

    def ping(self):
        return True

    def scan(self, fileobj):
        return Verdict("clean", score=0.0)


def test_validate_registry_rejects_mixed_scored_in_a_category(monkeypatch):
    # A category is one axis, so it can't mix a scored and an unscored engine.
    monkeypatch.setitem(scanner_mod._BUILDERS, "scored", _ScoredScanner)
    monkeypatch.setitem(scanner_mod._cache, "scored", _ScoredScanner())
    monkeypatch.setattr(
        scanner_mod.settings, "default_scanners", '{"malware": ["clamav", "scored"]}'
    )
    with pytest.raises(RuntimeError, match="mixes scored"):
        validate_registry()


# --- ScanReport strict aggregation + per-category reduction ---


def test_report_malware_wins():
    report = ScanReport([_malware("clamav", "clean"), _malware("jcop", "malware", "X")])
    assert report.malware
    assert not report.all_errored
    assert report.categories() == {"malware": True}


def test_report_all_errored():
    report = ScanReport(
        [_malware("clamav", "error", "boom"), _malware("jcop", "error", "x")]
    )
    assert report.all_errored


def test_report_partial_error_is_not_all_errored():
    report = ScanReport(
        [_malware("clamav", "clean"), _malware("jcop", "error", "boom")]
    )
    assert not report.all_errored
    assert not report.malware


def test_report_partial_error_axis_is_unknown():
    # One scanner clean, one errored → the axis can't be asserted clean, so the
    # aggregate is None (unknown) rather than a falsely-clean False.
    report = ScanReport(
        [_malware("clamav", "clean"), _malware("jcop", "error", "boom")]
    )
    assert report.categories() == {"malware": None}
    assert report.as_dict()["malware"] is None


def test_report_as_dict_omits_null_reason():
    d = ScanReport([_malware("clamav", "clean", None, time=0.01)]).as_dict()
    assert d["malware"] is False
    assert "reason" not in d["scanners"][0]
    assert d["scanners"][0]["scanner"] == "clamav"
    assert d["scanners"][0]["category"] == "malware"


# --- per-category aggregation across axes ---


def test_report_scored_axis_reduces_by_max():
    report = ScanReport(
        [
            _malware("clamav", "clean"),
            ScannerResult("nudenet", "nsfw", "flagged", "porn", score=0.9, scored=True),
            ScannerResult("othernsfw", "nsfw", "clean", score=0.4, scored=True),
        ]
    )
    d = report.as_dict()
    assert d["malware"] is False
    assert d["nsfw"] == 0.9  # max across the nsfw axis
    assert d["scanners"][1]["score"] == 0.9


def test_report_scored_axis_null_when_no_score():
    # An nsfw scanner that errored contributes no score → axis is null, not 0.0.
    report = ScanReport(
        [ScannerResult("nudenet", "nsfw", "error", "boom", scored=True)]
    )
    assert report.as_dict()["nsfw"] is None


# --- ClamavScanner: raw INSTREAM reply -> Verdict ---


def _clamd_scan(status, reason):
    sc = ClamavScanner()
    cd = mock.MagicMock()
    cd.instream.return_value = {"stream": (status, reason)}
    with mock.patch.object(sc, "_client", return_value=cd):
        return sc.scan(b"data")


def test_clamd_clean():
    assert _clamd_scan("OK", None).kind == "clean"


def test_clamd_malware():
    v = _clamd_scan("FOUND", "Eicar-Test-Signature")
    assert v.malware
    assert v.reason == "Eicar-Test-Signature"


def test_clamav_error_tag_not_preserved():
    # Stock clamd never emits exav's structured tags, so the base — which knows
    # nothing about them — surfaces a generic UNSCANNABLE.
    v = _clamd_scan("ERROR", "PASSWORD-PROTECTED")
    assert v.kind == "unscannable"
    assert v.reason == "UNSCANNABLE"


@pytest.mark.parametrize("reason", ["Encrypted.PDF", "Broken archive"])
def test_clamd_untagged_error_is_unscannable(reason):
    v = _clamd_scan("ERROR", reason)
    assert v.kind == "unscannable"
    assert v.reason == "UNSCANNABLE"


@pytest.mark.parametrize(
    "reason",
    [
        "Can't allocate memory",
        "Time limit reached",
        "No space left on device",
        "TIMEOUT",
    ],
)
def test_clamd_transient_error_raises(reason):
    with pytest.raises(ScannerError):
        _clamd_scan("ERROR", reason)


def test_clamd_connection_error_raises_scanner_error():
    sc = ClamavScanner()
    cd = mock.MagicMock()
    cd.instream.side_effect = clamd.ConnectionError("down")
    with mock.patch.object(sc, "_client", return_value=cd):
        with pytest.raises(ScannerError):
            sc.scan(b"data")


# --- host pools + backends ---


def test_parse_hosts():
    assert parse_hosts("a:3310, b:3311 ,c") == [("a", 3310), ("b", 3311), ("c", 3310)]


def test_clamav_hosts_balances_per_scan(monkeypatch):
    monkeypatch.setattr(scanner_mod.settings, "clamav_hosts", "h1:3310,h2:3311")
    sc = ClamavScanner()
    _, hosts = sc._endpoints()
    assert set(hosts) == {("h1", 3310), ("h2", 3311)}


def test_exav_requires_hosts(monkeypatch):
    monkeypatch.setattr(scanner_mod.settings, "exav_hosts", "")
    with pytest.raises(RuntimeError):
        ExavScanner()


def test_exav_uses_its_own_pool_and_skips_version(monkeypatch):
    monkeypatch.setattr(scanner_mod.settings, "exav_hosts", "exav1:3310")
    sc = ExavScanner()
    assert isinstance(sc, ClamavScanner)  # reuses INSTREAM / verdict handling
    assert sc._endpoints() == (None, [("exav1", 3310)])
    assert sc.version() is None


@pytest.mark.parametrize(
    "tag", ["LIMITS-EXCEEDED", "UNSCANNABLE", "PASSWORD-PROTECTED"]
)
def test_exav_error_tag_is_unscannable(monkeypatch, tag):
    # exav (unlike the base) recognises its structured tags and preserves them.
    monkeypatch.setattr(scanner_mod.settings, "exav_hosts", "exav1:3310")
    v = ExavScanner()._error_verdict(tag)
    assert v.kind == "unscannable"
    assert v.reason == tag


def test_exav_transient_tag_still_retries(monkeypatch):
    # A bare transient token is infra, not a file tag → falls back to a retry.
    monkeypatch.setattr(scanner_mod.settings, "exav_hosts", "exav1:3310")
    with pytest.raises(ScannerError):
        ExavScanner()._error_verdict("TIMEOUT")


def test_resolve_accepts_configured_exav(monkeypatch):
    monkeypatch.setattr(scanner_mod.settings, "exav_hosts", "exav1:3310")
    scanner_mod._cache.pop("exav", None)
    try:
        assert resolve_scanners(scanners=["clamav", "exav"]) == ["clamav", "exav"]
    finally:
        scanner_mod._cache.pop("exav", None)


# --- parallel run_scanners ---


class _FakeScanner:
    category = "malware"
    scored = False

    def scan(self, fileobj):
        assert fileobj.read() == b"payload"  # each scanner gets its own handle at 0
        return Verdict("clean")


def test_run_scanners_runs_each_on_its_own_handle(monkeypatch):
    monkeypatch.setitem(scanner_mod._cache, "a", _FakeScanner())
    monkeypatch.setitem(scanner_mod._cache, "b", _FakeScanner())
    monkeypatch.setitem(scanner_mod._BUILDERS, "a", _FakeScanner)
    monkeypatch.setitem(scanner_mod._BUILDERS, "b", _FakeScanner)

    report = run_scanners(["a", "b"], lambda: io.BytesIO(b"payload"))
    assert [r.scanner for r in report.results] == ["a", "b"]  # order preserved
    assert all(r.kind == "clean" for r in report.results)


class _CrashScanner:
    category = "malware"
    scored = False

    def scan(self, fileobj):
        raise ValueError("boom")  # a backend bug — NOT a ScannerError


def test_run_scanners_isolates_a_backend_crash(monkeypatch):
    # A backend raising something other than ScannerError becomes an error
    # result, not a 500 that aborts its siblings.
    monkeypatch.setitem(scanner_mod._cache, "crash", _CrashScanner())
    monkeypatch.setitem(scanner_mod._BUILDERS, "crash", _CrashScanner)
    monkeypatch.setitem(scanner_mod._cache, "ok", _FakeScanner())
    monkeypatch.setitem(scanner_mod._BUILDERS, "ok", _FakeScanner)

    report = run_scanners(["crash", "ok"], lambda: io.BytesIO(b"payload"))
    crash, ok = report.results
    assert crash.kind == "error"
    assert "internal error" in crash.reason
    assert ok.kind == "clean"  # sibling still ran


# --- unscannable_tag ---


@pytest.mark.parametrize(
    "reason,expected",
    [
        ("LIMITS-EXCEEDED", "LIMITS-EXCEEDED"),
        ("UNSCANNABLE", "UNSCANNABLE"),
        ("TRUNCATED-STREAM", "TRUNCATED-STREAM"),  # future exav code, surfaced verbatim
        ("TIMEOUT", None),  # bare transient token is not a tag
        ("Can't allocate memory", None),
        ("Encrypted.PDF", None),
        ("", None),
        (None, None),
    ],
)
def test_unscannable_tag(reason, expected):
    assert unscannable_tag(reason) == expected
