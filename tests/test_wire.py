"""API wire formats: the v1 downgrade of a canonical (v2) payload."""

import pytest

import wire


def _v2(kind, category="malware", **rest):
    return {
        "job_id": "j1",
        "status": "done",
        "verdicts": {category: {"kind": kind, **rest}},
        "scanners": [{"scanner": "clamav", "category": category, "kind": kind}],
    }


@pytest.mark.parametrize(
    "kind,scalar",
    [("clean", False), ("malware", True), ("partial", None), ("error", None)],
)
def test_the_discrete_scalar_follows_the_verdict(kind, scalar):
    assert wire.to_v1(_v2(kind))["malware"] is scalar


def test_the_verdicts_key_never_reaches_a_v1_caller():
    """v1 is the shape that existed before verdicts. Leaving the key in would
    make the two views drift in the caller's hands, not just on the wire."""
    out = wire.to_v1(_v2("clean"))
    assert "verdicts" not in out
    assert out["scanners"] == _v2("clean")["scanners"]  # the breakdown is untouched


def test_an_unreadable_file_is_a_permanent_error_kind():
    """``partial`` is the file's own fault and no retry changes it: the word a
    v1 caller has for that is ``error_kind: file`` beside a null scalar."""
    out = wire.to_v1(_v2("partial", reason="UNSCANNABLE"))
    assert out["malware"] is None
    assert out["error_kind"] == "file"
    assert out["error"] == "UNSCANNABLE"


def test_a_failed_engine_is_a_retryable_error_kind():
    out = wire.to_v1(_v2("error", reason="boom"))
    assert out["malware"] is None
    assert out["error_kind"] == "transient"


def test_a_clean_verdict_carries_no_error_kind():
    """A residual kind beside a clean scalar would say the axis has no answer
    when it has one."""
    out = wire.to_v1(_v2("clean"))
    assert "error_kind" not in out and "error" not in out


def test_the_job_envelope_outranks_the_derived_pair():
    """A pre-scan failure classified itself — it knows more than a verdict
    reduced after the fact, so it is never overwritten."""
    payload = {**_v2("error", reason="engines down"), "error_kind": "file"}
    assert wire.to_v1(payload)["error_kind"] == "file"


def test_a_flagged_hit_reaches_a_v1_caller_as_a_detection():
    """v1 has no word for a content-policy hit. Blocking it while mislabelling
    it is the lesser evil: reporting ``False`` would unlock the download."""
    assert wire.to_v1(_v2("flagged", reason="nsfw"))["malware"] is True


def test_a_scored_axis_reports_its_score_not_a_boolean():
    payload = _v2("flagged", category="nsfw", reason="porn", score=0.9)
    assert wire.to_v1(payload)["nsfw"] == 0.9


def test_a_scored_clean_axis_reports_the_highest_score_seen():
    payload = _v2("clean", category="nsfw", score=0.4)
    assert wire.to_v1(payload)["nsfw"] == 0.4


def test_a_word_this_version_does_not_know_has_no_answer():
    """A verdict added after v1 was frozen cannot be expressed in it. ``None``
    is the honest answer — and the one a v1 caller must not read as clean."""
    assert wire.to_v1(_v2("quarantined"))["malware"] is None


def test_a_payload_without_verdicts_passes_through():
    """A pending seed, or a pre-scan failure that never reached a scanner, is
    already v1-shaped."""
    seed = {"job_id": "j1", "status": "pending", "filename": "f.bin"}
    assert wire.to_v1(seed) == seed


def test_every_category_gets_its_own_scalar():
    payload = {
        "verdicts": {
            "malware": {"kind": "clean"},
            "nsfw": {"kind": "flagged", "score": 0.7},
        }
    }
    out = wire.to_v1(payload)
    assert out["malware"] is False and out["nsfw"] == 0.7


def test_the_error_pair_describes_the_malware_axis():
    """``error_kind`` is a single key for the whole response, so with several
    axes it can only speak for one — the one any v1 caller reads."""
    payload = {
        "verdicts": {
            "malware": {"kind": "partial", "reason": "UNSCANNABLE"},
            "nsfw": {"kind": "error", "reason": "boom"},
        }
    }
    assert wire.to_v1(payload)["error_kind"] == "file"


def test_serialize_keeps_the_canonical_shape_but_stamps_it():
    payload = _v2("clean")
    out = wire.serialize(payload, wire.V2)
    assert out["verdicts"] == payload["verdicts"]
    assert out["api_version"] == wire.V2
    assert "api_version" not in payload  # the caller's dict is left alone


def test_serialize_stamps_a_downgraded_body_with_the_version_it_is_in():
    """The shape and the stamp must agree, or the stamp is worse than nothing."""
    out = wire.serialize(_v2("clean"), wire.V1)
    assert out["api_version"] == wire.V1
    assert "verdicts" not in out and out["malware"] is False


def test_the_stamp_is_what_a_receiver_compares_against_its_own_setting():
    """A caller builds its request path from a version string. The stamp uses
    that same spelling so the comparison needs no translation."""
    assert wire.V1 == "v1.0" and wire.V2 == "v2.0"
    assert wire.of_path(f"/api/{wire.V2}/scan-async") == wire.V2


@pytest.mark.parametrize(
    "path,version",
    [
        ("/api/v1.0/scan", wire.V1),
        ("/api/v2.0/scan", wire.V2),
        ("/api/v1.0/jobs/abc", wire.V1),
        ("/metrics", wire.V2),
    ],
)
def test_the_path_prefix_picks_the_version(path, version):
    assert wire.of_path(path) == version
