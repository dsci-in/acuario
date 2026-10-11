"""Tests for non-destructive same-locus finding de-duplication."""

from __future__ import annotations

from acuario.scanner.dedup import annotate_duplicate_loci, primaries
from acuario.scanner.state import Finding


def _f(**kw) -> Finding:
    kw.setdefault("id", "x")
    kw.setdefault("file", "api/app/identity.py")
    kw.setdefault("line_number", 39)
    kw.setdefault("finding_type", "auth_bypass")
    kw.setdefault("severity", "critical")
    kw.setdefault("evidence_level", "suspicion")
    kw.setdefault("description", "d")
    return Finding(**kw)


def test_same_locus_collapses_to_one_primary():
    fs = [
        _f(id="a", finding_type="auth_bypass"),
        _f(id="b", finding_type="broken_authentication"),
        _f(id="c", finding_type="auth_bypass", primitive_type="unknown"),
    ]
    dups = annotate_duplicate_loci(fs)
    assert dups == 2
    prim = primaries(fs)
    assert len(prim) == 1
    # every non-primary points at the single primary, and all ids survive
    p = prim[0]
    assert {f["id"] for f in fs} == {"a", "b", "c"}
    for f in fs:
        if f is not p:
            assert f["duplicate_of"] == p["id"]
    assert set(p["alias_ids"]) == {"a", "b", "c"} - {p["id"]}


def test_primary_is_highest_evidence_then_exploited():
    fs = [
        _f(id="weak", evidence_level="suspicion"),
        _f(id="strong", evidence_level="exploit_demonstrated", exploit_success=True),
        _f(id="mid", evidence_level="static_corroboration"),
    ]
    annotate_duplicate_loci(fs)
    p = primaries(fs)
    assert len(p) == 1
    assert p[0]["id"] == "strong"  # exploited/demonstrated is never hidden


def test_guard_keeps_distinct_primitives_separate():
    fs = [
        _f(id="sqli", finding_type="sql_injection", primitive_type="sql_injection"),
        _f(id="authz", finding_type="auth_bypass", primitive_type="auth_bypass"),
    ]
    dups = annotate_duplicate_loci(fs)
    # two genuinely different bugs on one line -> both stay primary
    assert dups == 0
    assert len(primaries(fs)) == 2


def test_unknown_primitive_merges_with_one_real_primitive():
    fs = [
        _f(id="real", primitive_type="auth_bypass"),
        _f(id="unk", primitive_type="unknown"),
    ]
    annotate_duplicate_loci(fs)
    assert len(primaries(fs)) == 1


def test_no_line_number_is_never_deduped():
    fs = [
        _f(id="a", line_number=None),
        _f(id="b", line_number=None),
    ]
    dups = annotate_duplicate_loci(fs)
    assert dups == 0
    assert len(primaries(fs)) == 2


def test_different_loci_are_independent():
    fs = [
        _f(id="a", line_number=39),
        _f(id="b", line_number=40),
    ]
    assert annotate_duplicate_loci(fs) == 0
    assert len(primaries(fs)) == 2


def test_idempotent():
    fs = [_f(id="a"), _f(id="b"), _f(id="c")]
    first = annotate_duplicate_loci(fs)
    second = annotate_duplicate_loci(fs)
    assert first == second == 2
    assert len(primaries(fs)) == 1
