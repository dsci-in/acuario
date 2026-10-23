"""The canonical-findings helper: the single source of truth for excluding
variant_loop seeds so inspect / eval / report / history agree on counts."""

from __future__ import annotations

from acuario.findings.types import canonical_findings, is_canonical


def test_is_canonical_drops_variant_loop_only():
    assert is_canonical({"id": "a", "discovered_by": "analyzer:unconstrained"})
    assert is_canonical({"id": "b", "discovered_by": "critic"})
    assert is_canonical({"id": "c"})  # no discovered_by -> canonical
    assert not is_canonical({"id": "d", "discovered_by": "variant_loop"})


def test_canonical_findings_filters_list():
    findings = [
        {"id": "a", "discovered_by": "analyzer:unconstrained"},
        {"id": "b", "discovered_by": "variant_loop"},
        {"id": "c", "discovered_by": "source_analyzer"},
        {"id": "d", "discovered_by": "variant_loop"},
    ]
    kept = canonical_findings(findings)
    assert [f["id"] for f in kept] == ["a", "c"]


def test_is_canonical_accepts_object_with_attr():
    class _F:
        discovered_by = "variant_loop"

    assert not is_canonical(_F())

    class _G:
        discovered_by = "critic"

    assert is_canonical(_G())
