"""Tests for the native PDF audit report."""

from __future__ import annotations

from pathlib import Path

from acuario.scanner.dedup import annotate_duplicate_loci
from acuario.scanner.pdf_report import render_pdf
from acuario.scanner.reporter import write_scanner_report
from acuario.scanner.state import Finding


def _f(**kw) -> Finding:
    kw.setdefault("id", "x")
    kw.setdefault("file", "app/a.py")
    kw.setdefault("line_number", 1)
    kw.setdefault("finding_type", "sql_injection")
    kw.setdefault("severity", "critical")
    kw.setdefault("evidence_level", "exploit_demonstrated")
    kw.setdefault("description", "A SQL injection in the search handler.")
    kw.setdefault("cwe", "CWE-89")
    return Finding(**kw)


def _is_pdf(path: Path) -> bool:
    data = path.read_bytes()
    return data[:5] == b"%PDF-" and b"%%EOF" in data[-2048:]


def test_render_pdf_produces_valid_pdf(tmp_path: Path):
    out = tmp_path / "report.pdf"
    findings = [
        _f(id="a", line_number=1, severity="critical"),
        _f(id="b", line_number=2, severity="high", code_snippet="x = eval(req.body)\n" * 3),
        _f(id="c", line_number=3, severity="medium"),
    ]
    render_pdf(
        str(out),
        session_id="audit-test",
        repo_url="/repo",
        findings=findings,
        verified_findings=findings,
        cost_summary={"is_self_hosted": True, "total_cost_usd": 0.0},
        duration_seconds=123.0,
        lab_stats={"skeptic_accepted": 3},
    )
    assert out.exists() and _is_pdf(out)


def test_render_pdf_handles_empty_findings(tmp_path: Path):
    out = tmp_path / "empty.pdf"
    render_pdf(str(out), session_id="s", repo_url="/r", findings=[], verified_findings=[])
    assert out.exists() and _is_pdf(out)


def test_render_pdf_survives_long_code_and_markup_chars(tmp_path: Path):
    # Long lines must soft-wrap; <, >, & must not break the paragraph markup.
    out = tmp_path / "edge.pdf"
    findings = [
        _f(
            id="a",
            description="uses <script> & compares a < b > c in the sink",
            code_snippet="q = 'SELECT * FROM t WHERE x=' + " + "a" * 400,
        )
    ]
    render_pdf(
        str(out), session_id="s", repo_url="/r", findings=findings, verified_findings=findings
    )
    assert out.exists() and _is_pdf(out)


def test_write_scanner_report_emits_pdf_when_requested(tmp_path: Path):
    findings = [_f(id="a", line_number=1), _f(id="b", line_number=2, severity="high")]
    paths = write_scanner_report(
        output_dir=str(tmp_path),
        session_id="sess",
        repo_url="/repo",
        findings=findings,
        verified_findings=findings,
        spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
        formats=["pdf"],
    )
    assert "pdf" in paths
    assert Path(paths["pdf"]).name == "report.pdf"
    assert _is_pdf(Path(paths["pdf"]))


def test_pdf_included_in_all_formats(tmp_path: Path):
    paths = write_scanner_report(
        output_dir=str(tmp_path),
        session_id="sess2",
        repo_url="/repo",
        findings=[_f(id="a")],
        verified_findings=[_f(id="a")],
        spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
        formats=["all"],
    )
    assert {"sarif", "markdown", "json", "pdf"} <= set(paths)


def test_render_pdf_folds_duplicates(tmp_path: Path):
    # Two findings at one locus -> one primary; the PDF must still build.
    out = tmp_path / "dup.pdf"
    findings = [_f(id="a", line_number=5), _f(id="b", line_number=5, finding_type="auth_bypass")]
    annotate_duplicate_loci(findings)
    assert sum(1 for f in findings if not f.get("duplicate_of")) == 1
    render_pdf(
        str(out), session_id="s", repo_url="/r", findings=findings, verified_findings=findings
    )
    assert out.exists() and _is_pdf(out)
