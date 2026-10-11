"""C1: SCA vulnerable-dependency scan.

Guards the recall win (four packages now emit findings) AND
the false-positive discipline (exact versions only; ranges without a lockfile
are skipped; patched versions are not flagged).
"""

from __future__ import annotations

import json
from pathlib import Path

from acuario.scanner.sca import (
    _exact_version,
    _in_range,
    _version_core,
    scan_dependencies,
)


def _write(dir_path: Path, deps: dict, lock: dict | None = None) -> None:
    (dir_path / "package.json").write_text(json.dumps({"dependencies": deps}))
    if lock is not None:
        (dir_path / "package-lock.json").write_text(json.dumps(lock))


# --- version helpers --------------------------------------------------------


def test_version_core_parsing():
    assert _version_core("1.2.7") == (1, 2, 7)
    assert _version_core("v1.2.7") == (1, 2, 7)
    assert _version_core("=1.2.7") == (1, 2, 7)
    assert _version_core("1.2.7-beta.1") == (1, 2, 7)
    assert _version_core("2") == (2, 0, 0)


def test_in_range_boundaries():
    # vulnerable below fixed, safe at/above fixed
    assert _in_range("4.17.20", "0.0.0", "4.17.21") is True
    assert _in_range("4.17.21", "0.0.0", "4.17.21") is False  # fixed version is safe
    assert _in_range("4.18.0", "0.0.0", "4.17.21") is False
    # introduced lower bound is inclusive
    assert _in_range("0.7.0", "0.8.1", "1.6.0") is False
    assert _in_range("0.8.1", "0.8.1", "1.6.0") is True


def test_exact_version_accepts_pins_rejects_ranges():
    assert _exact_version("1.2.7") == "1.2.7"
    assert _exact_version("=1.2.7") == "1.2.7"
    assert _exact_version("1.2.7-beta") == "1.2.7-beta"
    for rng in ("^1.2.7", "~1.2.7", ">=1.0.0", "1.x", "*", "1 || 2", "git+https://x", "file:../p"):
        assert _exact_version(rng) is None, rng


# --- scan -------------------------------------------------------------------


def test_four_audit_packages_flagged(tmp_path):
    _write(
        tmp_path,
        {"marked": "1.2.7", "lodash": "4.17.20", "axios": "0.21.1", "node-fetch": "2.6.0"},
    )
    cves = {f.get("related_cve") for f in scan_dependencies(str(tmp_path))}
    # At least the headline CVE for each of the four is present.
    assert {"CVE-2022-21681", "CVE-2021-23337", "CVE-2021-3749", "CVE-2022-0235"} <= cves


def test_findings_are_static_corroboration_vuln_dependency(tmp_path):
    _write(tmp_path, {"marked": "1.2.7"})
    fs = scan_dependencies(str(tmp_path))
    assert fs
    for f in fs:
        assert f.get("finding_type") == "vulnerable_dependency"
        # Must be a VALID evidence_level or the adversarial_threshold gate prunes it.
        assert f.get("evidence_level") == "static_corroboration"
        assert f.get("discovered_by") == "sca"
        assert f.get("file") == "package.json"


def test_patched_version_not_flagged(tmp_path):
    _write(tmp_path, {"lodash": "4.17.21"})  # fixed version
    assert scan_dependencies(str(tmp_path)) == []


def test_range_without_lockfile_is_skipped(tmp_path):
    # FP discipline: a caret/tilde range without a lockfile is NOT guessed.
    _write(tmp_path, {"marked": "^1.2.7"})
    assert scan_dependencies(str(tmp_path)) == []


def test_lockfile_resolves_a_range(tmp_path):
    # package.json declares a range; the lockfile pins the vulnerable version.
    _write(
        tmp_path,
        {"marked": "^1.2.0"},
        lock={
            "lockfileVersion": 3,
            "packages": {"": {}, "node_modules/marked": {"version": "1.2.7"}},
        },
    )
    cves = {f.get("related_cve") for f in scan_dependencies(str(tmp_path))}
    assert "CVE-2022-21681" in cves


def test_node_modules_is_not_walked(tmp_path):
    # A vulnerable package.json buried in node_modules must not be scanned as a
    # target manifest (only the resolved deps of a real manifest are checked).
    _write(tmp_path, {"react": "18.2.0"})  # clean root manifest
    nm = tmp_path / "node_modules" / "evil"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text(json.dumps({"dependencies": {"marked": "1.2.7"}}))
    assert scan_dependencies(str(tmp_path)) == []


def test_unknown_package_produces_nothing(tmp_path):
    _write(tmp_path, {"react": "18.2.0", "react-dom": "18.2.0"})
    assert scan_dependencies(str(tmp_path)) == []
