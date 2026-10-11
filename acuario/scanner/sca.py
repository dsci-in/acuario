"""Software Composition Analysis - flag known-vulnerable dependencies.

The analyzer reads code, not manifests, so vulnerable dependencies can be
reasoned about with the correct CVEs but never emitted as findings. This
module closes that gap deterministically: parse the npm dependency manifests
+ lockfiles, match resolved versions against a bundled offline advisory
snapshot, and emit one finding per (package, advisory).

Routing (see runner): SCA findings are added to the verified set directly,
bypassing the skeptic / debate / validator. A dependency finding has no in-code
trace, so feeding it through the LLM gates would mass-refute it and corrupt the
sound refute statistics - the whole point is a separate deterministic stream.

False-positive discipline: a finding is emitted ONLY when an EXACT resolved
version is known (from a lockfile, or an exact pin in package.json) and it falls
inside an advisory's vulnerable range. Loose semver ranges without a lockfile
are skipped, never guessed - a false "you are vulnerable" is worse than a miss.

The advisory set is a curated OFFLINE seed of common high-profile npm CVEs.
It is meant to be expanded; there is no network fetch.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path

from acuario.findings.types import Finding

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Advisory:
    """One known-vulnerable version range for an npm package.

    Vulnerable iff ``introduced <= version < fixed`` (semver-core compare).
    """

    package: str
    fixed: str
    cve: str
    cwe: str
    severity: str
    summary: str
    introduced: str = "0.0.0"


# Curated offline seed. Expand as needed - there is no network advisory fetch.
_NPM_ADVISORIES: tuple[Advisory, ...] = (
    # The four packages (the recall gap this closes).
    Advisory("marked", "4.0.10", "CVE-2022-21681", "CWE-1333", "high", "ReDoS in inline parsing"),
    Advisory("marked", "4.0.10", "CVE-2022-21680", "CWE-1333", "high", "ReDoS in block parsing"),
    Advisory(
        "lodash", "4.17.21", "CVE-2021-23337", "CWE-77", "high", "Command injection via template"
    ),
    Advisory("lodash", "4.17.21", "CVE-2020-28500", "CWE-1333", "medium", "ReDoS in toNumber/trim"),
    Advisory("axios", "0.21.2", "CVE-2021-3749", "CWE-400", "high", "ReDoS via trim regex"),
    Advisory(
        "axios",
        "1.6.0",
        "CVE-2023-45857",
        "CWE-200",
        "medium",
        "Leaks XSRF-TOKEN to third-party host on redirect",
        introduced="0.8.1",
    ),
    Advisory(
        "node-fetch",
        "2.6.7",
        "CVE-2022-0235",
        "CWE-200",
        "high",
        "Exposes sensitive headers/cookie on cross-site redirect",
    ),
    Advisory(
        "node-fetch",
        "2.6.1",
        "CVE-2020-15168",
        "CWE-770",
        "medium",
        "No size limit on response body (DoS)",
    ),
    # Common high-profile npm CVEs (breadth beyond the audit set).
    Advisory("minimist", "1.2.6", "CVE-2021-44906", "CWE-1321", "high", "Prototype pollution"),
    Advisory("ejs", "3.1.7", "CVE-2022-29078", "CWE-94", "critical", "Template injection -> RCE"),
    Advisory(
        "glob-parent", "5.1.2", "CVE-2020-28469", "CWE-400", "high", "ReDoS in enclosure regex"
    ),
    Advisory(
        "json5", "2.2.2", "CVE-2022-46175", "CWE-1321", "high", "Prototype pollution via parse"
    ),
    Advisory(
        "semver",
        "7.5.2",
        "CVE-2022-25883",
        "CWE-1333",
        "high",
        "ReDoS in range parsing",
        introduced="7.0.0",
    ),
    Advisory(
        "qs",
        "6.5.3",
        "CVE-2022-24999",
        "CWE-1321",
        "high",
        "Prototype pollution / DoS via __proto__",
        introduced="6.5.0",
    ),
    Advisory(
        "follow-redirects",
        "1.14.8",
        "CVE-2022-0536",
        "CWE-200",
        "medium",
        "Leaks Authorization header on cross-domain redirect",
    ),
)

_ADVISORY_INDEX: dict[str, list[Advisory]] = {}
for _adv in _NPM_ADVISORIES:
    _ADVISORY_INDEX.setdefault(_adv.package, []).append(_adv)

_SKIP_DIRS = frozenset({".git", "node_modules", "vendor", "dist", "build", ".venv", "venv"})


def _version_core(v: str) -> tuple[int, int, int]:
    """Numeric major.minor.patch core of a semver string.

    Ignores prerelease / build metadata (a first-cut simplification): '1.2.7',
    'v1.2.7', '=1.2.7', '1.2.7-beta.1' all reduce to (1, 2, 7).
    """
    s = v.strip().lstrip("vV=")
    core = re.split(r"[-+]", s, maxsplit=1)[0]
    nums: list[int] = []
    for part in core.split(".")[:3]:
        m = re.match(r"\d+", part)
        nums.append(int(m.group()) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2])


def _in_range(version: str, introduced: str, fixed: str) -> bool:
    return _version_core(introduced) <= _version_core(version) < _version_core(fixed)


_EXACT_RE = re.compile(r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.\-]+)?$")


def _exact_version(spec: str) -> str | None:
    """Return the exact version if *spec* is a clean pin, else None.

    A range (^1.2.7, ~1.2.7, >=1, 1.x, *, '1 || 2', 'git+...', 'file:...') is
    NOT exact - we skip it rather than risk a false positive when no lockfile
    resolved the actually-installed version.
    """
    s = spec.strip().lstrip("vV=")
    return s if _EXACT_RE.match(s) else None


def _resolved_versions(manifest_dir: Path) -> set[tuple[str, str]]:
    """Best available exact (name, version) pairs for a package.json directory.

    Prefers package-lock.json (resolved, includes transitive + multiple
    versions); adds exact pins declared in package.json. Ranges without a
    lockfile entry are omitted (see _exact_version).
    """
    pairs: set[tuple[str, str]] = set()

    pkg = manifest_dir / "package.json"
    try:
        data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, ValueError):
        data = {}
    if isinstance(data, dict):
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, spec in (data.get(section) or {}).items():
                exact = _exact_version(str(spec))
                if exact:
                    pairs.add((name, exact))

    lock = manifest_dir / "package-lock.json"
    if lock.exists():
        try:
            lock_data = json.loads(lock.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, ValueError):
            lock_data = {}
        if isinstance(lock_data, dict):
            # npm v2/v3: "packages" keyed by "node_modules/<name>".
            for key, meta in (lock_data.get("packages") or {}).items():
                if not key or not isinstance(meta, dict):
                    continue
                name = key.rsplit("node_modules/", 1)[-1]
                ver = meta.get("version")
                if name and ver:
                    pairs.add((name, str(ver)))
            # npm v1: "dependencies" keyed by name.
            for name, meta in (lock_data.get("dependencies") or {}).items():
                if isinstance(meta, dict) and meta.get("version"):
                    pairs.add((name, str(meta["version"])))

    return pairs


def _dep_line_number(pkg_path: Path, name: str) -> int | None:
    """Best-effort line of a dependency's declaration in package.json."""
    try:
        text = pkg_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    for i, line in enumerate(text.splitlines(), 1):
        if f'"{name}"' in line:
            return i
    return None


def scan_dependencies(repo_path: str) -> list[Finding]:
    """Return vulnerable_dependency findings for every package.json in the tree.

    Deterministic: no LLM, no network. Skips node_modules/vendor/build.
    """
    findings: list[Finding] = []
    root = Path(repo_path)
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        if "package.json" not in filenames:
            continue
        pkg_path = Path(dirpath) / "package.json"
        rel = Path(os.path.relpath(pkg_path, root)).as_posix()
        for name, version in sorted(_resolved_versions(Path(dirpath))):
            for adv in _ADVISORY_INDEX.get(name, ()):
                if not _in_range(version, adv.introduced, adv.fixed):
                    continue
                findings.append(
                    Finding(
                        id=f"sca-{uuid.uuid4().hex[:8]}",
                        file=rel,
                        line_number=_dep_line_number(pkg_path, name),
                        finding_type="vulnerable_dependency",
                        cwe=adv.cwe,
                        severity=adv.severity,  # type: ignore[arg-type]
                        confidence="high",
                        description=(
                            f"{name}@{version} is affected by {adv.cve}: {adv.summary} "
                            f"(fixed in {adv.fixed}). Declared in {rel}."
                        ),
                        code_snippet=f'"{name}": "{version}"',
                        evidence_level="static_corroboration",
                        discovered_by="sca",
                        related_cve=adv.cve,
                    )
                )
    if findings:
        logger.info("[sca] matched %d vulnerable dependency finding(s)", len(findings))
    return findings
