"""Enforce the NFR-006 branch-coverage thresholds from coverage.py JSON output.

Usage (after ``coverage run -m pytest`` and ``coverage json``)::

    python scripts/check_coverage.py coverage.json

Thresholds (NFR-006, approved by the owner 2026-11-18): branch coverage of at
least 90% for each of ``policy.py``, ``proxy.py``, ``pipeline.py``,
``paths.py``, ``audit.py`` and ``store.py``, measured per file, and at least
85% over every production module under ``src/sentinel``.

Branch coverage is ``covered_branches / num_branches`` (branch arcs), not
coverage.py's combined line-and-branch percentage. Comparisons use integers,
so a value exactly at a threshold passes and nothing is rounded up.

Exit status: 0 when every threshold is met; 1 when a threshold is missed or
a production module is absent from the data; 2 when the input is unusable
(missing or malformed file, or not measured with branch coverage).

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = REPO / "src" / "sentinel"

#: Per-module minimum branch coverage, in percent (NFR-006).
MODULE_THRESHOLDS: dict[str, int] = {
    "audit.py": 90,
    "paths.py": 90,
    "pipeline.py": 90,
    "policy.py": 90,
    "proxy.py": 90,
    "store.py": 90,
}
#: Minimum branch coverage over every production module, in percent.
OVERALL_THRESHOLD = 85


class InputError(Exception):
    """The coverage data cannot be used."""


@dataclass(frozen=True)
class ModuleBranches:
    """Branch counts for one production module."""

    name: str
    covered: int
    total: int

    @property
    def percent(self) -> float:
        """Branch coverage in percent (100.0 when there are no branches)."""
        return 100.0 if self.total == 0 else 100.0 * self.covered / self.total


def meets(covered: int, total: int, threshold: int) -> bool:
    """Whether ``covered / total`` is at least ``threshold`` percent, exactly."""
    return covered * 100 >= threshold * total


def production_modules(source: Path) -> list[str]:
    """Every ``.py`` file under ``source``, as POSIX paths relative to it."""
    if not source.is_dir():
        raise InputError(f"source directory not found: {source}")
    return sorted(p.relative_to(source).as_posix() for p in source.rglob("*.py"))


def load(path: Path) -> dict:
    """Read coverage.py JSON and check that branch coverage was measured."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise InputError(f"coverage data not found: {path}") from None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise InputError(f"coverage data is not readable JSON: {path}") from None
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        raise InputError("coverage data has no 'files' table")
    meta = data.get("meta")
    if not isinstance(meta, dict) or meta.get("branch_coverage") is not True:
        raise InputError("coverage data was not measured with branch coverage")
    return data


def collect(data: dict, modules: list[str], package: str) -> dict[str, ModuleBranches]:
    """Branch counts per production module; absent modules are left out."""
    found: dict[str, ModuleBranches] = {}
    for key, entry in data["files"].items():
        posix = Path(key).as_posix()
        marker = f"{package}/"
        if marker not in posix:
            continue
        name = posix.rsplit(marker, 1)[1]
        if name not in modules:
            continue
        summary = entry.get("summary") if isinstance(entry, dict) else None
        try:
            covered = summary["covered_branches"]
            total = summary["num_branches"]
        except (TypeError, KeyError):
            raise InputError(f"no branch counts for {name}") from None
        if (
            type(covered) is not int
            or type(total) is not int
            or not 0 <= covered <= total
        ):
            raise InputError(f"invalid branch counts for {name}")
        if name in found:
            raise InputError(f"{name} appears more than once in the data")
        found[name] = ModuleBranches(name, covered, total)
    return found


def check(
    data: dict,
    modules: list[str],
    *,
    package: str = "sentinel",
    thresholds: dict[str, int] = MODULE_THRESHOLDS,
    overall: int = OVERALL_THRESHOLD,
) -> tuple[list[str], list[str]]:
    """Return (report lines, failure lines). No failures means success."""
    found = collect(data, modules, package)
    lines: list[str] = []
    failures: list[str] = []

    missing = [m for m in modules if m not in found]
    for name in missing:
        failures.append(f"{name}: not measured (absent from the coverage data)")
    for name in thresholds:
        if name not in modules:
            failures.append(f"{name}: thresholded module not found in the source")

    lines.append(f"{'module':<24}{'branches':>12}{'coverage':>10}  threshold")
    for name in modules:
        if name not in found:
            continue
        m = found[name]
        limit = thresholds.get(name)
        status = ""
        if limit is not None:
            if m.total == 0:
                status = f">= {limit}%  FAIL (no branches measured)"
                failures.append(f"{name}: no branches measured")
            elif meets(m.covered, m.total, limit):
                status = f">= {limit}%  ok"
            else:
                status = f">= {limit}%  FAIL"
                failures.append(
                    f"{name}: {m.percent:.2f}% branch coverage "
                    f"({m.covered}/{m.total}) is below {limit}%"
                )
        lines.append(
            f"{name:<24}{f'{m.covered}/{m.total}':>12}{m.percent:>9.2f}%  {status}"
        )

    covered = sum(m.covered for m in found.values())
    total = sum(m.total for m in found.values())
    if total == 0:
        failures.append("overall: no branches measured")
        lines.append("overall: no branches measured")
    else:
        percent = 100.0 * covered / total
        ok = meets(covered, total, overall)
        lines.append(
            f"{'OVERALL':<24}{f'{covered}/{total}':>12}{percent:>9.2f}%  "
            f">= {overall}%  {'ok' if ok else 'FAIL'}"
        )
        if not ok:
            failures.append(
                f"overall: {percent:.2f}% branch coverage ({covered}/{total}) "
                f"is below {overall}%"
            )
    return lines, failures


def main(argv: list[str] | None = None) -> int:
    """Run the check; print a table and any failures; return the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("coverage_json", type=Path, help="coverage.py JSON report")
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help="production package directory (default: src/sentinel)",
    )
    args = parser.parse_args(argv)
    try:
        data = load(args.coverage_json)
        modules = production_modules(args.source)
        lines, failures = check(data, modules, package=args.source.name)
    except InputError as exc:
        print(f"coverage check: error: {exc}", file=sys.stderr)
        return 2
    print("\n".join(lines))
    if failures:
        print("\ncoverage check FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("\ncoverage check passed (NFR-006 branch coverage)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
