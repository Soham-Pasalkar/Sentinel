"""The NFR-006 coverage checker (``scripts/check_coverage.py``).

The checker gates CI, so it is tested like security code: synthetic
coverage.py JSON with known branch counts, including exact boundaries,
missing modules, data without branch coverage, and malformed input.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_coverage.py"
_spec = importlib.util.spec_from_file_location("check_coverage", SCRIPT)
cc = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("check_coverage", cc)  # dataclasses resolve their module
_spec.loader.exec_module(cc)

GUARDED = sorted(cc.MODULE_THRESHOLDS)


def make_source(tmp_path, names=(*GUARDED, "client.py", "__init__.py")):
    source = tmp_path / "src" / "sentinel"
    source.mkdir(parents=True)
    for name in names:
        (source / name).write_text("")
    return source


def coverage_data(counts, *, branch=True, prefix="src/sentinel/"):
    """counts: {module: (covered, total)} -> coverage.py JSON structure."""
    return {
        "meta": {"version": "7.17.3", "branch_coverage": branch},
        "files": {
            f"{prefix}{name}": {"summary": {"covered_branches": c, "num_branches": t}}
            for name, (c, t) in counts.items()
        },
    }


def all_full(extra=None):
    counts = {name: (10, 10) for name in GUARDED}
    counts["client.py"] = (10, 10)
    counts["__init__.py"] = (0, 0)
    counts.update(extra or {})
    return counts


def run(tmp_path, data, source=None, capsys=None):
    source = source or make_source(tmp_path)
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(data))
    return cc.main([str(path), "--source", str(source)])


def test_project_thresholds_are_the_approved_ones():
    assert cc.MODULE_THRESHOLDS == {
        "policy.py": 90,
        "proxy.py": 90,
        "pipeline.py": 90,
        "paths.py": 90,
        "audit.py": 90,
        "store.py": 90,
        "detector.py": 90,  # C-13, OD-9 (owner 2026-11-18)
    }
    assert cc.OVERALL_THRESHOLD == 85


def test_full_coverage_passes(tmp_path, capsys):
    assert run(tmp_path, coverage_data(all_full())) == 0
    out = capsys.readouterr().out
    assert "coverage check passed" in out
    for name in GUARDED:
        assert name in out


def test_exactly_at_the_module_threshold_passes(tmp_path):
    assert run(tmp_path, coverage_data(all_full({"proxy.py": (90, 100)}))) == 0


@pytest.mark.parametrize("module", GUARDED)
def test_each_guarded_module_is_enforced_independently(tmp_path, capsys, module):
    # 8999/10000 = 89.99%: below 90% by less than a rounding step.
    data = coverage_data(all_full({module: (8999, 10000)}))
    assert run(tmp_path, data) == 1
    err = capsys.readouterr().err
    assert f"{module}: 89.99% branch coverage (8999/10000) is below 90%" in err


def test_overall_threshold_counts_every_production_module(tmp_path, capsys):
    # Guarded modules all pass, but an unguarded module drags the total down.
    data = coverage_data(all_full({"client.py": (0, 100)}))
    assert run(tmp_path, data) == 1
    assert "overall:" in capsys.readouterr().err


def test_overall_exactly_at_threshold_passes(tmp_path):
    counts = {name: (9, 10) for name in GUARDED}  # 54/60
    counts["client.py"] = (31, 40)  # total 85/100
    counts["__init__.py"] = (0, 0)
    assert run(tmp_path, coverage_data(counts)) == 0


def test_an_unmeasured_production_module_fails(tmp_path, capsys):
    counts = all_full()
    del counts["client.py"]
    assert run(tmp_path, coverage_data(counts)) == 1
    assert "client.py: not measured" in capsys.readouterr().err


def test_a_missing_guarded_module_fails(tmp_path, capsys):
    counts = all_full()
    del counts["pipeline.py"]
    assert run(tmp_path, coverage_data(counts)) == 1
    assert "pipeline.py: not measured" in capsys.readouterr().err


def test_a_guarded_module_missing_from_the_source_fails(tmp_path, capsys):
    source = make_source(tmp_path, names=("client.py", "policy.py"))
    data = coverage_data({"client.py": (1, 1), "policy.py": (1, 1)})
    assert run(tmp_path, data, source=source) == 1
    assert "proxy.py: thresholded module not found" in capsys.readouterr().err


def test_a_guarded_module_without_branches_fails(tmp_path, capsys):
    assert run(tmp_path, coverage_data(all_full({"store.py": (0, 0)}))) == 1
    assert "store.py: no branches measured" in capsys.readouterr().err


def test_line_only_data_is_refused(tmp_path, capsys):
    assert run(tmp_path, coverage_data(all_full(), branch=False)) == 2
    assert "not measured with branch coverage" in capsys.readouterr().err


def test_absolute_file_keys_are_matched(tmp_path):
    data = coverage_data(all_full(), prefix="/home/runner/work/x/src/sentinel/")
    assert run(tmp_path, data) == 0


def test_files_outside_the_package_are_ignored(tmp_path):
    data = coverage_data(all_full())
    data["files"]["tests/test_x.py"] = {
        "summary": {"covered_branches": 0, "num_branches": 50}
    }
    assert run(tmp_path, data) == 0


@pytest.mark.parametrize(
    "summary",
    [
        {},
        {"covered_branches": 5},
        {"covered_branches": 11, "num_branches": 10},
        {"covered_branches": -1, "num_branches": 10},
        {"covered_branches": 5.0, "num_branches": 10},
        {"covered_branches": True, "num_branches": 10},
    ],
)
def test_invalid_branch_counts_are_input_errors(tmp_path, capsys, summary):
    data = coverage_data(all_full())
    data["files"]["src/sentinel/policy.py"]["summary"] = summary
    assert run(tmp_path, data) == 2
    assert "policy.py" in capsys.readouterr().err


@pytest.mark.parametrize(
    "content", ["", "not json", "[]", '{"meta": {"branch_coverage": true}}']
)
def test_malformed_input_is_an_input_error(tmp_path, content):
    source = make_source(tmp_path)
    path = tmp_path / "coverage.json"
    path.write_text(content)
    assert cc.main([str(path), "--source", str(source)]) == 2


def test_missing_input_file_is_an_input_error(tmp_path):
    source = make_source(tmp_path)
    assert cc.main([str(tmp_path / "absent.json"), "--source", str(source)]) == 2


def test_missing_source_directory_is_an_input_error(tmp_path):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(coverage_data(all_full())))
    assert cc.main([str(path), "--source", str(tmp_path / "nope")]) == 2


def test_the_real_source_tree_has_every_guarded_module():
    modules = cc.production_modules(cc.DEFAULT_SOURCE)
    assert set(cc.MODULE_THRESHOLDS) <= set(modules)
    assert "client.py" in modules and "__init__.py" in modules
