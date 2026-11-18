"""The quickstart runs as documented (C-12 acceptance; FR-023).

It runs in a separate process from an empty working directory, using the
installed package (``pip install -e .``). FR-023: it must demonstrate an
allowed call, path-traversal, ungranted-tool and unknown-agent denials, an
approval-required call, and print audit rows; only the allowed call may
execute. It must leave no file behind, in the working directory, the
repository or the temporary directory it uses.
"""

import os
import subprocess
import sys
from pathlib import Path

QUICKSTART = Path(__file__).resolve().parents[2] / "examples" / "quickstart.py"
REPO = QUICKSTART.parents[1]

RR, IR, DEC, ES, OF, RC = (
    "REQUEST_RECEIVED",
    "IDENTITY_RESOLVED",
    "DECISION",
    "EXECUTION_STARTED",
    "OUTPUT_FILTERED",
    "REQUEST_COMPLETED",
)


def _denied(label, tool, decision, reason):
    return [
        f"{label}: {tool} decision={decision} reason={reason} "
        "execution=not_started output=None",
        f"  audit: {RR}",
        f"  audit: {IR}",
        f"  audit: {DEC} decision={decision} reason={reason}",
        f"  audit: {RC} decision={decision} reason={reason} execution=not_started",
    ]


EXPECTED = [
    "allow: add decision=allow reason=ALLOWED execution=succeeded output=5",
    f"  audit: {RR}",
    f"  audit: {IR}",
    f"  audit: {DEC} decision=allow reason=ALLOWED",
    f"  audit: {ES}",
    f"  audit: {OF}",
    f"  audit: {RC} decision=allow reason=ALLOWED execution=succeeded",
    *_denied("traversal", "read_file", "deny", "RESTRICTED_PATH"),
    *_denied("ungranted", "subtract", "deny", "UNAUTHORIZED_TOOL"),
    *_denied("unknown agent", "add", "deny", "UNAUTHORIZED_AGENT"),
    *_denied("approval", "delete_note", "require_approval", "DESTRUCTIVE_TOOL"),
    "calls: add=1 subtract=0 read_file=0 delete_note=0",
]


def _run(tmp_path):
    workdir = tmp_path / "cwd"
    tempdir = tmp_path / "tmp"
    workdir.mkdir()
    tempdir.mkdir()
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["TMPDIR"] = str(tempdir)  # tempfile uses it: cleanup is observable
    result = subprocess.run(  # noqa: S603 - fixed: this interpreter, the repo quickstart
        [sys.executable, str(QUICKSTART)],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return result, workdir, tempdir


def test_quickstart_demonstrates_every_fr023_scenario(tmp_path):
    before = {p.name for p in REPO.iterdir()}
    result, workdir, tempdir = _run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert result.stdout.splitlines() == EXPECTED
    assert list(workdir.iterdir()) == []  # no database in the working directory
    assert list(tempdir.iterdir()) == []  # workspace and database removed
    assert {p.name for p in REPO.iterdir()} == before  # nor in the repository


def test_only_the_allowed_call_executes(tmp_path):
    # Read from the tools' own counters: the allowed call ran exactly once,
    # and the traversal, ungranted, unknown-agent and approval-required calls
    # never entered their tool.
    result, _, _ = _run(tmp_path)
    assert result.returncode == 0, result.stderr
    (calls,) = [
        line for line in result.stdout.splitlines() if line.startswith("calls:")
    ]
    counts = dict(item.split("=") for item in calls.removeprefix("calls: ").split())
    assert counts == {"add": "1", "subtract": "0", "read_file": "0", "delete_note": "0"}
    results = {
        line.split(":")[0]: line
        for line in result.stdout.splitlines()
        if not line.startswith(("  ", "calls:"))
    }
    assert set(results) == {
        "allow",
        "traversal",
        "ungranted",
        "unknown agent",
        "approval",
    }
    for label, line in results.items():
        executed = "execution=succeeded" in line
        assert executed is (label == "allow"), line
    # Every request printed its audit rows, ending with REQUEST_COMPLETED.
    audit = [line for line in result.stdout.splitlines() if line.startswith("  ")]
    assert sum(RC in line for line in audit) == 5
    assert "secret" not in result.stdout  # the outside file was never read


def test_quickstart_uses_only_the_public_api():
    source = QUICKSTART.read_text()
    imports = [
        line for line in source.splitlines() if line.startswith(("import ", "from "))
    ]
    sentinel_imports = [line for line in imports if "sentinel" in line]
    assert sentinel_imports == [
        "from sentinel import SecurityPolicy, SentinelClient, SentinelConfig, ToolGrant"
    ]
