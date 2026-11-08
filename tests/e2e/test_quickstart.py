"""The quickstart runs as documented (C-12 acceptance).

It runs in a separate process from an empty working directory, using the
installed package (``pip install -e .``), and must leave no file behind.
"""

import os
import subprocess
import sys
from pathlib import Path

QUICKSTART = Path(__file__).resolve().parents[2] / "examples" / "quickstart.py"
REPO = QUICKSTART.parents[1]


def test_quickstart_runs_and_leaves_no_database(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    before = {p.name for p in REPO.iterdir()}
    result = subprocess.run(  # noqa: S603 - fixed: this interpreter, the repo quickstart
        [sys.executable, str(QUICKSTART)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    lines = result.stdout.splitlines()
    assert lines == [
        "add:      decision=allow execution=succeeded output=5",
        "subtract: decision=deny reason=UNAUTHORIZED_TOOL execution=not_started",
        "audit:    REQUEST_RECEIVED > IDENTITY_RESOLVED > DECISION > "
        "EXECUTION_STARTED > OUTPUT_FILTERED > REQUEST_COMPLETED",
    ]
    assert list(tmp_path.iterdir()) == []  # no database in the working directory
    assert {p.name for p in REPO.iterdir()} == before  # nor in the repository


def test_quickstart_uses_only_the_public_api():
    source = QUICKSTART.read_text()
    imports = [
        line for line in source.splitlines() if line.startswith(("import ", "from "))
    ]
    sentinel_imports = [line for line in imports if "sentinel" in line]
    assert sentinel_imports == [
        "from sentinel import SecurityPolicy, SentinelClient, SentinelConfig, ToolGrant"
    ]
