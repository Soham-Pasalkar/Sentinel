"""Default audit storage (C-09): FR-024, C4.5, D-11.

Every test runs in a temporary working directory, so the repository is never
touched.
"""

import logging
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel.audit import REQUEST_RECEIVED, AuditLogger
from sentinel.store import DEFAULT_AUDIT_DB_PATH, MEMORY, AuditStore

T0 = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
SRC = str(Path(__file__).resolve().parents[2] / "src")


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return Path.cwd()


def test_default_is_a_durable_file_in_the_working_directory(workdir, caplog):
    assert DEFAULT_AUDIT_DB_PATH == "sentinel_audit.db"
    with caplog.at_level(logging.INFO, logger="sentinel.store"):
        store = AuditStore()
    expected = workdir / "sentinel_audit.db"
    try:
        assert store.path == str(expected) and os.path.isabs(store.path)
        assert store.durable is True
        assert expected.is_file()  # created at construction
        assert any(str(expected) in r.getMessage() for r in caplog.records)
        assert not any(r.levelno >= logging.WARNING for r in caplog.records)
    finally:
        store.close()


def test_path_is_resolved_at_construction(workdir, tmp_path, monkeypatch):
    store = AuditStore("audit.db")
    try:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        AuditLogger(store, clock=lambda: T0).record(REQUEST_RECEIVED, request_id="r")
        assert store.path == str(workdir / "audit.db")
        assert not (elsewhere / "audit.db").exists()
    finally:
        store.close()


def test_importing_creates_no_database(workdir):
    env = {**os.environ, "PYTHONPATH": SRC}
    subprocess.run(
        [sys.executable, "-c", "import sentinel.store, sentinel.audit, sentinel.proxy"],
        cwd=workdir,
        env=env,
        check=True,
    )
    assert list(workdir.iterdir()) == []


def test_rows_survive_closing_and_reopening(workdir):
    with AuditStore() as store:
        AuditLogger(store, clock=lambda: T0).record(REQUEST_RECEIVED, request_id="kept")
    with AuditStore() as again:
        assert [r.request_id for r in again.read()] == ["kept"]


def test_memory_is_explicit_warned_and_not_durable(workdir, caplog):
    with caplog.at_level(logging.WARNING, logger="sentinel.store"):
        store = AuditStore(MEMORY)
    try:
        assert store.path == ":memory:" and store.durable is False
        assert any("memory" in r.getMessage() for r in caplog.records)
        AuditLogger(store, clock=lambda: T0).record(REQUEST_RECEIVED, request_id="r")
        assert len(store.read()) == 1
        assert list(workdir.iterdir()) == []  # no file
    finally:
        store.close()


def test_memory_records_do_not_survive(workdir):
    with AuditStore(MEMORY) as store:
        AuditLogger(store, clock=lambda: T0).record(REQUEST_RECEIVED, request_id="r")
    with AuditStore(MEMORY) as fresh:
        assert fresh.read() == ()


def test_default_path_never_in_memory():
    import inspect

    default = inspect.signature(AuditStore).parameters["path"].default
    assert default == "sentinel_audit.db" != MEMORY
