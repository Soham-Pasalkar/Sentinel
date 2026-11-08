"""Audit store and logger tests (C-09): C4.2, C4.5, C4.6, C1.7; D-09, D-11,
D-20, D-24f, D-29; FR-012, SEC-005, SEC-018, NFR-017; I-20 to I-22."""

import inspect
import json
import logging
import os
import sqlite3
import threading
from datetime import UTC, datetime, timedelta, timezone

import pytest

from sentinel import audit as audit_module
from sentinel import store as store_module
from sentinel.audit import (
    DECISION,
    ERROR,
    EVENT_TYPES,
    EXECUTION_STARTED,
    FINDING,
    IDENTITY_RESOLVED,
    MASK,
    OUTPUT_FILTERED,
    OUTPUT_WITHHELD,
    REQUEST_COMPLETED,
    REQUEST_RECEIVED,
    AuditLogger,
)
from sentinel.exceptions import (
    AuditIntegrityError,
    AuditUnavailableError,
    ConfigurationError,
    SentinelError,
)
from sentinel.models import (
    AUDIT_UNAVAILABLE,
    DUPLICATE_TOOL_CALL,
    INVALID_REQUEST,
    TOOL_FAILED,
    UNAUTHORIZED_TOOL,
    Decision,
    Execution,
)
from sentinel.store import COLUMNS, SCHEMA_VERSION, AuditRow, AuditStore

CANARY = "CANARY-8a4e-not-in-audit"
T0 = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


@pytest.fixture
def db(tmp_path):
    return tmp_path / "audit.db"


@pytest.fixture
def store(db):
    s = AuditStore(db)
    yield s
    s.close()


@pytest.fixture
def logger(store):
    return AuditLogger(store, clock=lambda: T0)


def other_connection(db):
    return sqlite3.connect(db)


def row(**overrides):
    fields = {
        "seq": None,
        "event_id": "e-1",
        "request_id": "req-1",
        "event_type": REQUEST_RECEIVED,
        "occurred_at": T0.isoformat(),
        "agent_id": None,
        "session_id": None,
        "tool": None,
        "decision": None,
        "reason": None,
        "policy_version": None,
        "action_digest": None,
        "execution": None,
        "detail": None,
        "schema_version": SCHEMA_VERSION,
    }
    fields.update(overrides)
    return AuditRow(**fields)


# ================================================================ schema


def test_schema_matches_c42_exactly(store, db):
    with other_connection(db) as conn:
        info = list(conn.execute("PRAGMA table_info(audit_events)"))
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        indexes = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert [c[1] for c in info] == list(COLUMNS)
    assert COLUMNS == (
        "seq",
        "event_id",
        "request_id",
        "event_type",
        "occurred_at",
        "agent_id",
        "session_id",
        "tool",
        "decision",
        "reason",
        "policy_version",
        "action_digest",
        "execution",
        "detail",
        "schema_version",
    )
    types = {c[1]: c[2] for c in info}
    assert types["seq"] == "INTEGER" and types["schema_version"] == "INTEGER"
    assert all(
        types[c] == "TEXT" for c in COLUMNS if c not in ("seq", "schema_version")
    )
    notnull = {c[1] for c in info if c[3]}
    assert notnull == {
        "seq",
        "event_id",
        "request_id",
        "event_type",
        "occurred_at",
        "schema_version",
    }
    assert [c[1] for c in info if c[5]] == ["seq"]
    assert tables - {"sqlite_sequence"} == {"audit_events"}  # the only v1 table
    assert "audit_events_request_id" in indexes
    assert version == SCHEMA_VERSION == 1
    with other_connection(db) as conn:
        assert conn.execute("PRAGMA foreign_key_list(audit_events)").fetchall() == []


def test_event_id_is_unique_and_seq_orders_writes(store):
    assert store.insert(row(event_id="a")) == 1
    assert store.insert(row(event_id="b")) == 2
    with pytest.raises(AuditUnavailableError):
        store.insert(row(event_id="a"))
    assert [r.event_id for r in store.read()] == ["a", "b"]


def test_wal_and_synchronous_full(store, db):
    assert store._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert store._conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL
    with other_connection(db) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_existing_compatible_database_reopens_with_rows(db, logger, store):
    logger.record(REQUEST_RECEIVED, request_id="r1")
    store.close()
    with AuditStore(db) as again:
        assert [r.request_id for r in again.read()] == ["r1"]


@pytest.mark.parametrize("version", [0, 2, 99])
def test_unsupported_schema_version_is_refused(db, version):
    AuditStore(db).close()
    with other_connection(db) as conn:
        conn.execute(f"PRAGMA user_version={version}")
    with pytest.raises(ConfigurationError):
        AuditStore(db)


def test_different_columns_are_refused(db):
    with other_connection(db) as conn:
        conn.execute("CREATE TABLE audit_events (seq INTEGER PRIMARY KEY, x TEXT)")
        conn.execute("PRAGMA user_version=1")
    with pytest.raises(ConfigurationError):
        AuditStore(db)


def test_different_columns_with_the_right_index_are_refused(db):
    with other_connection(db) as conn:
        conn.execute(
            "CREATE TABLE audit_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, "
            "request_id TEXT NOT NULL, note TEXT)"
        )
        conn.execute(
            "CREATE INDEX audit_events_request_id ON audit_events (request_id)"
        )
        conn.execute("PRAGMA user_version=1")
    with pytest.raises(ConfigurationError):
        AuditStore(db)


def test_store_refuses_to_run_without_wal(db, monkeypatch):
    real_connect = store_module.sqlite3.connect

    class NoWal:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, *args):
            if sql == "PRAGMA journal_mode=WAL":
                return real_connect(":memory:").execute("SELECT 'delete'")
            return self._conn.execute(sql, *args)

        def close(self):
            self._conn.close()

    monkeypatch.setattr(
        store_module.sqlite3, "connect", lambda *a, **k: NoWal(real_connect(*a, **k))
    )
    with pytest.raises(ConfigurationError):
        AuditStore(db)


def test_missing_index_is_refused(db):
    AuditStore(db).close()
    with other_connection(db) as conn:
        conn.execute("DROP INDEX audit_events_request_id")
    with pytest.raises(ConfigurationError):
        AuditStore(db)


def test_foreign_database_is_refused_not_overwritten(db):
    with other_connection(db) as conn:
        conn.execute("CREATE TABLE other (x TEXT)")
        conn.execute("INSERT INTO other VALUES ('keep')")
        conn.execute("PRAGMA user_version=7")
    with pytest.raises(ConfigurationError):
        AuditStore(db)
    with other_connection(db) as conn:
        assert conn.execute("SELECT x FROM other").fetchall() == [("keep",)]


def test_schema_change_after_opening_refuses_writes(store, db):
    with other_connection(db) as conn:
        conn.execute("PRAGMA user_version=5")
    with pytest.raises(AuditUnavailableError):
        store.insert(row())
    assert store.read() == ()


# ============================================================= durability


def test_committed_row_is_visible_through_a_second_connection(logger, db):
    committed = logger.record(REQUEST_RECEIVED, request_id="req-1", agent_id="a")
    with other_connection(db) as conn:
        rows = conn.execute(
            "SELECT seq, event_id, request_id FROM audit_events"
        ).fetchall()
    assert rows == [(committed.seq, committed.event_id, "req-1")]


def test_each_event_is_its_own_commit(logger, db):
    # From inside a second connection, the first event is visible before the
    # second one is written.
    logger.record(REQUEST_RECEIVED, request_id="r")
    with other_connection(db) as conn:
        assert conn.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 1
    logger.record(IDENTITY_RESOLVED, request_id="r")
    with other_connection(db) as conn:
        assert conn.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 2


def test_record_returns_the_committed_row(logger):
    committed = logger.record(
        DECISION,
        request_id="r",
        agent_id="a",
        session_id="s",
        tool="t",
        decision=Decision.ALLOW,
        reason="ALLOWED",
        policy_version="v1",
        action_digest="d" * 64,
        detail={"finding_codes": []},
    )
    stored = logger.store.read("r")[0]
    assert committed == stored
    assert stored.decision == "allow"
    assert stored.occurred_at == "2026-11-08T12:00:00+00:00"
    assert stored.schema_version == 1
    assert json.loads(stored.detail) == {"finding_codes": []}


# ============================================================ append-only


def test_no_update_or_delete_api():
    for cls in (AuditStore, AuditLogger):
        public = {n for n in dir(cls) if not n.startswith("_")}
        assert not any(
            w in n
            for n in public
            for w in ("update", "delete", "remove", "clear", "truncate", "replace")
        )
    assert {n for n in dir(AuditStore) if not n.startswith("_")} == {
        "insert",
        "read",
        "close",
        "path",
        "durable",
    }


def test_store_executes_only_insert_select_and_setup_sql(db):
    # Trace every statement the real store runs on a fresh database, through
    # inserts and reads: no UPDATE, DELETE, DROP, REPLACE or ALTER ever runs.
    statements = []
    s = AuditStore(db)
    s._conn.set_trace_callback(statements.append)
    logger = AuditLogger(s, clock=lambda: T0)
    for i in range(3):
        logger.record(REQUEST_RECEIVED, request_id=f"r{i}")
    s.read()
    s.read("r1")
    s.close()
    verbs = {stmt.split()[0].upper() for stmt in statements}
    assert verbs <= {"BEGIN", "PRAGMA", "INSERT", "SELECT", "COMMIT"}
    assert not any(
        w in stmt.upper()
        for stmt in statements
        for w in ("UPDATE", "DELETE", "DROP", "REPLACE", "ALTER")
    )


def test_bounded_read_returns_the_first_rows_and_validates_limit(logger):
    # D-17: the limit is part of the query; reconstruction keeps limit=None.
    for i in range(5):
        logger.record(REQUEST_RECEIVED, request_id="r" if i % 2 else "s")
    store = logger.store
    assert [r.seq for r in store.read(limit=2)] == [1, 2]
    assert [r.seq for r in store.read("r", limit=1)] == [2]
    assert len(store.read()) == 5
    for bad in (0, -1, True, 1.5, "2"):
        with pytest.raises(ValueError):
            store.read(limit=bad)


def test_earlier_rows_are_unchanged_by_later_inserts(logger):
    first = logger.record(REQUEST_RECEIVED, request_id="r1", detail={"k": "v"})
    for i in range(20):
        logger.record(REQUEST_RECEIVED, request_id=f"r{i + 2}")
    assert logger.store.read("r1") == (first,)


def test_no_pickle_or_repr_serialization():
    for module in (store_module, audit_module):
        source = inspect.getsource(module)
        assert "pickle" not in source
        assert "repr(" not in source
        assert "default=str" not in source


def test_rows_with_non_c42_types_are_refused(store):
    for bad in (
        row(request_id=None),
        row(event_type=5),
        row(detail={"x": 1}),
        row(schema_version=2),
        row(schema_version="1"),
        row(agent_id=b"a"),
    ):
        with pytest.raises(ValueError):
            store.insert(bad)
    with pytest.raises(TypeError):
        store.insert({"request_id": "r"})
    assert store.read() == ()


# ============================================================= concurrency


def test_eight_concurrent_writers_lose_nothing(logger, db):
    barrier = threading.Barrier(8)
    errors = []

    def writer(n):
        barrier.wait()
        try:
            for i in range(50):
                logger.record(REQUEST_RECEIVED, request_id=f"w{n}-{i}", detail={"i": i})
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(type(exc).__name__)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    with other_connection(db) as conn:
        rows = conn.execute(
            "SELECT seq, event_id, request_id, detail FROM audit_events ORDER BY seq"
        ).fetchall()
    assert len(rows) == 400
    assert [r[0] for r in rows] == list(range(1, 401))
    assert len({r[1] for r in rows}) == 400
    assert {r[2] for r in rows} == {f"w{n}-{i}" for n in range(8) for i in range(50)}
    # per writer, events stay in the order they were written
    for n in range(8):
        own = [json.loads(r[3])["i"] for r in rows if r[2].startswith(f"w{n}-")]
        assert own == list(range(50))


def test_repeated_parallel_runs_are_consistent(tmp_path):
    for trial in range(5):
        with AuditStore(tmp_path / f"t{trial}.db") as s:
            logger = AuditLogger(s, clock=lambda: T0)
            barrier = threading.Barrier(8)

            def writer(n, logger=logger, barrier=barrier):
                barrier.wait()
                for i in range(10):
                    logger.record(FINDING, request_id=f"{n}-{i}")

            threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            rows = s.read()
            assert len(rows) == 80 and len({r.event_id for r in rows}) == 80
            assert s.read() == rows  # deterministic reads


def test_two_stores_on_one_file_follow_sqlite_locking(db):
    with AuditStore(db) as a, AuditStore(db) as b:
        AuditLogger(a, clock=lambda: T0).record(REQUEST_RECEIVED, request_id="from-a")
        AuditLogger(b, clock=lambda: T0).record(REQUEST_RECEIVED, request_id="from-b")
        assert [r.request_id for r in a.read()] == ["from-a", "from-b"]
        assert b.read() == a.read()


# ========================================================== fault injection


def test_locked_database_refuses_the_write(db):
    with AuditStore(db, busy_timeout_seconds=0.05) as s:
        blocker = sqlite3.connect(db, timeout=0)
        blocker.execute("BEGIN IMMEDIATE")
        try:
            with pytest.raises(AuditUnavailableError) as info:
                s.insert(row())
        finally:
            blocker.execute("ROLLBACK")
            blocker.close()
        assert str(info.value) == "audit event could not be committed"
        assert s.read() == ()
        s.insert(row())  # usable again once the lock is gone


def test_closed_store_refuses_reads_and_writes(store):
    store.close()
    store.close()  # idempotent
    with pytest.raises(AuditUnavailableError):
        store.insert(row())
    with pytest.raises(AuditUnavailableError):
        store.read()


def test_write_failure_raises_never_success(store, monkeypatch):
    class Failing:
        in_transaction = False

        def execute(self, sql, *args):
            if sql.startswith("INSERT"):
                raise sqlite3.OperationalError("disk I/O error " + CANARY)
            return store_module.sqlite3.connect(":memory:").execute("SELECT 1")

    monkeypatch.setattr(store, "_conn", Failing())
    with pytest.raises(AuditUnavailableError) as info:
        store.insert(row())
    assert CANARY not in str(info.value) and info.value.__cause__ is None
    assert info.value.__context__ is None or info.value.__suppress_context__


def test_read_failure_raises(store, monkeypatch):
    class Failing:
        def execute(self, *a):
            raise sqlite3.DatabaseError("malformed " + CANARY)

    monkeypatch.setattr(store, "_conn", Failing())
    with pytest.raises(AuditUnavailableError) as info:
        store.read()
    assert CANARY not in str(info.value)


@pytest.mark.parametrize(
    "path",
    ["", "\x00", 5, None, b"audit.db"],
    ids=["empty", "nul", "int", "none", "bytes"],
)
def test_invalid_paths_are_configuration_errors(path):
    with pytest.raises(ConfigurationError):
        AuditStore(path)


def test_connection_failure_is_sanitised(db, monkeypatch):
    def failing(*args, **kwargs):
        raise sqlite3.OperationalError(f"unable to open {CANARY}")

    monkeypatch.setattr(store_module.sqlite3, "connect", failing)
    with pytest.raises(ConfigurationError) as info:
        AuditStore(db)
    assert CANARY not in str(info.value)
    assert info.value.__cause__ is None and info.value.__suppress_context__


def test_missing_directory_is_not_created(tmp_path):
    target = tmp_path / "missing" / "audit.db"
    with pytest.raises(ConfigurationError) as info:
        AuditStore(target)
    assert not target.parent.exists()
    assert str(tmp_path) not in str(info.value)


def test_directory_as_database_path_is_refused(tmp_path):
    with pytest.raises(ConfigurationError):
        AuditStore(tmp_path)


def test_unreadable_file_is_refused_without_leaking_its_path(tmp_path):
    bad = tmp_path / f"{CANARY}.db"
    bad.write_bytes(b"this is not a sqlite database" * 100)
    with pytest.raises(ConfigurationError) as info:
        AuditStore(bad)
    assert CANARY not in str(info.value) and CANARY not in repr(info.value)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_read_only_file_refuses_writes(db):
    AuditStore(db).close()
    os.chmod(db, 0o444)
    try:
        try:
            s = AuditStore(db)
        except ConfigurationError:
            return  # refused at construction: also fail closed
        with s, pytest.raises(AuditUnavailableError):
            s.insert(row())
    finally:
        os.chmod(db, 0o644)


@pytest.mark.parametrize("timeout", [-1, float("nan"), float("inf"), "5", True])
def test_invalid_busy_timeout_is_rejected(db, timeout):
    with pytest.raises(ConfigurationError):
        AuditStore(db, busy_timeout_seconds=timeout)


# ==================================================== logger field rules


@pytest.mark.parametrize(
    "kwargs",
    [
        {"event_type": "TOOL_EXECUTED"},  # rev. 1 name, not in C4.3
        {"event_type": REQUEST_RECEIVED, "request_id": ""},
        {"event_type": REQUEST_RECEIVED, "decision": Decision.ALLOW},
        {"event_type": DECISION},  # needs a decision
        {"event_type": DECISION, "decision": "allow"},  # not the enum
        {"event_type": REQUEST_COMPLETED},  # needs execution
        {"event_type": FINDING, "execution": Execution.SUCCEEDED},
        {"event_type": EXECUTION_STARTED},  # needs action_digest
        {"event_type": ERROR},  # needs an error code
        {
            "event_type": DECISION,
            "decision": Decision.DENY,
            "reason": DUPLICATE_TOOL_CALL,
        },
        {
            "event_type": REQUEST_COMPLETED,
            "decision": Decision.DENY,
            "reason": UNAUTHORIZED_TOOL,
            "execution": Execution.SUCCEEDED,
        },
        {
            "event_type": REQUEST_COMPLETED,
            "decision": None,
            "reason": TOOL_FAILED,
            "execution": Execution.NOT_STARTED,
        },
        {
            "event_type": REQUEST_COMPLETED,
            "decision": None,
            "reason": INVALID_REQUEST,
            "execution": Execution.UNKNOWN,
        },
        {"event_type": REQUEST_RECEIVED, "agent_id": ""},
        {"event_type": REQUEST_RECEIVED, "tool": 5},
        {"event_type": REQUEST_RECEIVED, "detail": ["not", "a", "mapping"]},
    ],
)
def test_events_that_misstate_what_happened_are_refused(logger, kwargs):
    kwargs.setdefault("request_id", "r")
    event_type = kwargs.pop("event_type")
    with pytest.raises((ValueError, TypeError)):
        logger.record(event_type, **kwargs)
    assert logger.store.read() == ()


def test_every_c43_event_type_can_be_recorded(logger):
    digest = "d" * 64
    logger.record(REQUEST_RECEIVED, request_id="r", detail={"arguments": {"q": 1}})
    logger.record(IDENTITY_RESOLVED, request_id="r", detail={"authorized": True})
    logger.record(FINDING, request_id="r", detail={"code": "X", "severity": 1})
    logger.record(
        DECISION,
        request_id="r",
        decision=Decision.ALLOW,
        reason="ALLOWED",
        action_digest=digest,
    )
    logger.record(EXECUTION_STARTED, request_id="r", action_digest=digest)
    logger.record(OUTPUT_FILTERED, request_id="r")
    logger.record(OUTPUT_WITHHELD, request_id="r2")
    logger.record(ERROR, request_id="r", reason=TOOL_FAILED, detail={"stage": "tool"})
    logger.record(
        REQUEST_COMPLETED,
        request_id="r",
        decision=Decision.ALLOW,
        reason="ALLOWED",
        action_digest=digest,
        execution=Execution.SUCCEEDED,
    )
    assert {r.event_type for r in logger.store.read()} == EVENT_TYPES


def test_operational_refusal_and_audit_unavailable_keep_their_meaning(logger):
    logger.record(
        REQUEST_COMPLETED,
        request_id="r",
        decision=None,
        reason=DUPLICATE_TOOL_CALL,
        execution=Execution.NOT_STARTED,
    )
    logger.record(
        REQUEST_COMPLETED,
        request_id="r2",
        decision=Decision.ALLOW,
        reason=AUDIT_UNAVAILABLE,
        execution=Execution.SUCCEEDED,
    )
    rows = logger.store.read()
    assert (rows[0].decision, rows[0].reason) == (None, DUPLICATE_TOOL_CALL)
    assert (rows[1].decision, rows[1].execution) == ("allow", "succeeded")


@pytest.mark.parametrize(
    "clock",
    [
        lambda: datetime(2026, 1, 1),
        lambda: datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=1))),
        lambda: "now",
    ],
)
def test_clock_must_be_utc(store, clock):
    with pytest.raises(ValueError):
        AuditLogger(store, clock=clock).record(REQUEST_RECEIVED, request_id="r")
    assert store.read() == ()


def test_detail_is_masked_and_truncated_before_storage(logger, db):
    logger.record(
        REQUEST_RECEIVED,
        request_id="r",
        detail={
            "arguments": {
                "password": CANARY,
                "note": "x" * 5000,
                "q": f"Bearer {CANARY}",
            }
        },
    )
    with other_connection(db) as conn:
        stored = conn.execute("SELECT detail FROM audit_events").fetchone()[0]
    assert CANARY not in stored
    detail = json.loads(stored)
    assert detail["arguments"]["password"] == MASK
    assert len(detail["arguments"]["note"]) == 1024
    assert detail["arguments"]["q"] == MASK


def test_detail_with_non_json_values_is_refused(logger):
    for bad in ({"x": object()}, {"x": {1, 2}}, {"x": float("nan")}, {1: "x"}):
        with pytest.raises(ValueError):
            logger.record(REQUEST_RECEIVED, request_id="r", detail=bad)
    assert logger.store.read() == ()


# ===================================================== failure fallback


def test_failed_write_logs_masked_fallback_and_raises(logger, caplog):
    logger.store.close()
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        with pytest.raises(AuditUnavailableError) as info:
            logger.record(
                REQUEST_COMPLETED,
                request_id="req-9",
                decision=Decision.ALLOW,
                reason=AUDIT_UNAVAILABLE,
                execution=Execution.SUCCEEDED,
                detail={"token": CANARY, "output": f"ghp_{'a' * 30}"},
            )
    assert info.value.error_code == AUDIT_UNAVAILABLE
    records = [r for r in caplog.records if r.name == "sentinel.audit"]
    assert len(records) == 1
    text = records[0].getMessage()
    assert "req-9" in text and "REQUEST_COMPLETED" in text and "succeeded" in text
    assert CANARY not in text and "ghp_" not in text


def test_fallback_failure_never_hides_the_audit_error(logger, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("logging is down")

    monkeypatch.setattr(audit_module._LOG, "warning", broken)
    logger.store.close()
    with pytest.raises(AuditUnavailableError):
        logger.record(REQUEST_RECEIVED, request_id="r")


def test_audit_exceptions_are_sentinel_errors():
    assert issubclass(AuditUnavailableError, SentinelError)
    assert issubclass(AuditIntegrityError, SentinelError)
    assert issubclass(AuditIntegrityError, ValueError)
    assert AuditUnavailableError.error_code == "AUDIT_UNAVAILABLE"


def test_no_configuration_enables_exception_message_storage():
    # AT-33: no option stores message text in v1.
    for cls in (AuditStore, AuditLogger):
        params = set(inspect.signature(cls).parameters)
        assert not any(
            w in p for p in params for w in ("message", "traceback", "verbose", "debug")
        )
