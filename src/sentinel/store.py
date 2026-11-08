"""Audit store: the append-only ``audit_events`` table in SQLite (C-09).

Implements decision record C4.2 (schema), C4.5 (storage defaults) and C4.6
(limits) with D-09, D-11 and D-20 (audit writes), using the standard-library
``sqlite3`` module (NFR-002; no SQLAlchemy).

* One table, ``audit_events``, exactly as C4.2, with an index on
  ``request_id``. No foreign keys.
* Schema version (interpretation I-20): ``PRAGMA user_version`` = 1 plus the
  per-row ``schema_version`` column. A database with another version, or
  with different columns, is refused at construction (``ConfigurationError``)
  and every insert re-checks the version inside its transaction.
* ``journal_mode=WAL`` and ``synchronous=FULL``: an insert is committed, and
  durable as far as the filesystem honours ``fsync``, when ``insert`` returns.
* Insert and read only: there is no update or delete API (SEC-018).
  Append-only through Sentinel's API only; anyone with write access to the
  file can change it (C4.6 item 1). Not tamper-proof.
* Serialized writes: one connection per store, used under one lock, so
  inserts from many threads are consistent (D-20). Multi-process use relies
  only on SQLite's own file locking; it is not coordinated or supported
  (C4.6 item 3).
* The default path ``sentinel_audit.db`` is resolved to an absolute path at
  construction and logged at INFO; nothing happens at import. ``":memory:"``
  is accepted only explicitly, logs a WARNING and reports ``durable=False``.

Errors are fixed text: no SQL, file path or value (SEC-008). This module is
internal.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path

from sentinel.exceptions import AuditUnavailableError, ConfigurationError

__all__ = [
    "COLUMNS",
    "DEFAULT_AUDIT_DB_PATH",
    "MEMORY",
    "SCHEMA_VERSION",
    "AuditRow",
    "AuditStore",
]

_LOG = logging.getLogger(__name__)

DEFAULT_AUDIT_DB_PATH = "sentinel_audit.db"
MEMORY = ":memory:"
SCHEMA_VERSION = 1

#: C4.2 columns in order: (name, SQL type, NOT NULL).
_SCHEMA = (
    ("seq", "INTEGER", True),
    ("event_id", "TEXT", True),
    ("request_id", "TEXT", True),
    ("event_type", "TEXT", True),
    ("occurred_at", "TEXT", True),
    ("agent_id", "TEXT", False),
    ("session_id", "TEXT", False),
    ("tool", "TEXT", False),
    ("decision", "TEXT", False),
    ("reason", "TEXT", False),
    ("policy_version", "TEXT", False),
    ("action_digest", "TEXT", False),
    ("execution", "TEXT", False),
    ("detail", "TEXT", False),
    ("schema_version", "INTEGER", True),
)
COLUMNS = tuple(name for name, _, _ in _SCHEMA)

_CREATE_TABLE = """
CREATE TABLE audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    event_id TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    agent_id TEXT,
    session_id TEXT,
    tool TEXT,
    decision TEXT,
    reason TEXT,
    policy_version TEXT,
    action_digest TEXT,
    execution TEXT,
    detail TEXT,
    schema_version INTEGER NOT NULL
)
"""
_CREATE_INDEX = "CREATE INDEX audit_events_request_id ON audit_events (request_id)"
_INSERT = (
    f"INSERT INTO audit_events ({', '.join(COLUMNS[1:])}) "  # noqa: S608 - constant
    f"VALUES ({', '.join('?' for _ in COLUMNS[1:])})"
)
_SELECT = f"SELECT {', '.join(COLUMNS)} FROM audit_events"  # noqa: S608 - constant


@dataclass(frozen=True, slots=True)
class AuditRow:
    """One ``audit_events`` row (C4.2). ``detail`` is the stored JSON text."""

    seq: int | None
    event_id: str
    request_id: str
    event_type: str
    occurred_at: str
    agent_id: str | None
    session_id: str | None
    tool: str | None
    decision: str | None
    reason: str | None
    policy_version: str | None
    action_digest: str | None
    execution: str | None
    detail: str | None
    schema_version: int


def _check_row(row: AuditRow) -> None:
    """Refuse rows whose values are not the C4.2 types (fixed text)."""
    for name, sql_type, required in _SCHEMA[1:]:
        value = getattr(row, name)
        if value is None:
            if required:
                raise ValueError("audit row is missing a required column")
        elif sql_type == "TEXT" and type(value) is not str:
            raise ValueError("audit row has a non-text value in a text column")
        elif sql_type == "INTEGER" and type(value) is not int:
            raise ValueError("audit row has a non-integer value in an integer column")
    if row.schema_version != SCHEMA_VERSION:
        raise ValueError("audit row has an unsupported schema version")


class AuditStore:
    """The SQLite audit store. One connection, serialized by a lock."""

    def __init__(
        self,
        path: str | os.PathLike[str] = DEFAULT_AUDIT_DB_PATH,
        *,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        """Open (and if needed create) the store.

        Args:
            path: the database file, or ``":memory:"`` explicitly. A relative
                path is resolved against the working directory now.
            busy_timeout_seconds: how long a write waits for SQLite's lock.

        Raises:
            ConfigurationError: the path is invalid, the file cannot be
                opened or configured, or the schema is not the C4.2 one.
        """
        if isinstance(path, os.PathLike):
            path = os.fspath(path)
        if type(path) is not str or not path or "\x00" in path:
            raise ConfigurationError("audit_db_path must be a non-empty path")
        if type(busy_timeout_seconds) not in (int, float) or not (
            0 <= busy_timeout_seconds < float("inf")
        ):
            raise ConfigurationError("busy_timeout_seconds must be a finite number")
        self._memory = path == MEMORY
        if self._memory:
            self._path = MEMORY
            _LOG.warning("audit store is in memory: records do not survive the process")
        else:
            resolved = Path(path).absolute()  # no "~" expansion
            if not resolved.parent.is_dir():
                raise ConfigurationError("audit store directory does not exist")
            if resolved.exists() and not resolved.is_file():
                raise ConfigurationError("audit store path is not a file")
            self._path = str(resolved)
        self._lock = threading.Lock()
        self._closed = False
        try:
            self._conn = sqlite3.connect(
                self._path,
                timeout=float(busy_timeout_seconds),
                isolation_level=None,  # explicit BEGIN/COMMIT below
                check_same_thread=False,  # shared under self._lock only
            )
        except (sqlite3.Error, OSError):
            raise ConfigurationError("audit store cannot be opened") from None
        try:
            self._configure()
        except ConfigurationError:
            self._conn.close()
            raise
        except sqlite3.Error:
            self._conn.close()
            raise ConfigurationError("audit store cannot be configured") from None
        if not self._memory:
            _LOG.info("audit store opened at %s", self._path)

    # ----------------------------------------------------------- setup

    def _configure(self) -> None:
        conn = self._conn
        mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        if not self._memory and str(mode).lower() != "wal":
            raise ConfigurationError("audit store cannot use WAL")
        conn.execute("PRAGMA synchronous=FULL")
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_events'"
        ).fetchone()
        if version == 0 and not exists:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(_CREATE_TABLE)
                conn.execute(_CREATE_INDEX)
                conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                conn.execute("COMMIT")
            except sqlite3.Error:
                conn.execute("ROLLBACK")
                raise
            return
        if version != SCHEMA_VERSION or not exists:
            raise ConfigurationError("audit store has an unsupported schema")
        columns = tuple(
            (name, sql_type.upper(), bool(notnull) or name == "seq")
            for _, name, sql_type, notnull, _, _ in conn.execute(
                "PRAGMA table_info(audit_events)"
            )
        )
        index = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' "
            "AND name='audit_events_request_id'"
        ).fetchone()
        if columns != _SCHEMA or not index:
            raise ConfigurationError("audit store has an unsupported schema")

    # ---------------------------------------------------------- properties

    @property
    def path(self) -> str:
        """The resolved absolute database path, or ``":memory:"``."""
        return self._path

    @property
    def durable(self) -> bool:
        """Whether records survive the process (``False`` for ``:memory:``)."""
        return not self._memory

    # ------------------------------------------------------------- writes

    def insert(self, row: AuditRow) -> int:
        """Commit one event row and return its ``seq``.

        Raises:
            ValueError: the row does not have the C4.2 column types.
            AuditUnavailableError: the row could not be committed (store
                closed, locked, read-only, schema changed, I/O error).
        """
        if type(row) is not AuditRow:
            raise TypeError("insert takes an AuditRow")
        _check_row(row)
        values = tuple(getattr(row, name) for name in COLUMNS[1:])
        with self._lock:
            if self._closed:
                raise AuditUnavailableError("audit store is closed")
            conn = self._conn
            try:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    version = conn.execute("PRAGMA user_version").fetchone()[0]
                    if version != SCHEMA_VERSION:
                        raise AuditUnavailableError("audit store schema changed")
                    seq = conn.execute(_INSERT, values).lastrowid
                    conn.execute("COMMIT")
                except BaseException:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise
            except sqlite3.Error:
                raise AuditUnavailableError(
                    "audit event could not be committed"
                ) from None
        return int(seq)

    # -------------------------------------------------------------- reads

    def read(self, request_id: str | None = None) -> tuple[AuditRow, ...]:
        """Return committed rows ordered by ``seq``, optionally for one request.

        Raises:
            AuditUnavailableError: the store is closed or cannot be read.
        """
        if request_id is not None and type(request_id) is not str:
            raise TypeError("request_id must be a str")
        with self._lock:
            if self._closed:
                raise AuditUnavailableError("audit store is closed")
            try:
                if request_id is None:
                    cursor = self._conn.execute(_SELECT + " ORDER BY seq")
                else:
                    cursor = self._conn.execute(
                        _SELECT + " WHERE request_id = ? ORDER BY seq", (request_id,)
                    )
                rows = cursor.fetchall()
            except sqlite3.Error:
                raise AuditUnavailableError("audit events could not be read") from None
        return tuple(AuditRow(*row) for row in rows)

    # -------------------------------------------------------------- close

    def close(self) -> None:
        """Close the connection. Later inserts and reads raise. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._conn.close()

    def __enter__(self) -> AuditStore:
        """Use the store as a context manager."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close the store."""
        self.close()
