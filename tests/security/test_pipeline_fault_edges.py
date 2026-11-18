"""Pipeline fault paths not reached by the §6 matrix (M1 gate remediation).

Each test injects one fault at a point the testing §6 matrix does not cover
and checks the security outcome: the tool does not run (or its interruption
is recorded truthfully), the claim and the ``tool_call_id`` guard key are
released, nothing is reported as a policy DENY, and no exception text reaches
the result or the audit (C1.6–C1.8, Q-03c, SEC-005, SEC-008, SEC-027, D-29).
"""

import asyncio
import logging
import sqlite3

import pytest

from sentinel import pipeline as pipeline_module
from sentinel.audit import reconstruct
from sentinel.models import (
    AUDIT_UNAVAILABLE,
    DUPLICATE_TOOL_CALL,
    INTERNAL_ERROR,
    INVALID_REQUEST,
    Decision,
    Execution,
)
from sentinel.proxy import ToolCallGuard

CANARY = "CANARY-edge-7c41-not-in-results-or-audit"


class Abort(BaseException):
    """A non-``Exception`` interruption (like ``KeyboardInterrupt``)."""


def inject(env, event_type, exc):
    """Make the store raise ``exc`` when ``event_type`` is inserted."""
    inner = env.store.insert

    def insert(row):
        if row.event_type == event_type:
            raise exc
        return inner(row)

    env.store.insert = insert

    def restore():
        env.store.insert = inner

    return restore


class Clock:
    """An injectable monotonic clock for the ``tool_call_id`` guard."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def timed(make_env):
    clock = Clock()
    env = make_env(guard=ToolCallGuard(clock=clock))
    env.clock = clock
    return env


def assert_call_id_retired_not_leaked(env, call_id):
    """The abandoned claim moved its guard entry to a terminal state (D-31).

    A repeat within the TTL is refused (fail closed); after the TTL the entry
    expires and the id is admitted once. An entry left in flight would block
    the id forever, which this would detect.
    """
    repeat = env.pipeline.evaluate(env.raw(tool_call_id=call_id))
    assert (repeat.decision, repeat.error_code) == (None, DUPLICATE_TOOL_CALL)
    assert env.calls["read"] == 0
    env.clock.now += 301.0
    again = env.pipeline.evaluate(env.raw(tool_call_id=call_id))
    assert again.execution is Execution.SUCCEEDED
    assert env.calls["read"] == 1


def all_rows_text(env):
    with sqlite3.connect(env.db) as conn:
        return repr(conn.execute("SELECT * FROM audit_events").fetchall())


def test_unexpected_error_committing_execution_started_releases_the_claim(timed):
    # After the proxy claim, an unexpected (non-audit) error while writing
    # EXECUTION_STARTED is an internal error: the claimed run is abandoned,
    # its guard key retired, and the tool never runs.
    env = timed
    restore = inject(env, "EXECUTION_STARTED", RuntimeError(CANARY))
    r = env.pipeline.evaluate(env.raw(tool_call_id="call-x"))
    assert (r.decision, r.reason, r.error_code) == (
        None,
        INTERNAL_ERROR,
        INTERNAL_ERROR,
    )
    assert r.execution is Execution.NOT_STARTED
    assert not r.output_released and r.output is None
    assert r.audit_complete  # ERROR and REQUEST_COMPLETED were committed
    assert env.calls["read"] == 0
    assert env.events(r.request_id) == [
        "REQUEST_RECEIVED",
        "IDENTITY_RESOLVED",
        "DECISION",
        "ERROR",
        "REQUEST_COMPLETED",
    ]
    assert reconstruct(env.rows(r.request_id))[r.request_id].execution is (
        Execution.NOT_STARTED
    )
    assert CANARY not in repr(r) and CANARY not in all_rows_text(env)
    restore()
    assert_call_id_retired_not_leaked(env, "call-x")


def test_interruption_while_committing_execution_started_never_runs_the_tool(
    timed,
):
    # A BaseException after the claim but before EXECUTION_STARTED commits:
    # the run is abandoned, the exception propagates unchanged, and the audit
    # reconstructs the request as not executed.
    env = timed
    restore = inject(env, "EXECUTION_STARTED", Abort())
    with pytest.raises(Abort):
        env.pipeline.evaluate(env.raw(tool_call_id="call-y"))
    assert env.calls["read"] == 0
    rows = env.store.read()
    state = next(iter(reconstruct(rows).values()))
    assert state.execution is Execution.NOT_STARTED
    assert [row.event_type for row in rows] == [
        "REQUEST_RECEIVED",
        "IDENTITY_RESOLVED",
        "DECISION",
    ]
    restore()
    assert_call_id_retired_not_leaked(env, "call-y")


def test_unexpected_error_before_request_received_commits(env):
    # Nothing was committed, so nothing more is written for the request and
    # the audit is incomplete; still an internal error, never a DENY.
    inject(env, "REQUEST_RECEIVED", RuntimeError(CANARY))
    r = env.pipeline.evaluate(env.raw())
    assert (r.decision, r.reason, r.error_code) == (
        None,
        INTERNAL_ERROR,
        INTERNAL_ERROR,
    )
    assert r.execution is Execution.NOT_STARTED
    assert not r.audit_complete and not r.output_released
    assert env.calls["read"] == 0
    assert env.store.read() == ()
    assert CANARY not in repr(r)


def test_failed_error_event_write_skips_the_completion(env, monkeypatch):
    # An internal error whose ERROR event cannot be committed: no further
    # events (I-25), audit incomplete, still decision=None INTERNAL_ERROR.
    def boom(*args, **kwargs):
        raise RuntimeError(CANARY)

    monkeypatch.setattr(env.pipeline._policy, "evaluate", boom)
    env.failing = {"ERROR"}
    r = env.pipeline.evaluate(env.raw())
    assert (r.decision, r.error_code, r.execution) == (
        None,
        INTERNAL_ERROR,
        Execution.NOT_STARTED,
    )
    assert not r.audit_complete
    assert env.events(r.request_id) == ["REQUEST_RECEIVED", "IDENTITY_RESOLVED"]
    assert env.calls["read"] == 0
    assert CANARY not in all_rows_text(env)


def test_unrecordable_argument_values_are_marked_not_recorded(env):
    # A value that cannot be stored (not JSON-native) is replaced in the
    # REQUEST_RECEIVED detail; the request itself is refused, not denied.
    raw = env.raw(arguments={"path": {CANARY}})
    r = env.pipeline.evaluate(raw)
    assert (r.decision, r.error_code) == (None, INVALID_REQUEST)
    assert env.calls["read"] == 0
    detail = env.rows(r.request_id)[0].detail
    assert "[not recordable]" in detail
    assert CANARY not in all_rows_text(env)


def test_failed_best_effort_completion_never_replaces_the_interruption(env, caplog):
    # The tool is interrupted after entry and the best-effort completion
    # itself raises: the original BaseException still propagates, a warning
    # is logged, and the audit reconstructs the request as unknown.
    env.raise_in_tool = Abort()
    inject(env, "REQUEST_COMPLETED", RuntimeError(CANARY))
    with caplog.at_level(logging.WARNING, logger=pipeline_module.__name__):
        with pytest.raises(Abort):
            env.pipeline.evaluate(env.raw())
    assert env.calls["read"] == 1
    assert "best-effort audit after an interruption failed" in caplog.text
    assert CANARY not in caplog.text
    state = next(iter(reconstruct(env.store.read()).values()))
    assert state.execution is Execution.UNKNOWN


def test_sync_tool_interrupted_in_a_worker_thread_through_the_async_entry(env):
    # A sync-only tool reached through the internal async entry runs in a
    # worker thread (I-27). An interruption there is recorded as unknown and
    # re-raised unchanged; it is never a DENY or not_started.
    env.raise_in_tool = Abort()
    with pytest.raises(Abort):
        asyncio.run(env.pipeline.evaluate_async(env.raw()))
    assert env.calls["read"] == 1
    rows = env.store.read()
    completed = [row for row in rows if row.event_type == "REQUEST_COMPLETED"]
    assert len(completed) == 1
    assert completed[0].execution == Execution.UNKNOWN.value
    assert completed[0].decision == Decision.ALLOW.value
    assert '"interruption":"Abort"' in completed[0].detail
    state = next(iter(reconstruct(rows).values()))
    assert state.execution is Execution.UNKNOWN


def test_audit_unavailable_on_execution_started_is_not_an_internal_error(timed):
    # Contrast with the first test: the anticipated audit failure keeps the
    # policy decision and its own code (C1.7), and still nothing runs.
    env = timed
    env.failing = {"EXECUTION_STARTED"}
    r = env.pipeline.evaluate(env.raw(tool_call_id="call-z"))
    assert (r.decision, r.error_code) == (Decision.ALLOW, AUDIT_UNAVAILABLE)
    assert env.calls["read"] == 0
    env.failing = set()
    assert_call_id_retired_not_leaked(env, "call-z")
