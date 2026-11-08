"""Testing §6 failure-injection matrix at pipeline level (C-11): SEC-005,
SEC-006, SEC-009, C1.6, C1.7, C1.8; AT-40, AT-43, AT-45; I-24 to I-26.

Every row runs a request that would otherwise be ALLOW, injects one fault,
and checks decision, reason, execution, output release, audit completeness,
error code, invocation count, and that no exception text, path or SQL
reaches the result or the audit rows. ``evaluate`` raises in no row except
the simulated process kill.
"""

import json
import sqlite3

import pytest

from sentinel import pipeline as pipeline_module
from sentinel.audit import reconstruct
from sentinel.exceptions import ConfigurationError
from sentinel.models import (
    ACTION_MISMATCH,
    ALLOWED,
    AUDIT_UNAVAILABLE,
    INTERNAL_ERROR,
    OUTPUT_FILTER_FAILED,
    RESTRICTED_PATH,
    TOOL_FAILED,
    UNAUTHORIZED_TOOL,
    Decision,
    Execution,
    SecurityFinding,
    Severity,
)
from sentinel.policy import SecurityPolicy
from sentinel.proxy import ProxyRun
from sentinel.registry import ToolRegistry

CANARY = "CANARY-fa17-not-in-results-or-audit"
NS, OK, FAIL, UNK = (
    Execution.NOT_STARTED,
    Execution.SUCCEEDED,
    Execution.FAILED,
    Execution.UNKNOWN,
)


class LowFinding:
    """A detector that always yields one LOW finding, so FINDING is written."""

    def analyze(self, request, context):
        return (SecurityFinding(code="LOW_NOTE", severity=Severity.LOW, evidence="x"),)


def row(r):
    return (
        r.decision,
        r.reason,
        r.execution,
        r.output_released,
        r.audit_complete,
        r.error_code,
    )


def no_leaks(env, r):
    text = repr(r) + r.model_dump_json()
    with sqlite3.connect(env.db) as conn:
        text += repr(conn.execute("SELECT * FROM audit_events").fetchall())
    assert CANARY not in text
    assert "Traceback" not in text and "SELECT " not in text


# =========================================================== audit writes


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        (
            "REQUEST_RECEIVED",
            (None, AUDIT_UNAVAILABLE, NS, False, False, AUDIT_UNAVAILABLE),
        ),
        (
            "IDENTITY_RESOLVED",
            (None, AUDIT_UNAVAILABLE, NS, False, False, AUDIT_UNAVAILABLE),
        ),
        ("FINDING", (None, AUDIT_UNAVAILABLE, NS, False, False, AUDIT_UNAVAILABLE)),
        (
            "DECISION",
            (Decision.ALLOW, AUDIT_UNAVAILABLE, NS, False, False, AUDIT_UNAVAILABLE),
        ),
        (
            "EXECUTION_STARTED",
            (Decision.ALLOW, AUDIT_UNAVAILABLE, NS, False, False, AUDIT_UNAVAILABLE),
        ),
    ],
)
def test_pre_execution_audit_failure_never_invokes(make_env, event, expected):
    # AT-45: before policy → decision None; after policy → preserved.
    env = make_env(detector=LowFinding())
    env.failing.add(event)
    r = env.pipeline.evaluate(env.raw())
    assert row(r) == expected
    assert env.total_calls() == 0
    no_leaks(env, r)


def test_decision_write_failure_after_a_deny_keeps_the_policy_reason(env):
    env.failing.add("DECISION")
    r = env.pipeline.evaluate(env.raw("send_email", {"to": "a", "body": "b"}))
    assert row(r) == (
        Decision.DENY,
        UNAUTHORIZED_TOOL,
        NS,
        False,
        False,
        AUDIT_UNAVAILABLE,
    )


def test_decision_write_failure_claims_nothing(env):
    # Nothing is claimed before DECISION is committed: the same call id is
    # still free for a later request.
    env.failing.add("DECISION")
    first = env.pipeline.evaluate(env.raw(tool_call_id="call-d"))
    assert first.error_code == AUDIT_UNAVAILABLE
    assert len(env.guard) == 0
    env.failing.clear()
    second = env.pipeline.evaluate(env.raw(tool_call_id="call-d"))
    assert second.execution is OK and env.calls["read"] == 1


def test_completion_failure_after_a_proxy_refusal_has_no_decision(env):
    # A path change after EXECUTION_STARTED is an operational refusal; if its
    # REQUEST_COMPLETED also fails, the result still carries decision None.
    real_insert = env.store.insert

    def swap_after_started(row):
        seq = real_insert(row)
        if row.event_type == "EXECUTION_STARTED":
            (env.ws / "sub").rename(env.ws / "sub_old")
            (env.ws / "sub").symlink_to(env.outside, target_is_directory=True)
            env.failing.add("REQUEST_COMPLETED")
        return seq

    env.store.insert = swap_after_started
    r = env.pipeline.evaluate(
        env.raw(arguments={"path": str(env.ws / "sub" / "b.txt")})
    )
    assert row(r) == (None, AUDIT_UNAVAILABLE, NS, False, False, AUDIT_UNAVAILABLE)
    assert env.calls["read"] == 0


def test_execution_started_failure_abandons_the_claimed_run(env, monkeypatch):
    claimed = []
    real_claim = env.proxy.claim

    def spy_claim(*args, **kwargs):
        run = real_claim(*args, **kwargs)
        claimed.append(run)
        return run

    monkeypatch.setattr(env.proxy, "claim", spy_claim)
    abandoned = []
    real_abandon = ProxyRun.abandon
    monkeypatch.setattr(
        ProxyRun,
        "abandon",
        lambda self: (abandoned.append(self), real_abandon(self))[1],
    )
    env.failing.add("EXECUTION_STARTED")
    r = env.pipeline.evaluate(env.raw(tool_call_id="call-x"))
    assert r.error_code == AUDIT_UNAVAILABLE and env.calls["read"] == 0
    assert abandoned == claimed and claimed[0].state == "not_started"
    # The guard entry was retired (terminal), the decision stays consumed.
    assert len(env.guard) == 1
    with pytest.raises(RuntimeError):
        claimed[0].execute()
    assert env.calls["read"] == 0


@pytest.mark.parametrize(
    ("event", "tool_fault", "filter_fault", "expected", "calls"),
    [
        (
            "OUTPUT_FILTERED",
            None,
            False,
            (Decision.ALLOW, AUDIT_UNAVAILABLE, OK, False, False, AUDIT_UNAVAILABLE),
            1,
        ),
        (
            "REQUEST_COMPLETED",
            None,
            False,
            (Decision.ALLOW, AUDIT_UNAVAILABLE, OK, False, False, AUDIT_UNAVAILABLE),
            1,
        ),
        (
            "ERROR",
            RuntimeError(CANARY),
            False,
            (Decision.ALLOW, AUDIT_UNAVAILABLE, FAIL, False, False, AUDIT_UNAVAILABLE),
            1,
        ),
        (
            "ERROR",
            None,
            True,
            (Decision.ALLOW, AUDIT_UNAVAILABLE, OK, False, False, AUDIT_UNAVAILABLE),
            1,
        ),
        (
            "OUTPUT_WITHHELD",
            None,
            True,
            (Decision.ALLOW, AUDIT_UNAVAILABLE, OK, False, False, AUDIT_UNAVAILABLE),
            1,
        ),
    ],
    ids=[
        "output-filtered",
        "completed",
        "error-after-tool-failure",
        "error-after-filter-failure",
        "output-withheld",
    ],
)
def test_post_execution_audit_failure_keeps_the_truth(
    make_env, event, tool_fault, filter_fault, expected, calls
):
    def broken_filter(out):
        raise ValueError(CANARY)

    env = make_env(output_filter=broken_filter) if filter_fault else make_env()
    env.raise_in_tool = tool_fault
    env.failing.add(event)
    r = env.pipeline.evaluate(env.raw())
    assert row(r) == expected
    assert r.output is None
    assert env.calls["read"] == calls  # never retried
    no_leaks(env, r)


def test_completion_failure_after_a_deny(env):
    env.failing.add("REQUEST_COMPLETED")
    r = env.pipeline.evaluate(env.raw("send_email", {"to": "a", "body": "b"}))
    assert row(r) == (
        Decision.DENY,
        UNAUTHORIZED_TOOL,
        NS,
        False,
        False,
        AUDIT_UNAVAILABLE,
    )


# ===================================================== unexpected errors


def _boom(*args, **kwargs):
    raise RuntimeError(CANARY + " /private/secret/path")


@pytest.mark.parametrize("stage", ["gateway", "identity", "detector", "policy"])
def test_unexpected_errors_before_execution_are_internal_errors(
    env, monkeypatch, stage
):
    # AT-40: never "deny"; ERROR (D-29 fields) then REQUEST_COMPLETED(NULL).
    if stage == "gateway":
        monkeypatch.setattr(pipeline_module, "validate_request", _boom)
    elif stage == "identity":
        monkeypatch.setattr(env.identity, "authenticate", _boom)
    elif stage == "detector":
        monkeypatch.setattr(
            env.pipeline, "_detector", type("D", (), {"analyze": staticmethod(_boom)})()
        )
    else:
        monkeypatch.setattr(env.pipeline._policy, "evaluate", _boom)
    r = env.pipeline.evaluate(env.raw())
    assert row(r) == (None, INTERNAL_ERROR, NS, False, True, INTERNAL_ERROR)
    assert env.total_calls() == 0
    events = env.events(r.request_id)
    assert events[-2:] == ["ERROR", "REQUEST_COMPLETED"]
    error = env.rows(r.request_id)[-2]
    assert error.reason == INTERNAL_ERROR
    detail = json.loads(error.detail)
    assert set(detail) == {"exception_type", "module", "function", "line", "stage"}
    assert detail["exception_type"] == "builtins.RuntimeError"
    assert env.rows(r.request_id)[-1].decision is None
    no_leaks(env, r)


def test_registry_lookup_failure_in_the_proxy_is_an_internal_error(env, monkeypatch):
    monkeypatch.setattr(env.proxy, "_registry", ToolRegistry())
    r = env.pipeline.evaluate(env.raw())
    assert row(r) == (None, INTERNAL_ERROR, NS, False, True, INTERNAL_ERROR)
    assert env.calls["read"] == 0


def test_action_digest_mismatch_is_an_operational_refusal(env, monkeypatch):
    real = env.pipeline._policy.evaluate

    def tampering(*args, **kwargs):
        decision = real(*args, **kwargs)
        object.__setattr__(
            decision.action, "_canonical_arguments", '{"path":"/etc/passwd"}'
        )
        return decision

    monkeypatch.setattr(env.pipeline._policy, "evaluate", tampering)
    r = env.pipeline.evaluate(env.raw())
    assert row(r) == (None, ACTION_MISMATCH, NS, False, True, ACTION_MISMATCH)
    assert env.calls["read"] == 0
    rows = env.rows(r.request_id)
    assert rows[-2].event_type == "DECISION" and rows[-2].decision == "allow"
    assert rows[-1].decision is None and rows[-1].reason == ACTION_MISMATCH


def test_path_changed_after_execution_started_is_refused(env):
    # The swap happens right after EXECUTION_STARTED is committed, before the
    # proxy's re-resolution.
    real_insert = env.store.insert

    def swap_after_started(row):
        seq = real_insert(row)
        if row.event_type == "EXECUTION_STARTED":
            (env.ws / "sub").rename(env.ws / "sub_old")
            (env.ws / "sub").symlink_to(env.outside, target_is_directory=True)
        return seq

    env.store.insert = swap_after_started
    r = env.pipeline.evaluate(
        env.raw(arguments={"path": str(env.ws / "sub" / "b.txt")})
    )
    assert row(r) == (None, RESTRICTED_PATH, NS, False, True, RESTRICTED_PATH)
    assert env.calls["read"] == 0
    assert env.events(r.request_id)[-2:] == ["EXECUTION_STARTED", "REQUEST_COMPLETED"]
    assert reconstruct(env.store.read())[r.request_id].execution is NS


def test_tool_exception_is_contained(env):
    env.raise_in_tool = RuntimeError(CANARY)
    r = env.pipeline.evaluate(env.raw())
    assert row(r) == (Decision.ALLOW, TOOL_FAILED, FAIL, False, True, TOOL_FAILED)
    assert env.calls["read"] == 1
    assert env.events(r.request_id)[-2:] == ["ERROR", "REQUEST_COMPLETED"]
    no_leaks(env, r)


def test_output_filter_exception_withholds_output(make_env):
    def broken(out):
        raise ValueError(CANARY)

    env = make_env(output_filter=broken)
    r = env.pipeline.evaluate(env.raw())
    assert row(r) == (
        Decision.ALLOW,
        OUTPUT_FILTER_FAILED,
        OK,
        False,
        True,
        OUTPUT_FILTER_FAILED,
    )
    assert env.calls["read"] == 1
    assert env.events(r.request_id)[-3:] == [
        "ERROR",
        "OUTPUT_WITHHELD",
        "REQUEST_COMPLETED",
    ]
    no_leaks(env, r)


def test_internal_error_after_execution_keeps_allow_and_truth(env, monkeypatch):
    # AT-43: an error while mapping the result after the tool ran.
    def broken_events(flow, outcome):
        raise RuntimeError(CANARY)

    monkeypatch.setattr(env.pipeline, "_complete_events", broken_events)
    r = env.pipeline.evaluate(env.raw())
    assert row(r) == (Decision.ALLOW, INTERNAL_ERROR, OK, False, False, INTERNAL_ERROR)
    assert r.output is None and env.calls["read"] == 1
    no_leaks(env, r)


class Killed(BaseException):
    """Simulates the process being killed inside the tool."""


def test_process_killed_after_execution_started_reconstructs_unknown(env):
    env.raise_in_tool = Killed()
    with pytest.raises(Killed):
        env.pipeline.evaluate(env.raw())
    rid = env.store.read()[0].request_id
    assert env.calls["read"] == 1
    state = reconstruct(env.store.read())[rid]
    assert state.execution is UNK  # best-effort REQUEST_COMPLETED(unknown)
    rc = env.rows(rid)[-1]
    assert (rc.execution, json.loads(rc.detail)) == (
        "unknown",
        {"interruption": "Killed"},
    )


def test_kill_with_the_store_down_still_reconstructs_unknown(env):
    # AT-10: the best-effort completion fails too; the original propagates.
    env.raise_in_tool = Killed()
    env.failing.update({"REQUEST_COMPLETED", "OUTPUT_FILTERED", "ERROR"})
    with pytest.raises(Killed):
        env.pipeline.evaluate(env.raw())
    rid = env.store.read()[0].request_id
    state = reconstruct(env.store.read())[rid]
    assert (state.execution, state.basis) == (UNK, "no_completion")


def test_invalid_policy_or_prefix_fails_at_construction(tmp_path):
    with pytest.raises(ConfigurationError):
        SecurityPolicy(version="")
    from sentinel.identity import IdentityStore
    from sentinel.models import ToolGrant

    reg = ToolRegistry()
    from pydantic import BaseModel, ConfigDict

    class P(BaseModel):
        model_config = ConfigDict(extra="forbid")
        path: str

    reg.register(
        "r",
        arg_schema=P,
        destructive=False,
        path_args=("path",),
        sync_fn=lambda path: path,
    )
    with pytest.raises(ConfigurationError):
        IdentityStore(reg).register_agent(
            "a",
            grants=(
                ToolGrant(tool="r", allowed_path_prefixes=(str(tmp_path / "nope"),)),
            ),
        )


def test_successful_baseline_for_comparison(env):
    r = env.pipeline.evaluate(env.raw())
    assert row(r) == (Decision.ALLOW, ALLOWED, OK, True, True, None)
