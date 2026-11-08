"""E2E-01 … E2E-09 at pipeline level, with exact C4.3 event sequences
(testing §8; FR-012, SEC-005, SEC-006; NI-06, NI-12; AT-25)."""

import logging
import sqlite3

import pytest

from sentinel.models import (
    ALLOWED,
    AUDIT_UNAVAILABLE,
    DESTRUCTIVE_TOOL,
    DUPLICATE_TOOL_CALL,
    INVALID_REQUEST,
    RESTRICTED_PATH,
    UNAUTHORIZED_AGENT,
    UNAUTHORIZED_TOOL,
    Decision,
    Execution,
)

RR, IR, FIND, DEC, ES = (
    "REQUEST_RECEIVED",
    "IDENTITY_RESOLVED",
    "FINDING",
    "DECISION",
    "EXECUTION_STARTED",
)
OF, OW, RC, ERR = "OUTPUT_FILTERED", "OUTPUT_WITHHELD", "REQUEST_COMPLETED", "ERROR"


def outcome(r):
    return (r.decision, r.reason, r.execution, r.output_released, r.audit_complete)


def test_e2e_01_allowed_read_executes_once_with_complete_audit(env):
    r = env.pipeline.evaluate(env.raw())
    assert outcome(r) == (Decision.ALLOW, ALLOWED, Execution.SUCCEEDED, True, True)
    assert r.output == "hello" and r.error_code is None
    assert env.calls["read"] == 1
    assert env.events(r.request_id) == [RR, IR, DEC, ES, OF, RC]
    rc = env.rows(r.request_id)[-1]
    assert (rc.decision, rc.execution, rc.reason) == ("allow", "succeeded", ALLOWED)


def test_e2e_01_execution_started_was_committed_before_the_call(env):
    # NI-06: from inside the spy, a separate connection already sees
    # DECISION(allow) and EXECUTION_STARTED with the same action digest.
    env.pipeline.evaluate(env.raw())
    seen = env.seen_in_spy[0]
    assert [e[0] for e in seen] == [RR, IR, DEC, ES]
    assert seen[2][1] == "allow"
    assert seen[2][2] == seen[3][2] is not None


def test_e2e_02_path_traversal_is_a_policy_denial(env):
    r = env.pipeline.evaluate(
        env.raw(arguments={"path": str(env.ws) + "/../outside/secret.txt"})
    )
    assert outcome(r) == (
        Decision.DENY,
        RESTRICTED_PATH,
        Execution.NOT_STARTED,
        False,
        True,
    )
    assert env.calls["read"] == 0
    assert env.events(r.request_id) == [RR, IR, DEC, RC]


def test_e2e_03_ungranted_tool_is_denied(env):
    r = env.pipeline.evaluate(env.raw("send_email", {"to": "a@b.c", "body": "hi"}))
    assert outcome(r) == (
        Decision.DENY,
        UNAUTHORIZED_TOOL,
        Execution.NOT_STARTED,
        False,
        True,
    )
    assert env.calls["email"] == 0
    assert env.events(r.request_id) == [RR, IR, DEC, RC]


def test_e2e_04_unknown_agent_is_denied(env):
    r = env.pipeline.evaluate(env.raw(agent_id="unknown_agent"))
    assert outcome(r) == (
        Decision.DENY,
        UNAUTHORIZED_AGENT,
        Execution.NOT_STARTED,
        False,
        True,
    )
    assert env.calls["read"] == 0
    assert env.events(r.request_id) == [RR, IR, DEC, RC]


def test_e2e_05_destructive_tool_requires_approval_and_never_runs(env):
    r = env.pipeline.evaluate(env.raw("delete_file"))
    assert outcome(r) == (
        Decision.REQUIRE_APPROVAL,
        DESTRUCTIVE_TOOL,
        Execution.NOT_STARTED,
        False,
        True,
    )
    assert env.calls["delete"] == 0
    assert (env.ws / "data.txt").exists()
    assert env.events(r.request_id) == [RR, IR, DEC, RC]


def test_e2e_06_missing_fields_are_an_operational_refusal(env):
    r = env.pipeline.evaluate({"agent_id": "research_agent"})
    assert outcome(r) == (None, INVALID_REQUEST, Execution.NOT_STARTED, False, True)
    assert r.error_code == INVALID_REQUEST
    assert env.total_calls() == 0
    assert env.events(r.request_id) == [RR, RC]
    assert env.rows(r.request_id)[-1].decision is None


def test_e2e_07_decision_write_failure_preserves_allow_and_never_runs(env):
    env.failing.add(DEC)
    r = env.pipeline.evaluate(env.raw())
    assert outcome(r) == (
        Decision.ALLOW,
        AUDIT_UNAVAILABLE,
        Execution.NOT_STARTED,
        False,
        False,
    )
    assert r.error_code == AUDIT_UNAVAILABLE
    assert env.calls["read"] == 0
    assert env.events(r.request_id) == [RR, IR]  # then the store is down


def test_e2e_08_identity_injected_in_arguments_is_refused(env):
    r = env.pipeline.evaluate(
        env.raw(arguments={"path": str(env.ws / "data.txt"), "agent_id": "admin"})
    )
    assert outcome(r) == (None, INVALID_REQUEST, Execution.NOT_STARTED, False, True)
    assert env.calls["read"] == 0
    assert env.events(r.request_id) == [RR, RC]


def test_e2e_09_completion_write_failure_keeps_success_and_withholds(env, caplog):
    env.failing.add(RC)
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        r = env.pipeline.evaluate(env.raw())
    assert outcome(r) == (
        Decision.ALLOW,
        AUDIT_UNAVAILABLE,
        Execution.SUCCEEDED,
        False,
        False,
    )
    assert r.output is None and r.error_code == AUDIT_UNAVAILABLE
    assert env.calls["read"] == 1  # the side effect happened and is reported
    assert env.events(r.request_id) == [RR, IR, DEC, ES, OF]  # RC missing
    assert any(
        "audit event not committed" in rec.getMessage() for rec in caplog.records
    )


def test_findings_are_recorded_in_order_before_the_decision(make_env):
    from sentinel.models import SecurityFinding, Severity

    class Detector:
        def analyze(self, request, context):
            return (
                SecurityFinding(code="B_LOW", severity=Severity.LOW, evidence="b"),
                SecurityFinding(code="A_MED", severity=Severity.MEDIUM, evidence="a"),
            )

    env = make_env(detector=Detector())
    r = env.pipeline.evaluate(env.raw())
    assert r.decision is Decision.ALLOW
    assert env.events(r.request_id) == [RR, IR, FIND, FIND, DEC, ES, OF, RC]


def test_duplicate_tool_call_id_is_audited_as_a_refusal(env):
    # AT-25: DECISION(allow), then REQUEST_COMPLETED(NULL, DUPLICATE_TOOL_CALL);
    # no EXECUTION_STARTED.
    first = env.pipeline.evaluate(env.raw(tool_call_id="call-1"))
    second = env.pipeline.evaluate(env.raw(tool_call_id="call-1"))
    assert first.execution is Execution.SUCCEEDED
    assert outcome(second) == (
        None,
        DUPLICATE_TOOL_CALL,
        Execution.NOT_STARTED,
        False,
        True,
    )
    assert env.calls["read"] == 1
    assert env.events(second.request_id) == [RR, IR, DEC, RC]
    rows = env.rows(second.request_id)
    assert rows[2].decision == "allow" and rows[3].decision is None
    assert rows[3].reason == DUPLICATE_TOOL_CALL


def test_every_event_carries_the_request_identity(env):
    r = env.pipeline.evaluate(env.raw())
    rows = env.rows(r.request_id)
    assert {row.request_id for row in rows} == {r.request_id}
    assert [row.agent_id for row in rows] == ["research_agent"] * len(rows)
    assert all(row.tool == "read_file" for row in rows)
    assert rows[2].policy_version == "test-1"
    digests = {row.action_digest for row in rows if row.event_type in (DEC, ES, RC)}
    assert len(digests) == 1 and None not in digests


def test_request_received_keeps_the_masked_original_arguments(env):
    import json

    r = env.pipeline.evaluate(
        env.raw(arguments={"path": str(env.ws) + "/sub/../data.txt"})
    )
    detail = json.loads(env.rows(r.request_id)[0].detail)
    assert detail["arguments"]["path"].endswith("/sub/../data.txt")  # as received


def test_events_are_visible_through_a_second_connection_immediately(env):
    r = env.pipeline.evaluate(env.raw())
    with sqlite3.connect(env.db) as conn:
        n = conn.execute(
            "SELECT count(*) FROM audit_events WHERE request_id=?", (r.request_id,)
        ).fetchone()[0]
    assert n == 6


def test_memory_store_never_reports_a_complete_audit(make_env):
    env = make_env(db_path=":memory:")
    r = env.pipeline.evaluate(env.raw())
    assert r.execution is Execution.SUCCEEDED
    assert r.audit_complete is False and r.output_released is False and r.output is None
    assert env.calls["read"] == 1


def test_repeated_requests_reuse_one_pipeline(env):
    results = [env.pipeline.evaluate(env.raw()) for _ in range(5)]
    assert len({r.request_id for r in results}) == 5
    assert all(r.output == "hello" for r in results)
    assert env.calls["read"] == 5


def test_closed_pipeline_refuses_with_audit_unavailable(env):
    env.pipeline.close()
    r = env.pipeline.evaluate(env.raw())
    assert outcome(r) == (None, AUDIT_UNAVAILABLE, Execution.NOT_STARTED, False, False)
    assert env.calls["read"] == 0


@pytest.mark.parametrize("raw", [None, "request", 42, ["tool"]])
def test_non_mapping_input_is_an_invalid_request(env, raw):
    r = env.pipeline.evaluate(raw)
    assert (r.decision, r.reason) == (None, INVALID_REQUEST)
    assert env.events(r.request_id) == [RR, RC]
