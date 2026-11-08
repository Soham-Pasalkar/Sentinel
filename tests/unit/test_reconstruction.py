"""Reconstruction tests (C-09): C4.3, C4.4; SEC-023; NI-15 (unit part); I-23.

Event sequences are committed through the real logger and store, then
classified from the rows alone.
"""

from datetime import UTC, datetime

import pytest

from sentinel.audit import (
    DECISION,
    ERROR,
    EXECUTION_STARTED,
    FINDING,
    IDENTITY_RESOLVED,
    OUTPUT_FILTERED,
    OUTPUT_WITHHELD,
    REQUEST_COMPLETED,
    REQUEST_RECEIVED,
    AuditLogger,
    RequestState,
    reconstruct,
)
from sentinel.exceptions import AuditIntegrityError
from sentinel.models import (
    ACTION_MISMATCH,
    ALLOWED,
    AUDIT_UNAVAILABLE,
    DECISION_ALREADY_USED,
    DESTRUCTIVE_TOOL,
    DUPLICATE_TOOL_CALL,
    INTERNAL_ERROR,
    INVALID_REQUEST,
    OUTPUT_FILTER_FAILED,
    RESTRICTED_PATH,
    TOOL_FAILED,
    UNAUTHORIZED_TOOL,
    Decision,
    Execution,
)
from sentinel.store import AuditRow, AuditStore

T0 = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
D = "d" * 64
ALLOW, DENY, APPROVE = Decision.ALLOW, Decision.DENY, Decision.REQUIRE_APPROVAL
NS, OK, FAIL, UNK = (
    Execution.NOT_STARTED,
    Execution.SUCCEEDED,
    Execution.FAILED,
    Execution.UNKNOWN,
)


@pytest.fixture
def log(tmp_path):
    store = AuditStore(tmp_path / "a.db")
    yield AuditLogger(store, clock=lambda: T0)
    store.close()


def rr(log, r):
    log.record(REQUEST_RECEIVED, request_id=r)


def pre(log, r, decision, reason, findings=0):
    rr(log, r)
    log.record(IDENTITY_RESOLVED, request_id=r)
    for i in range(findings):
        log.record(FINDING, request_id=r, detail={"i": i})
    log.record(
        DECISION, request_id=r, decision=decision, reason=reason, action_digest=D
    )


def es(log, r):
    log.record(EXECUTION_STARTED, request_id=r, action_digest=D)


def rc(log, r, decision, reason, execution):
    log.record(
        REQUEST_COMPLETED,
        request_id=r,
        decision=decision,
        reason=reason,
        execution=execution,
        action_digest=D if decision is ALLOW else None,
    )


def state(log, r):
    return reconstruct(log.store.read())[r]


# ============================================ C4.4 classification table


def test_normal_execution(log):
    pre(log, "r", ALLOW, ALLOWED, findings=2)
    es(log, "r")
    log.record(OUTPUT_FILTERED, request_id="r")
    rc(log, "r", ALLOW, ALLOWED, OK)
    assert state(log, "r") == RequestState(
        request_id="r",
        decision=ALLOW,
        execution=OK,
        basis="recorded",
        completed=True,
        completed_decision=ALLOW,
        reason=ALLOWED,
        output="filtered",
    )


def test_policy_denial(log):
    pre(log, "r", DENY, UNAUTHORIZED_TOOL)
    rc(log, "r", DENY, UNAUTHORIZED_TOOL, NS)
    s = state(log, "r")
    assert (s.decision, s.execution, s.basis) == (DENY, NS, "not_allowed")


def test_require_approval(log):
    pre(log, "r", APPROVE, DESTRUCTIVE_TOOL)
    rc(log, "r", APPROVE, DESTRUCTIVE_TOOL, NS)
    s = state(log, "r")
    assert (s.decision, s.execution, s.basis) == (APPROVE, NS, "not_allowed")


def test_invalid_request_has_no_decision(log):
    rr(log, "r")
    rc(log, "r", None, INVALID_REQUEST, NS)
    s = state(log, "r")
    assert (s.decision, s.execution, s.basis, s.reason) == (
        None,
        NS,
        "no_decision",
        INVALID_REQUEST,
    )


def test_internal_error_before_execution(log):
    rr(log, "r")
    log.record(IDENTITY_RESOLVED, request_id="r")
    log.record(ERROR, request_id="r", reason=INTERNAL_ERROR, detail={"stage": "policy"})
    rc(log, "r", None, INTERNAL_ERROR, NS)
    s = state(log, "r")
    assert (s.decision, s.execution, s.basis) == (None, NS, "no_decision")


def test_audit_unavailable_before_execution_is_not_executed(log):
    # DECISION(allow) committed, EXECUTION_STARTED write failed: never ran.
    pre(log, "r", ALLOW, ALLOWED)
    s = state(log, "r")
    assert (s.decision, s.execution, s.basis, s.completed) == (
        ALLOW,
        NS,
        "not_started",
        False,
    )


def test_audit_unavailable_on_the_decision_write(log):
    rr(log, "r")
    log.record(IDENTITY_RESOLVED, request_id="r")
    s = state(log, "r")
    assert (s.decision, s.execution, s.basis) == (None, NS, "no_decision")


@pytest.mark.parametrize("code", [DUPLICATE_TOOL_CALL, DECISION_ALREADY_USED])
def test_operational_refusal_after_allow_is_not_a_denial(log, code):
    pre(log, "r", ALLOW, ALLOWED)
    rc(log, "r", None, code, NS)
    s = state(log, "r")
    assert (s.decision, s.completed_decision, s.execution, s.reason) == (
        ALLOW,
        None,
        NS,
        code,
    )


@pytest.mark.parametrize("code", [RESTRICTED_PATH, ACTION_MISMATCH])
def test_proxy_block_after_execution_started_is_recorded_not_started(log, code):
    pre(log, "r", ALLOW, ALLOWED)
    es(log, "r")
    rc(log, "r", None, code, NS)
    s = state(log, "r")
    assert (s.execution, s.basis, s.reason) == (NS, "recorded", code)


def test_tool_failure(log):
    pre(log, "r", ALLOW, ALLOWED)
    es(log, "r")
    log.record(ERROR, request_id="r", reason=TOOL_FAILED)
    rc(log, "r", ALLOW, TOOL_FAILED, FAIL)
    assert state(log, "r").execution is FAIL


def test_filter_failure_after_success_stays_succeeded(log):
    pre(log, "r", ALLOW, ALLOWED)
    es(log, "r")
    log.record(OUTPUT_WITHHELD, request_id="r")
    rc(log, "r", ALLOW, OUTPUT_FILTER_FAILED, OK)
    s = state(log, "r")
    assert (s.execution, s.output, s.reason) == (OK, "withheld", OUTPUT_FILTER_FAILED)


def test_unknown_after_interruption_is_recorded_unknown(log):
    pre(log, "r", ALLOW, ALLOWED)
    es(log, "r")
    rc(log, "r", ALLOW, ALLOWED, UNK)
    s = state(log, "r")
    assert (s.execution, s.basis) == (UNK, "recorded")


def test_missing_completion_after_execution_started_is_unknown(log):
    # Crash, kill or post-execution audit loss: never "not executed".
    pre(log, "r", ALLOW, ALLOWED)
    es(log, "r")
    s = state(log, "r")
    assert (s.execution, s.basis, s.completed) == (UNK, "no_completion", False)


def test_post_execution_audit_loss_after_output_event_is_unknown(log):
    pre(log, "r", ALLOW, ALLOWED)
    es(log, "r")
    log.record(OUTPUT_FILTERED, request_id="r")
    assert state(log, "r").execution is UNK


def test_post_execution_audit_unavailable_recorded(log):
    pre(log, "r", ALLOW, ALLOWED)
    es(log, "r")
    rc(log, "r", ALLOW, AUDIT_UNAVAILABLE, OK)
    assert state(log, "r").execution is OK


def test_many_requests_are_classified_independently_in_order(log):
    pre(log, "a", DENY, UNAUTHORIZED_TOOL)
    pre(log, "b", ALLOW, ALLOWED)
    rc(log, "a", DENY, UNAUTHORIZED_TOOL, NS)
    es(log, "b")
    rr(log, "c")
    states = reconstruct(log.store.read())
    assert list(states) == ["a", "b", "c"]
    assert [s.execution for s in states.values()] == [NS, UNK, NS]


def test_reconstruction_ignores_input_order(log):
    pre(log, "r", ALLOW, ALLOWED)
    es(log, "r")
    rc(log, "r", ALLOW, ALLOWED, OK)
    rows = log.store.read()
    assert reconstruct(reversed(rows)) == reconstruct(rows)


# ===================================================== inconsistencies


def raw_row(seq, event_type, **kw):
    fields = dict(
        seq=seq,
        event_id=f"e{seq}",
        request_id="r",
        event_type=event_type,
        occurred_at=T0.isoformat(),
        agent_id=None,
        session_id=None,
        tool=None,
        decision=None,
        reason=None,
        policy_version=None,
        action_digest=None,
        execution=None,
        detail=None,
        schema_version=1,
    )
    fields.update(kw)
    return AuditRow(**fields)


ALLOW_ROW = dict(decision="allow", reason=ALLOWED, action_digest=D)


@pytest.mark.parametrize(
    "rows",
    [
        [raw_row(1, IDENTITY_RESOLVED)],  # does not start with REQUEST_RECEIVED
        [raw_row(1, REQUEST_RECEIVED), raw_row(2, REQUEST_RECEIVED)],
        [
            raw_row(1, REQUEST_RECEIVED),
            raw_row(2, DECISION, **ALLOW_ROW),
            raw_row(3, DECISION, **ALLOW_ROW),
        ],
        [
            raw_row(1, REQUEST_RECEIVED),
            raw_row(2, EXECUTION_STARTED, action_digest=D),
        ],  # no decision
        [
            raw_row(1, REQUEST_RECEIVED),
            raw_row(2, DECISION, decision="deny", reason=UNAUTHORIZED_TOOL),
            raw_row(3, EXECUTION_STARTED, action_digest=D),
        ],  # started after a deny
        [
            raw_row(1, REQUEST_RECEIVED),
            raw_row(2, DECISION, **ALLOW_ROW),
            raw_row(3, EXECUTION_STARTED, action_digest="e" * 64),
        ],  # digest differs
        [
            raw_row(1, REQUEST_RECEIVED),
            raw_row(2, DECISION, **ALLOW_ROW),
            raw_row(3, EXECUTION_STARTED, action_digest=D),
            raw_row(4, EXECUTION_STARTED, action_digest=D),
        ],
        [
            raw_row(1, REQUEST_RECEIVED),
            raw_row(2, OUTPUT_FILTERED),
        ],  # output without start
        [
            raw_row(1, REQUEST_RECEIVED),
            raw_row(
                2, REQUEST_COMPLETED, reason=INVALID_REQUEST, execution="not_started"
            ),
            raw_row(
                3, REQUEST_COMPLETED, reason=INVALID_REQUEST, execution="not_started"
            ),
        ],
        [
            raw_row(1, REQUEST_RECEIVED),
            raw_row(
                2, REQUEST_COMPLETED, reason=INVALID_REQUEST, execution="not_started"
            ),
            raw_row(3, IDENTITY_RESOLVED),
        ],  # event after completion
        [
            raw_row(1, REQUEST_RECEIVED),
            raw_row(2, DECISION, **ALLOW_ROW),
            raw_row(
                3,
                REQUEST_COMPLETED,
                decision="allow",
                reason=ALLOWED,
                execution="succeeded",
            ),
        ],  # ran without ES
        [
            raw_row(1, REQUEST_RECEIVED),
            raw_row(2, DECISION, decision="deny", reason=UNAUTHORIZED_TOOL),
            raw_row(
                3,
                REQUEST_COMPLETED,
                decision="allow",
                reason=ALLOWED,
                execution="not_started",
            ),
        ],  # contradicts
        [
            raw_row(1, REQUEST_RECEIVED),
            raw_row(2, DECISION, decision="error", reason=INTERNAL_ERROR),
        ],
        [
            raw_row(1, REQUEST_RECEIVED),
            raw_row(2, REQUEST_COMPLETED, reason=INVALID_REQUEST, execution="maybe"),
        ],
        [
            raw_row(1, REQUEST_RECEIVED),
            raw_row(2, REQUEST_COMPLETED, reason=INVALID_REQUEST),
        ],  # no execution
        [raw_row(1, REQUEST_RECEIVED), raw_row(2, "TOOL_EXECUTED")],
        [raw_row(None, REQUEST_RECEIVED)],  # not a committed row
    ],
)
def test_inconsistent_sequences_are_refused(rows):
    with pytest.raises(AuditIntegrityError) as info:
        reconstruct(rows)
    assert info.value.args and isinstance(info.value.args[0], str)


def test_error_events_may_follow_completion():
    rows = [
        raw_row(1, REQUEST_RECEIVED),
        raw_row(2, REQUEST_COMPLETED, reason=INVALID_REQUEST, execution="not_started"),
        raw_row(3, ERROR, reason=INTERNAL_ERROR),
    ]
    assert reconstruct(rows)["r"].execution is NS


def test_reconstruction_does_not_depend_on_policy_or_registry():
    import ast
    import inspect

    from sentinel import audit

    tree = ast.parse(
        inspect.getsource(audit.reconstruct) + inspect.getsource(audit._reconstruct_one)
    )
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert not names & {
        "PolicyEngine",
        "SecurityPolicy",
        "ToolRegistry",
        "IdentityStore",
    }


def test_reconstruction_never_reports_a_denial_for_a_refusal(log):
    for i, code in enumerate([DUPLICATE_TOOL_CALL, INVALID_REQUEST, INTERNAL_ERROR]):
        r = f"r{i}"
        if code == DUPLICATE_TOOL_CALL:
            pre(log, r, ALLOW, ALLOWED)
        else:
            rr(log, r)
        rc(log, r, None, code, NS)
    for s in reconstruct(log.store.read()).values():
        assert s.decision is not DENY and s.completed_decision is None
