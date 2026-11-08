from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

import sentinel
from sentinel.action import AuthorizedAction
from sentinel.models import (
    NULL_DECISION_CODES,
    RESERVED_ARGUMENT_KEYS,
    Decision,
    Execution,
    PipelineResult,
    SecurityDecision,
    SecurityFinding,
    SecurityRequest,
    Severity,
    ToolSpec,
)

CANARY = "CANARY-models-4c1d"


def request(**overrides):
    fields = {
        "request_id": "req-1",
        "received_at": datetime(2026, 10, 28, 12, 0, tzinfo=UTC),
        "agent_id": "agent-1",
        "session_id": "sess-1",
        "tool": "read_file",
        "arguments": {"path": "/workspace/a.txt"},
    }
    fields.update(overrides)
    return SecurityRequest(**fields)


class ReadArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    path: str
    limit: int = 10


class OpenArgs(BaseModel):
    path: str


def action(request_id="req-1"):
    return AuthorizedAction(
        request_id=request_id, agent_id="agent-1", tool="read_file", arguments={}
    )


def result(**overrides):
    fields = {
        "request_id": "req-1",
        "decision": Decision.ALLOW,
        "reason": "POLICY",
        "execution": Execution.SUCCEEDED,
        "output_released": True,
        "output": "data",
        "audit_complete": True,
        "error_code": None,
    }
    fields.update(overrides)
    return PipelineResult(**fields)


# --- enums


def test_decision_values_are_exactly_the_three_lowercase_policy_values():
    assert {d.value for d in Decision} == {"allow", "deny", "require_approval"}
    assert "error" not in {d.value for d in Decision}


def test_severity_order_and_execution_values():
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert {e.value for e in Execution} == {
        "not_started",
        "succeeded",
        "failed",
        "unknown",
    }


# --- SecurityRequest


def test_valid_request_and_frozen():
    req = request(tool_call_id="call_1")
    assert req.tool_call_id == "call_1"
    with pytest.raises(ValidationError):
        req.agent_id = "other"


@pytest.mark.parametrize(
    "overrides",
    [
        {"agent_id": 7},  # strict: no int -> str coercion
        {"tool": ""},
        {"session_id": ""},
        {"arguments": [("path", "/x")]},
        {"received_at": "2026-10-28T12:00:00+00:00"},  # strict: no str -> datetime
        {"received_at": datetime(2026, 10, 28, 12, 0)},  # naive
        {
            "received_at": datetime(
                2026, 10, 28, 12, 0, tzinfo=timezone(timedelta(hours=2))
            )
        },
        {"unexpected": True},  # extra field
    ],
)
def test_request_rejects_invalid_values_without_coercion(overrides):
    with pytest.raises(ValidationError):
        request(**overrides)


def test_request_requires_a_session_for_tool_call_id():
    fields = {
        "request_id": "req-1",
        "received_at": datetime(2026, 10, 28, tzinfo=UTC),
        "agent_id": "agent-1",
        "tool": "read_file",
        "arguments": {},
        "tool_call_id": "call_1",
    }
    with pytest.raises(ValidationError):
        SecurityRequest(**fields)


@pytest.mark.parametrize("key", sorted(RESERVED_ARGUMENT_KEYS))
def test_reserved_identity_keys_in_arguments_are_rejected_not_stripped(key):
    with pytest.raises(ValidationError):
        request(arguments={"path": "/x", key: "spoofed"})


def test_auth_token_is_secret_in_repr_json_and_errors():
    req = request(auth_token=CANARY)
    assert req.auth_token.get_secret_value() == CANARY
    assert CANARY not in repr(req)
    assert CANARY not in req.model_dump_json()
    with pytest.raises(ValidationError) as err:
        request(auth_token=CANARY, agent_id=["not", CANARY])
    assert CANARY not in str(err.value)


# --- ToolSpec


def test_tool_spec_valid():
    spec = ToolSpec(
        name="read_file", arg_schema=ReadArgs, destructive=False, path_args=("path",)
    )
    assert spec.destructive is False


def test_destructive_and_schema_are_required():
    with pytest.raises(ValidationError):
        ToolSpec(name="read_file", arg_schema=ReadArgs)
    with pytest.raises(ValidationError):
        ToolSpec(name="read_file", destructive=True)


@pytest.mark.parametrize(
    "overrides",
    [
        {"destructive": "true"},  # strict: no str -> bool
        {"destructive": 1},
        {"arg_schema": OpenArgs},  # schema must forbid extra fields
        {"arg_schema": dict},
        {"path_args": ("missing",)},
        {"path_args": ("limit",)},  # not a str field
        {"path_args": ["path"]},  # strict: tuple required
    ],
)
def test_tool_spec_rejects_invalid_metadata(overrides):
    fields = {"name": "read_file", "arg_schema": ReadArgs, "destructive": False}
    fields.update(overrides)
    with pytest.raises(ValidationError):
        ToolSpec(**fields)


# --- SecurityFinding


def test_finding_severity_is_strict():
    assert SecurityFinding(code="PROMPT_INJECTION", severity=Severity.HIGH, evidence="")
    with pytest.raises(ValidationError):
        SecurityFinding(code="PROMPT_INJECTION", severity=3, evidence="")


# --- SecurityDecision


def test_decision_binds_to_its_action():
    d = SecurityDecision(
        request_id="req-1",
        decision=Decision.ALLOW,
        reason="POLICY",
        policy_version="v1",
        action=action(),
    )
    assert d.action.digest == action().digest
    with pytest.raises(ValidationError):
        SecurityDecision(
            request_id="req-1",
            decision=Decision.ALLOW,
            reason="POLICY",
            policy_version="v1",
            action=action("req-2"),
        )


def test_policy_decision_cannot_be_none_or_carry_non_policy_reason():
    base = {"request_id": "req-1", "policy_version": "v1", "action": action()}
    with pytest.raises(ValidationError):
        SecurityDecision(decision=None, reason="POLICY", **base)
    for reason in ("INTERNAL_ERROR", "INVALID_REQUEST", "ACTION_MISMATCH"):
        with pytest.raises(ValidationError):
            SecurityDecision(decision=Decision.DENY, reason=reason, **base)
    assert SecurityDecision(decision=Decision.DENY, reason="RESTRICTED_PATH", **base)


# --- PipelineResult: the C1.6 table (rev. 6)

NOT_RUN = {"execution": Execution.NOT_STARTED, "output_released": False, "output": None}

VALID_ROWS = {
    "invalid request": {
        "decision": None,
        "reason": "INVALID_REQUEST",
        "error_code": "INVALID_REQUEST",
        **NOT_RUN,
    },
    "internal error before execution": {
        "decision": None,
        "reason": "INTERNAL_ERROR",
        "error_code": "INTERNAL_ERROR",
        **NOT_RUN,
    },
    "audit unavailable before policy": {
        "decision": None,
        "reason": "AUDIT_UNAVAILABLE",
        "error_code": "AUDIT_UNAVAILABLE",
        "audit_complete": False,
        **NOT_RUN,
    },
    "audit unavailable after allow": {
        "decision": Decision.ALLOW,
        "error_code": "AUDIT_UNAVAILABLE",
        "audit_complete": False,
        **NOT_RUN,
    },
    "audit unavailable after deny": {
        "decision": Decision.DENY,
        "reason": "UNAUTHORIZED_TOOL",
        "error_code": "AUDIT_UNAVAILABLE",
        "audit_complete": False,
        **NOT_RUN,
    },
    "action mismatch": {
        "decision": None,
        "reason": "ACTION_MISMATCH",
        "error_code": "ACTION_MISMATCH",
        **NOT_RUN,
    },
    "path changed": {
        "decision": None,
        "reason": "RESTRICTED_PATH",
        "error_code": "RESTRICTED_PATH",
        **NOT_RUN,
    },
    "decision already used": {
        "decision": None,
        "reason": "DECISION_ALREADY_USED",
        "error_code": "DECISION_ALREADY_USED",
        **NOT_RUN,
    },
    "duplicate tool call": {
        "decision": None,
        "reason": "DUPLICATE_TOOL_CALL",
        "error_code": "DUPLICATE_TOOL_CALL",
        **NOT_RUN,
    },
    "guard capacity": {
        "decision": None,
        "reason": "GUARD_CAPACITY_EXHAUSTED",
        "error_code": "GUARD_CAPACITY_EXHAUSTED",
        **NOT_RUN,
    },
    "policy deny on path": {
        "decision": Decision.DENY,
        "reason": "RESTRICTED_PATH",
        **NOT_RUN,
    },
    "approval required": {
        "decision": Decision.REQUIRE_APPROVAL,
        "reason": "DESTRUCTIVE",
        **NOT_RUN,
    },
    "closing audit failed after success": {
        "execution": Execution.SUCCEEDED,
        "output_released": False,
        "output": None,
        "audit_complete": False,
        "error_code": "AUDIT_UNAVAILABLE",
    },
    "tool failed": {
        "execution": Execution.FAILED,
        "output_released": False,
        "output": None,
        "error_code": "TOOL_FAILED",
    },
    "internal error after execution": {
        "execution": Execution.SUCCEEDED,
        "output_released": False,
        "output": None,
        "error_code": "INTERNAL_ERROR",
    },
    "interruption recorded as unknown": {
        "execution": Execution.UNKNOWN,
        "output_released": False,
        "output": None,
    },
    "allowed and released": {},
}


@pytest.mark.parametrize("name", list(VALID_ROWS))
def test_valid_result_rows(name):
    r = result(**VALID_ROWS[name])
    if r.decision is None:
        assert r.execution is Execution.NOT_STARTED
        assert r.output_released is False and r.output is None


INVALID_ROWS = {
    "internal error as deny": {
        "decision": Decision.DENY,
        "reason": "INTERNAL_ERROR",
        "error_code": "INTERNAL_ERROR",
        **NOT_RUN,
    },
    "deny with internal error code": {
        "decision": Decision.DENY,
        "reason": "UNAUTHORIZED_TOOL",
        "error_code": "INTERNAL_ERROR",
        **NOT_RUN,
    },
    "refusal as deny": {
        "decision": Decision.DENY,
        "reason": "ACTION_MISMATCH",
        "error_code": "ACTION_MISMATCH",
        **NOT_RUN,
    },
    "invalid request as deny": {
        "decision": Decision.DENY,
        "reason": "INVALID_REQUEST",
        **NOT_RUN,
    },
    "refusal with allow": {
        "decision": Decision.ALLOW,
        "error_code": "DUPLICATE_TOOL_CALL",
        **NOT_RUN,
    },
    "path changed with allow": {
        "decision": Decision.ALLOW,
        "error_code": "RESTRICTED_PATH",
        **NOT_RUN,
    },
    "approval with internal error": {
        "decision": Decision.REQUIRE_APPROVAL,
        "reason": "DESTRUCTIVE",
        "error_code": "INTERNAL_ERROR",
        **NOT_RUN,
    },
    "internal error with allow before execution": {
        "decision": Decision.ALLOW,
        "error_code": "INTERNAL_ERROR",
        **NOT_RUN,
    },
    "none without code": {
        "decision": None,
        "reason": "X",
        "error_code": None,
        **NOT_RUN,
    },
    "none with non-refusal code": {
        "decision": None,
        "reason": "TOOL_FAILED",
        "error_code": "TOOL_FAILED",
        **NOT_RUN,
    },
    "none with reason mismatch": {
        "decision": None,
        "reason": "POLICY",
        "error_code": "INVALID_REQUEST",
        **NOT_RUN,
    },
    "none but executed": {
        "decision": None,
        "reason": "INTERNAL_ERROR",
        "error_code": "INTERNAL_ERROR",
        "execution": Execution.SUCCEEDED,
        "output_released": False,
        "output": None,
    },
    "deny but executed": {
        "decision": Decision.DENY,
        "reason": "UNAUTHORIZED_TOOL",
        "execution": Execution.FAILED,
        "output_released": False,
        "output": None,
    },
    "deny with unknown": {
        "decision": Decision.DENY,
        "reason": "UNAUTHORIZED_TOOL",
        "execution": Execution.UNKNOWN,
        "output_released": False,
        "output": None,
    },
    "released with incomplete audit": {"audit_complete": False},
    "released after failure": {"execution": Execution.FAILED},
    "output without release": {"output_released": False, "output": "data"},
    "released for a refusal": {
        "decision": None,
        "reason": "INVALID_REQUEST",
        "error_code": "INVALID_REQUEST",
        "execution": Execution.NOT_STARTED,
    },
    "decision string error": {"decision": "error", **NOT_RUN},
    "decision string coercion": {"decision": "allow"},
}


@pytest.mark.parametrize("name", list(INVALID_ROWS))
def test_invalid_result_rows_are_rejected(name):
    with pytest.raises(ValidationError):
        result(**INVALID_ROWS[name])


def test_every_null_decision_code_is_accepted_only_with_none():
    for code in NULL_DECISION_CODES:
        assert result(decision=None, reason=code, error_code=code, **NOT_RUN)


def test_result_serializes_lowercase_and_hides_output_in_repr():
    r = result(output=CANARY)
    assert '"decision":"allow"' in r.model_dump_json()
    assert CANARY not in repr(r)
    refused = result(
        decision=None, reason="INVALID_REQUEST", error_code="INVALID_REQUEST", **NOT_RUN
    )
    assert '"decision":null' in refused.model_dump_json()


def test_models_are_not_exported_publicly():
    # C-12 deliberately exports the result and enum types the public client
    # signatures use (FR-016, FR-017; I-33); the other models stay internal.
    internal = {
        "SecurityRequest",
        "ToolSpec",
        "SecurityDecision",
        "SecurityFinding",
        "CapabilityEnvelope",
        "SecurityContext",
        "RateLimit",
    }
    assert not internal & set(sentinel.__all__)
    assert not any(hasattr(sentinel, name) for name in internal)
    assert {"PipelineResult", "Decision", "Execution", "Severity", "ToolGrant"} <= set(
        sentinel.__all__
    )
