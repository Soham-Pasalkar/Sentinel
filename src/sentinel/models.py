"""Core Sentinel models and result semantics (C-03).

Implements decision record C1.2 (request), C1.3 (tool metadata), C1.4/C1.5
(decisions), C1.6 (result model, including the Q-03c internal-error and the
rev. 6 operational-refusal semantics). ``ToolGrant``, ``RateLimit``,
``CapabilityEnvelope`` and ``SecurityContext`` are deliberately absent: they
wait for decision D-24b (C-07).

Key rule: ``decision`` holds only an actual policy decision. Operational
refusals and internal errors carry ``decision=None`` with a specific
``error_code``; a pre-execution ``AUDIT_UNAVAILABLE`` keeps the policy decision
if one was reached. A decision value is never used merely to say that execution
was refused.

All models are frozen, strict (no type coercion) and reject unknown fields.
Validation errors never echo input values (SEC-008). This module is internal:
it is not exported from ``sentinel``.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import IntEnum, StrEnum
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StringConstraints,
    field_validator,
    model_validator,
)

from sentinel.action import AuthorizedAction

__all__ = [
    "Decision",
    "Execution",
    "PipelineResult",
    "SecurityDecision",
    "SecurityFinding",
    "SecurityRequest",
    "Severity",
    "ToolSpec",
]

NonEmptyStr = Annotated[str, StringConstraints(min_length=1)]

# --------------------------------------------------------------------------- codes

INVALID_REQUEST = "INVALID_REQUEST"
INTERNAL_ERROR = "INTERNAL_ERROR"
AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
ACTION_MISMATCH = "ACTION_MISMATCH"
RESTRICTED_PATH = "RESTRICTED_PATH"
DECISION_ALREADY_USED = "DECISION_ALREADY_USED"
DUPLICATE_TOOL_CALL = "DUPLICATE_TOOL_CALL"
GUARD_CAPACITY_EXHAUSTED = "GUARD_CAPACITY_EXHAUSTED"
UNAUTHORIZED_AGENT = "UNAUTHORIZED_AGENT"
UNAUTHORIZED_TOOL = "UNAUTHORIZED_TOOL"
CAPABILITY_EXCEEDED = "CAPABILITY_EXCEEDED"
RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
TOOL_FAILED = "TOOL_FAILED"
OUTPUT_FILTER_FAILED = "OUTPUT_FILTER_FAILED"

#: Error codes allowed when ``decision`` is ``None`` (C1.6 rev. 6 invariant).
NULL_DECISION_CODES = frozenset(
    {
        INVALID_REQUEST,
        INTERNAL_ERROR,
        AUDIT_UNAVAILABLE,
        ACTION_MISMATCH,
        RESTRICTED_PATH,
        DECISION_ALREADY_USED,
        DUPLICATE_TOOL_CALL,
        GUARD_CAPACITY_EXHAUSTED,
    }
)

#: Operational refusals that always carry ``decision=None`` (owner, rev. 6).
REFUSAL_CODES = frozenset(
    {
        INVALID_REQUEST,
        ACTION_MISMATCH,
        RESTRICTED_PATH,
        DECISION_ALREADY_USED,
        DUPLICATE_TOOL_CALL,
        GUARD_CAPACITY_EXHAUSTED,
    }
)

#: Codes that can never be the reason of an actual policy decision.
#: ``RESTRICTED_PATH`` is excluded: it is also a policy reason (C1.5 row 3).
NON_POLICY_REASONS = NULL_DECISION_CODES - {RESTRICTED_PATH}

#: Keys reserved for identity; rejected inside tool arguments (D-04, Q-04b).
RESERVED_ARGUMENT_KEYS = frozenset(
    {"agent_id", "session_id", "auth_token", "request_id", "tool_call_id"}
)

_CONFIG = ConfigDict(
    frozen=True, strict=True, extra="forbid", hide_input_in_errors=True
)


# --------------------------------------------------------------------------- enums


class Decision(StrEnum):
    """An actual policy decision; serialized lowercase (D-24i)."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class Severity(IntEnum):
    """Finding severity, ordered LOW < MEDIUM < HIGH < CRITICAL (D-24c)."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Execution(StrEnum):
    """Whether the tool function ran (C1.6)."""

    NOT_STARTED = "not_started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------- models


class SecurityRequest(BaseModel):
    """A validated tool-call request (C1.1, C1.2).

    ``agent_id`` and ``session_id`` come from trusted application code.
    ``tool_call_id`` is optional, adapter-supplied, and used only by the
    duplicate-call guard; it is never part of the action digest.
    """

    model_config = _CONFIG

    request_id: NonEmptyStr
    received_at: datetime
    agent_id: NonEmptyStr
    session_id: NonEmptyStr
    tool: NonEmptyStr
    arguments: dict[str, Any]
    auth_token: SecretStr | None = Field(default=None, strict=False)
    tool_call_id: NonEmptyStr | None = None

    @field_validator("received_at")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        """Reject naive or non-UTC timestamps."""
        if value.utcoffset() != timedelta(0):
            raise ValueError("received_at must be timezone-aware UTC")
        return value

    @field_validator("arguments")
    @classmethod
    def _reject_reserved_keys(cls, value: dict[str, Any]) -> dict[str, Any]:
        """Reject reserved identity keys inside the tool arguments (Q-04b)."""
        if RESERVED_ARGUMENT_KEYS.intersection(value):
            raise ValueError("arguments contain a reserved identity key")
        return value


class ToolSpec(BaseModel):
    """Security-relevant metadata of a registered tool (C1.3).

    The registry holds the callable beside the spec, never inside it. The
    registered ``name`` defines the tool's identity (D-07).
    """

    model_config = _CONFIG

    name: NonEmptyStr
    arg_schema: type[BaseModel]
    destructive: bool
    path_args: tuple[NonEmptyStr, ...] = ()

    @model_validator(mode="after")
    def _check_schema(self) -> ToolSpec:
        """Require a closed schema whose path arguments are top-level ``str``."""
        if self.arg_schema.model_config.get("extra") != "forbid":
            raise ValueError("arg_schema must forbid extra fields")
        fields = self.arg_schema.model_fields
        for name in self.path_args:
            if name not in fields or fields[name].annotation is not str:
                raise ValueError("path_args must name top-level str fields")
        return self


class SecurityFinding(BaseModel):
    """A detector finding; evidence must already be masked (C1.8, SEC-008)."""

    model_config = _CONFIG

    code: NonEmptyStr
    severity: Severity
    evidence: str


class SecurityDecision(BaseModel):
    """An actual policy decision bound to one exact action (C1.4, C1.5).

    Never constructed for operational refusals or internal errors: those have
    no policy decision.
    """

    model_config = ConfigDict(
        frozen=True,
        strict=True,
        extra="forbid",
        hide_input_in_errors=True,
        arbitrary_types_allowed=True,
    )

    request_id: NonEmptyStr
    decision: Decision
    reason: NonEmptyStr
    policy_version: NonEmptyStr
    finding_codes: tuple[NonEmptyStr, ...] = ()
    risk_score: float | None = None
    action: AuthorizedAction

    @model_validator(mode="after")
    def _check_binding(self) -> SecurityDecision:
        """Bind the decision to its action and keep reasons policy-only."""
        if self.action.request_id != self.request_id:
            raise ValueError("decision and action belong to different requests")
        if self.reason in NON_POLICY_REASONS:
            raise ValueError("reason is not a policy reason")
        return self


class PipelineResult(BaseModel):
    """Outcome of one request (C1.6, rev. 6).

    ``decision`` is the actual policy decision, or ``None`` when an
    operational refusal or an internal error left no applicable decision.
    """

    model_config = ConfigDict(
        frozen=True,
        strict=True,
        extra="forbid",
        hide_input_in_errors=True,
        arbitrary_types_allowed=True,
    )

    request_id: NonEmptyStr
    decision: Decision | None
    reason: NonEmptyStr
    execution: Execution
    output_released: bool
    output: Any = Field(default=None, repr=False)
    audit_complete: bool
    error_code: NonEmptyStr | None = None

    @model_validator(mode="after")
    def _check_invariants(self) -> PipelineResult:
        """Enforce the C1.6 invariants."""
        not_started = self.execution is Execution.NOT_STARTED
        if self.decision is not Decision.ALLOW and not not_started:
            raise ValueError("only an allowed action can have started")
        if self.output_released and not (
            self.execution is Execution.SUCCEEDED and self.audit_complete
        ):
            raise ValueError("output released without success and complete audit")
        if not self.output_released and self.output is not None:
            raise ValueError("output present but not released")
        if self.decision is None:
            if self.error_code not in NULL_DECISION_CODES:
                raise ValueError("decision None requires a refusal or error code")
            if self.reason != self.error_code:
                raise ValueError("decision None requires reason == error_code")
        else:
            if self.error_code in REFUSAL_CODES:
                raise ValueError("an operational refusal carries no decision")
            if self.decision is not Decision.ALLOW:
                if self.reason in NON_POLICY_REASONS:
                    raise ValueError("reason is not a policy reason")
                if self.error_code == INTERNAL_ERROR:
                    raise ValueError("internal error is not a policy decision")
            elif self.error_code == INTERNAL_ERROR and not_started:
                raise ValueError("internal error before execution carries no decision")
        return self
