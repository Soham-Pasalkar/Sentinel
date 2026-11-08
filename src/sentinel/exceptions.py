"""Sentinel exception hierarchy (C-03; requirement FR-018).

Every exception raised by Sentinel's API is a ``SentinelError``. Exceptions for
actual policy decisions (``ActionDenied``, ``ApprovalRequired``) are kept apart
from exceptions for operational refusals (``ExecutionRefused``) and internal
errors (``InternalEvaluationError``), so a refusal or an internal failure is
never reported as a policy denial (decision record C1.6, C1.8; Q-03c).

Messages carry stable codes only, never argument values, secrets or exception
text from tools (SEC-008).
"""

from __future__ import annotations

__all__ = [
    "ActionDenied",
    "ApprovalRequired",
    "AuditIntegrityError",
    "AuditUnavailableError",
    "ConfigurationError",
    "ExecutionRefused",
    "InternalEvaluationError",
    "InvalidRequestError",
    "RegistrationError",
    "SentinelError",
    "ToolExecutionError",
]


class SentinelError(Exception):
    """Base class for every exception raised by Sentinel."""


class InvalidRequestError(SentinelError):
    """A request or one of its values is invalid (``INVALID_REQUEST``)."""


class ConfigurationError(SentinelError):
    """Sentinel was configured with invalid or unsafe settings."""


class RegistrationError(SentinelError):
    """A tool or agent registration was rejected."""


class ActionDenied(SentinelError):
    """Policy denied the action (``decision="deny"``).

    Used only for actual policy decisions, never for operational refusals.
    """

    def __init__(self, reason: str) -> None:
        """Record the policy reason code."""
        super().__init__(reason)
        self.reason = reason


class ApprovalRequired(SentinelError):
    """Policy requires approval (``decision="require_approval"``); not executed."""

    def __init__(self, reason: str) -> None:
        """Record the policy reason code."""
        super().__init__(reason)
        self.reason = reason


class ExecutionRefused(SentinelError):
    """Execution was refused for an operational reason, not by policy.

    Covers ``decision=None`` refusals such as ``INVALID_REQUEST``,
    ``ACTION_MISMATCH`` or ``DUPLICATE_TOOL_CALL``. The tool was not executed.
    """

    def __init__(self, error_code: str) -> None:
        """Record the refusal's error code."""
        super().__init__(error_code)
        self.error_code = error_code


class InternalEvaluationError(SentinelError):
    """An unexpected internal error prevented a decision (``INTERNAL_ERROR``).

    Not a policy denial. Raised only to callers that opt into exceptions.
    """

    def __init__(self, error_code: str = "INTERNAL_ERROR") -> None:
        """Record the error code."""
        super().__init__(error_code)
        self.error_code = error_code


class AuditUnavailableError(SentinelError):
    """An audit event could not be committed or read (``AUDIT_UNAVAILABLE``).

    Raised by the audit store and logger (C-09). The pipeline (C-11) maps it
    to ``AUDIT_UNAVAILABLE``; a pre-execution failure means no invocation.
    """

    error_code = "AUDIT_UNAVAILABLE"


class AuditIntegrityError(SentinelError, ValueError):
    """Committed audit events for a request are inconsistent (C4.4, I-23)."""


class ToolExecutionError(SentinelError):
    """The tool was allowed but its output is not released.

    ``execution`` states whether the tool ran (``not_started``, ``succeeded``,
    ``failed`` or ``unknown``). ``audit_complete`` states whether every required
    audit event was committed.
    """

    def __init__(
        self, error_code: str, *, execution: str, audit_complete: bool
    ) -> None:
        """Record the error code, execution status and audit completeness."""
        super().__init__(error_code)
        self.error_code = error_code
        self.execution = execution
        self.audit_complete = audit_complete
