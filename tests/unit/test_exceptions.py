import pytest

from sentinel.action import ActionEncodingError
from sentinel.exceptions import (
    ActionDenied,
    ApprovalRequired,
    ConfigurationError,
    ExecutionRefused,
    InternalEvaluationError,
    InvalidRequestError,
    RegistrationError,
    SentinelError,
    ToolExecutionError,
)

ALL = [
    ActionDenied,
    ApprovalRequired,
    ConfigurationError,
    ExecutionRefused,
    InternalEvaluationError,
    InvalidRequestError,
    RegistrationError,
    ToolExecutionError,
]


@pytest.mark.parametrize("cls", ALL)
def test_every_exception_is_a_sentinel_error(cls):
    assert issubclass(cls, SentinelError)


@pytest.mark.parametrize("cls", [ExecutionRefused, InternalEvaluationError])
def test_refusals_and_internal_errors_are_not_policy_denials(cls):
    assert not issubclass(cls, ActionDenied)
    assert not issubclass(cls, ApprovalRequired)


def test_exception_attributes():
    assert ActionDenied("UNAUTHORIZED_TOOL").reason == "UNAUTHORIZED_TOOL"
    assert ExecutionRefused("DUPLICATE_TOOL_CALL").error_code == "DUPLICATE_TOOL_CALL"
    assert InternalEvaluationError().error_code == "INTERNAL_ERROR"
    err = ToolExecutionError(
        "AUDIT_UNAVAILABLE", execution="succeeded", audit_complete=False
    )
    assert (err.error_code, err.execution, err.audit_complete) == (
        "AUDIT_UNAVAILABLE",
        "succeeded",
        False,
    )


def test_action_encoding_error_is_an_invalid_request_and_still_a_value_error():
    assert issubclass(ActionEncodingError, InvalidRequestError)
    assert issubclass(ActionEncodingError, ValueError)
