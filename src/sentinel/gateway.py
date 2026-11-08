"""Request gateway: validation, strict arguments, canonical paths (C-06).

Turns an untrusted raw request mapping into a validated, immutable
``SecurityRequest`` and the ``AuthorizedAction`` candidate that policy
evaluates and the proxy executes (decision record C1.1-C1.4, C2.3-C2.4;
FR-001, FR-003, FR-004; SEC-013).

Steps, in order; each failure raises ``InvalidRequestError`` (an operational
refusal: ``decision=None``, ``INVALID_REQUEST``; never a policy denial):

1. Shape: ``raw`` is a mapping whose keys are exactly ``agent_id``,
   ``session_id``, ``tool``, ``arguments`` and optionally ``auth_token`` and
   ``tool_call_id`` (FR-001, C1.2); unknown keys are refused, as by the
   ``SecurityRequest`` model. ``arguments`` must be a ``dict`` and
   ``auth_token`` a ``str``. The remaining field rules (types, non-empty
   strings, UTC ``received_at``, reserved identity keys inside ``arguments``
   refused rather than stripped, D-04) are the ``SecurityRequest`` model's,
   applied when the request is built in step 5.
2. Tool: the name must be registered in the ``ToolRegistry`` (FR-003).
3. Arguments: validated once against the tool's ``arg_schema`` with
   ``strict=True`` (no coercion; extra keys refused by the schema, D-08).
4. Paths: every ``path_args`` field must be present, and its value is replaced
   by ``paths.canonicalise(value)`` (C2.3, C2.4). Containment is not checked
   here: that is policy (C-08).
5. Action and request: an ``AuthorizedAction`` over the validated arguments
   with the canonical paths, encoded canonically and detached from the
   caller's data; then the ``SecurityRequest`` holding a copy of them.

The action's arguments are the caller's validated values, not a model dump:
schema defaults for omitted fields are not added, and nothing is converted.
``request_id`` and ``received_at`` are assigned by the caller (the pipeline,
C1.1) before validation. Errors carry fixed text only, never input values
(SEC-008); Pydantic errors are not chained.

The gateway decides nothing, executes nothing and writes no audit events.
This module is internal: it is not exported from ``sentinel``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from sentinel.action import AuthorizedAction
from sentinel.exceptions import InvalidRequestError
from sentinel.models import SecurityRequest, ToolSpec
from sentinel.paths import canonicalise
from sentinel.registry import ToolRegistry

__all__ = ["ValidatedRequest", "validate_request"]

_REQUIRED_KEYS = frozenset({"agent_id", "session_id", "tool", "arguments"})
_OPTIONAL_KEYS = frozenset({"auth_token", "tool_call_id"})


@dataclass(frozen=True, slots=True)
class ValidatedRequest:
    """The gateway's output: the request, its action candidate and tool spec.

    ``request.arguments`` and ``action.arguments`` hold the same canonical
    values; the action is authoritative (it is what the digest covers).
    """

    request: SecurityRequest
    action: AuthorizedAction
    spec: ToolSpec


def _request(fields: dict[str, Any]) -> SecurityRequest:
    """Build a ``SecurityRequest``, hiding Pydantic's error text."""
    try:
        return SecurityRequest(**fields)
    except ValidationError:
        raise InvalidRequestError("request is malformed") from None


def validate_request(
    raw: Mapping[str, Any],
    *,
    registry: ToolRegistry,
    request_id: str,
    received_at: datetime,
) -> ValidatedRequest:
    """Validate a raw request and build its action candidate.

    Args:
        raw: the request mapping built by trusted application code; only
            ``tool`` and ``arguments`` may come from the model.
        registry: the registry holding the tool's metadata.
        request_id: the identifier the pipeline assigned to this request.
        received_at: the timezone-aware UTC time the request was received.

    Returns:
        The validated request, its ``AuthorizedAction`` and the ``ToolSpec``.

    Raises:
        InvalidRequestError: the request is malformed, names an unregistered
            tool, carries a reserved key in ``arguments``, fails strict schema
            validation, has an invalid or missing path argument, or contains
            values that cannot be part of an action.
    """
    if not isinstance(raw, Mapping):
        raise InvalidRequestError("request must be a mapping")
    keys = set(raw)
    if not _REQUIRED_KEYS <= keys:
        raise InvalidRequestError("request is missing a required field")
    if not keys <= _REQUIRED_KEYS | _OPTIONAL_KEYS:
        raise InvalidRequestError("request has an unexpected field")
    fields = {key: raw[key] for key in keys}
    arguments = fields["arguments"]
    if type(arguments) is not dict:
        raise InvalidRequestError("arguments must be a dict")
    token = fields.get("auth_token")
    if token is not None and type(token) is not str:
        # SecurityRequest accepts auth_token leniently (so a str can become a
        # SecretStr), which would also decode bytes; the gateway does not.
        raise InvalidRequestError("auth_token must be a string")

    tool = registry.lookup(fields["tool"])
    if tool is None:
        raise InvalidRequestError("tool is not registered")
    spec = tool.spec
    try:
        spec.arg_schema.model_validate(arguments, strict=True)
    except ValidationError:
        # The tool's schema may not hide input values; never pass them on.
        raise InvalidRequestError("arguments do not match the tool schema") from None

    validated = dict(arguments)
    for name in spec.path_args:
        if name not in validated:
            # A tool-side default path would escape every path check.
            raise InvalidRequestError("a path argument is missing")
        validated[name] = canonicalise(validated[name])

    action = AuthorizedAction(
        request_id=request_id,
        agent_id=fields["agent_id"],
        tool=spec.name,
        arguments=validated,
    )
    request = _request(
        {
            **fields,
            "arguments": action.arguments,
            "request_id": request_id,
            "received_at": received_at,
        }
    )
    return ValidatedRequest(request=request, action=action, spec=spec)
