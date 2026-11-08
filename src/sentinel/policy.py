"""Policy engine: the deterministic, default-deny decision (C-08).

Implements decision record C1.5 with D-24a (default deny through explicit
grants), D-24b (whole-tool grants), D-24c (order and tie-break), D-06
(destructive tools need approval) and D-15 (``tool_spec`` passed explicitly;
no Tool-Abuse detector). First matching row wins:

1. ``context.authorized`` is false → DENY ``UNAUTHORIZED_AGENT``
2. no grant for the tool in the envelope → DENY ``UNAUTHORIZED_TOOL``
3. a path argument outside the grant's prefixes → DENY ``RESTRICTED_PATH``
   (every ``path_args`` value is checked with ``paths.is_contained``; an empty
   prefix list contains nothing, ``("/",)`` contains every absolute path)
4. a finding with severity ≥ ``deny_at_severity`` → DENY with the code of the
   highest-severity such finding; ties → the smallest code
5. rate limits: M4 (C-15); not evaluated here
6. destructive tool and ``require_approval_for_destructive`` → REQUIRE_APPROVAL
   ``DESTRUCTIVE_TOOL``
7. otherwise → ALLOW ``ALLOWED``

A grant is necessary, never sufficient: it only lets evaluation reach rows
3-7. The decision embeds the exact ``AuthorizedAction`` it was evaluated for.
``finding_codes`` lists every finding's code by descending severity, then
ascending code, so the input order never matters. ``risk_score`` is left
``None`` (informational, no approved formula; interpretation I-11).

Evaluation is pure: no I/O, clock, randomness, registry or logging. Inputs
that do not belong to one request raise ``TypeError`` or ``ValueError``
instead of producing a decision (I-10); the pipeline reports that as
``INTERNAL_ERROR``, never as DENY. This module is internal.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from sentinel.action import AuthorizedAction, action_digest
from sentinel.exceptions import ConfigurationError, InvalidRequestError
from sentinel.models import (
    ALLOWED,
    DESTRUCTIVE_TOOL,
    RESTRICTED_PATH,
    UNAUTHORIZED_AGENT,
    UNAUTHORIZED_TOOL,
    Decision,
    NonEmptyStr,
    SecurityContext,
    SecurityDecision,
    SecurityFinding,
    SecurityRequest,
    Severity,
    ToolSpec,
)
from sentinel.paths import is_contained

__all__ = ["PolicyEngine", "SecurityPolicy"]


class SecurityPolicy(BaseModel):
    """Policy settings, constructed in code (FR-009).

    Credentials are identity configuration, not policy (I-6). Invalid values
    raise ``ConfigurationError``; there is no permissive fallback.
    """

    model_config = ConfigDict(
        frozen=True, strict=True, extra="forbid", hide_input_in_errors=True
    )

    version: NonEmptyStr
    deny_at_severity: Severity = Severity.HIGH
    require_approval_for_destructive: bool = True

    def __init__(self, /, **data: Any) -> None:
        """Validate the settings; raise ``ConfigurationError`` if invalid."""
        try:
            super().__init__(**data)
        except ValidationError:
            raise ConfigurationError("invalid security policy") from None


def _sorted_findings(findings: object) -> tuple[SecurityFinding, ...]:
    """Return the findings by descending severity, then ascending code."""
    if isinstance(findings, str | bytes) or not isinstance(findings, Iterable):
        raise TypeError("findings must be a collection of SecurityFinding")
    items = tuple(findings)
    if any(type(item) is not SecurityFinding for item in items):
        raise TypeError("findings must be a collection of SecurityFinding")
    return tuple(sorted(items, key=lambda f: (-f.severity, f.code)))


def _check_inputs(
    request: SecurityRequest,
    context: SecurityContext,
    tool_spec: ToolSpec,
    action: AuthorizedAction,
) -> None:
    """Refuse inputs that do not describe one and the same request (I-10)."""
    for value, cls in (
        (request, SecurityRequest),
        (context, SecurityContext),
        (tool_spec, ToolSpec),
        (action, AuthorizedAction),
    ):
        if type(value) is not cls:
            raise TypeError("policy input has the wrong type")
    if not tool_spec.name == request.tool == action.tool:
        raise ValueError("tool_spec does not describe the requested tool")
    if request.request_id != action.request_id:
        raise ValueError("request and action have different request ids")
    if not request.agent_id == action.agent_id == context.agent_id:
        raise ValueError("request, action and context name different agents")
    try:
        digest = action_digest(
            request_id=request.request_id,
            agent_id=request.agent_id,
            tool=request.tool,
            arguments=request.arguments,
        )
    except InvalidRequestError:
        raise ValueError("request arguments cannot form an action") from None
    if digest != action.digest:
        raise ValueError("request arguments differ from the action's")
    arguments = action.arguments
    if any(name not in arguments for name in tool_spec.path_args):
        raise ValueError("action is missing a path argument")


class PolicyEngine:
    """Evaluates one request against a ``SecurityPolicy``."""

    def __init__(self, policy: SecurityPolicy) -> None:
        """Create an engine for ``policy``.

        Raises:
            ConfigurationError: ``policy`` is not a ``SecurityPolicy``.
        """
        if type(policy) is not SecurityPolicy:
            raise ConfigurationError("policy must be a SecurityPolicy")
        self._policy = policy

    @property
    def policy(self) -> SecurityPolicy:
        """The policy this engine applies."""
        return self._policy

    def evaluate(
        self,
        request: SecurityRequest,
        context: SecurityContext,
        findings: Iterable[SecurityFinding],
        tool_spec: ToolSpec,
        *,
        action: AuthorizedAction,
    ) -> SecurityDecision:
        """Decide one request (C1.5) and bind the decision to ``action``.

        Args:
            request: the validated request (C-06).
            context: the identity facts for the request's agent (C-07).
            findings: the detector's findings; may be empty.
            tool_spec: the registry's spec for the requested tool (D-15).
            action: the gateway's action candidate for this request (I-9).

        Raises:
            TypeError: an input has the wrong type.
            ValueError: the inputs do not belong to one request.
        """
        _check_inputs(request, context, tool_spec, action)
        ordered = _sorted_findings(findings)
        decision, reason = self._decide(context, tool_spec, action, ordered)
        return SecurityDecision(
            request_id=action.request_id,
            decision=decision,
            reason=reason,
            policy_version=self._policy.version,
            finding_codes=tuple(f.code for f in ordered),
            action=action,
        )

    def _decide(
        self,
        context: SecurityContext,
        tool_spec: ToolSpec,
        action: AuthorizedAction,
        ordered: tuple[SecurityFinding, ...],
    ) -> tuple[Decision, str]:
        """Apply rows 1-7 in order; the first matching row wins."""
        if not context.authorized:
            return Decision.DENY, UNAUTHORIZED_AGENT
        envelope = context.envelope
        grant = None if envelope is None else envelope.grant_for(tool_spec.name)
        if grant is None:
            return Decision.DENY, UNAUTHORIZED_TOOL
        if tool_spec.path_args:
            arguments = action.arguments
            for name in tool_spec.path_args:
                if not is_contained(arguments[name], grant.allowed_path_prefixes):
                    return Decision.DENY, RESTRICTED_PATH
        # Sorted by severity, then code: the first finding decides row 4.
        if ordered and ordered[0].severity >= self._policy.deny_at_severity:
            return Decision.DENY, ordered[0].code
        if tool_spec.destructive and self._policy.require_approval_for_destructive:
            return Decision.REQUIRE_APPROVAL, DESTRUCTIVE_TOOL
        return Decision.ALLOW, ALLOWED
