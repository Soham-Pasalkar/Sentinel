"""The public Sentinel client (C-12; FR-013, FR-016, D-17, D-24i).

``SentinelClient`` is the supported entry point. It owns one long-lived
pipeline (C-11) for its lifetime and only delegates:

* ``register_tool`` → the tool registry (C-05);
* ``register_agent`` → the identity store (C-07);
* ``evaluate_request`` → the pipeline, which validates, authenticates,
  decides, executes through the proxy and audits every step;
* ``audit_events`` → a bounded, read-only query of the audit store.

The client makes no security decision itself. Tools are invoked only by the
proxy, and audit events are written only by the pipeline. There is no public
async method (D-30) and no way to reach the pipeline, proxy or store through
the client.

Until C-14 the output filter is an explicit pass-through, and until C-13 the
detector finds nothing: neither is a security control yet.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from types import TracebackType
from typing import Any

from pydantic import BaseModel, SecretStr

from sentinel.config import SentinelConfig
from sentinel.exceptions import AuditIntegrityError, InvalidRequestError
from sentinel.models import Decision, Execution, PipelineResult, ToolGrant
from sentinel.pipeline import build_pipeline
from sentinel.policy import SecurityPolicy
from sentinel.proxy import pass_through_filter
from sentinel.registry import _MISSING, ToolRegistry
from sentinel.store import AuditRow

__all__ = ["MAX_AUDIT_EVENTS", "AuditEvent", "SentinelClient"]

#: Hard cap on events returned by one ``audit_events`` call (D-17). A v1 API
#: safeguard, not a retention policy.
MAX_AUDIT_EVENTS = 1_000


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One committed audit event, as returned by ``audit_events``.

    Immutable. ``detail`` is the stored JSON text, already masked and bounded
    when the event was written; it is not parsed into Python objects.
    """

    seq: int
    event_id: str
    request_id: str
    event_type: str
    occurred_at: datetime
    agent_id: str | None
    session_id: str | None
    tool: str | None
    decision: Decision | None
    reason: str | None
    policy_version: str | None
    action_digest: str | None
    execution: Execution | None
    detail: str | None
    schema_version: int


def _event(row: AuditRow) -> AuditEvent:
    try:
        decision = None if row.decision is None else Decision(row.decision)
        execution = None if row.execution is None else Execution(row.execution)
        occurred_at = datetime.fromisoformat(row.occurred_at)
    except ValueError:
        raise AuditIntegrityError("audit row has an unknown value") from None
    return AuditEvent(
        seq=int(row.seq or 0),
        event_id=row.event_id,
        request_id=row.request_id,
        event_type=row.event_type,
        occurred_at=occurred_at,
        agent_id=row.agent_id,
        session_id=row.session_id,
        tool=row.tool,
        decision=decision,
        reason=row.reason,
        policy_version=row.policy_version,
        action_digest=row.action_digest,
        execution=execution,
        detail=row.detail,
        schema_version=row.schema_version,
    )


class SentinelClient:
    """Evaluates and executes agent tool calls under a ``SecurityPolicy``.

    Construction opens the audit store: by default the durable file
    ``sentinel_audit.db`` in the working directory (D-11). Call ``close()``
    (or use ``with``) to release it. Register tools first, then agents.
    """

    def __init__(
        self, policy: SecurityPolicy, config: SentinelConfig | None = None
    ) -> None:
        """Create a client.

        Args:
            policy: the policy every request is evaluated against.
            config: settings (audit path, credential requirement, guard
                limits); ``SentinelConfig()`` defaults if omitted.

        Raises:
            ConfigurationError: invalid policy, configuration or audit store.
        """
        if config is None:
            config = SentinelConfig()
        self._pipeline = build_pipeline(
            config,
            registry=ToolRegistry(),
            policy=policy,
            output_filter=pass_through_filter,
        )

    def register_tool(
        self,
        name: str,
        *,
        arg_schema: type[BaseModel] = _MISSING,
        destructive: bool = _MISSING,
        path_args: tuple[str, ...] = (),
        sync_fn: Callable[..., Any] | None = None,
        async_fn: Callable[..., Any] | None = None,
    ) -> None:
        """Register a tool once (C-05). It is never called here.

        Args:
            name: the tool's unique name and identity.
            arg_schema: Pydantic model of the arguments; must forbid extras.
                Required: omitting it raises ``RegistrationError`` (C-05).
            destructive: whether the tool is destructive. Required, no
                default: omitting it raises ``RegistrationError`` (D-06).
            path_args: names of top-level ``str`` fields holding paths.
            sync_fn: the sync entry point.
            async_fn: the async entry point (used by framework adapters).

        Raises:
            RegistrationError: invalid or duplicate registration.
            ConfigurationError: a path tool on Windows (D-21).
        """
        self._pipeline.registry.register(
            name,
            arg_schema=arg_schema,
            destructive=destructive,
            path_args=path_args,
            sync_fn=sync_fn,
            async_fn=async_fn,
        )

    def register_agent(
        self,
        agent_id: str,
        *,
        credential: SecretStr | None = None,
        user_id: str | None = None,
        disabled: bool = False,
        grants: Iterable[ToolGrant] = (),
    ) -> None:
        """Register an agent once, with its grants (C-07, D-24b).

        Args:
            agent_id: the agent's unique identifier.
            credential: the agent's token; stored only as a digest.
            user_id: the user the agent acts for, if any.
            disabled: a disabled agent is never authorized.
            grants: whole-tool grants for already registered tools.

        Raises:
            RegistrationError: invalid or duplicate registration.
            ConfigurationError: invalid path prefixes or a rate-limited grant.
        """
        self._pipeline.identity.register_agent(
            agent_id,
            credential=credential,
            user_id=user_id,
            disabled=disabled,
            grants=grants,
        )

    def evaluate_request(self, raw: Mapping[str, Any]) -> PipelineResult:
        """Evaluate one tool call and, if allowed, execute it.

        ``raw`` is built by trusted application code: ``agent_id`` and
        ``session_id`` come from the application, and only ``tool`` and
        ``arguments`` from the model. Returns for every request outcome,
        including denial, approval required, refusals, tool and filter
        failures and audit failures.

        Raises:
            TypeError: ``raw`` is not a mapping (API misuse; I-32).
        """
        if not isinstance(raw, Mapping):
            raise TypeError("raw must be a mapping")
        return self._pipeline.evaluate(raw)

    def audit_events(
        self, request_id: str | None = None, limit: int = 100
    ) -> tuple[AuditEvent, ...]:
        """Return committed audit events in ``seq`` order (D-17).

        Read-only. At most ``limit`` events (the first ones), 1 to 1,000.

        Raises:
            TypeError: ``request_id`` is not a ``str`` or ``limit`` not an int.
            InvalidRequestError: empty ``request_id`` or ``limit`` out of range.
            AuditUnavailableError: the store is closed or cannot be read.
        """
        if request_id is not None and type(request_id) is not str:
            raise TypeError("request_id must be a str or None")
        if request_id == "":
            raise InvalidRequestError("request_id must not be empty")
        if type(limit) is not int:
            raise TypeError("limit must be an int")
        if not 1 <= limit <= MAX_AUDIT_EVENTS:
            raise InvalidRequestError("limit must be between 1 and 1000")
        rows = self._pipeline.audit.store.read(request_id, limit=limit)
        return tuple(_event(row) for row in rows)

    def close(self) -> None:
        """Close the audit store. Idempotent.

        Afterwards ``evaluate_request`` returns ``AUDIT_UNAVAILABLE`` results
        (nothing runs) and ``audit_events`` raises ``AuditUnavailableError``.
        """
        self._pipeline.close()

    def __enter__(self) -> SentinelClient:
        """Use the client as a context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the client."""
        self.close()
