"""Pipeline: the sole orchestrator and the only audit writer (C-11; D-16).

``Pipeline.evaluate(raw)`` runs one request through gateway (C-06), identity
(C-07), detector (stub until C-13), policy (C-08) and proxy (C-10), commits
every C4.3 event through ``AuditLogger`` (C-09) before the next stage, and
returns a ``PipelineResult`` (C1.6). ``await Pipeline.evaluate_async(raw)``
is the internal async counterpart (D-30): blocking stages run in a worker
thread, and an async-native tool is awaited on the caller's loop (D-20).

Event order (C4.3)::

    REQUEST_RECEIVED
      ├─ invalid ─► REQUEST_COMPLETED(None, INVALID_REQUEST)
      └─ IDENTITY_RESOLVED → FINDING×n → DECISION
            ├─ deny / require_approval ─► REQUEST_COMPLETED
            ├─ allow, claim refused ─► REQUEST_COMPLETED(None, <code>)
            └─ allow → EXECUTION_STARTED → [ERROR] → [OUTPUT_FILTERED |
               ERROR, OUTPUT_WITHHELD] → REQUEST_COMPLETED

An unexpected exception before execution writes ERROR (D-29 fields) and
REQUEST_COMPLETED(None, INTERNAL_ERROR). After a failed audit write no
further event is written (I-25), and the tool is never invoked if that write
came before EXECUTION_STARTED (SEC-005). ``audit_complete`` requires every
required event to be committed to a durable store (C4.5). Output is released
only when the tool succeeded, the filter released it and the audit is
complete. A claimed request is never invoked twice (C1.7).

A ``BaseException`` after the tool was entered gets one synchronous,
bounded, best-effort REQUEST_COMPLETED(``unknown``) and is re-raised
unchanged (C1.6). This module is internal: it is not exported, and the async
entry is not a stable API (D-30).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

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
    diagnostics_detail,
    mask,
)
from sentinel.config import SentinelConfig
from sentinel.detector import NullDetector
from sentinel.exceptions import (
    AuditUnavailableError,
    ConfigurationError,
    InvalidRequestError,
)
from sentinel.gateway import ValidatedRequest, validate_request
from sentinel.identity import IdentityStore
from sentinel.models import (
    AUDIT_UNAVAILABLE,
    INTERNAL_ERROR,
    INVALID_REQUEST,
    OUTPUT_FILTER_FAILED,
    TOOL_FAILED,
    Decision,
    Execution,
    PipelineResult,
)
from sentinel.policy import PolicyEngine, SecurityPolicy
from sentinel.proxy import (
    ExecutionProxy,
    ProxyOutcome,
    ProxyRun,
    ToolCallGuard,
    _diagnostics,
)
from sentinel.registry import ToolRegistry
from sentinel.store import AuditStore

__all__ = ["Pipeline", "build_pipeline"]

_LOG = logging.getLogger(__name__)

_STATE_EXECUTION = {
    "entered": Execution.UNKNOWN,
    "interrupted": Execution.UNKNOWN,
    "completed": Execution.SUCCEEDED,
    "failed": Execution.FAILED,
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _new_request_id() -> str:
    return str(uuid.uuid4())


def _column(value: object) -> str | None:
    """A raw identity field as a bounded, masked column value, or ``None``."""
    if type(value) is not str or not value:
        return None
    return mask(value)


@dataclass
class _Flow:
    """Mutable per-request state, used only by the pipeline."""

    request_id: str
    received_at: datetime
    columns: dict[str, str | None] = field(default_factory=dict)
    audit_ok: bool = True
    received: bool = False
    validated: ValidatedRequest | None = None
    decision: Decision | None = None
    policy_reason: str | None = None
    digest: str | None = None
    run: ProxyRun | None = None
    started: bool = False


@dataclass(frozen=True)
class _Prepared:
    """A request whose EXECUTION_STARTED is committed and whose run is claimed."""

    flow: _Flow
    run: ProxyRun
    mode: str


class Pipeline:
    """Runs requests through every Sentinel stage, in the C4.3 order."""

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        identity: IdentityStore,
        policy: PolicyEngine,
        audit: AuditLogger,
        proxy: ExecutionProxy,
        detector: Any = None,
        clock: Callable[[], datetime] = _utc_now,
        new_request_id: Callable[[], str] = _new_request_id,
    ) -> None:
        """Create a pipeline from long-lived components (one per process).

        Raises:
            ConfigurationError: a component has the wrong type.
        """
        for value, cls in (
            (registry, ToolRegistry),
            (identity, IdentityStore),
            (policy, PolicyEngine),
            (audit, AuditLogger),
            (proxy, ExecutionProxy),
        ):
            if type(value) is not cls:
                raise ConfigurationError("pipeline component has the wrong type")
        if detector is None:
            detector = NullDetector()
        if not callable(getattr(detector, "analyze", None)):
            raise ConfigurationError("detector must have an analyze method")
        self._registry = registry
        self._identity = identity
        self._policy = policy
        self._audit = audit
        self._proxy = proxy
        self._detector = detector
        self._clock = clock
        self._new_request_id = new_request_id

    @property
    def registry(self) -> ToolRegistry:
        """The tool registry (tools are registered before agents, I-1)."""
        return self._registry

    @property
    def identity(self) -> IdentityStore:
        """The identity store (agents are registered at setup, I-7)."""
        return self._identity

    @property
    def audit(self) -> AuditLogger:
        """The audit logger."""
        return self._audit

    def close(self) -> None:
        """Close the audit store. Later requests report ``AUDIT_UNAVAILABLE``."""
        self._audit.store.close()

    # --------------------------------------------------------- entries

    def evaluate(self, raw: Mapping[str, Any]) -> PipelineResult:
        """Evaluate and, if allowed, execute one request (sync tools)."""
        prepared = self._prepare(raw, asynchronous=False)
        if isinstance(prepared, PipelineResult):
            return prepared
        try:
            outcome = prepared.run.execute()
        except BaseException as exc:
            self._after_interruption(prepared, exc)
            raise
        return self._complete(prepared, outcome)

    async def evaluate_async(self, raw: Mapping[str, Any]) -> PipelineResult:
        """Internal async counterpart of ``evaluate`` (D-30; not a stable API)."""
        pending = asyncio.ensure_future(
            asyncio.to_thread(self._prepare, raw, asynchronous=True)
        )
        try:
            prepared = await asyncio.shield(pending)
        except asyncio.CancelledError:
            pending.add_done_callback(self._cleanup_after_cancelled_prepare)
            raise
        if isinstance(prepared, PipelineResult):
            return prepared
        run = prepared.run
        if prepared.mode == "async":
            try:
                outcome = await run.execute_async()
            except BaseException as exc:
                self._after_interruption(prepared, exc)
                raise
        else:
            running = asyncio.ensure_future(asyncio.to_thread(run.execute))
            try:
                outcome = await asyncio.shield(running)
            except asyncio.CancelledError:
                # The thread cannot be stopped; finish its audit truthfully.
                running.add_done_callback(
                    lambda task: self._finish_detached(prepared, task)
                )
                raise
            except BaseException as exc:
                self._after_interruption(prepared, exc)
                raise
        return await asyncio.to_thread(self._complete, prepared, outcome)

    # --------------------------------------------------- audit helpers

    def _write(self, flow: _Flow, event_type: str, **fields: Any) -> bool:
        """Commit one event; ``False`` (and audit incomplete) if it failed."""
        if not flow.audit_ok:
            return False
        try:
            self._audit.record(
                event_type, request_id=flow.request_id, **flow.columns, **fields
            )
        except AuditUnavailableError:
            flow.audit_ok = False
            return False
        return True

    def _result(
        self,
        flow: _Flow,
        *,
        decision: Decision | None,
        reason: str,
        execution: Execution,
        error_code: str | None = None,
        output: Any = None,
        released: bool = False,
    ) -> PipelineResult:
        complete = flow.audit_ok and self._audit.store.durable
        released = released and complete
        return PipelineResult(
            request_id=flow.request_id,
            decision=decision,
            reason=reason,
            execution=execution,
            output_released=released,
            output=output if released else None,
            audit_complete=complete,
            error_code=error_code,
        )

    def _audit_failed(
        self, flow: _Flow, execution: Execution = Execution.NOT_STARTED
    ) -> PipelineResult:
        """Result for a failed audit write (C1.7; I-24)."""
        decision = flow.decision
        if decision in (Decision.DENY, Decision.REQUIRE_APPROVAL):
            reason = flow.policy_reason or AUDIT_UNAVAILABLE
        else:
            reason = AUDIT_UNAVAILABLE
        flow.audit_ok = False
        return self._result(
            flow,
            decision=decision,
            reason=reason,
            execution=execution,
            error_code=AUDIT_UNAVAILABLE,
        )

    def _allow_fields(self, flow: _Flow) -> dict[str, Any]:
        return {"decision": Decision.ALLOW, "action_digest": flow.digest}

    # ------------------------------------------------ pre-execution

    def _prepare(
        self, raw: Mapping[str, Any], *, asynchronous: bool
    ) -> _Prepared | PipelineResult:
        """REQUEST_RECEIVED … EXECUTION_STARTED; sync, blocking."""
        flow = _Flow(request_id=self._new_request_id(), received_at=self._clock())
        stage = "request"
        try:
            flow.columns = self._raw_columns(raw)
            if not self._write(flow, REQUEST_RECEIVED, detail=self._raw_detail(raw)):
                return self._audit_failed(flow)
            flow.received = True

            stage = "gateway"
            try:
                validated = validate_request(
                    raw,
                    registry=self._registry,
                    request_id=flow.request_id,
                    received_at=flow.received_at,
                )
            except InvalidRequestError:
                return self._terminal_refusal(flow, INVALID_REQUEST)
            flow.validated = validated
            request = validated.request
            flow.columns = {
                "agent_id": request.agent_id,
                "session_id": request.session_id,
                "tool": request.tool,
            }

            stage = "identity"
            context = self._identity.authenticate(request)
            if not self._write(
                flow, IDENTITY_RESOLVED, detail={"authorized": context.authorized}
            ):
                return self._audit_failed(flow)

            stage = "detector"
            findings = tuple(self._detector.analyze(request, context))
            for finding in findings:
                if not self._write(
                    flow,
                    FINDING,
                    detail={
                        "code": finding.code,
                        "severity": finding.severity.name,
                        "evidence": finding.evidence,
                    },
                ):
                    return self._audit_failed(flow)

            stage = "policy"
            decision = self._policy.evaluate(
                request, context, findings, validated.spec, action=validated.action
            )
            flow.decision = decision.decision
            flow.policy_reason = decision.reason
            flow.digest = decision.action.digest
            if not self._write(
                flow,
                DECISION,
                decision=decision.decision,
                reason=decision.reason,
                policy_version=decision.policy_version,
                action_digest=flow.digest,
                detail={"finding_codes": list(decision.finding_codes)},
            ):
                return self._audit_failed(flow)
            if decision.decision is not Decision.ALLOW:
                if not self._write(
                    flow,
                    REQUEST_COMPLETED,
                    decision=decision.decision,
                    reason=decision.reason,
                    execution=Execution.NOT_STARTED,
                ):
                    return self._audit_failed(flow)
                return self._result(
                    flow,
                    decision=decision.decision,
                    reason=decision.reason,
                    execution=Execution.NOT_STARTED,
                )

            stage = "proxy"
            tool = self._registry.lookup(validated.spec.name)
            mode = (
                "async"
                if asynchronous and tool is not None and tool.async_fn is not None
                else "sync"
            )
            run = self._proxy.claim(request, decision, context, mode=mode)
            flow.run = run
            if run.state == "refused":
                flow.decision = None
                code = None if run.outcome is None else run.outcome.error_code
                return self._terminal_refusal(flow, code)

            if not self._write(flow, EXECUTION_STARTED, action_digest=flow.digest):
                run.abandon()
                return self._audit_failed(flow)
            flow.started = True
            return _Prepared(flow=flow, run=run, mode=mode)
        except Exception as exc:
            return self._internal_error(flow, exc, stage)
        except BaseException as exc:
            if flow.run is not None and flow.run.state == "claimed":
                flow.run.abandon()
                if flow.started:
                    self._best_effort_completion(flow, Execution.NOT_STARTED, exc)
            raise

    def _terminal_refusal(self, flow: _Flow, code: str | None) -> PipelineResult:
        """An operational refusal: ``decision=None`` with its code (C1.6)."""
        code = code or INTERNAL_ERROR
        if not self._write(
            flow,
            REQUEST_COMPLETED,
            decision=None,
            reason=code,
            execution=Execution.NOT_STARTED,
        ):
            return self._audit_failed(flow)
        return self._result(
            flow,
            decision=None,
            reason=code,
            execution=Execution.NOT_STARTED,
            error_code=code,
        )

    def _internal_error(
        self, flow: _Flow, exc: Exception, stage: str
    ) -> PipelineResult:
        """Unexpected error before execution: ``decision=None`` (Q-03c, D-29)."""
        if flow.run is not None and flow.run.state == "claimed":
            flow.run.abandon()
        flow.decision = None
        if not flow.received:
            # Nothing was committed yet; the request is still not executed.
            flow.audit_ok = False
        try:
            detail = diagnostics_detail(_diagnostics(exc, stage))
            if self._write(flow, ERROR, reason=INTERNAL_ERROR, detail=detail):
                self._write(
                    flow,
                    REQUEST_COMPLETED,
                    decision=None,
                    reason=INTERNAL_ERROR,
                    execution=Execution.NOT_STARTED,
                )
        except Exception:  # an event could not even be built
            flow.audit_ok = False
        return self._result(
            flow,
            decision=None,
            reason=INTERNAL_ERROR,
            execution=Execution.NOT_STARTED,
            error_code=INTERNAL_ERROR,
        )

    # ----------------------------------------------- post-execution

    def _complete(self, prepared: _Prepared, outcome: ProxyOutcome) -> PipelineResult:
        """Post-execution events and the result; sync, blocking."""
        flow = prepared.flow
        try:
            return self._complete_events(flow, outcome)
        except Exception:
            # After execution: keep the truth, withhold output (AT-43).
            flow.audit_ok = False
            execution = outcome.execution
            decision = None if execution is Execution.NOT_STARTED else Decision.ALLOW
            return self._result(
                flow,
                decision=decision,
                reason=INTERNAL_ERROR,
                execution=execution,
                error_code=INTERNAL_ERROR,
            )

    def _complete_events(self, flow: _Flow, outcome: ProxyOutcome) -> PipelineResult:
        execution = outcome.execution
        if execution is Execution.NOT_STARTED:
            # Proxy refusal after EXECUTION_STARTED (C4.3 "not_started*").
            flow.decision = None
            return self._terminal_refusal(flow, outcome.error_code)

        if execution is Execution.FAILED:
            if not (
                self._write(
                    flow,
                    ERROR,
                    reason=TOOL_FAILED,
                    detail=self._diagnostics_of(outcome),
                )
                and self._write(
                    flow,
                    REQUEST_COMPLETED,
                    **self._allow_fields(flow),
                    reason=TOOL_FAILED,
                    execution=Execution.FAILED,
                )
            ):
                return self._audit_failed(flow, Execution.FAILED)
            return self._result(
                flow,
                decision=Decision.ALLOW,
                reason=TOOL_FAILED,
                execution=Execution.FAILED,
                error_code=TOOL_FAILED,
            )

        if outcome.error_code == OUTPUT_FILTER_FAILED:
            if not (
                self._write(
                    flow,
                    ERROR,
                    reason=OUTPUT_FILTER_FAILED,
                    detail=self._diagnostics_of(outcome),
                )
                and self._write(flow, OUTPUT_WITHHELD)
                and self._write(
                    flow,
                    REQUEST_COMPLETED,
                    **self._allow_fields(flow),
                    reason=OUTPUT_FILTER_FAILED,
                    execution=Execution.SUCCEEDED,
                )
            ):
                return self._audit_failed(flow, Execution.SUCCEEDED)
            return self._result(
                flow,
                decision=Decision.ALLOW,
                reason=OUTPUT_FILTER_FAILED,
                execution=Execution.SUCCEEDED,
                error_code=OUTPUT_FILTER_FAILED,
            )

        reason = flow.policy_reason or ""
        if not (
            self._write(flow, OUTPUT_FILTERED)
            and self._write(
                flow,
                REQUEST_COMPLETED,
                **self._allow_fields(flow),
                reason=reason,
                execution=Execution.SUCCEEDED,
            )
        ):
            return self._audit_failed(flow, Execution.SUCCEEDED)
        return self._result(
            flow,
            decision=Decision.ALLOW,
            reason=reason,
            execution=Execution.SUCCEEDED,
            output=outcome.output,
            released=outcome.output_released,
        )

    @staticmethod
    def _diagnostics_of(outcome: ProxyOutcome) -> dict[str, Any] | None:
        return (
            None
            if outcome.diagnostics is None
            else diagnostics_detail(outcome.diagnostics)
        )

    # ------------------------------------------------- interruption

    def _best_effort_completion(
        self, flow: _Flow, execution: Execution, exc: BaseException
    ) -> None:
        """One bounded REQUEST_COMPLETED attempt; never raises (C1.6)."""
        try:
            self._write(
                flow,
                REQUEST_COMPLETED,
                **self._allow_fields(flow),
                reason=flow.policy_reason or "",
                execution=execution,
                detail={"interruption": type(exc).__name__},
            )
        except Exception:  # suppressed: the original exception wins
            _LOG.warning("best-effort audit after an interruption failed")

    def _after_interruption(self, prepared: _Prepared, exc: BaseException) -> None:
        """Record what is known after a ``BaseException`` during execution."""
        run = prepared.run
        if run.state == "claimed":
            run.abandon()
        execution = _STATE_EXECUTION.get(run.state, Execution.NOT_STARTED)
        self._best_effort_completion(prepared.flow, execution, exc)

    def _cleanup_after_cancelled_prepare(self, task: asyncio.Future[Any]) -> None:
        """The caller was cancelled during ``_prepare``; close what it opened."""
        if task.cancelled() or task.exception() is not None:
            return
        prepared = task.result()
        if isinstance(prepared, _Prepared):
            task.get_loop().run_in_executor(
                None,
                self._after_interruption,
                prepared,
                asyncio.CancelledError(),
            )

    def _finish_detached(self, prepared: _Prepared, task: asyncio.Future[Any]) -> None:
        """A sync tool finished in its thread after the caller was cancelled."""
        loop = task.get_loop()
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            loop.run_in_executor(None, self._after_interruption, prepared, exc)
        else:
            loop.run_in_executor(None, self._complete, prepared, task.result())

    # ---------------------------------------------------- raw input

    @staticmethod
    def _raw_columns(raw: object) -> dict[str, str | None]:
        if not isinstance(raw, Mapping):
            return {"agent_id": None, "session_id": None, "tool": None}
        return {
            "agent_id": _column(raw.get("agent_id")),
            "session_id": _column(raw.get("session_id")),
            "tool": _column(raw.get("tool")),
        }

    @staticmethod
    def _raw_detail(raw: object) -> dict[str, Any]:
        """The request as received, masked (C2.4: originals kept masked here)."""
        if not isinstance(raw, Mapping):
            return {"shape": "not a mapping"}
        detail: dict[str, Any] = {}
        for key in ("arguments", "tool_call_id"):
            if key in raw:
                try:
                    detail[key] = mask(raw[key])
                except ValueError:
                    detail[key] = "[not recordable]"
        return detail


def build_pipeline(
    config: SentinelConfig,
    *,
    registry: ToolRegistry,
    policy: SecurityPolicy,
    output_filter: Callable[[Any], Any],
    detector: Any = None,
    clock: Callable[[], datetime] = _utc_now,
) -> Pipeline:
    """Build a pipeline with one long-lived store, identity, guard and proxy.

    Raises:
        ConfigurationError: invalid configuration or audit store.
    """
    if type(config) is not SentinelConfig:
        raise ConfigurationError("config must be a SentinelConfig")
    store = AuditStore(config.audit_db_path)
    try:
        return Pipeline(
            registry=registry,
            identity=IdentityStore(
                registry, require_credentials=config.require_credentials
            ),
            policy=PolicyEngine(policy),
            audit=AuditLogger(store, clock=clock),
            proxy=ExecutionProxy(
                registry,
                output_filter=output_filter,
                guard=ToolCallGuard(
                    ttl_seconds=config.guard_ttl_seconds,
                    capacity=config.guard_capacity,
                ),
            ),
            detector=detector,
            clock=clock,
        )
    except BaseException:
        store.close()
        raise
