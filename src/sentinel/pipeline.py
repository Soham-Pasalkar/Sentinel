"""Pipeline: the sole orchestrator and the only audit writer (C-11; D-16).

``Pipeline.evaluate(raw)`` runs one request through gateway (C-06), identity
(C-07), detector (C-13, advisory), policy (C-08) and proxy (C-10), commits
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
bounded, best-effort REQUEST_COMPLETED(``unknown``, or ``succeeded`` if the
tool had returned: C1.6-I) and is re-raised unchanged (C1.6).

Async entry lifecycle (I-28, owner 2026-11-18). Blocking work runs as
executor jobs, never as asyncio Tasks, so caller cancellation and loop
teardown never cancel it: one job prepares the request (and, for a sync-only
tool, executes and audits it); a second writes an async-native tool's
completion. Jobs return their outcome or the original exception as a value
(``_JobResult``), so no exception is ever left unretrieved on a detached
future. ``_Handoff`` settles, under one lock, who closes a claimed run when
the caller leaves. A coroutine closed outside its own Task's step
(finalization) writes nothing and takes no blocking lock (K3). A completion
that cannot be submitted, or is dropped while the caller waits, returns
``INTERNAL_ERROR`` with the truthful execution (K1); a request whose job
never ran is not accepted (K1b).

This module is internal: it is not exported, and the async entry is not a
stable API (D-30).
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import functools
import logging
import threading
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
)
from sentinel.audit_shape import (
    INVALID,
    UNREGISTERED,
    SchemaKeys,
    identity_problem,
    path_canonicalised,
    path_metadata,
    summarize_arguments,
    valid_tool_name,
)
from sentinel.config import SentinelConfig
from sentinel.detector import HeuristicDetector, NullDetector
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
    _outside_own_step,
    _Owner,
    _task_owner,
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
    #: The request's ``arguments`` object, kept in memory only, to compare
    #: path arguments with their canonical form (G-3). Never persisted.
    raw_arguments: Any = None


@dataclass(frozen=True)
class _Prepared:
    """A request whose EXECUTION_STARTED is committed and whose run is claimed."""

    flow: _Flow
    run: ProxyRun
    mode: str


@dataclass(frozen=True)
class _JobResult:
    """What an executor job hands back. Jobs never raise (I-28)."""

    value: Any = None
    error: BaseException | None = None
    prepared: _Prepared | None = None


# Handoff states (I-28): who owns a request's claimed run.
_RUNNING = "running"  # the preparation job runs; the worker owns any claim
_ORPHANED = "orphaned"  # the caller left first; the worker closes any claim
_READY = "ready"  # an async-native run was handed to the caller
_TAKEN = "taken"  # the caller executes it
_CALLER_CLOSING = "caller_closing"  # the caller left after the handover
_WORKER_EXECUTING = "worker_executing"  # a sync-only run, executed by the job
_WORKER_CLOSING = "worker_closing"  # the job closes a claim nobody executes
_DONE = "done"
_STRANDED = "stranded"  # the caller was finalized while READY: no owner

#: ``detail.interruption`` when the worker closes a run because the caller's
#: event loop had already closed (no exception reached the caller).
_LOOP_CLOSED = "EventLoopClosed"


class _Handoff:
    """Ownership of one request's claimed run (I-28; owner 2026-11-18).

    Transitions read and write ``state`` under one lock; the actor acts after
    releasing it. The worker makes one transition out of RUNNING or
    ORPHANED (``no_claim``, ``publish`` or ``keep``), then at most one
    ``worker_done``. The caller makes at most one of ``take``, ``leave`` or
    ``finalize``, then ``finish``. Exactly one actor therefore closes or
    executes each claimed run.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._lock = threading.Lock()
        self._loop = loop
        self.state = _RUNNING
        self.prepared: _Prepared | None = None
        self.caller_left = False
        self.interruption = "CancelledError"

    def _illegal(self, operation: str) -> RuntimeError:
        return RuntimeError(f"handoff: {operation} in state {self.state}")

    # ------------------------------------------------------ worker side

    def no_claim(self) -> None:
        """Preparation ended without a claim to hand over."""
        with self._lock:
            if self.state not in (_RUNNING, _ORPHANED):
                raise self._illegal("no_claim")
            self.state = _DONE

    def publish(self, prepared: _Prepared) -> bool:
        """Hand an async-native run to the caller; ``False``: close it."""
        with self._lock:
            if self.state == _RUNNING and not self._loop.is_closed():
                self.state = _READY
                self.prepared = prepared
                return True
            if self.state == _RUNNING:  # H1: the caller's loop has closed
                self.interruption = _LOOP_CLOSED
            elif self.state != _ORPHANED:
                raise self._illegal("publish")
            self.state = _WORKER_CLOSING
            return False

    def keep(self) -> bool:
        """Execute a sync-only run in the worker; ``False``: close it."""
        with self._lock:
            if self.state == _RUNNING:
                self.state = _WORKER_EXECUTING
                return True
            if self.state != _ORPHANED:
                raise self._illegal("keep")
            self.state = _WORKER_CLOSING
            return False

    def worker_done(self) -> None:
        with self._lock:
            if self.state not in (_WORKER_EXECUTING, _WORKER_CLOSING):
                raise self._illegal("worker_done")
            self.state = _DONE

    def caller_gone(self) -> bool:
        """Whether nobody will receive the job's result."""
        return self.caller_left or self._loop.is_closed()

    # ------------------------------------------------------ caller side

    def take(self) -> _Prepared:
        with self._lock:
            if self.state != _READY or self.prepared is None:
                raise self._illegal("take")
            self.state = _TAKEN
            return self.prepared

    def leave(self, exc: BaseException) -> _Prepared | None:
        """The caller stops waiting; returns a run the caller must close."""
        with self._lock:
            self.caller_left = True
            if self.state == _RUNNING:
                self.interruption = type(exc).__name__
                self.state = _ORPHANED
            elif self.state == _READY:
                self.state = _CALLER_CLOSING
                return self.prepared
            return None

    def finalize(self) -> _Prepared | None:
        """``leave`` for a finalizer: never blocks, and nothing else (K3).

        Returns a run left claimed that the caller should abandon without
        blocking (``ProxyRun.abandon_deferred``).
        """
        if not self._lock.acquire(blocking=False):
            return None
        try:
            self.caller_left = True
            if self.state == _RUNNING:
                self.interruption = "GeneratorExit"
                self.state = _ORPHANED
            elif self.state == _READY:
                self.state = _STRANDED
                return self.prepared
            return None
        finally:
            self._lock.release()

    def finish(self) -> None:
        """TAKEN or CALLER_CLOSING → DONE.

        Only the caller is ever in those states, so no lock is taken (this
        may run in a finalizer).
        """
        if self.state in (_TAKEN, _CALLER_CLOSING):
            self.state = _DONE


def _dropped(job: asyncio.Future[Any], exc: BaseException, owner: _Owner) -> bool:
    """Whether ``exc`` comes from a job cancelled before it started.

    Only ``ThreadPoolExecutor.shutdown(cancel_futures=True)`` does that; a
    cancelled concurrent future never runs. The caller itself was not
    cancelled (its Task has no pending cancellation request).
    """
    task = owner[1]
    return (
        isinstance(exc, asyncio.CancelledError)
        and job.cancelled()
        and task is not None
        and task.cancelling() == 0
    )


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
        """Internal async counterpart of ``evaluate`` (D-30; not a stable API).

        See the module docstring and I-28 for the lifecycle. No SQLite or
        filesystem work runs on the loop except the C1.6 interruption record
        of an async-native tool (D-20).
        """
        owner = _task_owner()
        loop = owner[0]
        handoff = _Handoff(loop)
        try:
            job = self._submit(loop, self._prepare_job, raw, handoff)
        except Exception as exc:
            # K1b. If the executor queued the job before failing, the worker
            # finds the request ORPHANED and never executes the tool.
            handoff.leave(exc)
            return self._not_accepted()
        try:
            result = await asyncio.shield(job)
        except BaseException as exc:
            if _outside_own_step(owner):
                # Finalization (K3): no blocking lock, no audit write.
                stranded = handoff.finalize()
                if stranded is not None:
                    stranded.run.abandon_deferred()
                raise
            handed_over = handoff.leave(exc)
            if handed_over is not None:
                self._close_handed_over(loop, handed_over, exc)
                handoff.finish()
            if _dropped(job, exc, owner):
                return self._not_accepted()  # K1b: the job never ran
            raise
        if result.error is not None:
            raise result.error
        if result.prepared is None:
            return result.value
        prepared = handoff.take()
        try:
            return await self._execute_taken(owner, prepared, handoff)
        finally:
            handoff.finish()

    async def _execute_taken(
        self, owner: _Owner, prepared: _Prepared, handoff: _Handoff
    ) -> PipelineResult:
        """Run a handed-over async-native tool on the loop, then complete it."""
        loop = owner[0]
        flow = prepared.flow
        try:
            outcome = await prepared.run.execute_async()
        except Exception as exc:
            # Not from the tool: the proxy contains tool and filter
            # exceptions. E.g. the path re-check could not be submitted. The
            # tool was not entered: INTERNAL_ERROR (C1.8 rev. 5).
            return await self._in_worker(
                owner,
                handoff,
                (self._internal_error_job, flow, exc),
                lambda: self._unaudited(flow, Execution.NOT_STARTED),
            )
        except BaseException as exc:
            if not _outside_own_step(owner):
                self._interrupted_on_loop(loop, prepared, exc)
            raise
        return await self._in_worker(
            owner,
            handoff,
            (self._complete_job, prepared, outcome, handoff),
            lambda: self._unaudited(flow, outcome.execution),
        )

    async def _in_worker(
        self,
        owner: _Owner,
        handoff: _Handoff,
        call: tuple[Any, ...],
        unavailable: Callable[[], PipelineResult],
    ) -> PipelineResult:
        """Run one closing job; ``unavailable()`` if it cannot run (K1)."""
        try:
            job = self._submit(owner[0], *call)
        except Exception:
            return unavailable()
        try:
            result = await asyncio.shield(job)
        except BaseException as exc:
            if not _outside_own_step(owner) and _dropped(job, exc, owner):
                return unavailable()
            handoff.caller_left = True  # the job finishes on its own
            raise
        if result.error is not None:
            raise result.error
        return result.value

    # ------------------------------------------------- executor jobs

    def _submit(
        self, loop: asyncio.AbstractEventLoop, fn: Callable[..., _JobResult], *args: Any
    ) -> asyncio.Future[_JobResult]:
        """Submit ``fn(*args)`` as a default-executor job (contextvars copied).

        Raises whatever submission raises (closed loop, shut-down executor,
        a thread that cannot start). The job itself never raises.
        """
        context = contextvars.copy_context()
        return loop.run_in_executor(
            None, functools.partial(context.run, self._never_raises, fn, *args)
        )

    @staticmethod
    def _never_raises(fn: Callable[..., _JobResult], *args: Any) -> _JobResult:
        try:
            return fn(*args)
        except BaseException as exc:
            return _JobResult(error=exc)

    def _prepare_job(self, raw: Mapping[str, Any], handoff: _Handoff) -> _JobResult:
        """REQUEST_RECEIVED … EXECUTION_STARTED; a sync-only tool also runs."""
        try:
            prepared = self._prepare(raw, asynchronous=True)
        except BaseException as exc:
            handoff.no_claim()  # ``_prepare`` closed any claim itself
            self._warn_if_detached(handoff, exc)
            return _JobResult(error=exc)
        if not isinstance(prepared, _Prepared):
            handoff.no_claim()
            return _JobResult(value=prepared)
        if prepared.mode == "async":
            if handoff.publish(prepared):
                return _JobResult(prepared=prepared)
        elif handoff.keep():
            try:
                return self._execute_and_complete(prepared, handoff)
            finally:
                handoff.worker_done()
        # The caller has gone (or its loop closed): never execute (I-28).
        run = prepared.run
        if run.state == "claimed":
            run.abandon()
        self._best_effort_completion(
            prepared.flow, Execution.NOT_STARTED, handoff.interruption
        )
        handoff.worker_done()
        return _JobResult()

    def _execute_and_complete(
        self, prepared: _Prepared, handoff: _Handoff
    ) -> _JobResult:
        try:
            outcome = prepared.run.execute()
        except BaseException as exc:
            self._after_interruption(prepared, exc)
            self._warn_if_detached(handoff, exc)
            return _JobResult(error=exc)
        return self._complete_job(prepared, outcome, handoff)

    def _complete_job(
        self, prepared: _Prepared, outcome: ProxyOutcome, handoff: _Handoff
    ) -> _JobResult:
        """Post-execution events. Never records ``unknown``: the tool ended."""
        try:
            return _JobResult(value=self._complete(prepared, outcome))
        except BaseException as exc:  # ``_complete`` maps every ``Exception``
            self._warn_if_detached(handoff, exc)
            return _JobResult(error=exc)

    def _internal_error_job(self, flow: _Flow, exc: Exception) -> _JobResult:
        return _JobResult(value=self._internal_error(flow, exc, "proxy"))

    def _record_job(self, flow: _Flow, interruption: str) -> _JobResult:
        """REQUEST_COMPLETED(``not_started``) before entry (I-29, K2)."""
        self._best_effort_completion(flow, Execution.NOT_STARTED, interruption)
        return _JobResult()

    @staticmethod
    def _warn_if_detached(handoff: _Handoff, exc: BaseException) -> None:
        """One masked warning when a ``BaseException`` has nobody to reach.

        Runs in the worker thread, never on the loop. Only the exception's
        qualified type name is logged (D-29).
        """
        if isinstance(exc, Exception) or not handoff.caller_gone():
            return
        kind = type(exc)
        _LOG.warning(
            "tool call ended with %s.%s after its caller had gone",
            kind.__module__,
            kind.__qualname__,
        )

    # --------------------------------------------- caller-side closing

    def _close_handed_over(
        self, loop: asyncio.AbstractEventLoop, prepared: _Prepared, exc: BaseException
    ) -> None:
        """The caller left after the handover (T10): abandon, then record."""
        if prepared.run.state == "claimed":
            prepared.run.abandon()  # in memory; the guard entry is terminal
        self._submit_record(loop, prepared.flow, type(exc).__name__)

    def _interrupted_on_loop(
        self, loop: asyncio.AbstractEventLoop, prepared: _Prepared, exc: BaseException
    ) -> None:
        """Record a ``BaseException`` from ``execute_async`` (C1.6, I-29)."""
        execution = _STATE_EXECUTION.get(prepared.run.state, Execution.NOT_STARTED)
        if execution is Execution.NOT_STARTED:
            # Before entry: submitted to a worker, never written on the loop.
            self._submit_record(loop, prepared.flow, type(exc).__name__)
        else:
            # After entry: the one synchronous record C1.6 prescribes (D-20).
            self._best_effort_completion(prepared.flow, execution, type(exc).__name__)

    def _submit_record(
        self, loop: asyncio.AbstractEventLoop, flow: _Flow, interruption: str
    ) -> None:
        """Submit the ``not_started`` record; nothing on the loop if it fails.

        If it cannot be submitted, it is lost and the request reads as
        unknown (C4.4). Nothing is logged on the loop (D-LOG).
        """
        with contextlib.suppress(Exception):
            self._submit(loop, self._record_job, flow, interruption)

    @staticmethod
    def _not_accepted() -> PipelineResult:
        """K1b: no job ran, so nothing was accepted or written.

        The request id comes from ``uuid4`` directly: no injected callback
        runs on the loop.
        """
        return PipelineResult(
            request_id=str(uuid.uuid4()),
            decision=None,
            reason=INTERNAL_ERROR,
            execution=Execution.NOT_STARTED,
            output_released=False,
            audit_complete=False,
            error_code=INTERNAL_ERROR,
        )

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
            detail = self._raw_detail(raw, flow)
            if not self._write(flow, REQUEST_RECEIVED, detail=detail):
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
                "agent_id": self._agent_column(request.agent_id),
                "session_id": request.session_id,  # valid: the gateway checked it
                "tool": request.tool,  # a registered name
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
            decision_detail: dict[str, Any] = {
                "finding_codes": list(decision.finding_codes)
            }
            changed = path_canonicalised(
                flow.raw_arguments,
                request.arguments,
                self._schema_keys(request.tool),
            )
            if changed:
                decision_detail["paths_canonicalised"] = changed
            if not self._write(
                flow,
                DECISION,
                decision=decision.decision,
                reason=decision.reason,
                policy_version=decision.policy_version,
                action_digest=flow.digest,
                detail=decision_detail,
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
                    self._best_effort_completion(
                        flow, Execution.NOT_STARTED, type(exc).__name__
                    )
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
            return self._unaudited(flow, outcome.execution)

    def _unaudited(self, flow: _Flow, execution: Execution) -> PipelineResult:
        """The closing audit could not be done (C1.6 rev. 5; K1).

        Keeps the truthful ``execution``, withholds the output, and never
        claims audit completion. ``decision`` is ``allow`` once the tool ran,
        otherwise ``None``.
        """
        flow.audit_ok = False
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
        self, flow: _Flow, execution: Execution, interruption: str
    ) -> None:
        """One REQUEST_COMPLETED attempt; never raises an ``Exception`` (C1.6).

        Bounded in attempts (one) and work (one row), not in elapsed time: it
        can wait behind other writers, SQLite's busy timeout and ``fsync``
        (D-BOUND, owner 2026-11-18). ``interruption`` is the exception type
        name recorded in ``detail.interruption``.
        """
        try:
            self._write(
                flow,
                REQUEST_COMPLETED,
                **self._allow_fields(flow),
                reason=flow.policy_reason or "",
                execution=execution,
                detail={"interruption": interruption},
            )
        except Exception:  # suppressed: the original exception wins
            _LOG.warning("best-effort audit after an interruption failed")

    def _after_interruption(self, prepared: _Prepared, exc: BaseException) -> None:
        """Record what is known after a ``BaseException`` during execution."""
        run = prepared.run
        if run.state == "claimed":
            run.abandon()
        execution = _STATE_EXECUTION.get(run.state, Execution.NOT_STARTED)
        self._best_effort_completion(prepared.flow, execution, type(exc).__name__)

    # ---------------------------------------------------- raw input

    # ------------------------------------------- audit confidentiality (G-3)

    def _schema_keys(self, tool: object) -> SchemaKeys | None:
        """The cached schema keys of a registered tool, or ``None``."""
        if not valid_tool_name(tool):
            return None
        registered = self._registry.lookup(tool)
        return None if registered is None else registered.schema_keys

    def _agent_column(self, agent_id: object) -> str | None:
        """``agent_id`` as stored: registered value or a placeholder (G-3)."""
        if type(agent_id) is not str or not agent_id:
            return None
        if identity_problem(agent_id) is not None:
            return INVALID
        if not self._identity._is_registered(agent_id):
            return UNREGISTERED
        return agent_id

    def _raw_columns(self, raw: object) -> dict[str, str | None]:
        """Identity and tool columns before validation; never a raw value.

        ``agent_id``: the registered value, ``[invalid]`` or ``[unregistered]``;
        ``session_id``: a valid value or ``[invalid]``; ``tool``: a registered
        name or ``[unregistered]``. ``None`` when missing or not a ``str``.
        The request mapping is application-built (C1.2); only its ``get`` is
        called here, as before.
        """
        if not isinstance(raw, Mapping):
            return {"agent_id": None, "session_id": None, "tool": None}
        session = raw.get("session_id")
        if type(session) is not str or not session:
            session_column = None
        elif identity_problem(session) is not None:
            session_column = INVALID
        else:
            session_column = session
        tool = raw.get("tool")
        if type(tool) is not str:
            tool_column = None
        elif self._schema_keys(tool) is None:
            tool_column = UNREGISTERED
        else:
            tool_column = tool
        return {
            "agent_id": self._agent_column(raw.get("agent_id")),
            "session_id": session_column,
            "tool": tool_column,
        }

    def _raw_detail(self, raw: object, flow: _Flow) -> dict[str, Any]:
        """REQUEST_RECEIVED detail: structure only, never content (G-3).

        Bounded metadata about ``arguments`` (``audit_shape``), path metadata,
        and whether a ``tool_call_id`` was present. No argument key or value,
        path string or ``tool_call_id`` is recorded.
        """
        if not isinstance(raw, Mapping):
            return {"shape": "not a mapping"}
        arguments = raw.get("arguments")
        flow.raw_arguments = arguments
        keys = self._schema_keys(raw.get("tool"))
        return {
            "arguments": summarize_arguments(arguments, keys),
            "paths": path_metadata(arguments, keys),
            "tool_call_id_present": "tool_call_id" in raw,
        }


def _registered_schema_keys(
    registry: ToolRegistry,
) -> Callable[[str], SchemaKeys | None]:
    """The cached ``SchemaKeys`` of a registered tool (evidence labels, F-1)."""

    def resolve(tool: str) -> SchemaKeys | None:
        registered = registry.lookup(tool)
        return None if registered is None else registered.schema_keys

    return resolve


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

    ``detector`` defaults to the C-13 ``HeuristicDetector`` (OD-8).

    Raises:
        ConfigurationError: invalid configuration or audit store.
    """
    if type(config) is not SentinelConfig:
        raise ConfigurationError("config must be a SentinelConfig")
    if detector is None:
        detector = HeuristicDetector(schema_keys=_registered_schema_keys(registry))
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
