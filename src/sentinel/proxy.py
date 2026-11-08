"""Execution proxy: the only component that invokes tool callables (C-10).

Implements decision record C1.4 rules 2, 3 and 5 (binding, invocation,
single-use claim, D-25), C2.7 (path re-resolution), C3.5 rule 8 with D-27 and
D-31 (the ``tool_call_id`` guard), the C1.6 interruption handling (D-14) and
the D-19 output-filter failure rule. It is two-phase (interpretation I-12),
matching the C4.3 audit order:

1. ``ExecutionProxy.claim(request, decision, context, mode=...)`` checks that
   the ALLOW decision is bound to this exact request (else ``ACTION_MISMATCH``,
   I-13), resolves the tool in the registry (the only source of the callable
   and of ``path_args``), claims the decision once (``DECISION_ALREADY_USED``,
   keyed by the action digest, I-14) and claims the guard key
   ``(agent_id, session_id, tool_call_id)`` if a ``tool_call_id`` is present
   (``DUPLICATE_TOOL_CALL`` / ``GUARD_CAPACITY_EXHAUSTED``). It returns a
   ``ProxyRun``; a refused run carries its ``outcome`` and never executes.
2. The pipeline (C-11) commits ``EXECUTION_STARTED``.
3. ``run.execute()`` (sync tools) or ``await run.execute_async()`` (async
   tools) re-resolves every path argument with ``paths.reverify``
   (``RESTRICTED_PATH`` if any changed), sets ``entered``, calls the
   registered callable with a fresh copy of ``decision.action.arguments``,
   applies the output filter, and retires the guard entry.

Outcomes report facts, never decisions: ``error_code``, a truthful
``execution`` state, whether the filtered output is released, and structured
diagnostics (D-29 fields only: exception type, module, function, line,
stage; never message text or file paths). A ``BaseException`` after
``entered`` sets ``run.state == "interrupted"`` and propagates unchanged.

Not done here: validation, identity, detection, policy, audit and the mapping
to ``PipelineResult`` (C-11). Re-resolution narrows but does not close the
window before the tool's own ``open`` (C2). Both guards are process-local.
This module is internal.
"""

from __future__ import annotations

import inspect
import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sentinel.action import AuthorizedAction, action_digest
from sentinel.exceptions import ConfigurationError, InvalidRequestError
from sentinel.models import (
    ACTION_MISMATCH,
    DECISION_ALREADY_USED,
    DUPLICATE_TOOL_CALL,
    GUARD_CAPACITY_EXHAUSTED,
    INTERNAL_ERROR,
    OUTPUT_FILTER_FAILED,
    RESTRICTED_PATH,
    TOOL_FAILED,
    Decision,
    Execution,
    SecurityContext,
    SecurityDecision,
    SecurityRequest,
)
from sentinel.paths import reverify
from sentinel.registry import RegisteredTool, ToolRegistry

__all__ = [
    "DEFAULT_GUARD_CAPACITY",
    "DEFAULT_GUARD_TTL_SECONDS",
    "Diagnostics",
    "ExecutionProxy",
    "ProxyOutcome",
    "ProxyRun",
    "ToolCallGuard",
    "pass_through_filter",
]

#: D-31 defaults (rev. 11): TTL counted from the terminal state, and capacity.
DEFAULT_GUARD_TTL_SECONDS = 300.0
DEFAULT_GUARD_CAPACITY = 10_000

_MODES = ("sync", "async")


def pass_through_filter(output: Any) -> Any:
    """Return ``output`` unchanged. Not a security filter (filtering is C-14)."""
    return output


def _finite_real(value: object) -> bool:
    """Whether ``value`` is a finite ``int`` or ``float`` (``bool`` excluded)."""
    return type(value) in (int, float) and math.isfinite(value)


# ------------------------------------------------------------------ guard


class ToolCallGuard:
    """At-most-once guard per ``(agent_id, session_id, tool_call_id)`` (D-31).

    An entry is in flight from its claim until ``retire``; in-flight entries
    never expire. ``retire`` sets expiry to terminal time + TTL. Expired
    entries are purged before each claim. An unexpired entry is never evicted:
    a full guard refuses new claims. Process-local; not shared across
    workers or hosts.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_GUARD_TTL_SECONDS,
        capacity: int = DEFAULT_GUARD_CAPACITY,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create an empty guard.

        Args:
            ttl_seconds: lifetime of an entry after its request's terminal
                state; a positive, finite number.
            capacity: maximum number of entries; a positive ``int``.
            clock: a monotonic clock returning finite numbers (injectable).

        Raises:
            ConfigurationError: any setting is invalid.
        """
        if not _finite_real(ttl_seconds) or ttl_seconds <= 0:
            raise ConfigurationError("ttl_seconds must be a positive finite number")
        if type(capacity) is not int or capacity <= 0:
            raise ConfigurationError("capacity must be a positive int")
        if not callable(clock):
            raise ConfigurationError("clock must be callable")
        first = clock()
        if not _finite_real(first):
            raise ConfigurationError("clock must return a finite number")
        self._ttl = float(ttl_seconds)
        self._capacity = capacity
        self._clock = clock
        self._last = first
        self._entries: dict[tuple[str, str, str], float | None] = {}
        self._lock = threading.Lock()

    @property
    def ttl_seconds(self) -> float:
        """Lifetime of an entry after its request's terminal state."""
        return self._ttl

    @property
    def capacity(self) -> int:
        """Maximum number of entries."""
        return self._capacity

    def __len__(self) -> int:
        """Number of entries currently held (in flight or unexpired)."""
        with self._lock:
            return len(self._entries)

    def _now(self) -> float:
        """Read the clock; refuse invalid values (I-16). Call under the lock."""
        now = self._clock()
        if not _finite_real(now):
            raise RuntimeError("guard clock returned an invalid value")
        return now

    def claim(self, key: tuple[str, str, str]) -> str | None:
        """Claim ``key``; return ``None`` or the refusal's error code.

        Raises:
            RuntimeError: the clock returned an invalid value or moved
                backwards (I-16); nothing is claimed.
        """
        with self._lock:
            now = self._now()
            if now < self._last:
                raise RuntimeError("guard clock moved backwards")
            self._last = now
            expired = [
                k
                for k, expiry in self._entries.items()
                if expiry is not None and expiry <= now
            ]
            for k in expired:
                del self._entries[k]
            if key in self._entries:
                return DUPLICATE_TOOL_CALL
            if len(self._entries) >= self._capacity:
                return GUARD_CAPACITY_EXHAUSTED
            self._entries[key] = None
            return None

    def retire(self, key: tuple[str, str, str]) -> None:
        """Mark ``key``'s request terminal: it expires TTL from now.

        Never raises. If the clock is invalid or moved backwards, the entry
        stays in flight (it never expires), which fails closed (I-16).
        """
        with self._lock:
            if key not in self._entries or self._entries[key] is not None:
                return
            try:
                now = self._now()
            except RuntimeError:
                return
            if now < self._last:
                return
            self._last = now
            self._entries[key] = now + self._ttl


# --------------------------------------------------------------- outcomes


@dataclass(frozen=True, slots=True)
class Diagnostics:
    """Structured failure diagnostics (D-29): no message text, no paths."""

    exception_type: str
    module: str
    function: str
    line: int
    stage: str


def _diagnostics(exc: BaseException, stage: str) -> Diagnostics:
    """Describe where ``exc`` was raised, without its message or file path."""
    cls = type(exc)
    tb = exc.__traceback__
    module, function, line = "?", "?", 0
    if tb is not None:
        while tb.tb_next is not None:
            tb = tb.tb_next
        frame = tb.tb_frame
        module = str(frame.f_globals.get("__name__", "?"))
        function = frame.f_code.co_name
        line = tb.tb_lineno
    return Diagnostics(
        exception_type=f"{cls.__module__}.{cls.__qualname__}",
        module=module,
        function=function,
        line=line,
        stage=stage,
    )


@dataclass(frozen=True, slots=True)
class ProxyOutcome:
    """Execution facts for C-11. Not a decision and not a ``PipelineResult``.

    ``output_released`` means the filter stage released ``output``; the
    pipeline may still withhold it (for example if the audit fails).
    """

    error_code: str | None
    execution: Execution
    output_released: bool = False
    output: Any = field(default=None, repr=False)
    diagnostics: Diagnostics | None = None

    def __post_init__(self) -> None:
        """Keep output only on a clean, successful, released run."""
        if self.output_released:
            if self.execution is not Execution.SUCCEEDED or self.error_code:
                raise ValueError("only a clean successful run releases output")
        elif self.output is not None:
            raise ValueError("output present but not released")


def _refused(code: str) -> ProxyOutcome:
    return ProxyOutcome(error_code=code, execution=Execution.NOT_STARTED)


# -------------------------------------------------------------------- run


class ProxyRun:
    """One claimed (or refused) execution. Executes at most once.

    ``state``: ``refused`` (see ``outcome``), ``claimed``, ``executing``
    (re-resolution in progress), ``not_started``, ``entered``, ``completed``,
    ``failed`` or ``interrupted``. A claimed run must end in ``execute``,
    ``execute_async`` or ``abandon``, so its guard entry is retired.
    """

    def __init__(
        self,
        *,
        outcome: ProxyOutcome | None = None,
        tool: RegisteredTool | None = None,
        action: AuthorizedAction | None = None,
        prefixes: tuple[str, ...] = (),
        mode: str = "sync",
        output_filter: Callable[[Any], Any] = pass_through_filter,
        guard: ToolCallGuard | None = None,
        guard_key: tuple[str, str, str] | None = None,
    ) -> None:
        """Create a run; only ``ExecutionProxy.claim`` does this."""
        self._tool = tool
        self._action = action
        self._prefixes = prefixes
        self._mode = mode
        self._filter = output_filter
        self._guard = guard
        self._guard_key = guard_key
        self._lock = threading.Lock()
        self.outcome = outcome
        self.state = "refused" if outcome is not None else "claimed"

    def _start(self, mode: str) -> tuple[RegisteredTool, AuthorizedAction]:
        """Move from ``claimed`` to ``executing`` exactly once."""
        with self._lock:
            if self.state != "claimed" or self._tool is None or self._action is None:
                raise RuntimeError("this run cannot be executed")
            if mode != self._mode:
                raise RuntimeError("this run was claimed for the other mode")
            self.state = "executing"
            return self._tool, self._action

    def abandon(self) -> None:
        """Give up a claimed run without executing it (not started).

        For C-11 when a step between claim and execution fails (for example
        the ``EXECUTION_STARTED`` audit write). The decision stays used; the
        guard entry is retired (terminal: not-started after the claim).
        """
        with self._lock:
            if self.state != "claimed":
                raise RuntimeError("only a claimed run can be abandoned")
            self.state = "not_started"
        self._retire()

    def _interrupted(self) -> None:
        """Record a ``BaseException``: entered → interrupted; else not started."""
        if self.state == "entered":
            self.state = "interrupted"
        elif self.state == "executing":
            self.state = "not_started"

    def _finish(self, state: str, outcome: ProxyOutcome) -> ProxyOutcome:
        self.state = state
        self.outcome = outcome
        return outcome

    def _retire(self) -> None:
        if self._guard is not None and self._guard_key is not None:
            self._guard.retire(self._guard_key)

    def _paths_unchanged(self, tool: RegisteredTool, action: AuthorizedAction) -> bool:
        """Re-resolve every registered path argument (C2.7)."""
        arguments = action.arguments
        return all(
            reverify(arguments[name], self._prefixes) for name in tool.spec.path_args
        )

    def _after_return(self, result: Any) -> ProxyOutcome:
        """Apply the output filter to a normal return (D-19)."""
        self.state = "completed"
        if inspect.isawaitable(result):
            # A sync entry point handed back an unawaited coroutine: the tool
            # body did not run here. Never release or await it.
            if inspect.iscoroutine(result):
                result.close()
            return self._finish(
                "failed",
                ProxyOutcome(
                    error_code=TOOL_FAILED,
                    execution=Execution.FAILED,
                    diagnostics=Diagnostics("builtins.TypeError", "?", "?", 0, "tool"),
                ),
            )
        try:
            filtered = self._filter(result)
            if inspect.isawaitable(filtered):
                if inspect.iscoroutine(filtered):
                    filtered.close()
                raise TypeError("output filter returned an awaitable")
        except Exception as exc:
            return self._finish(
                "completed",
                ProxyOutcome(
                    error_code=OUTPUT_FILTER_FAILED,
                    execution=Execution.SUCCEEDED,
                    diagnostics=_diagnostics(exc, "output_filter"),
                ),
            )
        return self._finish(
            "completed",
            ProxyOutcome(
                error_code=None,
                execution=Execution.SUCCEEDED,
                output_released=True,
                output=filtered,
            ),
        )

    def _tool_failed(self, exc: Exception) -> ProxyOutcome:
        return self._finish(
            "failed",
            ProxyOutcome(
                error_code=TOOL_FAILED,
                execution=Execution.FAILED,
                diagnostics=_diagnostics(exc, "tool"),
            ),
        )

    def execute(self) -> ProxyOutcome:
        """Run a sync tool. Raises ``RuntimeError`` if not executable."""
        tool, action = self._start("sync")
        try:
            if not self._paths_unchanged(tool, action):
                return self._finish("not_started", _refused(RESTRICTED_PATH))
            fn = tool.sync_fn
            arguments = action.arguments  # a fresh copy (C1.4 rule 3)
            self.state = "entered"
            try:
                result = fn(**arguments)
            except Exception as exc:
                return self._tool_failed(exc)
            return self._after_return(result)
        except BaseException:
            self._interrupted()
            raise
        finally:
            self._retire()

    async def execute_async(self) -> ProxyOutcome:
        """Run an async tool, awaited on the caller's event loop."""
        tool, action = self._start("async")
        try:
            if not self._paths_unchanged(tool, action):
                return self._finish("not_started", _refused(RESTRICTED_PATH))
            fn = tool.async_fn
            arguments = action.arguments  # a fresh copy (C1.4 rule 3)
            self.state = "entered"
            try:
                result = await fn(**arguments)
            except Exception as exc:
                return self._tool_failed(exc)
            return self._after_return(result)
        except BaseException:
            self._interrupted()
            raise
        finally:
            self._retire()


# ------------------------------------------------------------------ proxy


def _bound(
    request: SecurityRequest, decision: SecurityDecision, context: SecurityContext
) -> bool:
    """Whether ``decision`` is an ALLOW bound to exactly this request (C1.4)."""
    action = decision.action
    if decision.decision is not Decision.ALLOW:
        return False
    if not decision.request_id == action.request_id == request.request_id:
        return False
    if not action.agent_id == request.agent_id == context.agent_id:
        return False
    if action.tool != request.tool or not context.authorized:
        return False
    try:
        recomputed = action_digest(
            request_id=action.request_id,
            agent_id=action.agent_id,
            tool=action.tool,
            arguments=action.arguments,
        )
        requested = action_digest(
            request_id=request.request_id,
            agent_id=request.agent_id,
            tool=request.tool,
            arguments=request.arguments,
        )
    except InvalidRequestError:
        return False
    return recomputed == action.digest == requested


class ExecutionProxy:
    """The sole invoker of registered tools."""

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        output_filter: Callable[[Any], Any],
        guard: ToolCallGuard | None = None,
    ) -> None:
        """Create a proxy.

        Args:
            registry: the authoritative tool registry.
            output_filter: applied to every return value; required, so a
                missing filter is never silently permissive. Until C-14,
                pass ``pass_through_filter`` explicitly.
            guard: the ``tool_call_id`` guard; a default-configured one if
                omitted.

        Raises:
            ConfigurationError: an argument has the wrong type.
        """
        if type(registry) is not ToolRegistry:
            raise ConfigurationError("registry must be a ToolRegistry")
        if not callable(output_filter):
            raise ConfigurationError("output_filter must be callable")
        if guard is None:
            guard = ToolCallGuard()
        elif type(guard) is not ToolCallGuard:
            raise ConfigurationError("guard must be a ToolCallGuard")
        self._registry = registry
        self._filter = output_filter
        self._guard = guard
        self._claimed: set[str] = set()
        self._lock = threading.Lock()

    @property
    def guard(self) -> ToolCallGuard:
        """The ``tool_call_id`` guard in use."""
        return self._guard

    def claim(
        self,
        request: SecurityRequest,
        decision: SecurityDecision,
        context: SecurityContext,
        *,
        mode: str = "sync",
    ) -> ProxyRun:
        """Check binding, resolve the tool and claim the decision and guard.

        Returns a ``ProxyRun``. If ``run.state == "refused"``, ``run.outcome``
        holds the refusal (nothing was invoked) and the run cannot execute.

        Raises:
            TypeError: an input has the wrong type (I-15).
            ValueError: ``mode`` is not ``"sync"`` or ``"async"``.
            RuntimeError: the guard clock is invalid (I-16).
        """
        for value, cls in (
            (request, SecurityRequest),
            (decision, SecurityDecision),
            (context, SecurityContext),
        ):
            if type(value) is not cls:
                raise TypeError("proxy input has the wrong type")
        if mode not in _MODES:
            raise ValueError("mode must be 'sync' or 'async'")

        tool = self._registry.lookup(request.tool)
        if tool is None:
            return ProxyRun(outcome=_refused(INTERNAL_ERROR))
        if (tool.sync_fn if mode == "sync" else tool.async_fn) is None:
            return ProxyRun(outcome=_refused(INTERNAL_ERROR))

        if not _bound(request, decision, context):
            return ProxyRun(outcome=_refused(ACTION_MISMATCH))
        action = decision.action
        grant = (
            None
            if context.envelope is None
            else context.envelope.grant_for(tool.spec.name)
        )
        if grant is None:
            return ProxyRun(outcome=_refused(ACTION_MISMATCH))
        arguments = action.arguments
        if any(name not in arguments for name in tool.spec.path_args):
            return ProxyRun(outcome=_refused(ACTION_MISMATCH))

        with self._lock:
            if action.digest in self._claimed:
                return ProxyRun(outcome=_refused(DECISION_ALREADY_USED))
            self._claimed.add(action.digest)

        key = None
        if request.tool_call_id is not None:
            key = (request.agent_id, request.session_id, request.tool_call_id)
            refusal = self._guard.claim(key)
            if refusal is not None:
                return ProxyRun(outcome=_refused(refusal))

        return ProxyRun(
            tool=tool,
            action=action,
            prefixes=grant.allowed_path_prefixes,
            mode=mode,
            output_filter=self._filter,
            guard=self._guard,
            guard_key=key,
        )
