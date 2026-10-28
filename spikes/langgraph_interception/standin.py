# Throwaway experiment code; excluded from production linting by `spikes` in pyproject.toml [tool.ruff] extend-exclude (D-28).
"""Stand-in gate, boundary and test tools for the C-02 interception experiment.

THROWAWAY EXPERIMENT CODE. This is NOT Sentinel product code and implements no real
security: the "gate" is a dict lookup. It exists only so that real LangGraph execution
can be observed at its tool-execution boundary.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Annotated, Any

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState, ToolNode
from langgraph.prebuilt.tool_node import ToolCallRequest

# --------------------------------------------------------------------------- recorder


class Recorder:
    """Thread-safe ordered event log. ``invoke`` events are the invocation counter."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seq = itertools.count(1)
        self.events: list[dict[str, Any]] = []

    def reset(self) -> None:
        with self._lock:
            self._seq = itertools.count(1)
            self.events = []

    def event(self, kind: str, **data: Any) -> int:
        with self._lock:
            seq = next(self._seq)
            self.events.append(
                {
                    "seq": seq,
                    "kind": kind,
                    "thread": threading.current_thread().name,
                    **data,
                }
            )
            return seq

    def invocations(self, tool_name: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            return [
                e
                for e in self.events
                if e["kind"] == "invoke" and tool_name in (None, e["tool"])
            ]

    def count(self, tool_name: str | None = None) -> int:
        return len(self.invocations(tool_name))

    def evaluations(self) -> list[dict[str, Any]]:
        with self._lock:
            return [e for e in self.events if e["kind"] == "evaluate"]


REC = Recorder()

# --------------------------------------------------------------------------- tools
# Each tool's ONLY effect is appending an "invoke" event (the observable counter).


def _typed(kwargs: dict[str, Any]) -> dict[str, str]:
    return {k: f"{type(v).__name__}:{v!r}" for k, v in kwargs.items()}


@tool
def increment(label: str) -> str:
    """Increment the observable counter (authorized in the experiment)."""
    REC.event("invoke", tool="increment", received=_typed({"label": label}))
    return f"incremented:{label}"


@tool
def dangerous(label: str) -> str:
    """Stand-in for a tool the policy denies."""
    REC.event("invoke", tool="dangerous", received=_typed({"label": label}))
    return f"dangerous:{label}"


@tool
def needs_approval(label: str) -> str:
    """Stand-in for a destructive tool that requires approval."""
    REC.event("invoke", tool="needs_approval", received=_typed({"label": label}))
    return f"approval:{label}"


@tool
def typed_count(n: int) -> str:
    """Tool with an integer argument, used to observe argument coercion."""
    REC.event("invoke", tool="typed_count", received=_typed({"n": n}))
    return f"n={n}"


@tool
def unwrapped(label: str) -> str:
    """Tool that is never registered with the gate."""
    REC.event("invoke", tool="unwrapped", received=_typed({"label": label}))
    return f"unwrapped:{label}"


@tool
def state_reader(label: str, state: Annotated[dict, InjectedState]) -> str:
    """Tool with a framework-injected argument the model does not supply."""
    REC.event(
        "invoke",
        tool="state_reader",
        received=_typed({"label": label}),
        injected_state_keys=sorted(state.keys()),
    )
    return f"state_reader:{label}"


ALL_TOOLS = {
    t.name: t
    for t in (
        increment,
        dangerous,
        needs_approval,
        typed_count,
        unwrapped,
        state_reader,
    )
}

# --------------------------------------------------------------------------- gate


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ActionDenied(Exception):
    """Raised by the boundary when the decision is DENY."""


class ApprovalRequired(Exception):
    """Raised by the boundary when the decision is REQUIRE_APPROVAL."""


class ActionMismatch(Exception):
    """Raised when the action about to execute differs from the evaluated action."""


def _digest(agent_id: str, tool_name: str, args_json: str) -> str:
    payload = json.dumps(
        {"agent_id": agent_id, "tool": tool_name, "args": json.loads(args_json)},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class Action:
    request_id: int
    agent_id: str
    tool: str
    args_json: str
    digest: str


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    action: Action


class Gate:
    """Stand-in policy: dict lookup, default deny, records every evaluation."""

    def __init__(self, policy: dict[str, Verdict], rec: Recorder = REC) -> None:
        self.policy = dict(policy)
        self._rec = rec
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def evaluate(self, agent_id: str, tool_name: str, args: dict[str, Any]) -> Decision:
        with self._lock:
            request_id = next(self._ids)
        args_json = json.dumps(args, sort_keys=True, default=repr)
        verdict = self.policy.get(tool_name, Verdict.DENY)
        reason = "POLICY" if tool_name in self.policy else "UNAUTHORIZED_TOOL"
        action = Action(
            request_id,
            agent_id,
            tool_name,
            args_json,
            _digest(agent_id, tool_name, args_json),
        )
        self._rec.event(
            "evaluate",
            tool=tool_name,
            request_id=request_id,
            verdict=verdict.value,
            digest=action.digest[:12],
            args=args_json,
        )
        return Decision(verdict, reason, action)

    def verify(
        self, decision: Decision, agent_id: str, tool_name: str, args: Any
    ) -> bool:
        """True iff (agent, tool, args) is exactly the action the decision covers."""
        try:
            args_json = json.dumps(args, sort_keys=True, default=repr)
            return _digest(agent_id, tool_name, args_json) == decision.action.digest
        except (TypeError, ValueError):
            return False


# --------------------------------------------------------------------------- boundary


class Boundary:
    """Prototype of the interception boundary: a ToolNode ``wrap_tool_call`` hook.

    on_block:   "raise"   -> raise ActionDenied / ApprovalRequired
                "message" -> return an error ToolMessage (never raises)
    verify:     check the request about to execute equals the evaluated action
    tamper:     test hook applied AFTER evaluation and BEFORE verification, simulating
                buggy or hostile code that changes the request in between
    """

    def __init__(
        self,
        gate: Gate,
        agent_id: str,
        *,
        on_block: str = "raise",
        verify: bool = True,
        tamper: Any = None,
    ) -> None:
        self.gate = gate
        self.agent_id = agent_id
        self.on_block = on_block
        self.verify = verify
        self.tamper = tamper

    # shared decision logic ---------------------------------------------------------
    def _prepare(self, request: ToolCallRequest) -> tuple[ToolCallRequest | None, Any]:
        """Return (request_to_execute, None) or (None, blocking_exception_or_message)."""
        call = request.tool_call
        decision = self.gate.evaluate(self.agent_id, call["name"], call["args"])
        if decision.verdict is Verdict.DENY:
            return None, ActionDenied(f"{decision.reason}")
        if decision.verdict is Verdict.REQUIRE_APPROVAL:
            return None, ApprovalRequired("REQUIRE_APPROVAL")
        req = self.tamper(request) if self.tamper else request
        if self.verify:
            same_tool = req.tool is not None and req.tool.name == decision.action.tool
            same_action = self.gate.verify(
                decision, self.agent_id, req.tool_call["name"], req.tool_call["args"]
            )
            if not (same_tool and same_action):
                return None, ActionMismatch("ACTION_MISMATCH")
        return req, None

    def _block(self, request: ToolCallRequest, exc: Exception) -> ToolMessage:
        if self.on_block == "raise":
            raise exc
        return ToolMessage(
            content=f"blocked: {exc}",
            name=request.tool_call["name"],
            tool_call_id=request.tool_call["id"],
            status="error",
        )

    # hooks --------------------------------------------------------------------------
    def wrap(self, request: ToolCallRequest, execute: Any) -> Any:
        req, blocked = self._prepare(request)
        if req is None:
            return self._block(request, blocked)
        REC.event("execute-called", tool=req.tool_call["name"])
        return execute(req)

    async def awrap(self, request: ToolCallRequest, execute: Any) -> Any:
        req, blocked = self._prepare(request)
        if req is None:
            return self._block(request, blocked)
        REC.event("execute-called", tool=req.tool_call["name"])
        return await execute(req)


def wrap_tools(
    tools: list[Any],
    boundary: Boundary,
    *,
    sync_hook: bool = True,
    async_hook: bool = True,
    **tool_node_kwargs: Any,
) -> ToolNode:
    """Prototype of the proposed ``wrap_tools``: build a ToolNode whose every tool is
    registered with the gate and whose executions pass through ``boundary``.

    Refuses to build if a tool is unknown to the gate (construction-time registration
    check). It covers ONLY the tools passed in; it makes no claim about anything else.
    """
    unknown = [t.name for t in tools if t.name not in boundary.gate.policy]
    if unknown:
        raise ValueError(f"tools not registered with the gate: {unknown}")
    return ToolNode(
        tools,
        wrap_tool_call=boundary.wrap if sync_hook else None,
        awrap_tool_call=boundary.awrap if async_hook else None,
        **tool_node_kwargs,
    )


# --------------------------------------------------------------------------- scripted model


class ScriptedModel:
    """A graph node that stands in for the LLM: emits prepared tool calls (no network).

    steps:          list of tool-call lists, emitted one list per model turn.
    retry_on_error: if the last tool message is an error, re-emit its tool calls up to
                    this many times (simulates an agent that retries a denied call).
    """

    def __init__(
        self, steps: list[list[dict[str, Any]]], retry_on_error: int = 0
    ) -> None:
        self.steps = steps
        self.retry_on_error = retry_on_error
        self.retries = 0
        self._ids = itertools.count(1)

    def _calls(self, calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {"name": c["name"], "args": c["args"], "id": f"call_{next(self._ids)}"}
            for c in calls
        ]

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        msgs = state["messages"]
        n_ai = sum(isinstance(m, AIMessage) for m in msgs)
        last = msgs[-1]
        if (
            self.retries < self.retry_on_error
            and isinstance(last, ToolMessage)
            and last.status == "error"
        ):
            self.retries += 1
            prev_ai = next(m for m in reversed(msgs) if isinstance(m, AIMessage))
            return {
                "messages": [AIMessage("", tool_calls=self._calls(prev_ai.tool_calls))]
            }
        if n_ai < len(self.steps):
            return {
                "messages": [AIMessage("", tool_calls=self._calls(self.steps[n_ai]))]
            }
        return {"messages": [AIMessage("done")]}
