# Throwaway experiment code; excluded from production linting by `spikes` in pyproject.toml [tool.ruff] extend-exclude (D-28).
"""Stand-ins for the C-02b compatibility experiment (async-native tools, Command tools, create_agent).

THROWAWAY EXPERIMENT CODE. Not Sentinel product code: the "gate" is a dict lookup and the "proxy" is a
small state machine. It reuses the C-02 stand-ins (Gate, Recorder, Verdict) from the sibling spike.
"""

from __future__ import annotations

import asyncio
import copy
import json
import sys
import threading
import time
from pathlib import Path
from typing import Annotated, Any

sys.path.insert(
    0, str(Path(__file__).resolve().parent.parent / "langgraph_interception")
)

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import ToolMessage
from langchain_core.tools import InjectedToolCallId, StructuredTool, ToolException, tool
from langgraph.types import Command
from pydantic import create_model
from standin import (  # noqa: E402  (sibling spike, see sys.path above)
    REC,
    ActionDenied,
    ActionMismatch,
    ApprovalRequired,
    Decision,
    Gate,
    Verdict,
)

# --------------------------------------------------------------------------- tools


def _typed(kwargs: dict[str, Any]) -> dict[str, str]:
    return {k: f"{type(v).__name__}:{v!r}" for k, v in kwargs.items()}


def _inv(name: str, **kw: Any) -> None:
    REC.event("invoke", tool=name, received=_typed(kw))


class SideEffectThenFail(Exception):
    """Raised by tools AFTER their side effect has happened (generic Exception subclass)."""


CANARY = "CANARY-SECRET-IN-EXCEPTION-TEXT"


@tool
def s_inc(label: str) -> str:
    """Sync tool, authorized."""
    _inv("s_inc", label=label)
    return f"inc:{label}"


@tool
def s_deny(label: str) -> str:
    """Sync tool, denied by policy."""
    _inv("s_deny", label=label)
    return f"deny:{label}"


@tool
def s_approval(label: str) -> str:
    """Sync tool, requires approval."""
    _inv("s_approval", label=label)
    return f"approval:{label}"


@tool
def s_fail_after(label: str) -> str:
    """Sync tool that performs its side effect and then raises."""
    _inv("s_fail_after", label=label)
    raise SideEffectThenFail(CANARY)


@tool
def s_raw(label: str) -> str:
    """Sync tool never registered with the gate."""
    _inv("s_raw", label=label)
    return f"raw:{label}"


@tool
async def a_inc(label: str) -> str:
    """Async-native tool, authorized."""
    await asyncio.sleep(0)
    _inv("a_inc", label=label)
    return f"a_inc:{label}"


@tool
async def a_deny(label: str) -> str:
    """Async-native tool, denied."""
    await asyncio.sleep(0)
    _inv("a_deny", label=label)
    return f"a_deny:{label}"


@tool
async def a_approval(label: str) -> str:
    """Async-native tool, requires approval."""
    await asyncio.sleep(0)
    _inv("a_approval", label=label)
    return f"a_approval:{label}"


@tool
async def a_fail_after(label: str) -> str:
    """Async-native tool that performs its side effect and then raises."""
    _inv("a_fail_after", label=label)
    await asyncio.sleep(0)
    raise SideEffectThenFail(CANARY)


@tool
async def a_slow(label: str) -> str:
    """Async-native tool that takes a while (cancellation probe)."""
    _inv("a_slow", label=label)
    try:
        await asyncio.sleep(0.6)
        REC.event("complete", tool="a_slow")
    except asyncio.CancelledError:
        REC.event("cancelled", tool="a_slow")
        raise
    return f"slow:{label}"


@tool
def c_note(label: str, tool_call_id: Annotated[str, InjectedToolCallId]) -> Command:
    """Command-returning tool: updates state and reports via a ToolMessage."""
    _inv("c_note", label=label)
    return Command(
        update={
            "notes": [label],
            "messages": [ToolMessage(f"noted:{label}", tool_call_id=tool_call_id)],
        }
    )


@tool
def c_goto(label: str, tool_call_id: Annotated[str, InjectedToolCallId]) -> Command:
    """Command-returning tool that also routes the graph to another node."""
    _inv("c_goto", label=label)
    return Command(
        goto="side_node",
        update={"messages": [ToolMessage(f"goto:{label}", tool_call_id=tool_call_id)]},
    )


@tool
def c_deny(label: str, tool_call_id: Annotated[str, InjectedToolCallId]) -> Command:
    """Command-returning tool, denied by policy (would route to side_node if it ran)."""
    _inv("c_deny", label=label)
    return Command(
        goto="side_node",
        update={
            "messages": [ToolMessage(f"c_deny:{label}", tool_call_id=tool_call_id)]
        },
    )


@tool
def c_approval(label: str, tool_call_id: Annotated[str, InjectedToolCallId]) -> Command:
    """Command-returning tool, requires approval."""
    _inv("c_approval", label=label)
    return Command(
        goto="side_node",
        update={
            "messages": [ToolMessage(f"c_approval:{label}", tool_call_id=tool_call_id)]
        },
    )


@tool
def c_fail_after(
    label: str, tool_call_id: Annotated[str, InjectedToolCallId]
) -> Command:
    """Command-returning tool that performs its side effect and then raises."""
    _inv("c_fail_after", label=label)
    raise SideEffectThenFail(CANARY)


@tool
async def ac_note(
    label: str, tool_call_id: Annotated[str, InjectedToolCallId]
) -> Command:
    """Async-native Command-returning tool."""
    await asyncio.sleep(0)
    _inv("ac_note", label=label)
    return Command(
        update={
            "notes": [label],
            "messages": [ToolMessage(f"anoted:{label}", tool_call_id=tool_call_id)],
        }
    )


POLICY = {
    "s_inc": Verdict.ALLOW,
    "s_deny": Verdict.DENY,
    "s_approval": Verdict.REQUIRE_APPROVAL,
    "s_fail_after": Verdict.ALLOW,
    "a_inc": Verdict.ALLOW,
    "a_deny": Verdict.DENY,
    "a_approval": Verdict.REQUIRE_APPROVAL,
    "a_fail_after": Verdict.ALLOW,
    "a_slow": Verdict.ALLOW,
    "c_note": Verdict.ALLOW,
    "c_goto": Verdict.ALLOW,
    "c_deny": Verdict.DENY,
    "c_approval": Verdict.REQUIRE_APPROVAL,
    "c_fail_after": Verdict.ALLOW,
    "ac_note": Verdict.ALLOW,
}

# --------------------------------------------------------------------------- proxy


class ToolFailed(Exception):
    """Internal: the original function raised. ``original`` is kept ONLY so the naive-adapter control can re-raise it."""

    original: BaseException | None = None


class Proxy:
    """Stand-in proxy: sole caller of original functions; single-use decisions; state machine.

    states[request_id]: claimed -> entered -> completed | failed | interrupted
    'interrupted' = a BaseException (e.g. CancelledError) escaped after the function was entered:
    whether the side effect happened is UNKNOWN to the caller.
    """

    def __init__(self, gate: Gate) -> None:
        self._gate = gate
        self._reg: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.states: dict[int, str] = {}
        self._call_ids: set[str] = set()

    def register(
        self, name: str, *, sync: Any = None, asynchronous: Any = None
    ) -> None:
        if name in self._reg:
            raise ValueError(f"duplicate registration: {name}")
        self._reg[name] = {"sync": sync, "async": asynchronous}

    def claim_call_id(self, call_id: str) -> bool:
        """At-most-once per framework tool_call_id. True if this is the first claim."""
        with self._lock:
            if call_id in self._call_ids:
                return False
            self._call_ids.add(call_id)
            return True

    def _claim(
        self, decision: Decision, agent_id: str, tool_name: str, live_args: Any
    ) -> None:
        if decision.verdict is not Verdict.ALLOW:
            raise ActionDenied("NOT_ALLOWED")
        if decision.action.tool != tool_name or not self._gate.verify(
            decision, agent_id, tool_name, live_args
        ):
            raise ActionMismatch("ACTION_MISMATCH")
        with self._lock:
            if decision.action.request_id in self.states:
                raise ActionMismatch("DECISION_ALREADY_USED")
            self.states[decision.action.request_id] = "claimed"

    async def _aclaim(self, *a: Any, **k: Any) -> None:
        self._claim(*a, **k)

    def execute(
        self,
        decision: Decision,
        agent_id: str,
        tool_name: str,
        live_args: Any,
        injected: dict | None = None,
    ) -> Any:
        self._claim(decision, agent_id, tool_name, live_args)
        rid = decision.action.request_id
        fn = self._reg[tool_name]["sync"]
        self.states[rid] = "entered"
        try:
            out = fn(
                **copy.deepcopy(json.loads(decision.action.args_json)),
                **(injected or {}),
            )
        except Exception as e:
            self.states[rid] = "failed"
            err = ToolFailed(type(e).__name__)
            err.original = e
            raise err from None
        except BaseException:
            self.states[rid] = "interrupted"
            raise
        self.states[rid] = "completed"
        return out

    async def aexecute(
        self,
        decision: Decision,
        agent_id: str,
        tool_name: str,
        live_args: Any,
        injected: dict | None = None,
    ) -> Any:
        await self._aclaim(decision, agent_id, tool_name, live_args)
        rid = decision.action.request_id
        fn = self._reg[tool_name]["async"]
        self.states[rid] = "entered"
        try:
            out = await fn(
                **copy.deepcopy(json.loads(decision.action.args_json)),
                **(injected or {}),
            )
        except Exception as e:
            self.states[rid] = "failed"
            err = ToolFailed(type(e).__name__)
            err.original = e
            raise err from None
        except BaseException:
            self.states[rid] = "interrupted"
            raise
        self.states[rid] = "completed"
        return out


class RacyProxy(Proxy):
    """CONTROL: deliberately non-atomic check-then-mark. Used to prove the concurrency tests can fail."""

    def _claim(
        self, decision: Decision, agent_id: str, tool_name: str, live_args: Any
    ) -> None:
        if decision.verdict is not Verdict.ALLOW:
            raise ActionDenied("NOT_ALLOWED")
        if decision.action.request_id in self.states:
            raise ActionMismatch("DECISION_ALREADY_USED")
        time.sleep(0.002)  # widen the check-then-act window
        self.states[decision.action.request_id] = "claimed"

    async def _aclaim(
        self, decision: Decision, agent_id: str, tool_name: str, live_args: Any
    ) -> None:
        if decision.action.request_id in self.states:
            raise ActionMismatch("DECISION_ALREADY_USED")
        await asyncio.sleep(0)  # yield between check and mark
        self.states[decision.action.request_id] = "claimed"


# --------------------------------------------------------------------------- adapter


def wrap_tools_c(
    tools: list[Any],
    gate: Gate,
    proxy: Proxy,
    agent_id: str,
    *,
    on_block: str = "tool_exception",
    on_tool_error: str = "convert",
    once_per_call_id: bool = False,
    allowed_injected: tuple[str, ...] = ("tool_call_id",),
) -> list[StructuredTool]:
    """Prototype of the proposed ``wrap_tools`` (Design B), extended for async, Command and tool_call_id.

    on_block:      "tool_exception" -> raise ToolException (handled in-tool -> error ToolMessage)
    on_tool_error: "convert"   -> original exception becomes a fixed-text ToolException
                   "propagate" -> NAIVE: the original exception escapes to the framework (control)
    once_per_call_id: refuse a second execution for the same framework tool_call_id
    """
    wrapped: list[StructuredTool] = []
    for t in tools:
        if isinstance(t, dict):
            raise TypeError(
                "provider built-in (dict) tools execute outside this process and cannot be wrapped"
            )
        if not isinstance(t, StructuredTool):
            raise TypeError(
                f"unsupported tool class (no .func/.coroutine to relocate): {type(t).__name__}"
            )
        if t.name not in gate.policy:
            raise ValueError(f"tool not registered with the gate: {t.name}")
        model_fields = set(t.tool_call_schema.model_fields)
        all_fields = set(t.get_input_schema().model_fields)
        injected = all_fields - model_fields
        bad = injected - set(allowed_injected)
        if bad:
            raise ValueError(
                f"tool {t.name} has framework-injected parameters: {sorted(bad)}"
            )
        needs_cid = "tool_call_id" in injected
        add_cid = once_per_call_id and not needs_cid
        schema = t.args_schema
        if add_cid:
            schema = create_model(
                f"{t.name}_SentinelArgs",
                __base__=t.args_schema,
                tool_call_id=(Annotated[str, InjectedToolCallId], ...),
            )
        proxy.register(t.name, sync=t.func, asynchronous=t.coroutine)

        def split(
            kwargs: dict[str, Any],
        ) -> tuple[dict[str, Any], dict[str, Any], str | None]:
            kwargs = dict(kwargs)
            cid = kwargs.get("tool_call_id")
            inj: dict[str, Any] = {}
            if needs_cid and "tool_call_id" in kwargs:
                inj["tool_call_id"] = kwargs.pop("tool_call_id")
            elif add_cid:
                kwargs.pop("tool_call_id", None)
            return kwargs, inj, cid

        def blocked(decision: Decision) -> ToolException:
            if decision.verdict is Verdict.DENY:
                return ToolException(f"blocked: {decision.reason}")
            return ToolException("blocked: REQUIRE_APPROVAL")

        def make_sync(name: str):
            def guarded(**kwargs: Any) -> Any:
                model_args, inj, cid = split(kwargs)
                decision = gate.evaluate(agent_id, name, model_args)
                if decision.verdict is not Verdict.ALLOW:
                    raise blocked(decision)
                if (
                    once_per_call_id
                    and cid is not None
                    and not proxy.claim_call_id(cid)
                ):
                    raise ToolException("blocked: DUPLICATE_TOOL_CALL")
                try:
                    return proxy.execute(
                        decision, agent_id, name, model_args, injected=inj
                    )
                except ToolFailed as e:
                    if on_tool_error == "propagate":
                        raise e.original
                    raise ToolException(
                        "tool failed (execution may have occurred)"
                    ) from None

            return guarded

        def make_async(name: str):
            async def aguarded(**kwargs: Any) -> Any:
                model_args, inj, cid = split(kwargs)
                decision = await asyncio.to_thread(
                    gate.evaluate, agent_id, name, model_args
                )
                if decision.verdict is not Verdict.ALLOW:
                    raise blocked(decision)
                if (
                    once_per_call_id
                    and cid is not None
                    and not proxy.claim_call_id(cid)
                ):
                    raise ToolException("blocked: DUPLICATE_TOOL_CALL")
                try:
                    return await proxy.aexecute(
                        decision, agent_id, name, model_args, injected=inj
                    )
                except ToolFailed as e:
                    if on_tool_error == "propagate":
                        raise e.original
                    raise ToolException(
                        "tool failed (execution may have occurred)"
                    ) from None

            return aguarded

        wrapped.append(
            StructuredTool.from_function(
                func=make_sync(t.name) if t.func is not None else None,
                coroutine=make_async(t.name) if t.coroutine is not None else None,
                name=t.name,
                description=t.description,
                args_schema=schema,
                handle_tool_error=(on_block == "tool_exception"),
                return_direct=t.return_direct,
                metadata={**(t.metadata or {}), "sentinel_protected": True},
            )
        )
    return wrapped


# --------------------------------------------------------------------------- misc


class FakeToolChat(GenericFakeChatModel):
    """Deterministic chat model for create_agent: replays prepared AIMessages, ignores bind_tools."""

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        return self


def agent_tool_coverage(agent: Any) -> dict[str, bool] | str:
    """Inspect a compiled agent/graph: {tool name: protected by Sentinel?}. Returns a string if not inspectable."""
    try:
        node = agent.nodes["tools"]
        tn = getattr(node, "bound", None)
        by_name = tn.tools_by_name
        return {
            n: bool((t.metadata or {}).get("sentinel_protected"))
            for n, t in by_name.items()
        }
    except Exception as e:  # noqa: BLE001
        return f"not inspectable: {type(e).__name__}: {str(e)[:80]}"
