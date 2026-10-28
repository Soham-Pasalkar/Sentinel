# Throwaway experiment code; excluded from production linting by `spikes` in pyproject.toml [tool.ruff] extend-exclude (D-28).
"""C-02b runner: real langchain.agents.create_agent + LangGraph, async-native tools, Command tools.

THROWAWAY EXPERIMENT CODE (not Sentinel product code). Run:  python run_c02b.py
Writes results/results_c02b.json. Exit code 1 if a REQUIRED check fails.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import operator
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import version
from pathlib import Path
from typing import Annotated, Any

import standin_c as C  # noqa: F401  (sets sys.path for the sibling spike)
from langchain.agents import create_agent
from langchain.agents.middleware import AgentMiddleware, ToolRetryMiddleware
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.types import RetryPolicy
from standin import REC, ActionMismatch, Gate, Verdict
from standin import ScriptedModel as Script
from standin import state_reader
from standin_c import (
    CANARY,
    POLICY,
    FakeToolChat,
    Proxy,
    RacyProxy,
    a_approval,
    a_deny,
    a_fail_after,
    a_inc,
    a_slow,
    ac_note,
    agent_tool_coverage,
    c_approval,
    c_deny,
    c_fail_after,
    c_goto,
    c_note,
    s_approval,
    s_deny,
    s_fail_after,
    s_inc,
    s_raw,
    wrap_tools_c,
)

AGENT = "research_agent"
ORIGINAL = {
    t.name: t
    for t in (
        s_inc,
        s_deny,
        s_approval,
        s_fail_after,
        s_raw,
        a_inc,
        a_deny,
        a_approval,
        a_fail_after,
        a_slow,
        c_note,
        c_goto,
        c_deny,
        c_approval,
        c_fail_after,
        ac_note,
    )
}
INPUT = {"messages": [HumanMessage("go")]}
MATRIX: list[dict[str, Any]] = []  # retry matrix rows


# --------------------------------------------------------------------------- harness


class Scenario:
    def __init__(self, sid: str, title: str) -> None:
        self.sid, self.title = sid, title
        self.checks: list[dict[str, Any]] = []
        self.observed: dict[str, Any] = {}
        self.notes: list[str] = []

    def check(self, desc: str, cond: bool) -> None:
        self.checks.append({"check": desc, "pass": bool(cond)})

    def observe(self, key: str, value: Any) -> None:
        self.observed[key] = value

    def note(self, text: str) -> None:
        self.notes.append(text)

    @property
    def ok(self) -> bool:
        return all(c["pass"] for c in self.checks)


_ids = itertools.count(1)


def ai(*calls: tuple[str, dict]) -> AIMessage:
    return AIMessage(
        "",
        tool_calls=[
            {"name": n, "args": a, "id": f"call_{next(_ids)}"} for n, a in calls
        ],
    )


def tc(name: str, **args: Any) -> tuple[str, dict]:
    return name, args


def fresh(policy: dict | None = None) -> tuple[Gate, Proxy]:
    REC.reset()
    gate = Gate(policy or POLICY, REC)
    return gate, Proxy(gate)


def make_agent(tools: list, script: list, middleware: tuple = (), **kw: Any):
    model = FakeToolChat(messages=iter([*script, AIMessage("done")]))
    return create_agent(model, tools=tools, middleware=list(middleware), **kw)


def agent_run(
    agent: Any, via: str = "invoke", config: dict | None = None
) -> dict[str, Any]:
    try:
        if via == "invoke":
            out = agent.invoke(INPUT, config)
        else:
            out = asyncio.run(agent.ainvoke(INPUT, config))
        return {"out": out, "error": None}
    except Exception as e:  # noqa: BLE001
        return {"out": None, "error": f"{type(e).__name__}: {str(e)[:110]}"}


def msgs(r: dict[str, Any]) -> list[str]:
    if not r["out"]:
        return [f"<error> {r['error']}"]
    res = []
    for m in r["out"]["messages"]:
        extra = f" status={m.status}" if isinstance(m, ToolMessage) else ""
        calls = (
            f" calls={[c['name'] for c in m.tool_calls]}"
            if getattr(m, "tool_calls", None)
            else ""
        )
        res.append(f"{type(m).__name__}{extra}{calls} {str(m.content)[:70]!r}")
    return res


def allow_before_invoke() -> bool:
    allows: dict[str, int] = {}
    for e in REC.events:
        if e["kind"] == "evaluate" and e["verdict"] == "allow":
            allows[e["tool"]] = allows.get(e["tool"], 0) + 1
        if e["kind"] == "invoke":
            if allows.get(e["tool"], 0) <= 0:
                return False
            allows[e["tool"]] -= 1
    return True


def text_of(r: dict[str, Any]) -> str:
    return " ".join(msgs(r))


# --------------------------------------------------------------------------- Experiment A


def exp_a_basic() -> Scenario:
    s = Scenario(
        "A1-A3", "create_agent: authorized / denied / approval-required (sync tools)"
    )
    for name, want_inv, want_text in (
        ("s_inc", 1, "inc:x"),
        ("s_deny", 0, "blocked: POLICY"),
        ("s_approval", 0, "blocked: REQUIRE_APPROVAL"),
    ):
        gate, proxy = fresh()
        tools = wrap_tools_c([ORIGINAL[name]], gate, proxy, AGENT)
        r = agent_run(make_agent(tools, [ai(tc(name, label="x"))]))
        s.check(
            f"[{name}] invocation counter == {want_inv}", REC.count(name) == want_inv
        )
        s.check(
            f"[{name}] exactly one gate evaluation, before any invocation",
            len(REC.evaluations()) == 1 and allow_before_invoke(),
        )
        s.check(f"[{name}] agent run completed without raising", r["error"] is None)
        s.observe(f"{name}.messages", msgs(r))
        s.observe(f"{name}.proxy_states", dict(proxy.states))
        if want_inv == 0:
            s.check(
                f"[{name}] explicit Sentinel decision surfaced ('{want_text}'), proxy never claimed it",
                want_text in text_of(r) and not proxy.states,
            )
    return s


def exp_a_framework_vs_decision() -> Scenario:
    s = Scenario(
        "A4", "Framework rejection before adapter entry vs explicit Sentinel decision"
    )
    gate, proxy = fresh()
    tools = wrap_tools_c([s_deny], gate, proxy, AGENT)
    r_ghost = agent_run(make_agent(tools, [ai(tc("ghost", label="x"))]))
    ghost = {
        "evaluations": len(REC.evaluations()),
        "invocations": REC.count(),
        "text": msgs(r_ghost),
    }
    gate, proxy = fresh()
    tools = wrap_tools_c([s_deny], gate, proxy, AGENT)
    r_deny = agent_run(make_agent(tools, [ai(tc("s_deny", label="x"))]))
    denied = {
        "evaluations": len(REC.evaluations()),
        "invocations": REC.count(),
        "text": msgs(r_deny),
    }
    s.observe("unknown_tool_name", ghost)
    s.observe("denied_tool", denied)
    s.check("unknown tool name: nothing executed", ghost["invocations"] == 0)
    s.check(
        "unknown tool name is rejected by the FRAMEWORK: Sentinel recorded no evaluation",
        ghost["evaluations"] == 0,
    )
    s.check(
        "denied tool: nothing executed, and Sentinel DID evaluate it (explicit decision)",
        denied["invocations"] == 0 and denied["evaluations"] == 1,
    )
    return s


def exp_a_coverage() -> Scenario:
    s = Scenario("A5-A6", "Unwrapped tools: never represented as protected")
    # A5: mixed agent
    gate, proxy = fresh()
    wrapped = wrap_tools_c([s_inc], gate, proxy, AGENT)
    agent = make_agent([*wrapped, s_raw], [ai(tc("s_raw", label="x"))])
    cov = agent_tool_coverage(agent)
    r = agent_run(agent)
    s.observe("A5.coverage", cov)
    s.observe(
        "A5.unwrapped_call",
        {"invocations": REC.count("s_raw"), "evaluations": len(REC.evaluations())},
    )
    s.check(
        "[control] an unwrapped tool in the same agent executes with NO Sentinel evaluation",
        REC.count("s_raw") == 1 and len(REC.evaluations()) == 0,
    )
    s.check(
        "coverage inspection of the compiled agent is available", isinstance(cov, dict)
    )
    s.check(
        "coverage inspection reports the unwrapped tool as NOT protected",
        isinstance(cov, dict)
        and cov.get("s_raw") is False
        and cov.get("s_inc") is True,
    )

    # A6: a tool injected by middleware (class attribute `tools`)
    class ExtraTools(AgentMiddleware):
        tools = [s_raw]

    gate, proxy = fresh()
    wrapped = wrap_tools_c([s_inc], gate, proxy, AGENT)
    agent = make_agent(
        wrapped, [ai(tc("s_raw", label="x"))], middleware=(ExtraTools(),)
    )
    cov = agent_tool_coverage(agent)
    r = agent_run(agent)
    s.observe("A6.coverage", cov)
    s.observe(
        "A6.middleware_tool_call",
        {
            "invocations": REC.count("s_raw"),
            "evaluations": len(REC.evaluations()),
            "messages": msgs(r),
        },
    )
    s.check(
        "[control] a middleware-provided tool executes with NO Sentinel evaluation",
        REC.count("s_raw") == 1 and len(REC.evaluations()) == 0,
    )
    s.check(
        "coverage inspection reports the middleware-provided tool as NOT protected",
        isinstance(cov, dict) and cov.get("s_raw") is False,
    )

    # wrap-time refusals
    from langchain_core.tools import BaseTool

    class ClassBasedTool(BaseTool):
        name: str = "s_inc"
        description: str = "class-based tool: no .func / .coroutine to relocate"

        def _run(self, label: str) -> str:
            return label

    gate, proxy = fresh()
    for label, obj in (
        ("provider built-in dict tool", {"type": "web_search"}),
        ("unregistered tool", s_raw),
        ("class-based BaseTool (no .func/.coroutine)", ClassBasedTool()),
    ):
        try:
            wrap_tools_c([obj], gate, Proxy(gate), AGENT)
            refused = False
        except (TypeError, ValueError) as e:
            refused = True
            s.observe(f"refusal[{label}]", str(e)[:100])
        s.check(f"wrap_tools refuses: {label}", refused)
    return s


def exp_a_middleware() -> Scenario:
    s = Scenario("A7-A8", "Agent middleware that modifies or redirects the tool call")

    class TamperArgs(AgentMiddleware):
        def wrap_tool_call(self, request, handler):
            return handler(
                request.override(
                    tool_call={**request.tool_call, "args": {"label": "TAMPERED"}}
                )
            )

    gate, proxy = fresh()
    wrapped = wrap_tools_c([s_inc], gate, proxy, AGENT)
    r = agent_run(
        make_agent(
            wrapped, [ai(tc("s_inc", label="original"))], middleware=(TamperArgs(),)
        )
    )
    ev = REC.evaluations()
    rec = REC.invocations("s_inc")
    s.observe("A7.evaluated_args", [e["args"] for e in ev])
    s.observe("A7.executed", [e["received"] for e in rec])
    s.check(
        "middleware changed the arguments: the gate evaluated the CHANGED arguments (authorization follows what executes)",
        len(ev) == 1 and "TAMPERED" in ev[0]["args"],
    )
    s.check(
        "evaluated arguments == executed arguments",
        len(rec) == 1 and "TAMPERED" in str(rec[0]["received"]),
    )

    # A8: middleware swaps the tool OBJECT for an unwrapped, denied original
    class SwapTool(AgentMiddleware):
        def wrap_tool_call(self, request, handler):
            return handler(request.override(tool=ORIGINAL["s_deny"]))

    gate, proxy = fresh()
    wrapped = wrap_tools_c([s_inc, s_deny], gate, proxy, AGENT)
    r = agent_run(
        make_agent(wrapped, [ai(tc("s_inc", label="x"))], middleware=(SwapTool(),))
    )
    s.observe(
        "A8.swapped_tool",
        {
            "invoked": [e["tool"] for e in REC.invocations()],
            "evaluations": len(REC.evaluations()),
            "messages": msgs(r),
        },
    )
    s.check(
        "[control] trusted middleware can swap in an ORIGINAL denied tool: it ran with no evaluation (bypass by trusted code)",
        REC.count("s_deny") == 1 and len(REC.evaluations()) == 0,
    )
    s.note(
        "A8 is a bypass by trusted code (middleware is part of the agent definition). It is documented, not defended."
    )
    return s


def retry_case(mech: str, kind: str, mode: str, once: bool, builder) -> dict[str, Any]:
    """Run one failing-after-side-effect tool under one retry mechanism and adapter mode."""
    gate, proxy = fresh()
    name = {"sync": "s_fail_after", "async": "a_fail_after", "command": "c_fail_after"}[
        kind
    ]
    tools = wrap_tools_c(
        [ORIGINAL[name]], gate, proxy, AGENT, on_tool_error=mode, once_per_call_id=once
    )
    r = builder(tools, name)
    row = {
        "mechanism": mech,
        "tool": kind,
        "adapter": f"on_tool_error={mode}" + (" + once_per_call_id" if once else ""),
        "executions": REC.count(name),
        "evaluations": len(REC.evaluations()),
        "states": sorted(proxy.states.values()),
        "error": r["error"],
        "canary_in_output_or_error": CANARY in text_of(r)
        if r["out"]
        else (CANARY in (r["error"] or "")),
    }
    MATRIX.append(row)
    return row


def exp_a_errors() -> Scenario:
    s = Scenario(
        "A10",
        "create_agent: tool failing AFTER its side effect, with ToolRetryMiddleware",
    )
    retry = lambda: ToolRetryMiddleware(
        max_retries=2,
        initial_delay=0.001,
        backoff_factor=1.0,
        max_delay=0.01,
        jitter=False,
    )

    def builder(tools, name):
        return agent_run(
            make_agent(tools, [ai(tc(name, label="x"))], middleware=(retry(),))
        )

    rows = {}
    for mode, once in (
        ("convert", False),
        ("propagate", False),
        ("propagate", True),
        ("convert", True),
    ):
        rows[(mode, once)] = retry_case(
            "ToolRetryMiddleware(max_retries=2)", "sync", mode, once, builder
        )
        s.observe(f"{mode}{' +once' if once else ''}", rows[(mode, once)])
    gate, proxy = fresh()
    once_tools = wrap_tools_c([s_inc], gate, proxy, AGENT, once_per_call_id=True)
    s.observe(
        "once_per_call_id.schemas",
        {
            "model_facing": sorted(once_tools[0].tool_call_schema.model_fields),
            "all_incl_injected": sorted(once_tools[0].get_input_schema().model_fields),
        },
    )
    s.check(
        "once_per_call_id adds an injected tool_call_id that stays invisible to the model",
        sorted(once_tools[0].tool_call_schema.model_fields) == ["label"]
        and "tool_call_id" in once_tools[0].get_input_schema().model_fields,
    )
    s.check(
        "[convert] failure converted to a fixed-text ToolException: the tool ran exactly once",
        rows[("convert", False)]["executions"] == 1,
    )
    s.check(
        "[convert] the exception text (canary) never reached the model",
        not rows[("convert", False)]["canary_in_output_or_error"],
    )
    s.check(
        "[convert + once_per_call_id] exactly once",
        rows[("convert", True)]["executions"] == 1,
    )
    s.check(
        "[propagate + once_per_call_id] the framework retried but the adapter blocked the repeats: exactly once",
        rows[("propagate", True)]["executions"] == 1,
    )
    s.check(
        "[control: naive propagate] the framework re-executed the tool after its post-execution failure (duplicate side effects)",
        rows[("propagate", False)]["executions"] > 1,
    )

    # agent-loop retry: the model itself re-issues the call after an error
    gate, proxy = fresh()
    tools = wrap_tools_c([s_fail_after], gate, proxy, AGENT)
    r = agent_run(
        make_agent(
            tools,
            [ai(tc("s_fail_after", label="x")), ai(tc("s_fail_after", label="x"))],
        )
    )
    s.observe(
        "agent_loop_retry",
        {
            "executions": REC.count("s_fail_after"),
            "decisions": len(proxy.states),
            "states": sorted(proxy.states.values()),
            "messages": msgs(r),
        },
    )
    s.check(
        "[agent-loop retry] model re-issued the call: two executions, each under its OWN decision (no decision consumed twice)",
        REC.count("s_fail_after") == 2 and len(proxy.states) == 2,
    )
    s.note(
        "An agent-loop retry is a new, separately authorized request. The adapter cannot tell it from a legitimate repeat; limiting it is a policy matter (e.g. rate limits, idempotency keys), not adapter logic."
    )
    return s


# --------------------------------------------------------------------------- Experiment B


def exp_b_basic() -> Scenario:
    s = Scenario("B1-B3", "Async-native tools: authorized / denied / approval-required")
    for name, want_inv in (("a_inc", 1), ("a_deny", 0), ("a_approval", 0)):
        gate, proxy = fresh()
        tools = wrap_tools_c([ORIGINAL[name]], gate, proxy, AGENT)
        r = agent_run(make_agent(tools, [ai(tc(name, label="x"))]), via="ainvoke")
        s.check(
            f"[{name} via create_agent.ainvoke] invocation counter == {want_inv}",
            REC.count(name) == want_inv,
        )
        s.check(
            f"[{name}] exactly one gate evaluation, before any invocation",
            len(REC.evaluations()) == 1 and allow_before_invoke(),
        )
        s.check(f"[{name}] completed without raising", r["error"] is None)
        s.observe(f"{name}.messages", msgs(r))
        s.observe(
            f"{name}.evaluation_thread",
            sorted({e["thread"] for e in REC.evaluations()}),
        )
        # the same through a plain ToolNode graph
        gate, proxy = fresh()
        tools = wrap_tools_c([ORIGINAL[name]], gate, proxy, AGENT)
        r2 = run_plain_graph(ToolNode(tools), [[tc(name, label="x")]], via="ainvoke")
        s.check(
            f"[{name} via StateGraph+ToolNode.ainvoke] invocation counter == {want_inv}",
            REC.count(name) == want_inv and len(REC.evaluations()) == 1,
        )

    # sync entry into an async-only tool
    gate, proxy = fresh()
    tools = wrap_tools_c([a_inc], gate, proxy, AGENT)
    r = agent_run(make_agent(tools, [ai(tc("a_inc", label="x"))]), via="invoke")
    wrapped_result = {
        "error": r["error"],
        "invocations": REC.count(),
        "evaluations": len(REC.evaluations()),
    }
    REC.reset()
    r0 = agent_run(make_agent([a_inc], [ai(tc("a_inc", label="x"))]), via="invoke")
    original_result = {
        "error": r0["error"],
        "invocations": REC.count(),
        "evaluations": 0,
    }
    s.observe("sync_invoke_on_async_only.wrapped", wrapped_result)
    s.observe("sync_invoke_on_async_only.original_control", original_result)
    s.check(
        "sync entry into an async-only wrapped tool does not execute and records no evaluation (fails closed, like the original)",
        wrapped_result["invocations"] == 0 and wrapped_result["evaluations"] == 0,
    )
    return s


def run_plain_graph(
    tool_node: ToolNode,
    steps: list,
    via: str = "invoke",
    retry: RetryPolicy | None = None,
    state: type = MessagesState,
    extra_nodes: dict | None = None,
):
    g = StateGraph(state)
    g.add_node(
        "model", Script([[{"name": n, "args": a} for n, a in step] for step in steps])
    )
    if retry:
        g.add_node("tools", tool_node, retry_policy=retry)
    else:
        g.add_node("tools", tool_node)
    g.add_edge(START, "model")
    g.add_conditional_edges("model", tools_condition)
    g.add_edge("tools", "model")
    for name, fn in (extra_nodes or {}).items():
        g.add_node(name, fn)
        g.add_edge(name, "model")
    app = g.compile()
    inp = {
        **INPUT,
        **({"notes": []} if "notes" in getattr(state, "__annotations__", {}) else {}),
    }
    try:
        out = app.invoke(inp) if via == "invoke" else asyncio.run(app.ainvoke(inp))
        return {"out": out, "error": None, "app": app}
    except Exception as e:  # noqa: BLE001
        return {"out": None, "error": f"{type(e).__name__}: {str(e)[:110]}", "app": app}


def race_trials(
    proxy_cls: type, mode: str, trials: int = 100, contenders: int = 8
) -> dict[str, Any]:
    """Many contenders try to consume ONE decision. Count executions per trial."""
    bad_trials, executions, already_used = 0, [], 0
    for _ in range(trials):
        REC.reset()
        gate = Gate(POLICY, REC)
        proxy = proxy_cls(gate)
        name = "a_inc" if mode == "async" else "s_inc"
        proxy.register(name, sync=s_inc.func, asynchronous=a_inc.coroutine)
        args = {"label": "x"}
        decision = gate.evaluate(AGENT, name, args)
        if mode == "async":

            async def go():
                return await asyncio.gather(
                    *[
                        proxy.aexecute(decision, AGENT, name, args)
                        for _ in range(contenders)
                    ],
                    return_exceptions=True,
                )

            results = asyncio.run(go())
        else:
            barrier = threading.Barrier(contenders)

            def worker():
                barrier.wait()
                try:
                    return proxy.execute(decision, AGENT, name, args)
                except Exception as e:  # noqa: BLE001
                    return e

            with ThreadPoolExecutor(contenders) as ex:
                results = list(ex.map(lambda _: worker(), range(contenders)))
        n = REC.count(name)
        executions.append(n)
        already_used += sum(isinstance(x, ActionMismatch) for x in results)
        if n != 1:
            bad_trials += 1
    return {
        "trials": trials,
        "contenders": contenders,
        "trials_with_executions_ne_1": bad_trials,
        "max_executions": max(executions),
        "refusals_total": already_used,
    }


def exp_b_concurrency() -> Scenario:
    s = Scenario("B5/D3", "Concurrent attempts to consume the same decision")
    for mode in ("async", "thread"):
        good = race_trials(Proxy, mode)
        racy = race_trials(RacyProxy, mode, trials=50)
        s.observe(f"{mode}.atomic_proxy", good)
        s.observe(f"{mode}.racy_control", racy)
        s.check(
            f"[{mode}] atomic single-use: 100 trials x 8 contenders, every trial executed exactly once",
            good["trials_with_executions_ne_1"] == 0 and good["max_executions"] == 1,
        )
        s.check(
            f"[{mode}] 7 of 8 contenders refused in every trial",
            good["refusals_total"] == good["trials"] * (good["contenders"] - 1),
        )
        s.check(
            f"[{mode}] test power: the deliberately racy control DID execute more than once in some trials",
            racy["trials_with_executions_ne_1"] > 0,
        )
    return s


def exp_b_cancellation() -> Scenario:
    s = Scenario("B6", "Cancellation of an async-native tool mid-execution")
    gate, proxy = fresh()
    tools = wrap_tools_c([a_slow], gate, proxy, AGENT)
    agent = make_agent(tools, [ai(tc("a_slow", label="x"))])

    async def go():
        outcome = "completed"
        try:
            await asyncio.wait_for(agent.ainvoke(INPUT), timeout=0.15)
        except asyncio.TimeoutError:
            outcome = "TimeoutError"
        await asyncio.sleep(
            0.9
        )  # long enough for a stray retry or for the tool to finish
        return outcome

    outcome = asyncio.run(go())
    s.observe("outcome", outcome)
    s.observe(
        "counters",
        {
            "started": REC.count("a_slow"),
            "completed": sum(e["kind"] == "complete" for e in REC.events),
            "cancelled": sum(e["kind"] == "cancelled" for e in REC.events),
            "evaluations": len(REC.evaluations()),
        },
    )
    s.observe("proxy_states", sorted(proxy.states.values()))
    s.check("the call was cancelled by the caller's timeout", outcome == "TimeoutError")
    s.check(
        "the tool had STARTED (side effect possible) and did not complete",
        REC.count("a_slow") == 1
        and not any(e["kind"] == "complete" for e in REC.events),
    )
    s.check(
        "no automatic re-execution after cancellation (counter stayed 1 for 0.9 s)",
        REC.count("a_slow") == 1,
    )
    s.check(
        "the decision is recorded as 'interrupted', NOT as 'never started' (execution status unknown, not 'not_started')",
        sorted(proxy.states.values()) == ["interrupted"],
    )
    s.note(
        "CancelledError is a BaseException: it passes through `except Exception` handlers. The proxy must mark the request interrupted (EXECUTION_STARTED written, no completion), which the audit reconstruction rules classify as 'unknown'."
    )
    return s


def exp_b_retries() -> Scenario:
    s = Scenario(
        "B7", "Async-native tool failing AFTER its side effect, with retry mechanisms"
    )
    rp = RetryPolicy(max_attempts=3, initial_interval=0.001, jitter=False)

    def with_retry_policy(tools, name):
        r = run_plain_graph(
            ToolNode(tools), [[tc(name, label="x")]], via="ainvoke", retry=rp
        )
        return {"out": r["out"], "error": r["error"]}

    def with_middleware(tools, name):
        mw = ToolRetryMiddleware(
            max_retries=2,
            initial_delay=0.001,
            backoff_factor=1.0,
            max_delay=0.01,
            jitter=False,
        )
        return agent_run(
            make_agent(tools, [ai(tc(name, label="x"))], middleware=(mw,)),
            via="ainvoke",
        )

    got = {}
    for mech, builder in (
        ("LangGraph RetryPolicy(max_attempts=3) on tools node", with_retry_policy),
        ("ToolRetryMiddleware(max_retries=2) in create_agent", with_middleware),
    ):
        for mode, once in (
            ("convert", False),
            ("propagate", False),
            ("propagate", True),
        ):
            row = retry_case(mech, "async", mode, once, builder)
            got[(mech, mode, once)] = row
            s.observe(f"{mech[:12]}|{mode}{'+once' if once else ''}", row)
    for mech in {m for m, _, _ in got}:
        s.check(
            f"[{mech[:22]}] convert: executed exactly once",
            got[(mech, "convert", False)]["executions"] == 1,
        )
        s.check(
            f"[{mech[:22]}] propagate + once_per_call_id: executed exactly once",
            got[(mech, "propagate", True)]["executions"] == 1,
        )
        s.check(
            f"[{mech[:22]}] control: naive propagate re-executed the tool",
            got[(mech, "propagate", False)]["executions"] > 1,
        )
    return s


# --------------------------------------------------------------------------- Experiment C


class CmdState(MessagesState):
    notes: Annotated[list[str], operator.add]


def side_node(state: Any) -> dict[str, Any]:
    REC.event("side-node-ran")
    return {"notes": ["side"]}


def cmd_graph(
    tools: list, steps: list, via: str = "invoke", retry: RetryPolicy | None = None
):
    return run_plain_graph(
        ToolNode(tools),
        steps,
        via=via,
        retry=retry,
        state=CmdState,
        extra_nodes={"side_node": side_node},
    )


def final_view(r: dict[str, Any]) -> dict[str, Any] | None:
    if not r["out"]:
        return None
    out = r["out"]
    return {
        "notes": out["notes"],
        "messages": [
            (type(m).__name__, getattr(m, "status", None), str(m.content))
            for m in out["messages"]
        ],
        "side_node_runs": sum(e["kind"] == "side-node-ran" for e in REC.events),
    }


def exp_c_semantics() -> Scenario:
    s = Scenario(
        "C1-C2",
        "Command-returning tools: return semantics preserved by the replacement tool",
    )
    for name in ("c_note", "c_goto"):
        REC.reset()
        r0 = cmd_graph([ORIGINAL[name]], [[tc(name, label="x")]])
        original_view = final_view(r0)
        gate, proxy = fresh()
        tools = wrap_tools_c([ORIGINAL[name]], gate, proxy, AGENT)
        r1 = cmd_graph(tools, [[tc(name, label="x")]])
        wrapped_view = final_view(r1)
        s.observe(f"{name}.original", original_view)
        s.observe(f"{name}.wrapped", wrapped_view)
        s.check(
            f"[{name}] original and wrapped runs both completed",
            r0["error"] is None and r1["error"] is None,
        )
        s.check(
            f"[{name}] the graph processed the returned Command identically (state, messages, routing)",
            original_view == wrapped_view,
        )
        s.check(
            f"[{name}] wrapped: invoked exactly once, one evaluation before it",
            REC.count(name) == 1
            and len(REC.evaluations()) == 1
            and allow_before_invoke(),
        )
    # tool_call_id passthrough: ToolNode itself validates the id inside the Command
    gate, proxy = fresh()
    tools = wrap_tools_c([c_note], gate, proxy, AGENT)
    r = cmd_graph(tools, [[tc("c_note", label="x")]])
    call_id = next(
        m for m in r["out"]["messages"] if isinstance(m, AIMessage) and m.tool_calls
    ).tool_calls[0]["id"]
    tm = next(m for m in r["out"]["messages"] if isinstance(m, ToolMessage))
    s.check(
        "InjectedToolCallId was forwarded to the original function (ToolMessage carries the model's call id)",
        tm.tool_call_id == call_id,
    )
    s.observe(
        "model_facing_schema_c_note", sorted(tools[0].tool_call_schema.model_fields)
    )
    s.check(
        "the injected id stays invisible to the model and to the gate's evaluated arguments",
        sorted(tools[0].tool_call_schema.model_fields) == ["label"]
        and REC.evaluations()[0]["args"] == '{"label": "x"}',
    )
    # other injected parameters still refused
    try:
        wrap_tools_c([state_reader], gate, Proxy(gate), AGENT)
        refused = False
    except ValueError:
        refused = True
    s.check(
        "tools with other injected parameters (InjectedState) are still refused",
        refused,
    )
    # async-native Command tool
    gate, proxy = fresh()
    tools = wrap_tools_c([ac_note], gate, proxy, AGENT)
    r = cmd_graph(tools, [[tc("ac_note", label="x")]], via="ainvoke")
    s.observe("ac_note.wrapped", final_view(r))
    s.check(
        "async-native Command tool: executed once and the Command (state update) was applied",
        REC.count("ac_note") == 1
        and r["out"] is not None
        and r["out"]["notes"] == ["x"],
    )
    return s


def exp_c_denial() -> Scenario:
    s = Scenario(
        "C3-C4",
        "Denied / approval-required Command tools: no Command, no routing, no execution",
    )
    for name in ("c_deny", "c_approval"):
        REC.reset()
        r0 = cmd_graph([ORIGINAL[name]], [[tc(name, label="x")]])
        control = final_view(r0)
        gate, proxy = fresh()
        tools = wrap_tools_c([ORIGINAL[name]], gate, proxy, AGENT)
        r1 = cmd_graph(tools, [[tc(name, label="x")]])
        view = final_view(r1)
        s.observe(f"{name}.control_unwrapped", control)
        s.observe(f"{name}.wrapped", view)
        s.check(
            f"[{name}] [control] the UNWRAPPED Command tool executes and routes to side_node",
            control is not None and control["side_node_runs"] >= 1,
        )
        s.check(f"[{name}] wrapped: function never invoked", REC.count(name) == 0)
        s.check(
            f"[{name}] wrapped: the Command's goto did not happen (side_node never ran)",
            view is not None and view["side_node_runs"] == 0,
        )
        s.check(
            f"[{name}] wrapped: no state update leaked (notes empty)",
            view is not None and view["notes"] == [],
        )
        s.check(
            f"[{name}] wrapped: represented as an error ToolMessage, not a Command",
            view is not None
            and any(
                m[0] == "ToolMessage" and m[1] == "error" for m in view["messages"]
            ),
        )
    return s


def exp_c_retries() -> Scenario:
    s = Scenario(
        "C5", "Command tool failing AFTER its side effect, with LangGraph RetryPolicy"
    )
    rp = RetryPolicy(max_attempts=3, initial_interval=0.001, jitter=False)

    def builder(tools, name):
        r = cmd_graph(tools, [[tc(name, label="x")]], retry=rp)
        return {"out": r["out"], "error": r["error"]}

    got = {}
    for mode, once in (("convert", False), ("propagate", False), ("propagate", True)):
        row = retry_case(
            "LangGraph RetryPolicy(max_attempts=3) on tools node",
            "command",
            mode,
            once,
            builder,
        )
        got[(mode, once)] = row
        s.observe(f"{mode}{'+once' if once else ''}", row)
    s.check(
        "[convert] executed exactly once", got[("convert", False)]["executions"] == 1
    )
    s.check(
        "[propagate + once_per_call_id] executed exactly once",
        got[("propagate", True)]["executions"] == 1,
    )
    s.check(
        "[control] naive propagate re-executed the Command tool",
        got[("propagate", False)]["executions"] > 1,
    )
    return s


def exp_c_create_agent() -> Scenario:
    s = Scenario("C6", "Command tool inside create_agent (custom state key)")
    from langchain.agents import AgentState

    class NotesState(AgentState):
        notes: Annotated[list[str], operator.add]

    for label, wrap in (("original", False), ("wrapped", True)):
        gate, proxy = fresh()
        tools = wrap_tools_c([c_note], gate, proxy, AGENT) if wrap else [c_note]
        try:
            agent = make_agent(
                tools, [ai(tc("c_note", label="x"))], state_schema=NotesState
            )
            out = agent.invoke({**INPUT, "notes": []})
            res = {"notes": out.get("notes"), "error": None}
        except Exception as e:  # noqa: BLE001
            res = {"notes": None, "error": f"{type(e).__name__}: {str(e)[:120]}"}
        s.observe(label, {**res, "invocations": REC.count("c_note")})
        s.check(
            f"[{label}] create_agent applied the Command state update",
            res["error"] is None and res["notes"] == ["x"],
        )
    return s


# --------------------------------------------------------------------------- Experiment D


def exp_d_binding() -> Scenario:
    s = Scenario(
        "D1-D2",
        "Decision bound to one exact action; single use (sync and async proxies)",
    )
    for mode in ("sync", "async"):
        name = "s_inc" if mode == "sync" else "a_inc"
        other = "s_deny" if mode == "sync" else "a_deny"

        def new():
            gate, proxy = fresh()
            proxy.register(name, sync=s_inc.func, asynchronous=a_inc.coroutine)
            proxy.register(other, sync=s_deny.func, asynchronous=a_deny.coroutine)
            return gate, proxy

        def attempt(proxy, decision, tool, args):
            try:
                if mode == "sync":
                    proxy.execute(decision, AGENT, tool, args)
                else:
                    asyncio.run(proxy.aexecute(decision, AGENT, tool, args))
                return "executed"
            except Exception as e:  # noqa: BLE001
                return type(e).__name__ + ":" + str(e)

        gate, proxy = new()
        d = gate.evaluate(AGENT, name, {"label": "a"})
        res = attempt(proxy, d, name, {"label": "b"})
        s.check(
            f"[{mode}] decision for args A cannot execute args B",
            res.startswith("ActionMismatch") and REC.count() == 0,
        )
        gate, proxy = new()
        d = gate.evaluate(AGENT, name, {"label": "a"})
        res = attempt(proxy, d, other, {"label": "a"})
        s.check(
            f"[{mode}] decision for tool X cannot execute tool Y",
            res.startswith("ActionMismatch") and REC.count() == 0,
        )
        gate, proxy = new()
        d = gate.evaluate(AGENT, other, {"label": "a"})  # DENY decision
        res = attempt(proxy, d, other, {"label": "a"})
        s.check(
            f"[{mode}] a DENY decision cannot be executed",
            res.startswith("ActionDenied") and REC.count() == 0,
        )
        gate, proxy = new()
        live = {"label": "a"}
        d = gate.evaluate(AGENT, name, live)
        live["label"] = "MUTATED"
        res = attempt(proxy, d, name, live)
        s.check(
            f"[{mode}] arguments mutated after evaluation are refused",
            res.startswith("ActionMismatch") and REC.count() == 0,
        )
        gate, proxy = new()
        d = gate.evaluate(AGENT, name, {"label": "a"})
        first = attempt(proxy, d, name, {"label": "a"})
        second = attempt(proxy, d, name, {"label": "a"})
        s.check(
            f"[{mode}] sequential replay: first executes, second refused (DECISION_ALREADY_USED)",
            first == "executed"
            and "DECISION_ALREADY_USED" in second
            and REC.count(name) == 1,
        )
    return s


def exp_d_matrix() -> Scenario:
    s = Scenario(
        "D4-D5",
        "DENY / REQUIRE_APPROVAL never execute: tool kind x verdict x entry point",
    )
    entry_sets = {
        "sync": [
            ("create_agent.invoke", "agent", "invoke"),
            ("create_agent.ainvoke", "agent", "ainvoke"),
            ("StateGraph+ToolNode.invoke", "graph", "invoke"),
            ("StateGraph+ToolNode.ainvoke", "graph", "ainvoke"),
        ],
        "async": [
            ("create_agent.ainvoke", "agent", "ainvoke"),
            ("StateGraph+ToolNode.ainvoke", "graph", "ainvoke"),
        ],
        "command": [
            ("StateGraph+ToolNode.invoke", "graph", "invoke"),
            ("StateGraph+ToolNode.ainvoke", "graph", "ainvoke"),
        ],
    }
    table = []

    def run_entry(name: str, kind_entry: str, how: str, via: str):
        gate, proxy = fresh()
        tools = wrap_tools_c([ORIGINAL[name]], gate, proxy, AGENT)
        if how == "agent":
            r = agent_run(make_agent(tools, [ai(tc(name, label="x"))]), via=via)
        else:
            r = cmd_graph(tools, [[tc(name, label="x")]], via=via)
        return {
            "invocations": REC.count(name),
            "evaluations": len(REC.evaluations()),
            "claimed_by_proxy": len(proxy.states),
            "error": r["error"],
        }

    for kind, prefix in (("sync", "s"), ("async", "a"), ("command", "c")):
        for verdict in ("deny", "approval"):
            name = f"{prefix}_{verdict}"
            for entry, how, via in entry_sets[kind]:
                row = {
                    "tool_kind": kind,
                    "verdict": verdict,
                    "entry": entry,
                    **run_entry(name, entry, how, via),
                }
                table.append(row)
                s.check(
                    f"[{kind}/{verdict}/{entry}] never executed, explicitly evaluated once, proxy never claimed",
                    row["invocations"] == 0
                    and row["evaluations"] == 1
                    and row["claimed_by_proxy"] == 0,
                )
    # async-native tools entered through a SYNC entry point: the framework fails before the adapter is reached
    for verdict in ("deny", "approval"):
        name = f"a_{verdict}"
        for entry, how, via in (
            ("create_agent.invoke", "agent", "invoke"),
            ("StateGraph+ToolNode.invoke", "graph", "invoke"),
        ):
            row = {
                "tool_kind": "async",
                "verdict": verdict,
                "entry": entry + " (sync entry into async-only tool)",
                **run_entry(name, entry, how, via),
            }
            table.append(row)
            s.check(
                f"[async/{verdict}/{entry} sync entry] never executed and never claimed (framework fails before adapter entry; no Sentinel evaluation)",
                row["invocations"] == 0
                and row["claimed_by_proxy"] == 0
                and row["evaluations"] == 0,
            )
    s.observe("matrix", table)
    s.observe("rows", len(table))
    return s


def exp_d_failure_state() -> Scenario:
    s = Scenario("D6", "A post-execution failure is not represented as 'not executed'")
    gate, proxy = fresh()
    tools = wrap_tools_c([s_fail_after], gate, proxy, AGENT)
    r = agent_run(make_agent(tools, [ai(tc("s_fail_after", label="x"))]))
    text = text_of(r)
    s.observe(
        "sync_failure",
        {
            "proxy_states": sorted(proxy.states.values()),
            "invocations": REC.count("s_fail_after"),
            "message_to_model": text,
        },
    )
    s.check(
        "sync failure: proxy state is 'failed' (the function was entered)",
        sorted(proxy.states.values()) == ["failed"] and REC.count("s_fail_after") == 1,
    )
    s.check(
        "sync failure: message says execution may have occurred and does not claim 'blocked'/'not executed'",
        "may have occurred" in text
        and "blocked" not in text
        and "not executed" not in text.lower(),
    )
    gate, proxy = fresh()
    tools = wrap_tools_c([a_fail_after], gate, proxy, AGENT)
    r = agent_run(make_agent(tools, [ai(tc("a_fail_after", label="x"))]), via="ainvoke")
    s.check(
        "async failure: proxy state 'failed', message says execution may have occurred",
        sorted(proxy.states.values()) == ["failed"]
        and "may have occurred" in text_of(r),
    )
    gate, proxy = fresh()
    tools = wrap_tools_c([s_deny], gate, proxy, AGENT)
    agent_run(make_agent(tools, [ai(tc("s_deny", label="x"))]))
    s.check(
        "contrast: a DENY leaves NO proxy state at all (never claimed, never entered)",
        len(proxy.states) == 0,
    )
    return s


SCENARIOS = [
    exp_a_basic,
    exp_a_framework_vs_decision,
    exp_a_coverage,
    exp_a_middleware,
    exp_a_errors,
    exp_b_basic,
    exp_b_concurrency,
    exp_b_cancellation,
    exp_b_retries,
    exp_c_semantics,
    exp_c_denial,
    exp_c_retries,
    exp_c_create_agent,
    exp_d_binding,
    exp_d_matrix,
    exp_d_failure_state,
]


def main() -> int:
    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True)
    results, failed = [], False
    print(
        f"python {sys.version.split()[0]}  langchain {version('langchain')}  langgraph {version('langgraph')}  langchain-core {version('langchain-core')}\n"
    )
    for fn in SCENARIOS:
        try:
            sc = fn()
        except Exception:  # noqa: BLE001
            sc = Scenario(fn.__name__, "UNEXPECTED ERROR")
            sc.check("scenario ran without an unexpected error", False)
            sc.note(traceback.format_exc())
        results.append(
            {
                "id": sc.sid,
                "title": sc.title,
                "ok": sc.ok,
                "checks": sc.checks,
                "observed": sc.observed,
                "notes": sc.notes,
            }
        )
        failed |= not sc.ok
        print(f"=== {sc.sid}: {sc.title} -> {'PASS' if sc.ok else 'FAIL'}")
        for c in sc.checks:
            print(f"   [{'PASS' if c['pass'] else 'FAIL'}] {c['check']}")
        for k, v in sc.observed.items():
            print(f"   observed {k}: {json.dumps(v, default=str)[:700]}")
        for n in sc.notes:
            print(f"   note: {n}")
        print()
    print("=== RETRY MATRIX (executions of a tool that fails AFTER its side effect)")
    for row in MATRIX:
        print(
            f"   {row['mechanism'][:52]:52s} | {row['tool']:7s} | {row['adapter']:38s} | executions={row['executions']} evaluations={row['evaluations']} canary_in_output_or_error={row['canary_in_output_or_error']} error={row['error']}"
        )
    (out_dir / "results_c02b.json").write_text(
        json.dumps(
            {"scenarios": results, "retry_matrix": MATRIX}, indent=2, default=str
        )
    )
    print("\nREQUIRED CHECKS:", "ALL PASS" if not failed else "FAILURES PRESENT")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
