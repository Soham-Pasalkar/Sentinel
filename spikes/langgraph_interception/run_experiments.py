# Throwaway experiment code; excluded from production linting by `spikes` in pyproject.toml [tool.ruff] extend-exclude (D-28).
"""C-02 experiment runner: real LangGraph StateGraph + ToolNode, scripted model, spy tools.

THROWAWAY EXPERIMENT CODE (not Sentinel product code). Run:  python run_experiments.py
Writes results/results.json and prints a transcript. Exit code 1 if a REQUIRED check fails.
"""

from __future__ import annotations

import asyncio
import json
import sys
import traceback
import warnings
from importlib.metadata import metadata, version
from pathlib import Path
from typing import Any

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.types import RetryPolicy

from standin import (
    REC,
    ActionDenied,
    Boundary,
    Gate,
    Verdict,
    dangerous,
    increment,
    needs_approval,
    state_reader,
    typed_count,
    unwrapped,
    wrap_tools,
)
from standin import ScriptedModel as ScriptedModel_

AGENT = "research_agent"
POLICY = {
    "increment": Verdict.ALLOW,
    "typed_count": Verdict.ALLOW,
    "state_reader": Verdict.ALLOW,
    "dangerous": Verdict.DENY,
    "needs_approval": Verdict.REQUIRE_APPROVAL,
}

# --------------------------------------------------------------------------- harness


class Scenario:
    def __init__(self, sid: str, title: str) -> None:
        self.sid, self.title = sid, title
        self.checks: list[dict[str, Any]] = []  # required, PASS/FAIL
        self.observed: dict[str, Any] = {}  # informational
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


def call(name: str, **args: Any) -> dict[str, Any]:
    return {"name": name, "args": args}


def summarize(out: Any) -> list[str]:
    if not isinstance(out, dict) or "messages" not in out:
        return [repr(out)[:100]]
    res = []
    for m in out["messages"]:
        kind = type(m).__name__
        extra = f" status={m.status}" if isinstance(m, ToolMessage) else ""
        calls = (
            f" calls={[c['name'] for c in m.tool_calls]}"
            if getattr(m, "tool_calls", None)
            else ""
        )
        res.append(f"{kind}{extra}{calls} {str(m.content)[:60]!r}")
    return res


def build_graph(
    tool_node: ToolNode, model: Any, retry_policy: RetryPolicy | None = None
):
    g = StateGraph(MessagesState)
    g.add_node("model", model)
    if retry_policy is not None:
        g.add_node("tools", tool_node, retry_policy=retry_policy)
    else:
        g.add_node("tools", tool_node)
    g.add_edge(START, "model")
    g.add_conditional_edges("model", tools_condition)
    g.add_edge("tools", "model")
    return g.compile()


INPUT = {"messages": [HumanMessage("go")]}


def run(app: Any, via: str = "invoke", config: dict | None = None) -> dict[str, Any]:
    """Run a compiled graph; never raises. Returns {'out': ..., 'error': ...}."""
    try:
        if via == "invoke":
            out = app.invoke(INPUT, config)
        elif via == "stream":
            chunks = list(app.stream(INPUT, config, stream_mode="values"))
            out = chunks[-1]
        elif via == "batch":
            out = app.batch([INPUT, INPUT], config)[0]
        elif via == "ainvoke":
            out = asyncio.run(app.ainvoke(INPUT, config))
        elif via == "astream":

            async def go() -> Any:
                last = None
                async for chunk in app.astream(INPUT, config, stream_mode="values"):
                    last = chunk
                return last

            out = asyncio.run(go())
        else:
            raise ValueError(via)
        return {"out": out, "error": None}
    except Exception as e:  # noqa: BLE001 - experiment records every failure
        return {"out": None, "error": f"{type(e).__name__}: {str(e)[:80]}"}


def fresh(policy: dict[str, Verdict] | None = None) -> Gate:
    REC.reset()
    return Gate(policy or POLICY, REC)


def ordering_ok() -> bool:
    """Every 'invoke' event is preceded by an 'evaluate' allow for the same tool."""
    allows: dict[str, int] = {}
    for e in REC.events:
        if e["kind"] == "evaluate" and e["verdict"] == "allow":
            allows[e["tool"]] = allows.get(e["tool"], 0) + 1
        if e["kind"] == "invoke":
            if allows.get(e["tool"], 0) <= 0:
                return False
            allows[e["tool"]] -= 1
    return True


# --------------------------------------------------------------------------- scenarios


def e1() -> Scenario:
    s = Scenario("E1", "Authorized invocation")
    gate = fresh()
    node = wrap_tools([increment], Boundary(gate, AGENT))
    r = run(build_graph(node, ScriptedModel_([[call("increment", label="a")]])))
    s.check("underlying function executed exactly once", REC.count("increment") == 1)
    s.check("exactly one gate evaluation", len(REC.evaluations()) == 1)
    s.check("evaluation preceded invocation", ordering_ok())
    s.check("graph completed without error", r["error"] is None)
    s.observe("invocation_counter", REC.count("increment"))
    s.observe("evaluations", len(REC.evaluations()))
    s.observe("messages", summarize(r["out"]))
    return s


def e2() -> Scenario:
    s = Scenario("E2", "Denied invocation")
    for mode in ("raise", "message"):
        gate = fresh()
        node = wrap_tools([dangerous], Boundary(gate, AGENT, on_block=mode))
        r = run(build_graph(node, ScriptedModel_([[call("dangerous", label="x")]])))
        s.check(
            f"[{mode}] underlying function never called", REC.count("dangerous") == 0
        )
        s.check(f"[{mode}] gate evaluated once", len(REC.evaluations()) == 1)
        s.observe(f"{mode}.counter", REC.count("dangerous"))
        s.observe(f"{mode}.graph_error", r["error"])
        s.observe(f"{mode}.messages", summarize(r["out"]) if r["out"] else None)
    # default-deny: tool absent from the policy table
    gate = fresh({"increment": Verdict.ALLOW})
    node = ToolNode(
        [dangerous], wrap_tool_call=Boundary(gate, AGENT, on_block="message").wrap
    )
    r = run(build_graph(node, ScriptedModel_([[call("dangerous", label="x")]])))
    s.check(
        "[default-deny] tool absent from policy is not executed",
        REC.count("dangerous") == 0,
    )
    s.observe("default_deny.messages", summarize(r["out"]) if r["out"] else r["error"])
    return s


def e3() -> Scenario:
    s = Scenario("E3", "Approval-required invocation")
    for mode in ("raise", "message"):
        gate = fresh()
        node = wrap_tools([needs_approval], Boundary(gate, AGENT, on_block=mode))
        r = run(
            build_graph(node, ScriptedModel_([[call("needs_approval", label="x")]]))
        )
        s.check(
            f"[{mode}] underlying function never called",
            REC.count("needs_approval") == 0,
        )
        s.check(f"[{mode}] gate evaluated once", len(REC.evaluations()) == 1)
        s.observe(f"{mode}.counter", REC.count("needs_approval"))
        s.observe(f"{mode}.graph_error", r["error"])
        s.observe(f"{mode}.messages", summarize(r["out"]) if r["out"] else None)
    return s


def e4() -> Scenario:
    s = Scenario("E4", "Incorrect or mismatched action")

    def tamper_args(req):  # change args after the decision
        return req.override(tool_call={**req.tool_call, "args": {"label": "TAMPERED"}})

    def tamper_tool(req):  # keep the evaluated name, swap the BaseTool object
        return req.override(tool=dangerous)

    # 4a control: framework with NO binding check
    gate = fresh()
    node = wrap_tools(
        [increment, dangerous],
        Boundary(gate, AGENT, verify=False, tamper=tamper_args, on_block="message"),
    )
    run(build_graph(node, ScriptedModel_([[call("increment", label="evaluated")]])))
    rec = REC.invocations("increment")
    s.observe("4a.control_args_swapped.received", [e["received"] for e in rec])
    s.observe(
        "4a.control_args_swapped.evaluations",
        [(e["tool"], e["digest"]) for e in REC.evaluations()],
    )
    s.check(
        "[control] framework itself does NOT stop a post-decision argument swap (documents the need for binding)",
        REC.count("increment") == 1 and "TAMPERED" in str(rec[0]["received"]),
    )

    # 4b verified
    gate = fresh()
    node = wrap_tools(
        [increment, dangerous],
        Boundary(gate, AGENT, tamper=tamper_args, on_block="message"),
    )
    r = run(build_graph(node, ScriptedModel_([[call("increment", label="evaluated")]])))
    s.check(
        "[verified] swapped arguments -> blocked, function never called",
        REC.count() == 0,
    )
    s.observe(
        "4b.verified_args_swapped.messages",
        summarize(r["out"]) if r["out"] else r["error"],
    )

    # 4c control: swap the tool object, keep the name
    gate = fresh()
    node = wrap_tools(
        [increment, dangerous],
        Boundary(gate, AGENT, verify=False, tamper=tamper_tool, on_block="message"),
    )
    run(build_graph(node, ScriptedModel_([[call("increment", label="evaluated")]])))
    s.observe("4c.control_tool_swapped.invoked", [e["tool"] for e in REC.invocations()])
    s.check(
        "[control] framework executes request.tool, not the evaluated name (a different tool ran)",
        REC.count("dangerous") == 1 and REC.count("increment") == 0,
    )

    # 4d verified
    gate = fresh()
    node = wrap_tools(
        [increment, dangerous],
        Boundary(gate, AGENT, tamper=tamper_tool, on_block="message"),
    )
    run(build_graph(node, ScriptedModel_([[call("increment", label="evaluated")]])))
    s.check(
        "[verified] swapped tool object -> blocked, nothing executed", REC.count() == 0
    )

    # 4e control: a wrapper may call execute() more than once for one decision
    gate = fresh()

    def double_exec(request, execute):
        gate.evaluate(AGENT, request.tool_call["name"], request.tool_call["args"])
        execute(request)
        return execute(request)

    node = ToolNode([increment], wrap_tool_call=double_exec)
    run(build_graph(node, ScriptedModel_([[call("increment", label="a")]])))
    s.observe(
        "4e.control_double_execute",
        {"evaluations": len(REC.evaluations()), "invocations": REC.count("increment")},
    )
    s.check(
        "[control] one evaluation can be followed by two executions (single-use must be enforced by the boundary)",
        len(REC.evaluations()) == 1 and REC.count("increment") == 2,
    )

    # 4f argument coercion between evaluation and execution
    gate = fresh()
    node = wrap_tools([typed_count], Boundary(gate, AGENT, on_block="message"))
    r = run(build_graph(node, ScriptedModel_([[call("typed_count", n="5")]])))
    s.observe(
        "4f.coercion.received", [e["received"] for e in REC.invocations("typed_count")]
    )
    s.observe("4f.coercion.evaluated_args", REC.evaluations()[0]["args"])
    s.observe("4f.coercion.messages", summarize(r["out"]) if r["out"] else r["error"])

    # 4g framework-injected arguments are invisible to the gate
    gate = fresh()
    node = wrap_tools([state_reader], Boundary(gate, AGENT, on_block="message"))
    run(build_graph(node, ScriptedModel_([[call("state_reader", label="x")]])))
    inv = REC.invocations("state_reader")
    s.observe(
        "4g.injected.received",
        [(e["received"], e.get("injected_state_keys")) for e in inv],
    )
    s.observe("4g.injected.gate_saw_args", REC.evaluations()[0]["args"])
    return s


def e5() -> Scenario:
    s = Scenario("E5", "Unwrapped / unregistered tools")
    # 5a: a plain ToolNode (no hook) in a graph
    gate = fresh()
    r = run(
        build_graph(
            ToolNode([unwrapped]), ScriptedModel_([[call("unwrapped", label="x")]])
        )
    )
    s.observe(
        "5a.plain_toolnode",
        {
            "invocations": REC.count("unwrapped"),
            "gate_evaluations": len(REC.evaluations()),
        },
    )
    s.check(
        "[control] a ToolNode that is not wrapped executes with NO Sentinel evaluation (unprotected path)",
        REC.count("unwrapped") == 1 and len(REC.evaluations()) == 0,
    )

    # 5b: protected node, model calls a tool that is not in that node
    gate = fresh()
    node = wrap_tools([increment], Boundary(gate, AGENT, on_block="message"))
    r = run(build_graph(node, ScriptedModel_([[call("unwrapped", label="x")]])))
    s.check(
        "model-emitted tool name absent from protected node is not executed",
        REC.count() == 0,
    )
    s.observe(
        "5b.unknown_name.evaluations",
        [(e["tool"], e["verdict"]) for e in REC.evaluations()],
    )
    s.observe(
        "5b.unknown_name.messages", summarize(r["out"]) if r["out"] else r["error"]
    )

    # 5c: wrapper installed but tool missing from the policy (bypassing wrap_tools' check)
    gate = fresh({"increment": Verdict.ALLOW})
    node = ToolNode(
        [unwrapped], wrap_tool_call=Boundary(gate, AGENT, on_block="message").wrap
    )
    run(build_graph(node, ScriptedModel_([[call("unwrapped", label="x")]])))
    s.check(
        "tool present in node but unknown to the gate is default-denied at call time",
        REC.count("unwrapped") == 0,
    )
    s.observe("5c.evaluations", [(e["tool"], e["verdict"]) for e in REC.evaluations()])

    # 5d: wrap_tools refuses to build
    gate = fresh({"increment": Verdict.ALLOW})
    try:
        wrap_tools([unwrapped], Boundary(gate, AGENT))
        refused = False
    except ValueError as e:
        refused = True
        s.observe("5d.construction_error", str(e))
    s.check("wrap_tools refuses at construction when a tool is not registered", refused)

    # 5e: direct invocation of a tool object that IS in a protected node
    gate = fresh()
    wrap_tools([increment], Boundary(gate, AGENT))
    increment.invoke({"label": "direct"})
    s.observe(
        "5e.direct_tool_invoke",
        {
            "invocations": REC.count("increment"),
            "gate_evaluations": len(REC.evaluations()),
        },
    )
    s.check(
        "[control] calling tool.invoke() directly bypasses the boundary (not claimed as protected)",
        REC.count("increment") == 1 and len(REC.evaluations()) == 0,
    )

    s.note(
        "The stand-in `wrap_tools` covers only the tools passed to it. Nothing else is claimed protected."
    )
    return s


def e6() -> Scenario:
    s = Scenario("E6", "Framework error handling, retries and loops")

    # 6a: raise + framework default error handling
    gate = fresh()
    node = wrap_tools([dangerous], Boundary(gate, AGENT, on_block="raise"))
    r = run(build_graph(node, ScriptedModel_([[call("dangerous", label="x")]])))
    s.observe(
        "6a.raise_default_handler",
        {
            "graph_error": r["error"],
            "invocations": REC.count(),
            "evaluations": len(REC.evaluations()),
        },
    )
    s.check("[raise, default handler] not executed", REC.count() == 0)

    # 6b: raise + handle_tool_errors=True, agent retries 3x
    gate = fresh()
    node = wrap_tools(
        [dangerous], Boundary(gate, AGENT, on_block="raise"), handle_tool_errors=True
    )
    r = run(
        build_graph(
            node, ScriptedModel_([[call("dangerous", label="x")]], retry_on_error=3)
        )
    )
    s.observe(
        "6b.raise_handled_agent_retries",
        {
            "graph_error": r["error"],
            "invocations": REC.count(),
            "evaluations": len(REC.evaluations()),
            "messages": summarize(r["out"]) if r["out"] else None,
        },
    )
    s.check("[raise, handled, agent retries x3] never executed", REC.count() == 0)
    s.check(
        "[raise, handled, agent retries x3] every retry was re-evaluated",
        len(REC.evaluations()) == 4,
    )

    # 6c: return error message, agent retries 3x
    gate = fresh()
    node = wrap_tools([dangerous], Boundary(gate, AGENT, on_block="message"))
    r = run(
        build_graph(
            node, ScriptedModel_([[call("dangerous", label="x")]], retry_on_error=3)
        )
    )
    s.observe(
        "6c.message_agent_retries",
        {
            "graph_error": r["error"],
            "invocations": REC.count(),
            "evaluations": len(REC.evaluations()),
        },
    )
    s.check("[message, agent retries x3] never executed", REC.count() == 0)

    # 6d: LangGraph RetryPolicy on the tools node + a denial exception
    gate = fresh()
    node = wrap_tools([dangerous], Boundary(gate, AGENT, on_block="raise"))
    rp = RetryPolicy(max_attempts=3, initial_interval=0.01, jitter=False)
    r = run(build_graph(node, ScriptedModel_([[call("dangerous", label="x")]]), rp))
    s.observe(
        "6d.denial_with_RetryPolicy",
        {
            "graph_error": r["error"],
            "invocations": REC.count(),
            "evaluations": len(REC.evaluations()),
        },
    )
    s.check("[denial + RetryPolicy] never executed", REC.count() == 0)

    # 6e: failure raised AFTER the tool ran (e.g. post-execution audit failure) + RetryPolicy
    for label, exc_type in (
        ("custom Exception subclass", type("PostExecError", (Exception,), {})),
        ("RuntimeError subclass", type("PostExecRuntime", (RuntimeError,), {})),
    ):
        gate = fresh()

        def run_then_fail(request, execute, _exc=exc_type, _gate=gate):
            _gate.evaluate(AGENT, request.tool_call["name"], request.tool_call["args"])
            execute(request)
            raise _exc("post-execution failure")

        node = ToolNode([increment], wrap_tool_call=run_then_fail)
        r = run(build_graph(node, ScriptedModel_([[call("increment", label="a")]]), rp))
        s.observe(
            f"6e.post_execution_failure[{label}]",
            {
                "graph_error": r["error"],
                "invocations": REC.count("increment"),
                "evaluations": len(REC.evaluations()),
            },
        )
    s.note(
        "6e shows whether a LangGraph RetryPolicy re-runs a tool whose wrapper raised AFTER execution (see observed counts)."
    )
    return s


def e7() -> Scenario:
    s = Scenario("E7", "Multiple tool calls in one step")
    for via in ("invoke", "ainvoke"):
        gate = fresh()
        node = wrap_tools(
            [increment, dangerous, needs_approval],
            Boundary(gate, AGENT, on_block="message"),
        )
        calls = [
            call("increment", label="a"),
            call("dangerous", label="b"),
            call("needs_approval", label="c"),
            call("increment", label="d"),
            call("increment", label="e"),
        ]
        r = run(build_graph(node, ScriptedModel_([calls])), via=via)
        s.check(
            f"[{via}] allowed tool ran exactly for its 3 allowed calls",
            REC.count("increment") == 3,
        )
        s.check(
            f"[{via}] denied and approval-required tools never ran",
            REC.count("dangerous") == 0 and REC.count("needs_approval") == 0,
        )
        s.check(
            f"[{via}] each of the 5 calls was evaluated independently",
            len(REC.evaluations()) == 5,
        )
        s.check(
            f"[{via}] every invocation was preceded by an allow evaluation",
            ordering_ok(),
        )
        s.observe(
            f"{via}.counters",
            {
                "increment": REC.count("increment"),
                "dangerous": REC.count("dangerous"),
                "needs_approval": REC.count("needs_approval"),
            },
        )
        s.observe(
            f"{via}.threads_by_event_kind",
            {
                k: sorted({e["thread"] for e in REC.events if e["kind"] == k})
                for k in ("evaluate", "invoke")
            },
        )
        s.observe(
            f"{via}.threads",
            sorted(
                {e["thread"] for e in REC.events if e["kind"] in ("evaluate", "invoke")}
            ),
        )
        s.observe(f"{via}.messages", summarize(r["out"]) if r["out"] else r["error"])
    return s


def e8() -> Scenario:
    s = Scenario("E8", "Boundary: which paths are intercepted")
    probes: dict[str, dict[str, Any]] = {}

    def probe(
        name: str, gate: Gate, denied_tool: str, *, expect_blocked: bool, note: str = ""
    ) -> None:
        probes[name] = {
            "denied_tool_invocations": REC.count(denied_tool),
            "evaluations": len(REC.evaluations()),
            "intercepted": len(REC.evaluations()) > 0,
            "blocked": REC.count(denied_tool) == 0,
            "note": note,
        }
        if expect_blocked:
            s.check(
                f"[{name}] gate evaluated AND denied tool not executed",
                len(REC.evaluations()) > 0 and REC.count(denied_tool) == 0,
            )

    steps = lambda: ScriptedModel_([[call("dangerous", label="x")]])  # noqa: E731

    for via in ("invoke", "stream", "batch", "ainvoke", "astream"):
        gate = fresh()
        node = wrap_tools([dangerous], Boundary(gate, AGENT, on_block="message"))
        run(build_graph(node, steps()), via=via)
        probe(f"graph.{via}", gate, "dangerous", expect_blocked=True)

    gate = fresh()
    node = wrap_tools(
        [dangerous], Boundary(gate, AGENT, on_block="message"), async_hook=False
    )
    run(build_graph(node, steps()), via="ainvoke")
    probe(
        "ainvoke with ONLY the sync hook installed",
        gate,
        "dangerous",
        expect_blocked=True,
        note="framework routes the async path through the sync hook",
    )

    gate = fresh()
    node = wrap_tools(
        [dangerous], Boundary(gate, AGENT, on_block="message"), sync_hook=False
    )
    run(build_graph(node, steps()), via="invoke")
    probes["invoke with ONLY the async hook installed"] = {
        "denied_tool_invocations": REC.count("dangerous"),
        "evaluations": len(REC.evaluations()),
        "intercepted": len(REC.evaluations()) > 0,
        "blocked": REC.count("dangerous") == 0,
        "note": "sync path with no sync hook",
    }
    s.observe(
        "sync_path_without_sync_hook",
        probes["invoke with ONLY the async hook installed"],
    )

    gate = fresh()
    node = wrap_tools([dangerous], Boundary(gate, AGENT, on_block="message"))
    try:
        out = node.invoke(
            {
                "messages": [
                    AIMessage(
                        "",
                        tool_calls=[
                            {"name": "dangerous", "args": {"label": "x"}, "id": "c1"}
                        ],
                    )
                ]
            }
        )
        err = None
    except Exception as e:  # noqa: BLE001
        out, err = None, f"{type(e).__name__}: {str(e)[:100]}"
    probe(
        "ToolNode.invoke() called directly (outside a graph)",
        gate,
        "dangerous",
        expect_blocked=False,
        note=err or "ok",
    )
    probes["ToolNode.invoke() called directly (outside a graph)"]["intercepted"] = None
    probes["ToolNode.invoke() called directly (outside a graph)"]["blocked"] = (
        "n/a: nothing ran (framework error), so no conclusion"
    )

    # nested graph as a node of an outer graph
    gate = fresh()
    node = wrap_tools([dangerous], Boundary(gate, AGENT, on_block="message"))
    inner = build_graph(node, steps())
    outer = StateGraph(MessagesState)
    outer.add_node("inner", inner)
    outer.add_edge(START, "inner")
    run(outer.compile())
    probe("tool node inside a subgraph", gate, "dangerous", expect_blocked=True)

    # callbacks: raising in on_tool_start on a plain (unwrapped) ToolNode
    for raise_error in (False, True):
        REC.reset()

        class Blocker(BaseCallbackHandler):
            def on_tool_start(self, serialized, input_str, **kwargs):  # noqa: ANN001
                REC.event("callback-start")
                raise ActionDenied("callback says no")

        Blocker.raise_error = raise_error
        r = run(
            build_graph(
                ToolNode([dangerous], handle_tool_errors=True),
                ScriptedModel_([[call("dangerous", label="x")]]),
            ),
            config={"callbacks": [Blocker()]},
        )
        probes[f"callback on_tool_start raising (raise_error={raise_error})"] = {
            "denied_tool_invocations": REC.count("dangerous"),
            "callback_fired": any(e["kind"] == "callback-start" for e in REC.events),
            "graph_error": r["error"],
        }
    REC.reset()
    r = run(
        build_graph(
            ToolNode([dangerous], handle_tool_errors=True),
            ScriptedModel_([[call("dangerous", label="x")]]),
        )
    )
    probes["same graph, caller omits the callback config"] = {
        "denied_tool_invocations": REC.count("dangerous"),
        "note": "callbacks come from the per-call config, not from the ToolNode",
    }
    s.observe("callback_blocking_is_reliable", False)

    # direct invocation bypasses
    REC.reset()
    dangerous.invoke({"label": "direct"})
    probes["tool.invoke() directly"] = {
        "denied_tool_invocations": REC.count("dangerous"),
        "evaluations": 0,
        "note": "bypass: not intercepted",
    }
    REC.reset()
    dangerous.func(label="direct")
    probes["underlying function called directly"] = {
        "denied_tool_invocations": REC.count("dangerous"),
        "evaluations": 0,
        "note": "bypass: not intercepted",
    }

    s.observe("probes", probes)
    s.note(
        "Intercepted = the gate was evaluated. 'blocked' only counts when the denied tool never ran."
    )
    return s


def e8b_prebuilt_and_meta() -> Scenario:
    s = Scenario("E8b", "Prebuilt agent, official hook, versions, deprecations")
    # versions / Python floor
    meta = {}
    for pkg in (
        "langgraph",
        "langgraph-prebuilt",
        "langchain-core",
        "langgraph-checkpoint",
    ):
        md = metadata(pkg)
        meta[pkg] = {"version": version(pkg), "requires_python": md["Requires-Python"]}
    s.observe("package_metadata", meta)
    s.check(
        "every installed LangGraph component supports Python 3.11 (D-01)",
        all(
            ">=3.10" in m["requires_python"]
            or ">=3.11" in m["requires_python"]
            or ">=3.9" in m["requires_python"]
            for m in meta.values()
        ),
    )

    # deprecation warnings when using the prebuilt API
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        gate = fresh()
        node = wrap_tools([dangerous], Boundary(gate, AGENT, on_block="message"))
        from langgraph.prebuilt import create_react_agent

        class FakeToolModel(GenericFakeChatModel):
            def bind_tools(self, tools, **kwargs):  # noqa: ANN001
                return self

        model = FakeToolModel(
            messages=iter(
                [
                    AIMessage(
                        "",
                        tool_calls=[
                            {"name": "dangerous", "args": {"label": "x"}, "id": "c1"}
                        ],
                    ),
                    AIMessage("done"),
                ]
            )
        )
        try:
            agent = create_react_agent(model, node)
            out = agent.invoke({"messages": [HumanMessage("go")]})
            err = None
        except Exception as e:  # noqa: BLE001
            out, err = None, f"{type(e).__name__}: {str(e)[:120]}"
    s.observe(
        "create_react_agent_with_prebuilt_ToolNode",
        {
            "error": err,
            "denied_tool_invocations": REC.count("dangerous"),
            "evaluations": len(REC.evaluations()),
            "messages": summarize(out) if out else None,
        },
    )
    s.check(
        "create_react_agent given our wrapped ToolNode does not execute the denied tool",
        REC.count("dangerous") == 0,
    )
    s.observe(
        "deprecation_warnings",
        sorted(
            {
                f"{w.category.__name__}: {str(w.message)[:110]}"
                for w in caught
                if issubclass(
                    w.category,
                    (DeprecationWarning, PendingDeprecationWarning, FutureWarning),
                )
            }
        ),
    )
    s.observe(
        "official_hook",
        "ToolNode(wrap_tool_call=..., awrap_tool_call=...) in langgraph.prebuilt.tool_node (present)",
    )
    return s


SCENARIOS = [e1, e2, e3, e4, e5, e6, e7, e8, e8b_prebuilt_and_meta]


def main() -> int:
    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True)
    results, failed = [], False
    print(
        f"python {sys.version.split()[0]}  langgraph {version('langgraph')}  langchain-core {version('langchain-core')}\n"
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
            print(f"   observed {k}: {json.dumps(v, default=str)[:600]}")
        for n in sc.notes:
            print(f"   note: {n}")
        print()
    (out_dir / "results.json").write_text(json.dumps(results, indent=2, default=str))
    print("REQUIRED CHECKS:", "ALL PASS" if not failed else "FAILURES PRESENT")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
