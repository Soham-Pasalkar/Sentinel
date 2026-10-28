# Throwaway experiment code; excluded from production linting by `spikes` in pyproject.toml [tool.ruff] extend-exclude (D-28).
"""C-02 Design B runner: wrap_tools returns replacement tools; a proxy is the sole executor.

THROWAWAY EXPERIMENT CODE (not Sentinel product code). Run:  python run_design_b.py
Same real LangGraph execution as run_experiments.py; only the integration shape differs.
"""

from __future__ import annotations

import asyncio
import json
import sys
import traceback
import warnings
from importlib.metadata import version
from pathlib import Path
from typing import Any

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import StructuredTool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.types import RetryPolicy

from run_experiments import (
    AGENT,
    POLICY,
    Scenario,
    build_graph,
    call,
    fresh,
    ordering_ok,
    run,
    summarize,
)
from standin import (
    REC,
    ActionMismatch,
    Verdict,
    dangerous,
    increment,
    needs_approval,
    state_reader,
    typed_count,
    unwrapped,
)
from standin import ScriptedModel as Script
from standin_b import Proxy, injected_params, wrap_tools_replace


def setup(tools, on_block="tool_exception", policy=None):
    gate = fresh(policy)
    proxy = Proxy(gate)
    return gate, proxy, wrap_tools_replace(tools, gate, proxy, AGENT, on_block=on_block)


def b1() -> Scenario:
    s = Scenario("B1", "Authorized invocation (replacement tools, plain ToolNode)")
    gate, proxy, wrapped = setup([increment])
    r = run(build_graph(ToolNode(wrapped), Script([[call("increment", label="a")]])))
    s.check("underlying function executed exactly once", REC.count("increment") == 1)
    s.check(
        "exactly one gate evaluation, preceding the invocation",
        len(REC.evaluations()) == 1 and ordering_ok(),
    )
    s.check(
        "invocation went through the proxy (exactly one proxy-execute event)",
        sum(e["kind"] == "proxy-execute" for e in REC.events) == 1,
    )
    s.check("graph completed without error", r["error"] is None)
    s.observe("counter", REC.count("increment"))
    s.observe("messages", summarize(r["out"]))
    return s


def b2_b3() -> Scenario:
    s = Scenario("B2/B3", "Denied and approval-required invocation")
    for tool_obj in (dangerous, needs_approval):
        for mode in ("tool_exception", "raise", "string"):
            gate, proxy, wrapped = setup([tool_obj], on_block=mode)
            r = run(
                build_graph(
                    ToolNode(wrapped), Script([[call(tool_obj.name, label="x")]])
                )
            )
            tag = f"[{tool_obj.name}/{mode}]"
            s.check(
                f"{tag} underlying function never called", REC.count(tool_obj.name) == 0
            )
            s.check(
                f"{tag} gate evaluated once, no proxy execution",
                len(REC.evaluations()) == 1
                and not any(e["kind"] == "proxy-execute" for e in REC.events),
            )
            s.observe(f"{tag}.graph_error", r["error"])
            s.observe(f"{tag}.messages", summarize(r["out"]) if r["out"] else None)
    return s


def b4() -> Scenario:
    s = Scenario("B4", "Mismatched action at the proxy; coercion; injected arguments")
    gate, proxy, wrapped = setup([increment, dangerous, typed_count])

    # a) forged: decision evaluated for label=a, used to execute label=b
    d = gate.evaluate(AGENT, "increment", {"label": "a"})
    try:
        proxy.execute(d, AGENT, "increment", {"label": "b"})
        blocked = False
    except ActionMismatch:
        blocked = True
    s.check("decision for args A cannot execute args B", blocked and REC.count() == 0)

    # b) decision for another tool
    d = gate.evaluate(AGENT, "increment", {"label": "a"})
    try:
        proxy.execute(d, AGENT, "typed_count", {"label": "a"})
        blocked = False
    except (ActionMismatch, Exception):  # noqa: BLE001
        blocked = True
    s.check("decision for tool X cannot execute tool Y", blocked and REC.count() == 0)

    # c) DENY decision handed to the proxy
    d = gate.evaluate(AGENT, "dangerous", {"label": "a"})
    try:
        proxy.execute(d, AGENT, "dangerous", {"label": "a"})
        blocked = False
    except Exception:  # noqa: BLE001
        blocked = True
    s.check(
        "a DENY decision cannot be executed", blocked and REC.count("dangerous") == 0
    )

    # d) args mutated between evaluation and execution
    live = {"label": "a"}
    d = gate.evaluate(AGENT, "increment", live)
    live["label"] = "MUTATED"
    try:
        proxy.execute(d, AGENT, "increment", live)
        blocked = False
    except ActionMismatch:
        blocked = True
    s.check(
        "arguments mutated after evaluation -> blocked", blocked and REC.count() == 0
    )

    # e) replay of one decision
    live = {"label": "once"}
    d = gate.evaluate(AGENT, "increment", live)
    proxy.execute(d, AGENT, "increment", live)
    try:
        proxy.execute(d, AGENT, "increment", live)
        replayed = True
    except ActionMismatch:
        replayed = False
    s.check(
        "a decision authorizes exactly one execution (replay blocked)",
        (not replayed) and REC.count("increment") == 1,
    )

    # f) executed values = snapshot taken at evaluation time
    live = {"label": "snap"}
    d = gate.evaluate(AGENT, "increment", live)
    proxy.execute(d, AGENT, "increment", live)
    s.observe(
        "4f.executed_received",
        [e["received"] for e in REC.invocations("increment")][-1],
    )

    # g) coercion: the framework coerces BEFORE the guarded function runs
    gate, proxy, wrapped = setup([typed_count])
    run(build_graph(ToolNode(wrapped), Script([[call("typed_count", n="5")]])))
    ev = REC.evaluations()[0]["args"]
    rec = REC.invocations("typed_count")[0]["received"]
    s.observe("4g.model_emitted", "{'n': '5'}")
    s.observe("4g.gate_evaluated", ev)
    s.observe("4g.function_received", rec)
    s.check(
        "evaluated value equals executed value after framework coercion (design B)",
        ev == '{"n": 5}' and rec == {"n": "int:5"},
    )

    # h) injected parameters are detected and refused at wrap time
    REC.reset()
    refused = False
    try:
        setup([state_reader], policy=POLICY)
    except ValueError as e:
        refused = True
        s.observe("4h.refusal", str(e))
    s.check("tool with framework-injected parameters is refused at wrap time", refused)
    s.check(
        "injected-parameter detection finds none on ordinary tools",
        injected_params(increment) == set(),
    )
    return s


def b5() -> Scenario:
    s = Scenario("B5", "Unwrapped, unregistered and original-object paths")
    gate, proxy, wrapped = setup([increment])
    r = run(build_graph(ToolNode(wrapped), Script([[call("unwrapped", label="x")]])))
    s.check("model-emitted name absent from the node is not executed", REC.count() == 0)
    s.observe("5a.unknown_name.evaluations", len(REC.evaluations()))
    s.observe(
        "5a.unknown_name.messages", summarize(r["out"]) if r["out"] else r["error"]
    )

    REC.reset()
    run(build_graph(ToolNode([unwrapped]), Script([[call("unwrapped", label="x")]])))
    s.observe(
        "5b.plain_toolnode",
        {
            "invocations": REC.count("unwrapped"),
            "gate_evaluations": len(REC.evaluations()),
        },
    )
    s.check(
        "[control] a node holding unwrapped tools executes with NO evaluation",
        REC.count("unwrapped") == 1 and not REC.evaluations(),
    )

    gate, proxy, wrapped = setup([increment])
    increment.invoke({"label": "original"})
    s.observe(
        "5c.original_object_invoke",
        {
            "invocations": REC.count("increment"),
            "gate_evaluations": len(REC.evaluations()),
        },
    )
    s.check(
        "[control] the ORIGINAL tool object stays callable and unguarded if the developer keeps using it",
        REC.count("increment") == 1 and not REC.evaluations(),
    )

    REC.reset()
    wrapped[0].invoke({"label": "via_wrapped"})
    s.observe(
        "5d.wrapped_object_direct_invoke",
        {
            "invocations": REC.count("increment"),
            "gate_evaluations": len(REC.evaluations()),
        },
    )
    s.check(
        "calling the WRAPPED tool directly is gated (unlike a ToolNode hook)",
        len(REC.evaluations()) == 1 and ordering_ok(),
    )

    try:
        wrap_tools_replace([unwrapped], gate, Proxy(gate), AGENT)
        refused = False
    except ValueError as e:
        refused = True
        s.observe("5e.construction_error", str(e))
    s.check("wrap_tools refuses an unregistered tool at construction", refused)
    return s


def b6() -> Scenario:
    s = Scenario("B6", "Framework error handling, retries, loops")
    rp = RetryPolicy(max_attempts=3, initial_interval=0.01, jitter=False)
    for mode in ("tool_exception", "raise", "string"):
        for handler_label, kwargs in (
            ("default handler", {}),
            ("handle_tool_errors=True", {"handle_tool_errors": True}),
        ):
            gate, proxy, wrapped = setup([dangerous], on_block=mode)
            r = run(
                build_graph(
                    ToolNode(wrapped, **kwargs),
                    Script([[call("dangerous", label="x")]], retry_on_error=3),
                )
            )
            s.check(
                f"[{mode} / {handler_label} / agent retries x3] never executed",
                REC.count("dangerous") == 0,
            )
            s.observe(
                f"{mode}/{handler_label}",
                {
                    "graph_error": r["error"],
                    "evaluations": len(REC.evaluations()),
                    "last_message": summarize(r["out"])[-2] if r["out"] else None,
                },
            )
    gate, proxy, wrapped = setup([dangerous], on_block="raise")
    r = run(
        build_graph(ToolNode(wrapped), Script([[call("dangerous", label="x")]]), rp)
    )
    s.check("[denial raised + RetryPolicy] never executed", REC.count("dangerous") == 0)
    s.observe(
        "denial_with_RetryPolicy",
        {"graph_error": r["error"], "evaluations": len(REC.evaluations())},
    )

    # failure AFTER execution (e.g. post-execution audit failure) + RetryPolicy
    for label, exc_type in (
        ("custom Exception subclass", type("PostExecError", (Exception,), {})),
        ("RuntimeError subclass", type("PostExecRuntime", (RuntimeError,), {})),
    ):
        gate = fresh()
        proxy = Proxy(gate)
        proxy.register("increment", increment.func)

        def run_then_fail(label: str, _g=gate, _p=proxy, _e=exc_type) -> str:
            d = _g.evaluate(AGENT, "increment", {"label": label})
            _p.execute(d, AGENT, "increment", {"label": label})
            raise _e("post-execution failure")

        t = StructuredTool.from_function(
            func=run_then_fail,
            name="increment",
            description="x",
            args_schema=increment.args_schema,
        )
        r = run(
            build_graph(ToolNode([t]), Script([[call("increment", label="a")]]), rp)
        )
        s.observe(
            f"post_execution_failure[{label}]",
            {
                "graph_error": r["error"],
                "invocations": REC.count("increment"),
                "evaluations": len(REC.evaluations()),
            },
        )

    # same failure, surfaced as a ToolException handled INSIDE the tool (never reaches the node)
    from langchain_core.tools import ToolException

    gate = fresh()
    proxy = Proxy(gate)
    proxy.register("increment", increment.func)

    def run_then_report(label: str) -> str:
        d = gate.evaluate(AGENT, "increment", {"label": label})
        proxy.execute(d, AGENT, "increment", {"label": label})
        raise ToolException("executed; audit incomplete; output withheld")

    t = StructuredTool.from_function(
        func=run_then_report,
        name="increment",
        description="x",
        args_schema=increment.args_schema,
        handle_tool_error=True,
    )
    r = run(build_graph(ToolNode([t]), Script([[call("increment", label="a")]]), rp))
    s.observe(
        "post_execution_failure[ToolException handled in-tool]",
        {
            "graph_error": r["error"],
            "invocations": REC.count("increment"),
            "evaluations": len(REC.evaluations()),
            "messages": summarize(r["out"]) if r["out"] else None,
        },
    )
    s.check(
        "a post-execution failure surfaced as an in-tool ToolException is NOT re-executed by RetryPolicy",
        REC.count("increment") == 1,
    )
    return s


def b7() -> Scenario:
    s = Scenario("B7", "Multiple tool calls in one step")
    for via in ("invoke", "ainvoke"):
        gate, proxy, wrapped = setup([increment, dangerous, needs_approval])
        calls = [
            call("increment", label="a"),
            call("dangerous", label="b"),
            call("needs_approval", label="c"),
            call("increment", label="d"),
            call("increment", label="e"),
        ]
        r = run(
            build_graph(ToolNode(wrapped, handle_tool_errors=True), Script([calls])),
            via=via,
        )
        s.check(
            f"[{via}] increment ran for exactly its 3 allowed calls",
            REC.count("increment") == 3,
        )
        s.check(
            f"[{via}] denied and approval-required never ran",
            REC.count("dangerous") == 0 and REC.count("needs_approval") == 0,
        )
        s.check(
            f"[{via}] 5 independent evaluations, each allow preceding its invocation",
            len(REC.evaluations()) == 5 and ordering_ok(),
        )
        s.observe(
            f"{via}.threads",
            sorted(
                {e["thread"] for e in REC.events if e["kind"] in ("evaluate", "invoke")}
            ),
        )
        s.observe(f"{via}.messages", summarize(r["out"]) if r["out"] else r["error"])
    return s


def b8() -> Scenario:
    s = Scenario("B8", "Boundary: which paths are intercepted (design B)")
    probes: dict[str, Any] = {}

    def record(name: str, *, must_block: bool = True) -> None:
        probes[name] = {
            "denied_invocations": REC.count("dangerous"),
            "evaluations": len(REC.evaluations()),
        }
        if must_block:
            s.check(
                f"[{name}] gate evaluated AND denied tool not executed",
                len(REC.evaluations()) > 0 and REC.count("dangerous") == 0,
            )

    for via in ("invoke", "stream", "batch", "ainvoke", "astream"):
        gate, proxy, wrapped = setup([dangerous], on_block="string")
        run(
            build_graph(ToolNode(wrapped), Script([[call("dangerous", label="x")]])),
            via=via,
        )
        record(f"graph.{via}")

    gate, proxy, wrapped = setup([dangerous], on_block="string")
    wrapped[0].invoke({"label": "x"})
    record("wrapped_tool.invoke() directly")
    REC.reset()  # isolate: this probe must show ITS OWN evaluation, not the previous probe's
    asyncio.run(wrapped[0].ainvoke({"label": "x"}))
    record("wrapped_tool.ainvoke() directly (no coroutine supplied)")
    s.observe(
        "ainvoke_threads",
        sorted({e["thread"] for e in REC.events if e["kind"] == "evaluate"}),
    )

    # create_react_agent with a plain list of wrapped tools: no ToolNode/hook configuration at all
    from langgraph.prebuilt import create_react_agent

    class FakeToolModel(GenericFakeChatModel):
        def bind_tools(self, tools, **kwargs):  # noqa: ANN001
            return self

    gate, proxy, wrapped = setup([dangerous], on_block="string")
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
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        agent = create_react_agent(model, wrapped)
        agent.invoke({"messages": [HumanMessage("go")]})
    record("create_react_agent(model, [wrapped tools]) - no hook configuration")

    gate, proxy, wrapped = setup([dangerous], on_block="string")
    inner = build_graph(ToolNode(wrapped), Script([[call("dangerous", label="x")]]))
    outer = StateGraph(MessagesState)
    outer.add_node("inner", inner)
    outer.add_edge(START, "inner")
    run(outer.compile())
    record("tool node inside a subgraph")

    # bypasses
    REC.reset()
    dangerous.invoke({"label": "direct"})
    probes["ORIGINAL tool object .invoke()"] = {
        "denied_invocations": REC.count("dangerous"),
        "evaluations": 0,
        "note": "bypass (developer kept the original)",
    }
    REC.reset()
    dangerous.func(label="direct")
    probes["ORIGINAL function called directly"] = {
        "denied_invocations": REC.count("dangerous"),
        "evaluations": 0,
        "note": "bypass",
    }

    s.observe("probes", probes)
    return s


SCENARIOS = [b1, b2_b3, b4, b5, b6, b7, b8]


def main() -> int:
    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True)
    results, failed = [], False
    print(
        f"DESIGN B  python {sys.version.split()[0]}  langgraph {version('langgraph')}  langchain-core {version('langchain-core')}\n"
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
            print(f"   observed {k}: {json.dumps(v, default=str)[:520]}")
        for n in sc.notes:
            print(f"   note: {n}")
        print()
    (out_dir / "results_design_b.json").write_text(
        json.dumps(results, indent=2, default=str)
    )
    print("REQUIRED CHECKS:", "ALL PASS" if not failed else "FAILURES PRESENT")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
