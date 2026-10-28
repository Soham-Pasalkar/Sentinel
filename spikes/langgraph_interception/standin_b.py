# Throwaway experiment code; excluded from production linting by `spikes` in pyproject.toml [tool.ruff] extend-exclude (D-28).
"""Design B stand-in: ``wrap_tools`` returns REPLACEMENT tools; a stand-in proxy is the
only caller of the original functions.

THROWAWAY EXPERIMENT CODE. Not Sentinel product code; the "gate" and "proxy" are toys.

Design A (standin.py) hooks ToolNode.wrap_tool_call: the FRAMEWORK still runs the function.
Design B (this file) swaps each tool for a guarded one that routes into the proxy, which
runs the original function itself. That matches the decision record (C1.4: the proxy
executes only decision.action) and the proposed ``wrap_tools(tools, client, agent_id)``
signature, which returns tools rather than a configured ToolNode.
"""

from __future__ import annotations

import copy
import json
import threading
from typing import Any, Callable

from langchain_core.tools import StructuredTool, ToolException

from standin import (
    REC,
    ActionDenied,
    ActionMismatch,
    ApprovalRequired,
    Decision,
    Gate,
    Recorder,
    Verdict,
)


class Proxy:
    """Stand-in proxy: the ONLY code that calls original functions.

    Executes exactly the evaluated action (the JSON snapshot taken at evaluation time),
    only for ALLOW, only if the live request still matches, and at most once per decision.
    """

    def __init__(self, gate: Gate, rec: Recorder = REC) -> None:
        self._gate = gate
        self._rec = rec
        self._registry: dict[str, Callable[..., Any]] = {}
        self._used: set[int] = set()
        self._lock = threading.Lock()

    def register(self, name: str, fn: Callable[..., Any]) -> None:
        if name in self._registry:
            raise ValueError(f"duplicate registration: {name}")
        self._registry[name] = fn

    def execute(
        self, decision: Decision, agent_id: str, tool_name: str, live_args: Any
    ) -> Any:
        if decision.verdict is not Verdict.ALLOW:
            raise ActionDenied("NOT_ALLOWED")
        if decision.action.tool != tool_name or not self._gate.verify(
            decision, agent_id, tool_name, live_args
        ):
            raise ActionMismatch("ACTION_MISMATCH")
        with self._lock:
            if decision.action.request_id in self._used:
                raise ActionMismatch("DECISION_ALREADY_USED")
            self._used.add(decision.action.request_id)
        fn = self._registry[tool_name]
        self._rec.event(
            "proxy-execute", tool=tool_name, request_id=decision.action.request_id
        )
        return fn(**copy.deepcopy(json.loads(decision.action.args_json)))


def injected_params(tool: Any) -> set[str]:
    """Parameters the framework injects at call time (invisible to the model and the gate)."""
    return set(tool.get_input_schema().model_fields) - set(
        tool.tool_call_schema.model_fields
    )


def wrap_tools_replace(
    tools: list[Any],
    gate: Gate,
    proxy: Proxy,
    agent_id: str,
    *,
    on_block: str = "tool_exception",
) -> list[StructuredTool]:
    """Prototype of the proposed ``wrap_tools``: returns replacement tools.

    on_block: "tool_exception" -> raise ToolException (tool has handle_tool_error=True)
              "raise"          -> raise ActionDenied / ApprovalRequired
              "string"         -> return an explanatory string (framework sees success)
    """
    wrapped: list[StructuredTool] = []
    for t in tools:
        if t.name not in gate.policy:
            raise ValueError(f"tool not registered with the gate: {t.name}")
        injected = injected_params(t)
        if injected:
            raise ValueError(
                f"tool {t.name} has framework-injected parameters: {sorted(injected)}"
            )
        proxy.register(t.name, t.func)

        def guarded(_name: str = t.name, **kwargs: Any) -> Any:
            decision = gate.evaluate(agent_id, _name, kwargs)
            if decision.verdict is not Verdict.ALLOW:
                exc = (
                    ActionDenied(decision.reason)
                    if decision.verdict is Verdict.DENY
                    else ApprovalRequired("REQUIRE_APPROVAL")
                )
                if on_block == "raise":
                    raise exc
                if on_block == "string":
                    return f"blocked: {exc}"
                raise ToolException(f"blocked: {exc}")
            return proxy.execute(decision, agent_id, _name, kwargs)

        wrapped.append(
            StructuredTool.from_function(
                func=guarded,
                name=t.name,
                description=t.description,
                args_schema=t.args_schema,
                handle_tool_error=(on_block == "tool_exception"),
            )
        )
    return wrapped
