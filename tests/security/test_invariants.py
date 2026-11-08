"""Negative security invariants NI-01 … NI-19 (testing §7), checked by one
shared helper across a corpus of E2E scenarios and fault injections (C-11)."""

import pytest

from sentinel.audit import reconstruct
from sentinel.models import (
    NON_POLICY_REASONS,
    NULL_DECISION_CODES,
    Decision,
    Execution,
    SecurityFinding,
    Severity,
)

CANARY = "CANARY-1a9b-invariants"


class HighFinding:
    def analyze(self, request, context):
        return (
            SecurityFinding(
                code="PROMPT_INJECTION", severity=Severity.HIGH, evidence="x"
            ),
        )


def _broken_filter(out):
    raise ValueError(CANARY)


SCENARIOS = {
    "allow": dict(),
    "path-deny": dict(arguments="outside"),
    "ungranted": dict(tool="send_email", arguments={"to": "a", "body": "b"}),
    "unknown-agent": dict(agent_id="nobody"),
    "approval": dict(tool="delete_file"),
    "invalid": dict(raw={"agent_id": "research_agent"}),
    "reserved-key": dict(arguments={"path": "WS/data.txt", "agent_id": "admin"}),
    "finding-deny": dict(env={"detector": HighFinding()}),
    "tool-fails": dict(tool_fault=RuntimeError(CANARY)),
    "filter-fails": dict(env={"output_filter": _broken_filter}),
    "fail-RR": dict(failing={"REQUEST_RECEIVED"}),
    "fail-IR": dict(failing={"IDENTITY_RESOLVED"}),
    "fail-DEC": dict(failing={"DECISION"}),
    "fail-ES": dict(failing={"EXECUTION_STARTED"}),
    "fail-OF": dict(failing={"OUTPUT_FILTERED"}),
    "fail-RC": dict(failing={"REQUEST_COMPLETED"}),
    "fail-RC-deny": dict(
        tool="send_email",
        arguments={"to": "a", "body": "b"},
        failing={"REQUEST_COMPLETED"},
    ),
    "duplicate-id": dict(repeat_call_id=True),
    "async-allow": dict(asynchronous=True, tool="aread_file"),
    "async-sync-tool": dict(asynchronous=True),
}


def run_scenario(make_env, spec):
    import asyncio

    env = make_env(**spec.get("env", {}))
    env.failing.update(spec.get("failing", set()))
    env.raise_in_tool = spec.get("tool_fault")
    args = spec.get("arguments")
    if args == "outside":
        args = {"path": str(env.outside / "secret.txt")}
    elif isinstance(args, dict) and "path" in args:
        args = {**args, "path": args["path"].replace("WS", str(env.ws))}
    raw = spec.get("raw") or env.raw(
        spec.get("tool", "read_file"),
        args,
        agent_id=spec.get("agent_id", "research_agent"),
    )
    if spec.get("repeat_call_id"):
        env.pipeline.evaluate(env.raw(tool_call_id="c"))
        raw = env.raw(tool_call_id="c")
    before = env.total_calls()
    if spec.get("asynchronous"):
        result = asyncio.run(env.pipeline.evaluate_async(raw))
    else:
        result = env.pipeline.evaluate(raw)
    return env, result, env.total_calls() - before


def check_invariants(env, result, spy):
    d, ex = result.decision, result.execution
    if d is Decision.DENY:
        assert spy == 0  # NI-01
        assert result.reason not in NON_POLICY_REASONS
    if d is Decision.REQUIRE_APPROVAL:
        assert spy == 0  # NI-02
    if spy == 0:
        assert ex is Execution.NOT_STARTED  # NI-07
    else:
        assert spy == 1 and ex in (
            Execution.SUCCEEDED,
            Execution.FAILED,
        )  # NI-07, NI-18
    if d is not Decision.ALLOW:
        assert ex is Execution.NOT_STARTED  # NI-14
    if result.output_released:
        assert ex is Execution.SUCCEEDED and result.audit_complete  # NI-14
    if not result.audit_complete:
        assert result.output is None and not result.output_released
    if result.error_code == "INTERNAL_ERROR":
        assert d is not Decision.DENY  # NI-19
    if d is None:
        assert result.error_code in NULL_DECISION_CODES  # NI-19, AT-46
        assert ex is Execution.NOT_STARTED and not result.output_released
    if d is not None:
        assert d.value in {"allow", "deny", "require_approval"}  # NI-19
    assert ex is not Execution.UNKNOWN  # the in-process pipeline never returns it
    rows = env.store.read(result.request_id)
    if result.audit_complete:
        types = [r.event_type for r in rows]
        assert (
            types.count("REQUEST_COMPLETED") == 1 and types[-1] == "REQUEST_COMPLETED"
        )  # NI-12
        assert types.count("DECISION") <= 1
        if "DECISION" not in types:
            assert d is None
    if rows:
        state = reconstruct(rows)[result.request_id]  # NI-15
        if spy == 0:
            assert state.execution in (Execution.NOT_STARTED, Execution.UNKNOWN)
            if "EXECUTION_STARTED" not in [r.event_type for r in rows]:
                assert state.execution is Execution.NOT_STARTED
        else:
            assert state.execution in (ex, Execution.UNKNOWN)
    for event_rows in env.seen_in_spy:  # NI-06
        kinds = [e[0] for e in event_rows]
        assert kinds[-2:] == ["DECISION", "EXECUTION_STARTED"]
        assert event_rows[-2][1] == "allow" and event_rows[-2][2] == event_rows[-1][2]


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_invariants_hold_in_every_scenario(make_env, name):
    env, result, spy = run_scenario(make_env, SCENARIOS[name])
    check_invariants(env, result, spy)


def test_allow_only_for_granted_tools(make_env):
    # NI-10: research_agent is granted read_file, delete_file and aread_file
    # only; every other registered tool is denied.
    env = make_env()
    granted = {"read_file", "delete_file", "aread_file"}
    for tool in env.registry.specs():
        args = {"to": "a", "body": "b"} if tool.name == "send_email" else None
        r = env.pipeline.evaluate(env.raw(tool.name, args))
        if r.decision is Decision.ALLOW:
            assert tool.name in granted
        if tool.name not in granted:
            assert r.decision is Decision.DENY and r.reason == "UNAUTHORIZED_TOOL"


def test_unauthorized_agent_never_runs(make_env):
    # NI-03.
    env = make_env()
    env.identity.register_agent("disabled_agent", disabled=True)
    for agent in ("nobody", "disabled_agent"):
        r = env.pipeline.evaluate(env.raw(agent_id=agent))
        assert r.decision is Decision.DENY and env.total_calls() == 0


def test_a_claimed_request_is_never_invoked_twice(make_env):
    # NI-18: whatever fails after the claim, no second invocation.
    for failing in ({"OUTPUT_FILTERED"}, {"REQUEST_COMPLETED"}, {"ERROR"}):
        env = make_env(output_filter=_broken_filter)
        env.failing.update(failing)
        env.pipeline.evaluate(env.raw())
        assert env.calls["read"] == 1
