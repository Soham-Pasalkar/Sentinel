"""NI-15 / SEC-023 at pipeline level (C-11): the C4.4 classification from
committed audit rows alone matches what actually happened (the spies)."""

import pytest

from sentinel.audit import reconstruct
from sentinel.models import Execution


def _broken_filter(out):
    raise ValueError("x")


@pytest.mark.parametrize(
    ("scenario", "expected", "basis"),
    [
        ("allow", Execution.SUCCEEDED, "recorded"),
        ("deny", Execution.NOT_STARTED, "not_allowed"),
        ("approval", Execution.NOT_STARTED, "not_allowed"),
        ("invalid", Execution.NOT_STARTED, "no_decision"),
        ("tool-fails", Execution.FAILED, "recorded"),
        ("filter-fails", Execution.SUCCEEDED, "recorded"),
        ("es-write-fails", Execution.NOT_STARTED, "not_started"),
        ("rc-write-fails", Execution.UNKNOWN, "no_completion"),
        ("duplicate", Execution.NOT_STARTED, "not_started"),
    ],
)
def test_reconstruction_matches_the_spies(make_env, scenario, expected, basis):
    env = (
        make_env(output_filter=_broken_filter)
        if scenario == "filter-fails"
        else make_env()
    )
    raw = env.raw()
    if scenario == "deny":
        raw = env.raw(arguments={"path": str(env.outside / "secret.txt")})
    elif scenario == "approval":
        raw = env.raw("delete_file")
    elif scenario == "invalid":
        raw = {"tool": "read_file"}
    elif scenario == "tool-fails":
        env.raise_in_tool = RuntimeError("boom")
    elif scenario == "es-write-fails":
        env.failing.add("EXECUTION_STARTED")
    elif scenario == "rc-write-fails":
        env.failing.add("REQUEST_COMPLETED")
    elif scenario == "duplicate":
        env.pipeline.evaluate(env.raw(tool_call_id="c"))
        raw = env.raw(tool_call_id="c")
    before = env.total_calls()
    r = env.pipeline.evaluate(raw)
    ran = env.total_calls() - before
    state = reconstruct(env.store.read())[r.request_id]
    assert (state.execution, state.basis) == (expected, basis)
    # Spy truth: never "not executed" when the tool ran.
    if ran:
        assert state.execution is not Execution.NOT_STARTED
    else:
        assert state.execution in (Execution.NOT_STARTED, Execution.UNKNOWN)


def test_every_request_in_a_mixed_run_reconstructs(env):
    requests = [
        env.raw(),
        env.raw("send_email", {"to": "a", "body": "b"}),
        {"agent_id": "research_agent"},
        env.raw("delete_file"),
        env.raw(),
    ]
    results = [env.pipeline.evaluate(r) for r in requests]
    states = reconstruct(env.store.read())
    assert list(states) == [r.request_id for r in results]
    assert [s.execution for s in states.values()] == [r.execution for r in results]
