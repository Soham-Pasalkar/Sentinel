"""Execution proxy tests (C-10): C1.4 rules 2/3/5, C2.7, C3.5 rule 8, D-19,
D-25, D-27, D-31, D-14 interruption; NI-08, NI-09, NI-13, NI-16; F14, F16;
AT-01-AT-03, AT-06, AT-07, AT-22, AT-23, AT-26, AT-35; SEC-010, SEC-011,
SEC-021, SEC-024, SEC-025.

Inputs are built with the real gateway (C-06), identity (C-07) and policy
(C-08). Mapping outcomes to ``PipelineResult`` and audit events is C-11.
"""

import asyncio
import contextlib
import functools
import inspect
import math
import os
import threading
import time
from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, ConfigDict

import sentinel
from sentinel import proxy as proxy_module
from sentinel.action import AuthorizedAction
from sentinel.exceptions import ConfigurationError
from sentinel.gateway import validate_request
from sentinel.identity import IdentityStore
from sentinel.models import (
    ACTION_MISMATCH,
    DECISION_ALREADY_USED,
    DUPLICATE_TOOL_CALL,
    GUARD_CAPACITY_EXHAUSTED,
    INTERNAL_ERROR,
    OUTPUT_FILTER_FAILED,
    RESTRICTED_PATH,
    TOOL_FAILED,
    UNAUTHORIZED_TOOL,
    Decision,
    Execution,
    PipelineResult,
    SecurityContext,
    SecurityDecision,
    ToolGrant,
    ToolSpec,
)
from sentinel.policy import PolicyEngine, SecurityPolicy
from sentinel.proxy import (
    DEFAULT_GUARD_CAPACITY,
    DEFAULT_GUARD_TTL_SECONDS,
    Diagnostics,
    ExecutionProxy,
    ProxyOutcome,
    ToolCallGuard,
    pass_through_filter,
)
from sentinel.registry import ToolRegistry

CANARY = "CANARY-5d1c-not-in-outcomes"
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


class PathArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str


class CopyArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    src: str
    dst: str


class CountArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    n: int


def run_async(fn):
    """Run an async test with asyncio.run (no async pytest plugin is installed)."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return asyncio.run(fn(*args, **kwargs))

    return wrapper


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


class Env:
    """Registry, identity, policy and proxy over a temporary workspace."""

    def __init__(self, tmp_path, *, guard=None, output_filter=pass_through_filter):
        self.ws = tmp_path / "ws"
        (self.ws / "sub").mkdir(parents=True)
        (self.ws / "a.txt").write_text("inside")
        (self.ws / "sub" / "b.txt").write_text("inside-b")
        self.outside = tmp_path / "outside"
        self.outside.mkdir()
        (self.outside / "b.txt").write_text("outside")
        self.calls = []
        self.registry = ToolRegistry()
        self.registry.register(
            "read_file",
            arg_schema=PathArgs,
            destructive=False,
            path_args=("path",),
            sync_fn=self.read_file,
        )
        self.registry.register(
            "copy",
            arg_schema=CopyArgs,
            destructive=False,
            path_args=("src", "dst"),
            sync_fn=self.copy,
        )
        self.registry.register(
            "count", arg_schema=CountArgs, destructive=False, sync_fn=self.count
        )
        self.registry.register(
            "acount", arg_schema=CountArgs, destructive=False, async_fn=self.acount
        )
        self.registry.register(
            "delete_file",
            arg_schema=PathArgs,
            destructive=True,
            path_args=("path",),
            sync_fn=self.read_file,
        )
        self.identity = IdentityStore(self.registry, require_credentials=False)
        prefix = (str(self.ws),)
        grants = (
            ToolGrant(tool="read_file", allowed_path_prefixes=prefix),
            ToolGrant(tool="copy", allowed_path_prefixes=prefix),
            ToolGrant(tool="delete_file", allowed_path_prefixes=prefix),
            ToolGrant(tool="count"),
            ToolGrant(tool="acount"),
        )
        self.identity.register_agent("agent-1", grants=grants)
        self.identity.register_agent("agent-2", grants=grants)
        self.policy = PolicyEngine(SecurityPolicy(version="test-1"))
        self.proxy = ExecutionProxy(
            self.registry, output_filter=output_filter, guard=guard
        )
        self._ids = 0
        self.raise_in_tool = None

    # --- tools (spies) ---
    def _record(self, name, kwargs):
        self.calls.append((name, dict(kwargs)))
        if self.raise_in_tool is not None:
            raise self.raise_in_tool

    def read_file(self, path):
        self._record("read_file", {"path": path})
        with open(path) as handle:
            return handle.read()

    def copy(self, src, dst):
        self._record("copy", {"src": src, "dst": dst})
        return "copied"

    def count(self, n):
        self._record("count", {"n": n})
        return n + 1

    async def acount(self, n):
        self._record("acount", {"n": n})
        await asyncio.sleep(0)
        return n + 1

    # --- inputs ---
    def inputs(self, tool="count", arguments=None, agent_id="agent-1", **raw_extra):
        if arguments is None:
            arguments = (
                {"n": 1}
                if tool in ("count", "acount")
                else {"path": str(self.ws / "a.txt")}
            )
        self._ids += 1
        raw = {
            "agent_id": agent_id,
            "session_id": raw_extra.pop("session_id", "sess-1"),
            "tool": tool,
            "arguments": arguments,
            **raw_extra,
        }
        validated = validate_request(
            raw,
            registry=self.registry,
            request_id=f"req-{self._ids}",
            received_at=NOW,
        )
        context = self.identity.authenticate(validated.request)
        decision = self.policy.evaluate(
            validated.request, context, (), validated.spec, action=validated.action
        )
        return validated.request, decision, context

    def run(self, tool="count", arguments=None, mode="sync", **raw_extra):
        request, decision, context = self.inputs(tool, arguments, **raw_extra)
        return self.proxy.claim(request, decision, context, mode=mode)


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def executed(outcome, value=None):
    assert outcome.error_code is None
    assert outcome.execution is Execution.SUCCEEDED
    assert outcome.output_released is True
    if value is not None:
        assert outcome.output == value


def refused(run, code):
    assert run.state == "refused"
    assert run.outcome == ProxyOutcome(error_code=code, execution=Execution.NOT_STARTED)


# ===================================================== decision binding


def test_allow_executes_exactly_once_with_the_authorized_arguments(env):
    run = env.run("count", {"n": 41})
    assert run.state == "claimed"
    executed(run.execute(), 42)
    assert env.calls == [("count", {"n": 41})]
    assert run.state == "completed"


def test_deny_decision_never_executes(env):
    request, decision, context = env.inputs("count")
    deny = SecurityDecision(
        request_id=decision.request_id,
        decision=Decision.DENY,
        reason=UNAUTHORIZED_TOOL,
        policy_version="v",
        action=decision.action,
    )
    refused(env.proxy.claim(request, deny, context), ACTION_MISMATCH)
    assert env.calls == []


def test_require_approval_decision_never_executes(env):
    request, decision, context = env.inputs("delete_file")
    assert decision.decision is Decision.REQUIRE_APPROVAL
    refused(env.proxy.claim(request, decision, context), ACTION_MISMATCH)
    assert env.calls == []


@pytest.mark.parametrize("bad", [None, "allow", object()])
def test_missing_or_wrong_type_decision_raises_and_never_executes(env, bad):
    request, _, context = env.inputs("count")
    with pytest.raises(TypeError):
        env.proxy.claim(request, bad, context)
    assert env.calls == []


def test_decision_for_another_request_is_refused(env):
    request_a, decision_a, context = env.inputs("count", {"n": 1})
    request_b, _, _ = env.inputs("count", {"n": 1})
    refused(env.proxy.claim(request_b, decision_a, context), ACTION_MISMATCH)
    # The misdirected attempt did not consume decision A.
    executed(env.proxy.claim(request_a, decision_a, context).execute(), 2)


def test_context_for_another_agent_is_refused(env):
    request, decision, _ = env.inputs("count")
    other = env.identity.authenticate(env.inputs("count", agent_id="agent-2")[0])
    refused(env.proxy.claim(request, decision, other), ACTION_MISMATCH)


def test_unauthorized_or_ungranted_context_is_refused(env):
    request, decision, context = env.inputs("count")
    unauthorized = SecurityContext(agent_id="agent-1", authorized=False)
    refused(env.proxy.claim(request, decision, unauthorized), ACTION_MISMATCH)
    no_grant = SecurityContext(agent_id="agent-1", authorized=True)
    refused(env.proxy.claim(request, decision, no_grant), ACTION_MISMATCH)
    assert env.calls == []


def test_decision_for_another_tool_is_refused(env):
    request, _, context = env.inputs("count", {"n": 1})
    _, other_decision, _ = env.inputs("acount", {"n": 1})
    refused(env.proxy.claim(request, other_decision, context), ACTION_MISMATCH)


def test_tampered_digest_is_refused(env):
    # NI-13: any mutation of decision.action after policy.
    request, decision, context = env.inputs("count", {"n": 1})
    object.__setattr__(decision.action, "_digest", "0" * 64)
    refused(env.proxy.claim(request, decision, context), ACTION_MISMATCH)


def test_tampered_action_arguments_are_refused(env):
    request, decision, context = env.inputs("count", {"n": 1})
    object.__setattr__(decision.action, "_canonical_arguments", '{"n":999}')
    refused(env.proxy.claim(request, decision, context), ACTION_MISMATCH)
    assert env.calls == []


@pytest.mark.parametrize("other", [{"n": 2}, {"n": True}, {"n": 1.0}])
def test_request_arguments_differing_from_the_action_are_refused(env, other):
    # 1, True and 1.0 compare equal in Python but not by digest.
    request, decision, context = env.inputs("count", {"n": 1})
    changed = request.model_copy(update={"arguments": other})
    refused(env.proxy.claim(changed, decision, context), ACTION_MISMATCH)
    assert env.calls == []


def test_forged_decision_for_other_arguments_is_refused(env):
    # AT-23: args A used for args B.
    request_b, _, context = env.inputs("count", {"n": 2})
    forged = SecurityDecision(
        request_id=request_b.request_id,
        decision=Decision.ALLOW,
        reason="ALLOWED",
        policy_version="forged",
        action=AuthorizedAction(
            request_id=request_b.request_id,
            agent_id="agent-1",
            tool="count",
            arguments={"n": 1},
        ),
    )
    refused(env.proxy.claim(request_b, forged, context), ACTION_MISMATCH)


def test_missing_path_argument_in_action_is_refused(env):
    request, decision, context = env.inputs("read_file")
    action = AuthorizedAction(
        request_id=request.request_id,
        agent_id="agent-1",
        tool="read_file",
        arguments={},
    )
    forged_request = request.model_copy(update={"arguments": {}})
    forged = decision.model_copy(update={"action": action})
    refused(env.proxy.claim(forged_request, forged, context), ACTION_MISMATCH)


# ===================================================== single use (D-25)


def test_second_use_of_a_decision_is_refused(env):
    # AT-22, sync path.
    request, decision, context = env.inputs("count")
    executed(env.proxy.claim(request, decision, context).execute())
    refused(env.proxy.claim(request, decision, context), DECISION_ALREADY_USED)
    assert len(env.calls) == 1


@run_async
async def test_second_use_of_a_decision_is_refused_async(env):
    # AT-22, async path.
    request, decision, context = env.inputs("acount")
    executed(
        await env.proxy.claim(request, decision, context, mode="async").execute_async()
    )
    refused(
        env.proxy.claim(request, decision, context, mode="async"), DECISION_ALREADY_USED
    )
    assert len(env.calls) == 1


def test_copied_or_reconstructed_decision_cannot_replay(env):
    request, decision, context = env.inputs("count")
    executed(env.proxy.claim(request, decision, context).execute())
    copy_ = decision.model_copy()
    rebuilt = SecurityDecision(
        request_id=decision.request_id,
        decision=decision.decision,
        reason=decision.reason,
        policy_version=decision.policy_version,
        action=AuthorizedAction(
            request_id=decision.action.request_id,
            agent_id=decision.action.agent_id,
            tool=decision.action.tool,
            arguments=decision.action.arguments,
        ),
    )
    assert copy_ is not decision and rebuilt is not decision
    refused(env.proxy.claim(request, copy_, context), DECISION_ALREADY_USED)
    refused(env.proxy.claim(request, rebuilt, context), DECISION_ALREADY_USED)
    assert len(env.calls) == 1


def test_failed_or_refused_execution_still_consumes_the_decision(env, tmp_path):
    env.raise_in_tool = ValueError(CANARY)
    request, decision, context = env.inputs("count")
    assert (
        env.proxy.claim(request, decision, context).execute().error_code == TOOL_FAILED
    )
    refused(env.proxy.claim(request, decision, context), DECISION_ALREADY_USED)
    # A run that fails path re-verification also keeps the decision used.
    env.raise_in_tool = None
    request, decision, context = env.inputs(
        "read_file", {"path": str(env.ws / "sub" / "b.txt")}
    )
    run = env.proxy.claim(request, decision, context)
    (env.ws / "sub").rename(env.ws / "sub_old")
    (env.ws / "sub").symlink_to(env.outside, target_is_directory=True)
    assert run.execute().error_code == RESTRICTED_PATH
    refused(env.proxy.claim(request, decision, context), DECISION_ALREADY_USED)


def test_independent_requests_do_not_collide(env):
    for _ in range(5):
        executed(env.run("count", {"n": 1}).execute(), 2)
    assert len(env.calls) == 5


def _contend(env, request, decision, context, threads=8):
    barrier = threading.Barrier(threads)
    results = []

    def worker():
        barrier.wait()
        run = env.proxy.claim(request, decision, context)
        if run.state == "claimed":
            results.append(run.execute().execution)
        else:
            results.append(run.outcome.error_code)

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    return results


def test_concurrent_consumption_executes_exactly_once(env):
    # AT-01: 8 threads, 100 trials.
    for _ in range(100):
        env.calls.clear()
        results = _contend(env, *env.inputs("count"))
        assert len(env.calls) == 1
        assert sorted(map(str, results)) == sorted(
            [str(Execution.SUCCEEDED)] + [DECISION_ALREADY_USED] * 7
        )


@run_async
async def test_concurrent_async_consumption_executes_exactly_once(env):
    # AT-02: 8 asyncio tasks.
    for _ in range(100):
        env.calls.clear()
        request, decision, context = env.inputs("acount")

        async def attempt(request=request, decision=decision, context=context):
            run = env.proxy.claim(request, decision, context, mode="async")
            if run.state == "claimed":
                return (await run.execute_async()).execution
            return run.outcome.error_code

        results = await asyncio.gather(*(attempt() for _ in range(8)))
        assert len(env.calls) == 1
        assert results.count(DECISION_ALREADY_USED) == 7


def test_the_concurrency_test_detects_a_non_atomic_claim(env, monkeypatch):
    # AT-03: against a deliberately racy claim, duplicates must be observed.
    class SlowSet(set):
        def __contains__(self, item):
            found = super().__contains__(item)
            time.sleep(0.005)
            return found

    env.proxy._claimed = SlowSet()
    env.proxy._lock = contextlib.nullcontext()
    duplicated = 0
    for _ in range(5):
        env.calls.clear()
        _contend(env, *env.inputs("count"))
        duplicated += len(env.calls) > 1
    assert duplicated >= 1


# ================================================= registry authority


def test_unregistered_tool_is_refused_as_internal_error(env, tmp_path):
    request, decision, context = env.inputs("count")
    other = ExecutionProxy(ToolRegistry(), output_filter=pass_through_filter)
    refused(other.claim(request, decision, context), INTERNAL_ERROR)
    assert env.calls == []


def test_registry_path_metadata_wins_over_a_fake_spec(env):
    # Policy was handed a spec without path_args, so it allowed a path outside
    # the grant; the proxy uses the registry's path_args and re-checks it.
    outside = str(env.outside / "b.txt")
    raw = {
        "agent_id": "agent-1",
        "session_id": "s",
        "tool": "read_file",
        "arguments": {"path": outside},
    }
    validated = validate_request(
        raw, registry=env.registry, request_id="r-x", received_at=NOW
    )
    context = env.identity.authenticate(validated.request)
    fake = ToolSpec(name="read_file", arg_schema=PathArgs, destructive=False)
    decision = env.policy.evaluate(
        validated.request, context, (), fake, action=validated.action
    )
    assert decision.decision is Decision.ALLOW
    run = env.proxy.claim(validated.request, decision, context)
    outcome = run.execute()
    assert outcome == ProxyOutcome(
        error_code=RESTRICTED_PATH, execution=Execution.NOT_STARTED
    )
    assert env.calls == []


def test_registry_callable_is_the_one_invoked(env):
    # Policy and proxy inputs carry no callable; the registry's runs.
    params = inspect.signature(ExecutionProxy.claim).parameters
    assert set(params) == {"self", "request", "decision", "context", "mode"}
    executed(env.run("count", {"n": 1}).execute(), 2)
    assert env.calls == [("count", {"n": 1})]


def test_missing_entry_point_is_refused_before_claiming(env):
    request, decision, context = env.inputs("acount")
    refused(env.proxy.claim(request, decision, context, mode="sync"), INTERNAL_ERROR)
    # Nothing was claimed: the async path can still use the decision.
    run = env.proxy.claim(request, decision, context, mode="async")
    assert run.state == "claimed"
    run.abandon()


def test_wrong_execution_method_is_refused(env):
    run = env.run("acount", mode="async")
    with pytest.raises(RuntimeError):
        run.execute()
    assert env.calls == []
    run.abandon()


def test_invalid_mode_raises(env):
    request, decision, context = env.inputs("count")
    with pytest.raises(ValueError):
        env.proxy.claim(request, decision, context, mode="thread")


def test_proxy_configuration_is_validated(env):
    with pytest.raises(ConfigurationError):
        ExecutionProxy({}, output_filter=pass_through_filter)
    with pytest.raises(ConfigurationError):
        ExecutionProxy(env.registry, output_filter=None)
    with pytest.raises(ConfigurationError):
        ExecutionProxy(env.registry, output_filter=pass_through_filter, guard=object())
    with pytest.raises(TypeError):
        ExecutionProxy(env.registry)  # a filter must be supplied explicitly


# ============================================== tool_call_id guard (D-31)


def test_guard_defaults():
    guard = ToolCallGuard()
    assert (DEFAULT_GUARD_TTL_SECONDS, DEFAULT_GUARD_CAPACITY) == (300.0, 10_000)
    assert (guard.ttl_seconds, guard.capacity) == (300.0, 10_000)


def test_duplicate_tool_call_id_is_refused(env):
    executed(env.run("count", tool_call_id="call-1").execute())
    run = env.run("count", tool_call_id="call-1")  # new request, same call id
    refused(run, DUPLICATE_TOOL_CALL)
    assert len(env.calls) == 1


def test_guard_key_includes_agent_and_session(env):
    # AT-06.
    executed(env.run("count", tool_call_id="call-1").execute())
    executed(env.run("count", tool_call_id="call-1", session_id="sess-2").execute())
    executed(env.run("count", tool_call_id="call-1", agent_id="agent-2").execute())
    assert len(env.calls) == 3
    assert len(env.proxy.guard) == 3


def test_missing_tool_call_id_skips_the_guard_but_not_single_use(env):
    request, decision, context = env.inputs("count")
    executed(env.proxy.claim(request, decision, context).execute())
    assert len(env.proxy.guard) == 0
    refused(env.proxy.claim(request, decision, context), DECISION_ALREADY_USED)


def test_tool_call_id_without_session_id_cannot_form_a_request(env):
    with pytest.raises(Exception):  # noqa: B017 - InvalidRequestError at the gateway
        validate_request(
            {
                "agent_id": "agent-1",
                "tool": "count",
                "arguments": {"n": 1},
                "tool_call_id": "call-1",
            },
            registry=env.registry,
            request_id="r",
            received_at=NOW,
        )


def test_refused_attempt_does_not_consume_the_call_id(env):
    # AT-07 at proxy level: a refusal before the guard creates no entry.
    request, decision, context = env.inputs("count", tool_call_id="call-1")
    changed = request.model_copy(update={"arguments": {"n": 5}})
    refused(env.proxy.claim(changed, decision, context), ACTION_MISMATCH)
    assert len(env.proxy.guard) == 0
    executed(env.proxy.claim(request, decision, context).execute())


def test_failed_invocation_still_consumes_the_call_id(tmp_path):
    clock = Clock()
    env = Env(tmp_path, guard=ToolCallGuard(clock=clock))
    env.raise_in_tool = RuntimeError(CANARY)
    assert env.run("count", tool_call_id="c").execute().error_code == TOOL_FAILED
    env.raise_in_tool = None
    clock.now += 299
    refused(env.run("count", tool_call_id="c"), DUPLICATE_TOOL_CALL)
    clock.now += 1
    executed(env.run("count", tool_call_id="c").execute())


def test_in_flight_entry_never_expires():
    # AT-35.
    clock = Clock()
    guard = ToolCallGuard(ttl_seconds=10, clock=clock)
    key = ("a", "s", "c")
    assert guard.claim(key) is None
    clock.now += 10_000
    assert guard.claim(key) == DUPLICATE_TOOL_CALL
    guard.retire(key)
    clock.now += 9.999
    assert guard.claim(key) == DUPLICATE_TOOL_CALL
    clock.now += 0.001
    assert guard.claim(key) is None  # purged: treated as new (documented limit)


def test_in_flight_entry_does_not_expire_during_a_long_tool_call(tmp_path):
    clock = Clock()
    env = Env(tmp_path, guard=ToolCallGuard(ttl_seconds=300, clock=clock))
    request, decision, context = env.inputs("count", tool_call_id="slow")
    run = env.proxy.claim(request, decision, context)
    clock.now += 10_000  # far beyond the TTL while still claimed / running
    refused(env.run("count", tool_call_id="slow"), DUPLICATE_TOOL_CALL)
    executed(run.execute())
    clock.now += 299
    refused(env.run("count", tool_call_id="slow"), DUPLICATE_TOOL_CALL)


def test_capacity_fails_closed_without_eviction():
    # AT-26.
    clock = Clock()
    guard = ToolCallGuard(ttl_seconds=60, capacity=3, clock=clock)
    keys = [("a", "s", f"c{i}") for i in range(3)]
    for key in keys:
        assert guard.claim(key) is None
    guard.retire(keys[0])  # terminal, within TTL
    assert guard.claim(("a", "s", "new")) == GUARD_CAPACITY_EXHAUSTED
    for key in keys:  # nothing was evicted
        assert guard.claim(key) == DUPLICATE_TOOL_CALL
    clock.now += 60
    assert guard.claim(("a", "s", "new")) is None  # keys[0] expired and purged
    assert len(guard) == 3


def test_capacity_refusal_through_the_proxy_and_calls_without_id_unaffected(tmp_path):
    env = Env(tmp_path, guard=ToolCallGuard(capacity=1, clock=Clock()))
    executed(env.run("count", tool_call_id="c1").execute())
    refused(env.run("count", tool_call_id="c2"), GUARD_CAPACITY_EXHAUSTED)
    executed(env.run("count").execute())


def test_concurrent_duplicate_claim_has_one_winner():
    guard = ToolCallGuard(clock=Clock())
    barrier = threading.Barrier(8)
    results = []

    def worker():
        barrier.wait()
        results.append(guard.claim(("a", "s", "c")))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(None) == 1
    assert results.count(DUPLICATE_TOOL_CALL) == 7


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ttl_seconds": 0},
        {"ttl_seconds": -1},
        {"ttl_seconds": math.nan},
        {"ttl_seconds": math.inf},
        {"ttl_seconds": True},
        {"ttl_seconds": "300"},
        {"capacity": 0},
        {"capacity": -5},
        {"capacity": True},
        {"capacity": 10.0},
        {"capacity": "10"},
        {"clock": None},
        {"clock": "monotonic"},
        {"clock": lambda: math.nan},
        {"clock": lambda: math.inf},
        {"clock": lambda: "1"},
        {"clock": lambda: True},
    ],
)
def test_invalid_guard_configuration_is_rejected(kwargs):
    with pytest.raises(ConfigurationError):
        ToolCallGuard(**kwargs)


def test_clock_moving_backwards_refuses_the_claim():
    clock = Clock(100.0)
    guard = ToolCallGuard(clock=clock)
    assert guard.claim(("a", "s", "1")) is None
    clock.now = 50.0
    with pytest.raises(RuntimeError):
        guard.claim(("a", "s", "2"))
    assert len(guard) == 1


def test_invalid_clock_value_later_refuses_the_claim():
    clock = Clock(100.0)
    guard = ToolCallGuard(clock=clock)
    clock.now = math.nan
    with pytest.raises(RuntimeError):
        guard.claim(("a", "s", "1"))


def test_retire_under_a_backwards_clock_keeps_the_entry_in_flight():
    clock = Clock(100.0)
    guard = ToolCallGuard(ttl_seconds=10, clock=clock)
    key = ("a", "s", "c")
    guard.claim(key)
    clock.now = 50.0
    guard.retire(key)  # does not raise
    clock.now = 10_000.0
    assert guard.claim(key) == DUPLICATE_TOOL_CALL  # never expires: fail closed


def test_guard_state_stays_bounded():
    clock = Clock()
    guard = ToolCallGuard(ttl_seconds=1, capacity=5, clock=clock)
    for i in range(1000):
        key = ("a", "s", str(i))
        assert guard.claim(key) is None
        guard.retire(key)
        clock.now += 1
        assert len(guard) <= 5


def test_production_clock_is_monotonic():
    defaults = inspect.signature(ToolCallGuard).parameters
    assert defaults["clock"].default is time.monotonic


# =================================================== path re-verification


def test_valid_path_executes(env):
    executed(env.run("read_file").execute(), "inside")


def test_changed_path_target_is_refused_before_invocation(env):
    # F16 at proxy level.
    run = env.run("read_file", {"path": str(env.ws / "sub" / "b.txt")})
    (env.ws / "sub").rename(env.ws / "sub_old")
    (env.ws / "sub").symlink_to(env.outside, target_is_directory=True)
    outcome = run.execute()
    assert outcome == ProxyOutcome(
        error_code=RESTRICTED_PATH, execution=Execution.NOT_STARTED
    )
    assert run.state == "not_started"
    assert env.calls == []


@run_async
async def test_changed_path_target_is_refused_on_the_async_path(tmp_path):
    env = Env(tmp_path)
    seen = []

    async def aread(path):
        seen.append(path)
        return "read"

    env.registry.register(
        "aread",
        arg_schema=PathArgs,
        destructive=False,
        path_args=("path",),
        async_fn=aread,
    )
    env.identity.register_agent(
        "agent-a",
        grants=(ToolGrant(tool="aread", allowed_path_prefixes=(str(env.ws),)),),
    )
    request, decision, context = env.inputs(
        "aread", {"path": str(env.ws / "sub" / "b.txt")}, agent_id="agent-a"
    )
    run = env.proxy.claim(request, decision, context, mode="async")
    (env.ws / "sub").rename(env.ws / "sub_old")
    (env.ws / "sub").symlink_to(env.outside, target_is_directory=True)
    outcome = await run.execute_async()
    assert outcome == ProxyOutcome(
        error_code=RESTRICTED_PATH, execution=Execution.NOT_STARTED
    )
    assert seen == []


def test_path_outside_the_proxys_grant_is_refused(env):
    # F14: a decision for a path the grant does not cover never runs.
    request, decision, _ = env.inputs("read_file")
    narrow = SecurityContext(
        agent_id="agent-1",
        authorized=True,
        envelope=env.identity.authenticate(request).envelope.model_copy(
            update={
                "grants": (
                    ToolGrant(
                        tool="read_file", allowed_path_prefixes=(str(env.outside),)
                    ),
                )
            }
        ),
    )
    run = env.proxy.claim(request, decision, narrow)
    assert run.execute().error_code == RESTRICTED_PATH
    assert env.calls == []


@pytest.mark.parametrize("which", ["src", "dst"])
def test_every_path_argument_is_reverified(env, which):
    (env.ws / "sub" / "c.txt").write_text("x")
    paths_ = {"src": str(env.ws / "a.txt"), "dst": str(env.ws / "a.txt")}
    paths_[which] = str(env.ws / "sub" / "c.txt")
    run = env.run("copy", paths_)
    (env.ws / "sub").rename(env.ws / "sub_old")
    (env.ws / "sub").symlink_to(env.outside, target_is_directory=True)
    assert run.execute().error_code == RESTRICTED_PATH
    assert env.calls == []


def test_refusals_carry_no_decision(env):
    run = env.run("read_file", {"path": str(env.ws / "sub" / "b.txt")})
    (env.ws / "sub").rename(env.ws / "sub_old")
    (env.ws / "sub").symlink_to(env.outside, target_is_directory=True)
    outcome = run.execute()
    assert not hasattr(outcome, "decision")
    # How C-11 reports it (C1.6 rev. 6): decision None, RESTRICTED_PATH.
    PipelineResult(
        request_id="req",
        decision=None,
        reason=RESTRICTED_PATH,
        error_code=RESTRICTED_PATH,
        execution=outcome.execution,
        output_released=False,
        audit_complete=True,
    )


# ================================================= invocation and filter


@run_async
async def test_async_success(env):
    run = env.run("acount", {"n": 4}, mode="async")
    executed(await run.execute_async(), 5)
    assert env.calls == [("acount", {"n": 4})]


def test_tool_receives_a_copy_of_the_action_arguments(tmp_path):
    # NI-08: kwargs equal decision.action.arguments; mutation inside the tool
    # does not change them.
    seen = {}

    def mutating(items):
        seen["items"] = items
        items.append("injected")
        return len(items)

    class ListArgs(BaseModel):
        model_config = ConfigDict(extra="forbid")
        items: list[str]

    env = Env(tmp_path)
    env.registry.register(
        "mutate", arg_schema=ListArgs, destructive=False, sync_fn=mutating
    )
    env.identity.register_agent("agent-m", grants=(ToolGrant(tool="mutate"),))
    request, decision, context = env.inputs(
        "mutate", {"items": ["a"]}, agent_id="agent-m"
    )
    executed(env.proxy.claim(request, decision, context).execute(), 2)
    assert decision.action.arguments == {"items": ["a"]}
    assert seen["items"] == ["a", "injected"]


@pytest.mark.parametrize("mode", ["sync", "async"])
@run_async
async def test_tool_failure_is_contained_without_its_message(env, mode):
    env.raise_in_tool = ValueError(CANARY)
    tool = "count" if mode == "sync" else "acount"
    run = env.run(tool, mode=mode)
    outcome = run.execute() if mode == "sync" else await run.execute_async()
    assert outcome.error_code == TOOL_FAILED
    assert outcome.execution is Execution.FAILED
    assert outcome.output_released is False and outcome.output is None
    assert run.state == "failed"
    d = outcome.diagnostics
    assert isinstance(d, Diagnostics)
    assert (d.exception_type, d.stage) == ("builtins.ValueError", "tool")
    assert d.module == __name__ and d.function == "_record" and d.line > 0
    text = repr(outcome) + str(outcome)
    assert CANARY not in text
    assert os.sep + "tests" + os.sep not in text  # no file paths


def test_output_filter_result_is_what_is_released(tmp_path):
    env = Env(tmp_path, output_filter=lambda out: f"[filtered:{out}]")
    executed(env.run("count", {"n": 1}).execute(), "[filtered:2]")


def test_output_filter_failure_withholds_output_and_keeps_succeeded(tmp_path):
    def broken(out):
        raise RuntimeError(CANARY + str(out))

    env = Env(tmp_path, output_filter=broken)
    run = env.run("count", {"n": 1})
    outcome = run.execute()
    assert outcome.error_code == OUTPUT_FILTER_FAILED
    assert outcome.execution is Execution.SUCCEEDED
    assert outcome.output_released is False and outcome.output is None
    assert outcome.diagnostics.stage == "output_filter"
    assert CANARY not in repr(outcome)
    assert len(env.calls) == 1  # never retried
    assert run.state == "completed"
    with pytest.raises(RuntimeError):
        run.execute()  # and it cannot be run again
    assert len(env.calls) == 1


def test_output_filter_returning_an_awaitable_is_a_filter_failure(tmp_path):
    async def coro_filter(out):
        return out

    env = Env(tmp_path, output_filter=coro_filter)
    outcome = env.run("count").execute()
    assert outcome.error_code == OUTPUT_FILTER_FAILED


def test_sync_entry_returning_a_coroutine_is_never_released(tmp_path):
    async def body():
        raise AssertionError("must never run")

    def sneaky(n):
        return body()

    env = Env(tmp_path)
    env.registry.register(
        "sneaky", arg_schema=CountArgs, destructive=False, sync_fn=sneaky
    )
    env.identity.register_agent("agent-s", grants=(ToolGrant(tool="sneaky"),))
    request, decision, context = env.inputs("sneaky", {"n": 1}, agent_id="agent-s")
    outcome = env.proxy.claim(request, decision, context).execute()
    assert outcome.error_code == TOOL_FAILED
    assert outcome.output is None


def test_interruption_after_entry_propagates_and_marks_interrupted(tmp_path):
    clock = Clock()
    env = Env(tmp_path, guard=ToolCallGuard(clock=clock))
    env.raise_in_tool = KeyboardInterrupt()
    run = env.run("count", tool_call_id="c")
    with pytest.raises(KeyboardInterrupt):
        run.execute()
    assert run.state == "interrupted"
    env.raise_in_tool = None
    refused(env.run("count", tool_call_id="c"), DUPLICATE_TOOL_CALL)
    clock.now += 300
    executed(env.run("count", tool_call_id="c").execute())  # retired at interruption


@run_async
async def test_cancellation_of_an_async_tool_marks_interrupted(env):
    started = asyncio.Event()

    async def slow(n):
        started.set()
        await asyncio.sleep(3600)

    env.registry.register(
        "slow", arg_schema=CountArgs, destructive=False, async_fn=slow
    )
    env.identity.register_agent("agent-c", grants=(ToolGrant(tool="slow"),))
    request, decision, context = env.inputs("slow", {"n": 1}, agent_id="agent-c")
    run = env.proxy.claim(request, decision, context, mode="async")
    assert run.state == "claimed"
    task = asyncio.ensure_future(run.execute_async())
    await asyncio.wait_for(started.wait(), timeout=5)  # never hang the suite
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert run.state == "interrupted"


def test_interruption_before_entry_is_not_started(env, monkeypatch):
    def boom(*args):
        raise KeyboardInterrupt

    monkeypatch.setattr(proxy_module, "reverify", boom)
    run = env.run("read_file")
    with pytest.raises(KeyboardInterrupt):
        run.execute()
    assert run.state == "not_started"
    assert env.calls == []


def test_runs_execute_at_most_once_and_refused_runs_never(env):
    run = env.run("count")
    run.execute()
    with pytest.raises(RuntimeError):
        run.execute()
    request, decision, context = env.inputs("delete_file")
    refused_run = env.proxy.claim(request, decision, context)
    with pytest.raises(RuntimeError):
        refused_run.execute()
    with pytest.raises(RuntimeError):
        refused_run.abandon()
    assert len(env.calls) == 1


def test_abandon_retires_the_guard_entry_and_keeps_the_decision_used(tmp_path):
    clock = Clock()
    env = Env(tmp_path, guard=ToolCallGuard(clock=clock))
    request, decision, context = env.inputs("count", tool_call_id="c")
    run = env.proxy.claim(request, decision, context)
    run.abandon()
    assert run.state == "not_started"
    with pytest.raises(RuntimeError):
        run.execute()
    refused(env.proxy.claim(request, decision, context), DECISION_ALREADY_USED)
    clock.now += 300
    executed(env.run("count", tool_call_id="c").execute())
    assert len(env.calls) == 1


def test_outcome_invariants():
    with pytest.raises(ValueError):
        ProxyOutcome(error_code=None, execution=Execution.FAILED, output_released=True)
    with pytest.raises(ValueError):
        ProxyOutcome(
            error_code=OUTPUT_FILTER_FAILED,
            execution=Execution.SUCCEEDED,
            output_released=True,
        )
    with pytest.raises(ValueError):
        ProxyOutcome(error_code=TOOL_FAILED, execution=Execution.FAILED, output="x")
    released = ProxyOutcome(
        error_code=None,
        execution=Execution.SUCCEEDED,
        output_released=True,
        output=CANARY,
    )
    assert released.output == CANARY
    assert CANARY not in repr(released)  # output is kept out of repr


def test_no_clock_files_or_randomness_beyond_injected_interfaces(tmp_path, monkeypatch):
    clock = Clock()
    env = Env(tmp_path, guard=ToolCallGuard(clock=clock))

    def boom(*a, **k):
        raise AssertionError("outside dependency used")

    monkeypatch.setattr(time, "monotonic", boom)
    monkeypatch.setattr(time, "time", boom)
    executed(env.run("count", tool_call_id="c").execute())
    source = inspect.getsource(proxy_module)
    assert "import random" not in source and "logging" not in source


def test_proxy_is_internal():
    assert not {"ExecutionProxy", "ProxyRun", "ToolCallGuard"} & set(sentinel.__all__)
    assert not hasattr(sentinel, "ExecutionProxy")
