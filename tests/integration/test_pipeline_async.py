"""Async pipeline entry (C-11): D-20, D-30, FR-026, NFR-016, SEC-027;
AT-02 (pipeline part), AT-08, AT-09, AT-34; I-27, I-28, I-30.

No async pytest plugin is installed; tests run their coroutine with
``asyncio.run``.
"""

import asyncio
import functools
import threading
import time

import pytest
from pydantic import BaseModel, ConfigDict

import sentinel
from sentinel.audit import reconstruct
from sentinel.models import (
    DUPLICATE_TOOL_CALL,
    Decision,
    Execution,
    SecurityFinding,
    Severity,
    ToolGrant,
)


def run_async(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return asyncio.run(fn(*args, **kwargs))

    return wrapper


class CountArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    n: int


async def wait_until(predicate, timeout=5.0):
    """Bounded wait for work that finishes in another thread."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached in time")
        await asyncio.sleep(0.01)


def track_insert_threads(env):
    threads = []
    real = env.store.insert

    def insert(row):
        threads.append(threading.get_ident())
        return real(row)

    env.store.insert = insert
    return threads


# ======================================================= thread placement


@run_async
async def test_async_tool_runs_on_the_loop_and_blocking_stages_do_not(env):
    loop_thread = threading.get_ident()
    detector_threads, tool_threads = [], []

    class Detector:
        def analyze(self, request, context):
            detector_threads.append(threading.get_ident())
            return ()

    env.pipeline._detector = Detector()
    env.tool_hook = lambda: tool_threads.append(threading.get_ident())
    insert_threads = track_insert_threads(env)
    r = await env.pipeline.evaluate_async(env.raw("aread_file"))
    assert (r.decision, r.execution, r.output) == (
        Decision.ALLOW,
        Execution.SUCCEEDED,
        "hello",
    )
    assert tool_threads == [loop_thread]  # awaited on the caller's loop
    assert detector_threads and loop_thread not in detector_threads
    assert insert_threads and loop_thread not in insert_threads  # SQLite off-loop


@run_async
async def test_path_recheck_for_async_tools_runs_off_the_loop(env, monkeypatch):
    # I-30: the C-10 fix.
    from sentinel import proxy as proxy_module

    loop_thread = threading.get_ident()
    seen = []
    real = proxy_module.reverify

    def spy(*args):
        seen.append(threading.get_ident())
        return real(*args)

    monkeypatch.setattr(proxy_module, "reverify", spy)
    r = await env.pipeline.evaluate_async(env.raw("aread_file"))
    assert r.execution is Execution.SUCCEEDED
    assert seen and loop_thread not in seen


@run_async
async def test_sync_tool_through_the_async_entry_runs_in_a_worker_thread(env):
    loop_thread = threading.get_ident()
    tool_threads = []
    env.tool_hook = lambda: tool_threads.append(threading.get_ident())
    r = await env.pipeline.evaluate_async(env.raw("read_file"))
    assert r.output == "hello"
    assert tool_threads and tool_threads[0] != loop_thread


@run_async
async def test_event_loop_stays_responsive_while_a_stage_blocks(env):
    released = threading.Event()
    waited = []

    class BlockingDetector:
        def analyze(self, request, context):
            waited.append(released.wait(timeout=5))
            return ()

    env.pipeline._detector = BlockingDetector()
    task = asyncio.ensure_future(env.pipeline.evaluate_async(env.raw("aread_file")))
    await asyncio.sleep(0.05)  # the loop runs while the detector blocks
    released.set()
    r = await asyncio.wait_for(task, timeout=5)
    assert waited == [True]  # released by the loop, so it was not on the loop
    assert r.execution is Execution.SUCCEEDED


def test_sync_entry_refuses_an_async_only_tool_without_starting_a_loop(env):
    # I-27: the sync entry never runs a coroutine.
    r = env.pipeline.evaluate(env.raw("aread_file"))
    assert (r.decision, r.error_code, r.execution) == (
        None,
        "INTERNAL_ERROR",
        Execution.NOT_STARTED,
    )
    assert env.calls["aread"] == 0


# ============================================================ cancellation


def _register_slow(env, *, sync=False):
    started, release = threading.Event(), threading.Event()
    calls = []

    async def slow(n):
        calls.append(n)
        started.set()
        await asyncio.sleep(3600)

    def slow_sync(n):
        calls.append(n)
        started.set()
        release.wait(timeout=5)
        return n

    if sync:
        env.registry.register(
            "slow", arg_schema=CountArgs, destructive=False, sync_fn=slow_sync
        )
    else:
        env.registry.register(
            "slow", arg_schema=CountArgs, destructive=False, async_fn=slow
        )
    env.identity.register_agent("slow_agent", grants=(ToolGrant(tool="slow"),))
    raw = {
        "agent_id": "slow_agent",
        "session_id": "s",
        "tool": "slow",
        "arguments": {"n": 1},
    }
    return raw, started, release, calls


@run_async
async def test_cancel_async_tool_mid_execution(env):
    # AT-08: CancelledError reaches the caller; REQUEST_COMPLETED(unknown);
    # no re-execution.
    raw, started, _, calls = _register_slow(env)
    task = asyncio.ensure_future(env.pipeline.evaluate_async(raw))
    await wait_until(started.is_set)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    rid = env.store.read()[0].request_id
    rows = env.rows(rid)
    assert [r.event_type for r in rows][-1] == "REQUEST_COMPLETED"
    assert rows[-1].execution == "unknown" and "CancelledError" in rows[-1].detail
    assert reconstruct(env.store.read())[rid].execution is Execution.UNKNOWN
    await asyncio.sleep(0.05)
    assert calls == [1]


@run_async
async def test_cancel_while_still_evaluating_never_runs_the_tool(env):
    # AT-09: cancelled before entry. The shielded pre-execution call finishes,
    # then the claimed run is abandoned and completed as not_started.
    released = threading.Event()
    in_detector = threading.Event()

    class BlockingDetector:
        def analyze(self, request, context):
            in_detector.set()
            released.wait(timeout=5)
            return ()

    env.pipeline._detector = BlockingDetector()
    task = asyncio.ensure_future(
        env.pipeline.evaluate_async(env.raw("aread_file", tool_call_id="c9"))
    )
    await wait_until(in_detector.is_set)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    released.set()
    rid = env.store.read()[0].request_id
    await wait_until(lambda: "REQUEST_COMPLETED" in env.events(rid))
    rows = env.rows(rid)
    assert [r.event_type for r in rows][-2:] == [
        "EXECUTION_STARTED",
        "REQUEST_COMPLETED",
    ]
    assert rows[-1].execution == "not_started"
    assert env.calls["aread"] == 0
    assert reconstruct(env.store.read())[rid].execution is Execution.NOT_STARTED


@run_async
async def test_cancel_while_a_sync_tool_runs_in_a_thread_audits_the_truth(env):
    # I-28: the thread cannot be stopped; its audit completes when it ends.
    raw, started, release, calls = _register_slow(env, sync=True)
    task = asyncio.ensure_future(env.pipeline.evaluate_async(raw))
    await wait_until(started.is_set)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    rid = env.store.read()[0].request_id
    await wait_until(lambda: "REQUEST_COMPLETED" in env.events(rid))
    rc = env.rows(rid)[-1]
    assert (rc.decision, rc.execution) == ("allow", "succeeded")
    assert calls == [1]


@run_async
async def test_cancellation_is_not_swallowed(env):
    raw, started, _, _ = _register_slow(env)
    task = asyncio.ensure_future(env.pipeline.evaluate_async(raw))
    await wait_until(started.is_set)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert task.cancelled()


# =========================================================== concurrency


@run_async
async def test_one_tool_call_id_executes_once_across_sync_and_async(env):
    # Shared guard: 4 sync threads and 4 async tasks race on one call id.
    loop = asyncio.get_running_loop()
    barrier = threading.Barrier(4)

    def sync_attempt():
        barrier.wait()
        return env.pipeline.evaluate(env.raw("read_file", tool_call_id="race"))

    sync_futures = [loop.run_in_executor(None, sync_attempt) for _ in range(4)]
    async_results = await asyncio.gather(
        *(
            env.pipeline.evaluate_async(env.raw("aread_file", tool_call_id="race"))
            for _ in range(4)
        )
    )
    results = list(async_results) + list(await asyncio.gather(*sync_futures))
    executed = [r for r in results if r.execution is Execution.SUCCEEDED]
    refused = [r for r in results if r.error_code == DUPLICATE_TOOL_CALL]
    assert len(executed) == 1 and len(refused) == 7
    assert env.calls["read"] + env.calls["aread"] == 1


@run_async
async def test_many_concurrent_requests_stay_consistent(env):
    # NFR-016: 8 threads x 200 and 8 tasks x 200 requests.
    loop = asyncio.get_running_loop()

    def worker():
        return [env.pipeline.evaluate(env.raw()) for _ in range(200)]

    threads = [loop.run_in_executor(None, worker) for _ in range(8)]

    async def task_worker():
        return [
            await env.pipeline.evaluate_async(env.raw("aread_file")) for _ in range(200)
        ]

    tasks = [task_worker() for _ in range(8)]
    batches = await asyncio.gather(*threads, *tasks)
    results = [r for batch in batches for r in batch]
    assert len(results) == 3200
    assert all(r.execution is Execution.SUCCEEDED and r.audit_complete for r in results)
    assert len({r.request_id for r in results}) == 3200
    rows = env.store.read()
    assert len(rows) == 3200 * 6
    assert len({row.event_id for row in rows}) == len(rows)
    states = reconstruct(rows)
    assert all(s.execution is Execution.SUCCEEDED for s in states.values())


@run_async
async def test_findings_through_the_async_entry_still_deny(make_env):
    class High:
        def analyze(self, request, context):
            return (
                SecurityFinding(
                    code="PROMPT_INJECTION", severity=Severity.HIGH, evidence="x"
                ),
            )

    env = make_env(detector=High())
    r = await env.pipeline.evaluate_async(env.raw("aread_file"))
    assert (r.decision, r.reason) == (Decision.DENY, "PROMPT_INJECTION")
    assert env.calls["aread"] == 0


# =============================================================== surface


def test_async_entry_is_internal():
    # AT-34 (C-11 part): nothing is exported.
    assert sentinel.__all__ == ["__version__"]
    assert not hasattr(sentinel, "Pipeline")
    assert not hasattr(sentinel, "evaluate_async")
