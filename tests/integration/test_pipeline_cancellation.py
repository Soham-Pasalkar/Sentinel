"""I-28 remediation (owner 2026-11-18): caller cancellation, executor failure
and ``BaseException`` handling through the internal async entry.

Decisions tested (decision record §12, 2026-11-18): I-28, I-29 (K2), K1,
K1b, C1.6-I, D-LOG. The invariants established here:

* a claimed run is executed or closed by exactly one actor, never both;
* no SQLite write runs on the event loop except the C1.6 record of an
  async-native tool interrupted after entry (D-20);
* every claimed run's guard entry becomes terminal;
* results stay truthful (``execution``, ``audit_complete``, output withheld);
* a waiting caller receives the original exception object.

Ordering is forced with ``threading.Event`` gates, executor control
(a single busy worker, ``shutdown(cancel_futures=True)``) and
``loop.call_soon_threadsafe``. ``wait_until`` only bounds a wait for work
that another thread finishes; it is never the ordering mechanism.
"""

import asyncio
import concurrent.futures
import functools
import gc
import logging
import random
import threading
import time

import pytest
from pydantic import BaseModel, ConfigDict

from sentinel import pipeline as pipeline_module
from sentinel import proxy as proxy_module
from sentinel.audit import reconstruct
from sentinel.models import Decision, Execution, ToolGrant

WAIT = 10.0


def run_async(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return asyncio.run(fn(*args, **kwargs))

    return wrapper


async def wait_until(predicate, timeout=WAIT):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached in time")
        await asyncio.sleep(0.005)


class CountArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    n: int


class Custom(BaseException):
    pass


def register(env, name, *, sync_fn=None, async_fn=None):
    env.registry.register(
        name,
        arg_schema=CountArgs,
        destructive=False,
        sync_fn=sync_fn,
        async_fn=async_fn,
    )
    env.identity.register_agent(f"{name}_agent", grants=(ToolGrant(tool=name),))
    return {
        "agent_id": f"{name}_agent",
        "session_id": "s",
        "tool": name,
        "arguments": {"n": 1},
        "tool_call_id": f"{name}-call",
    }


def key_of(raw):
    return (raw["agent_id"], raw["session_id"], raw["tool_call_id"])


def guard_terminal(env, key):
    len(env.guard)  # applies any deferred retirement
    return key in env.guard._entries and env.guard._entries[key] is not None


def requests(env):
    out = {}
    for row in env.store.read():
        out.setdefault(row.request_id, []).append(row)
    return out


def only_request(env):
    reqs = requests(env)
    assert len(reqs) == 1
    return next(iter(reqs.values()))


def track_inserts(env):
    seen = []
    real = env.store.insert

    def insert(row):
        seen.append((row.event_type, threading.get_ident()))
        return real(row)

    env.store.insert = insert
    return seen


@pytest.fixture
def handoffs(monkeypatch):
    created = []
    real_init = pipeline_module._Handoff.__init__

    def init(self, loop):
        real_init(self, loop)
        created.append(self)

    monkeypatch.setattr(pipeline_module._Handoff, "__init__", init)
    return created


def gated_detector(env):
    entered, release = threading.Event(), threading.Event()

    class Detector:
        def analyze(self, request, context):
            entered.set()
            assert release.wait(WAIT)
            return ()

    env.pipeline._detector = Detector()
    return entered, release


# ============================================ who closes a claimed run


@run_async
async def test_cancel_before_handover_the_worker_closes_the_run(env, handoffs):
    # T4 then T6: the caller leaves while preparing; the job never executes.
    loop_thread = threading.get_ident()
    inserts = track_inserts(env)
    entered, release = gated_detector(env)
    raw = env.raw("aread_file", tool_call_id="c1")
    task = asyncio.ensure_future(env.pipeline.evaluate_async(raw))
    await wait_until(entered.is_set)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    await wait_until(lambda: handoffs[0].state == pipeline_module._DONE)
    rows = only_request(env)
    assert [r.event_type for r in rows][-2:] == [
        "EXECUTION_STARTED",
        "REQUEST_COMPLETED",
    ]
    assert rows[-1].execution == "not_started" and "CancelledError" in rows[-1].detail
    assert all(t != loop_thread for _, t in inserts)  # nothing on the loop
    assert env.calls["aread"] == 0
    assert guard_terminal(env, key_of(raw))


@run_async
async def test_cancel_after_handover_the_caller_closes_it_off_the_loop(
    env, handoffs, monkeypatch
):
    # T2 then T10: the worker published the run (READY) and the caller is
    # cancelled before it resumes. The caller abandons it; a job records it.
    loop = asyncio.get_running_loop()
    loop_thread = threading.get_ident()
    inserts = track_inserts(env)
    left = threading.Event()
    box = []
    real_publish = pipeline_module._Handoff.publish
    real_leave = pipeline_module._Handoff.leave

    def publish(self, prepared):
        ok = real_publish(self, prepared)
        if ok:
            loop.call_soon_threadsafe(box[0].cancel)
            assert left.wait(WAIT)  # the caller leaves while READY
        return ok

    def leave(self, exc):
        try:
            return real_leave(self, exc)
        finally:
            left.set()

    monkeypatch.setattr(pipeline_module._Handoff, "publish", publish)
    monkeypatch.setattr(pipeline_module._Handoff, "leave", leave)
    raw = env.raw("aread_file", tool_call_id="c2")
    box.append(asyncio.ensure_future(env.pipeline.evaluate_async(raw)))
    with pytest.raises(asyncio.CancelledError):
        await box[0]
    await wait_until(lambda: only_request(env)[-1].event_type == "REQUEST_COMPLETED")
    rows = only_request(env)
    assert [r.event_type for r in rows][-2:] == [
        "EXECUTION_STARTED",
        "REQUEST_COMPLETED",
    ]
    assert rows[-1].execution == "not_started"
    rc_threads = [t for kind, t in inserts if kind == "REQUEST_COMPLETED"]
    assert rc_threads and loop_thread not in rc_threads  # K2: off the loop
    assert handoffs[0].state == pipeline_module._DONE
    assert env.calls["aread"] == 0
    assert guard_terminal(env, key_of(raw))


@run_async
async def test_cancel_during_the_path_recheck_submits_the_record(env, monkeypatch):
    # I-29 / K2: interrupted after EXECUTION_STARTED, before entry.
    loop_thread = threading.get_ident()
    inserts = track_inserts(env)
    entered, release = threading.Event(), threading.Event()
    real = proxy_module.reverify

    def gated(*args):
        entered.set()
        assert release.wait(WAIT)
        return real(*args)

    monkeypatch.setattr(proxy_module, "reverify", gated)
    raw = env.raw("aread_file", tool_call_id="c3")
    task = asyncio.ensure_future(env.pipeline.evaluate_async(raw))
    await wait_until(entered.is_set)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    await wait_until(lambda: only_request(env)[-1].event_type == "REQUEST_COMPLETED")
    rc = only_request(env)[-1]
    assert rc.execution == "not_started" and "CancelledError" in rc.detail
    assert [t for k, t in inserts if k == "REQUEST_COMPLETED"] != [loop_thread]
    assert loop_thread not in [t for _, t in inserts]
    assert env.calls["aread"] == 0
    assert guard_terminal(env, key_of(raw))


@run_async
async def test_cancel_after_entry_writes_the_c16_record_on_the_loop(env):
    # The only SQLite write on the loop (D-20): C1.6, synchronous.
    loop_thread = threading.get_ident()
    started = threading.Event()

    async def slow(n):
        started.set()
        await asyncio.sleep(3600)

    raw = register(env, "slow", async_fn=slow)
    inserts = track_inserts(env)
    task = asyncio.ensure_future(env.pipeline.evaluate_async(raw))
    await wait_until(started.is_set)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    rows = only_request(env)
    assert rows[-1].execution == "unknown"
    on_loop = [k for k, t in inserts if t == loop_thread]
    assert on_loop == ["REQUEST_COMPLETED"]
    assert guard_terminal(env, key_of(raw))


# ======================================== exceptions reach the caller


def first_exception(coro):
    """Run ``coro``; return the exception object at the call boundary."""

    async def main():
        try:
            await coro
        except BaseException as exc:
            return exc
        raise AssertionError("no exception")

    return asyncio.run(main())


KINDS = [
    pytest.param(Custom, id="custom"),
    pytest.param(KeyboardInterrupt, id="KeyboardInterrupt"),
    pytest.param(SystemExit, id="SystemExit"),
    pytest.param(GeneratorExit, id="GeneratorExit"),
    pytest.param(asyncio.CancelledError, id="CancelledError"),
]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("tool", ["aread_file", "read_file"])
def test_tool_base_exceptions_propagate_unchanged(env, kind, tool):
    # C1.6: the original object, the unknown record, a terminal guard entry.
    # A GeneratorExit raised by the tool is not finalization (K3).
    original = kind()
    env.raise_in_tool = original
    loop_threads = []

    async def call():
        loop_threads.append(threading.get_ident())
        return await env.pipeline.evaluate_async(env.raw(tool, tool_call_id="b1"))

    inserts = track_inserts(env)
    assert first_exception(call()) is original
    rc = only_request(env)[-1]
    assert (rc.event_type, rc.execution) == ("REQUEST_COMPLETED", "unknown")
    assert kind.__name__ in rc.detail
    rc_thread = [t for k, t in inserts if k == "REQUEST_COMPLETED"][0]
    assert (rc_thread == loop_threads[0]) is (tool == "aread_file")
    assert env.total_calls() == 1
    assert guard_terminal(env, ("research_agent", "sess-1", "b1"))


@pytest.mark.parametrize("tool", ["aread_file", "read_file"])
def test_filter_base_exception_after_return_records_succeeded(make_env, tool):
    # C1.6-I: the tool returned, so execution is known: succeeded. No output
    # is released and the original exception propagates.
    stop = Custom()

    def failing_filter(output):
        raise stop

    env = make_env(output_filter=failing_filter)
    assert first_exception(env.pipeline.evaluate_async(env.raw(tool))) is stop
    rows = only_request(env)
    assert [r.event_type for r in rows][-2:] == [
        "EXECUTION_STARTED",
        "REQUEST_COMPLETED",
    ]
    assert rows[-1].execution == "succeeded" and "Custom" in rows[-1].detail
    states = reconstruct(env.store.read())
    assert next(iter(states.values())).execution is Execution.SUCCEEDED


@run_async
async def test_detached_base_exception_is_logged_once_and_never_unretrieved(
    env, caplog
):
    loop = asyncio.get_running_loop()
    handled = []
    loop.set_exception_handler(lambda _loop, context: handled.append(context))
    started, release = threading.Event(), threading.Event()

    class Late(BaseException):
        pass

    def late(n):
        started.set()
        assert release.wait(WAIT)
        raise Late("secret-text")

    raw = register(env, "late", sync_fn=late)
    task = asyncio.ensure_future(env.pipeline.evaluate_async(raw))
    await wait_until(started.is_set)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with caplog.at_level(logging.WARNING, logger="sentinel.pipeline"):
        release.set()
        await wait_until(lambda: any("Late" in r.getMessage() for r in caplog.records))
    warnings = [r.getMessage() for r in caplog.records if "Late" in r.getMessage()]
    assert len(warnings) == 1 and "secret-text" not in warnings[0]
    assert only_request(env)[-1].execution == "unknown"
    gc.collect()
    await asyncio.sleep(0)
    assert handled == []
    assert guard_terminal(env, key_of(raw))


# ================================================== K1 and K1b mapping


def run_with_executor(executor, coro_fn):
    async def main():
        asyncio.get_running_loop().set_default_executor(executor)
        return await coro_fn()

    return asyncio.run(main())


@pytest.mark.parametrize("fails", [False, True])
def test_completion_that_cannot_be_submitted_returns_internal_error(env, fails):
    # K1: the tool ran; its completion job cannot be submitted.
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)

    async def closer(n):
        executor.shutdown(wait=False)
        if fails:
            raise ValueError("tool error")
        return n

    raw = register(env, "closer", async_fn=closer)
    r = run_with_executor(executor, lambda: env.pipeline.evaluate_async(raw))
    expected = Execution.FAILED if fails else Execution.SUCCEEDED
    assert (r.decision, r.reason, r.error_code, r.execution) == (
        Decision.ALLOW,
        "INTERNAL_ERROR",
        "INTERNAL_ERROR",
        expected,
    )
    assert (r.output_released, r.output, r.audit_complete) == (False, None, False)
    rows = only_request(env)
    assert rows[-1].event_type == "EXECUTION_STARTED"
    assert next(iter(reconstruct(rows).values())).execution is Execution.UNKNOWN
    assert guard_terminal(env, key_of(raw))


def test_completion_dropped_while_the_caller_waits_returns_internal_error(
    env, monkeypatch
):
    # K1: the completion job is queued behind a busy worker, then dropped.
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    gate = threading.Event()

    async def occupy(n):
        executor.submit(gate.wait, WAIT)  # the only worker is now busy
        return n

    raw = register(env, "occupy", async_fn=occupy)
    real_submit = env.pipeline._submit

    def submit(loop, fn, *args):
        job = real_submit(loop, fn, *args)
        if fn == env.pipeline._complete_job:
            executor.shutdown(wait=False, cancel_futures=True)
            gate.set()
        return job

    monkeypatch.setattr(env.pipeline, "_submit", submit)
    r = run_with_executor(executor, lambda: env.pipeline.evaluate_async(raw))
    assert (r.decision, r.error_code, r.execution, r.audit_complete) == (
        Decision.ALLOW,
        "INTERNAL_ERROR",
        Execution.SUCCEEDED,
        False,
    )
    assert r.output is None
    assert only_request(env)[-1].event_type == "EXECUTION_STARTED"


def test_cancel_while_the_completion_job_is_queued_still_completes(env, monkeypatch):
    # The caller leaves while its completion job waits for a worker; the job
    # is not cancelled with it (shielded) and records the truth.
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    gate = threading.Event()

    async def occupy(n):
        executor.submit(gate.wait, WAIT)
        return n

    raw = register(env, "occupy", async_fn=occupy)
    real_submit = env.pipeline._submit

    def submit(loop, fn, *args):
        job = real_submit(loop, fn, *args)
        if fn == env.pipeline._complete_job:
            asyncio.current_task().cancel()  # delivered at the next await
            loop.call_soon(gate.set)  # the worker frees up after that
        return job

    monkeypatch.setattr(env.pipeline, "_submit", submit)

    async def main():
        asyncio.get_running_loop().set_default_executor(executor)
        try:
            await env.pipeline.evaluate_async(raw)
        except asyncio.CancelledError:
            return "cancelled"

    assert asyncio.run(main()) == "cancelled"  # teardown joins the worker
    rc = only_request(env)[-1]
    assert (rc.event_type, rc.execution) == ("REQUEST_COMPLETED", "succeeded")
    assert guard_terminal(env, key_of(raw))


def test_cancel_while_the_preparation_job_is_queued_the_job_still_closes(env):
    # Shielded: the caller's cancellation does not drop the queued job. It
    # runs later, finds the request ORPHANED, and closes it as not started.
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    gate = threading.Event()

    async def main():
        asyncio.get_running_loop().set_default_executor(executor)
        executor.submit(gate.wait, WAIT)  # the job queues behind this
        task = asyncio.ensure_future(
            env.pipeline.evaluate_async(env.raw("aread_file", tool_call_id="q1"))
        )
        await asyncio.sleep(0)  # the task submits its job, then waits
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        gate.set()

    asyncio.run(main())  # teardown joins the worker, which runs the job
    rows = only_request(env)
    assert rows[-1].event_type == "REQUEST_COMPLETED"
    assert rows[-1].execution == "not_started"
    assert env.calls["aread"] == 0
    assert guard_terminal(env, ("research_agent", "sess-1", "q1"))


def assert_not_accepted(r):
    assert (r.decision, r.reason, r.error_code, r.execution) == (
        None,
        "INTERNAL_ERROR",
        "INTERNAL_ERROR",
        Execution.NOT_STARTED,
    )
    assert (r.output_released, r.audit_complete) == (False, False)
    assert r.request_id


def test_preparation_that_cannot_be_submitted_is_not_accepted(env, monkeypatch):
    # K1b: nothing ran, nothing is written, and no injected callback runs on
    # the loop.
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    executor.shutdown()
    monkeypatch.setattr(
        env.pipeline,
        "_new_request_id",
        lambda: pytest.fail("injected id generator called"),
    )
    monkeypatch.setattr(
        env.pipeline, "_clock", lambda: pytest.fail("injected clock called")
    )
    r = run_with_executor(executor, lambda: env.pipeline.evaluate_async(env.raw()))
    assert_not_accepted(r)
    assert env.store.read() == ()


def test_worker_start_failure_after_queueing_never_executes(env, monkeypatch, handoffs):
    # K1b: submit() queued the job, then could not start a thread. The job
    # later runs in the existing worker, finds the request ORPHANED and
    # closes it as not started, under its own request id.
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    gate = threading.Event()

    def cannot_start():
        raise RuntimeError("can't start new thread")

    async def main():
        asyncio.get_running_loop().set_default_executor(executor)
        executor.submit(gate.wait, WAIT)  # the only worker, now busy
        monkeypatch.setattr(executor, "_adjust_thread_count", cannot_start)
        result = await env.pipeline.evaluate_async(
            env.raw("aread_file", tool_call_id="late")
        )
        gate.set()
        return result

    r = asyncio.run(main())  # teardown joins the worker, which runs the job
    assert_not_accepted(r)
    rows = only_request(env)
    assert r.request_id != rows[0].request_id
    assert rows[-1].event_type == "REQUEST_COMPLETED"
    assert rows[-1].execution == "not_started" and "RuntimeError" in rows[-1].detail
    assert env.calls["aread"] == 0
    assert handoffs[0].state == pipeline_module._DONE
    assert guard_terminal(env, ("research_agent", "sess-1", "late"))


@pytest.mark.parametrize("caller_cancelled", [False, True])
def test_queued_preparation_dropped_before_it_starts(
    env, monkeypatch, caller_cancelled
):
    # K1b: shutdown(cancel_futures=True) drops the queued job. If the caller
    # was also cancelled, its cancellation wins.
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    gate = threading.Event()
    queued = []
    real_submit = env.pipeline._submit

    def submit(loop, fn, *args):
        job = real_submit(loop, fn, *args)
        queued.append(job)
        return job

    monkeypatch.setattr(env.pipeline, "_submit", submit)

    async def main():
        asyncio.get_running_loop().set_default_executor(executor)
        executor.submit(gate.wait, WAIT)
        task = asyncio.ensure_future(env.pipeline.evaluate_async(env.raw()))
        await wait_until(lambda: bool(queued))
        if caller_cancelled:
            task.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        gate.set()
        try:
            return await task
        except asyncio.CancelledError:
            return "cancelled"

    r = asyncio.run(main())
    if caller_cancelled:
        assert r == "cancelled"
    else:
        assert_not_accepted(r)
    assert env.store.read() == ()
    assert env.total_calls() == 0


# =============================================== repetition and teardown


def slow_tools(env):
    started, release = threading.Event(), threading.Event()

    async def aslow(n):
        env.calls["aread"] += 1
        started.set()
        await asyncio.sleep(3600)

    def sslow(n):
        env.calls["read"] += 1
        started.set()
        assert release.wait(WAIT)
        return n

    return (
        started,
        release,
        register(env, "aslow", async_fn=aslow),
        register(env, "sslow", sync_fn=sslow),
    )


@pytest.mark.parametrize("stage", ["prepare", "sync_tool", "async_tool"])
@run_async
async def test_repeated_cancellation_gives_one_completion(env, stage):
    started, release, araw, sraw = slow_tools(env)
    if stage == "prepare":
        started, release = gated_detector(env)
        raw = env.raw("aread_file", tool_call_id="r1")
    else:
        raw = sraw if stage == "sync_tool" else araw
    task = asyncio.ensure_future(env.pipeline.evaluate_async(raw))
    await wait_until(started.is_set)
    for _ in range(3):
        task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    await wait_until(lambda: only_request(env)[-1].event_type == "REQUEST_COMPLETED")
    await asyncio.sleep(0.05)  # no second record may follow
    kinds = [r.event_type for r in only_request(env)]
    assert kinds.count("REQUEST_COMPLETED") == 1
    assert env.total_calls() == (0 if stage == "prepare" else 1)


@pytest.mark.parametrize("stage", ["prepare", "sync_tool", "async_tool"])
def test_asyncio_run_teardown_still_closes_every_request(env, stage):
    # A2/B2 regression: the caller is cancelled by teardown; the job finishes
    # while the default executor is shut down, and records the truth.
    started, release, araw, sraw = slow_tools(env)
    if stage == "prepare":
        started, release = gated_detector(env)
        raw = env.raw("aread_file", tool_call_id="t1")
    else:
        raw = sraw if stage == "sync_tool" else araw

    async def main():
        loop = asyncio.get_running_loop()
        real = loop.shutdown_default_executor

        async def shutdown(*args, **kwargs):
            release.set()  # only after every task was cancelled
            return await real(*args, **kwargs)

        loop.shutdown_default_executor = shutdown
        asyncio.ensure_future(env.pipeline.evaluate_async(raw))
        await wait_until(started.is_set)

    asyncio.run(main())
    rc = only_request(env)[-1]
    assert rc.event_type == "REQUEST_COMPLETED"
    assert (
        rc.execution
        == {
            "prepare": "not_started",
            "sync_tool": "succeeded",
            "async_tool": "unknown",
        }[stage]
    )
    assert guard_terminal(env, key_of(raw))


@run_async
async def test_store_closed_while_a_sync_tool_runs(env):
    started, release, _, raw = slow_tools(env)
    task = asyncio.ensure_future(env.pipeline.evaluate_async(raw))
    await wait_until(started.is_set)
    await asyncio.to_thread(env.store.close)
    release.set()
    r = await task
    assert (r.decision, r.error_code, r.execution) == (
        Decision.ALLOW,
        "AUDIT_UNAVAILABLE",
        Execution.SUCCEEDED,
    )
    assert (r.output_released, r.audit_complete) == (False, False)
    assert "REQUEST_COMPLETED" not in env.events(r.request_id)
    assert guard_terminal(env, key_of(raw))


# ================================================================ stress


@run_async
async def test_seeded_cancellation_stress_keeps_every_invariant(env):
    # Bounded and seeded; asserts invariants only, so any interleaving is a
    # valid run. A backstop for the deterministic tests above.
    loop = asyncio.get_running_loop()
    handled = []
    loop.set_exception_handler(lambda _loop, context: handled.append(context))
    rng = random.Random(20261118)  # noqa: S311 - a seeded test schedule
    tasks = []
    for i in range(300):
        tool = rng.choice(["aread_file", "read_file"])
        task = asyncio.ensure_future(
            env.pipeline.evaluate_async(env.raw(tool, tool_call_id=f"s{i}"))
        )
        tasks.append(task)
        cancel_after = rng.choice([None, 0, 1, 2, 3, 5, 8])
        if cancel_after is not None:
            loop.call_later(cancel_after / 1000, task.cancel)
    await asyncio.gather(*tasks, return_exceptions=True)
    reqs = requests(env)

    def settled():
        current = requests(env)
        return all(
            "REQUEST_COMPLETED" in [r.event_type for r in rows]
            for rows in current.values()
        ) and len(current) == len(reqs)

    await wait_until(settled)
    reqs = requests(env)
    completions = [
        [r for r in rows if r.event_type == "REQUEST_COMPLETED"]
        for rows in reqs.values()
    ]
    assert all(len(c) == 1 for c in completions)  # exactly one each
    executed = sum(c[0].execution != "not_started" for c in completions)
    assert env.total_calls() == executed  # no duplicate or hidden execution
    assert 0 < executed < len(completions)  # both outcomes were exercised
    len(env.guard)
    assert all(v is not None for v in env.guard._entries.values())
    gc.collect()
    await asyncio.sleep(0)
    assert handled == []


# ============================================ stage-specific outcomes (§F)


def test_path_recheck_that_cannot_be_submitted_is_an_internal_error(env, monkeypatch):
    # C-9 / C1.8 rev. 5: an Exception before entry is an internal error, not
    # an interruption; ERROR and REQUEST_COMPLETED are written by a worker.
    loop_threads = []

    def no_thread(*args, **kwargs):
        raise RuntimeError("cannot schedule new futures after shutdown")

    async def main():
        loop_threads.append(threading.get_ident())
        monkeypatch.setattr(proxy_module.asyncio, "to_thread", no_thread)
        return await env.pipeline.evaluate_async(
            env.raw("aread_file", tool_call_id="r9")
        )

    inserts = track_inserts(env)
    r = asyncio.run(main())
    assert (r.decision, r.error_code, r.execution) == (
        None,
        "INTERNAL_ERROR",
        Execution.NOT_STARTED,
    )
    rows = only_request(env)
    assert [x.event_type for x in rows][-2:] == ["ERROR", "REQUEST_COMPLETED"]
    assert rows[-1].decision is None and rows[-1].execution == "not_started"
    assert loop_threads[0] not in [t for _, t in inserts]
    assert env.calls["aread"] == 0
    assert guard_terminal(env, ("research_agent", "sess-1", "r9"))


def test_internal_error_whose_record_cannot_be_submitted(env, monkeypatch):
    # The same, with the executor gone for the closing job too: the result
    # stays truthful and never claims audit completion.
    def no_thread(*args, **kwargs):
        raise RuntimeError("cannot schedule new futures after shutdown")

    real_submit = env.pipeline._submit

    def submit(loop, fn, *args):
        if fn == env.pipeline._internal_error_job:
            raise RuntimeError("cannot schedule new futures after shutdown")
        return real_submit(loop, fn, *args)

    async def main():
        monkeypatch.setattr(proxy_module.asyncio, "to_thread", no_thread)
        monkeypatch.setattr(env.pipeline, "_submit", submit)
        return await env.pipeline.evaluate_async(env.raw("aread_file"))

    r = asyncio.run(main())
    assert (r.decision, r.error_code, r.execution, r.audit_complete) == (
        None,
        "INTERNAL_ERROR",
        Execution.NOT_STARTED,
        False,
    )
    assert only_request(env)[-1].event_type == "EXECUTION_STARTED"


@pytest.mark.parametrize("tool", ["aread_file", "read_file"])
def test_base_exception_during_the_completion_audit_writes_nothing_more(
    env, monkeypatch, tool
):
    # §F row 10: the tool already ended, so nothing is recorded as unknown;
    # the waiting caller receives the original object.
    stop = Custom()

    def broken(prepared, outcome):
        raise stop

    monkeypatch.setattr(env.pipeline, "_complete", broken)
    assert first_exception(env.pipeline.evaluate_async(env.raw(tool))) is stop
    rows = only_request(env)
    assert rows[-1].event_type == "EXECUTION_STARTED"
    assert env.total_calls() == 1


@pytest.mark.parametrize("claimed", [False, True], ids=["before_claim", "after_claim"])
def test_preparation_base_exception_reaches_the_caller(env, handoffs, claimed):
    # §F rows 3-4: before EXECUTION_STARTED nothing executes and no
    # REQUEST_COMPLETED is written; after a claim the run is abandoned.
    stop = Custom()
    if claimed:
        real = env.store.insert

        def insert(row):
            if row.event_type == "EXECUTION_STARTED":
                raise stop
            return real(row)

        env.store.insert = insert
    else:

        class Detector:
            def analyze(self, request, context):
                raise stop

        env.pipeline._detector = Detector()
    raw = env.raw("aread_file", tool_call_id="p1")
    assert first_exception(env.pipeline.evaluate_async(raw)) is stop
    kinds = [r.event_type for r in only_request(env)]
    assert "REQUEST_COMPLETED" not in kinds and "EXECUTION_STARTED" not in kinds
    assert handoffs[0].state == pipeline_module._DONE
    assert env.calls["aread"] == 0
    key = ("research_agent", "sess-1", "p1")
    if claimed:
        assert guard_terminal(env, key)
    else:
        assert key not in env.guard._entries
