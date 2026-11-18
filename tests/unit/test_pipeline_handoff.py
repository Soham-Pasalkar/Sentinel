"""I-28 handoff state machine, job wrappers and the K3 in-step check.

Owner decisions 2026-11-18 (decision record §12): I-28, K3. Every
(state, operation) pair is checked, and the worker/caller races are forced
in both orders with barriers.
"""

import asyncio
import threading

import pytest

from sentinel import pipeline as pipeline_module
from sentinel import proxy as proxy_module
from sentinel.pipeline import Pipeline, _Handoff, _JobResult
from sentinel.proxy import _outside_own_step, _task_owner

P = pipeline_module
STATES = (
    P._RUNNING,
    P._ORPHANED,
    P._READY,
    P._TAKEN,
    P._CALLER_CLOSING,
    P._WORKER_EXECUTING,
    P._WORKER_CLOSING,
    P._DONE,
    P._STRANDED,
)
PREPARED = object()  # stands in for a _Prepared; the handoff never inspects it
ERR = "raises"


@pytest.fixture
def open_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


def handoff_in(state, loop):
    h = _Handoff(loop)
    h.state = state
    if state in (P._READY, P._TAKEN, P._CALLER_CLOSING, P._STRANDED):
        h.prepared = PREPARED
    return h


# (operation, state) -> (new state, return value) or ERR. States not listed
# are unchanged and return None.
WORKER_TABLE = {
    "no_claim": {
        P._RUNNING: (P._DONE, None),
        P._ORPHANED: (P._DONE, None),
    },
    "publish": {
        P._RUNNING: (P._READY, True),
        P._ORPHANED: (P._WORKER_CLOSING, False),
    },
    "keep": {
        P._RUNNING: (P._WORKER_EXECUTING, True),
        P._ORPHANED: (P._WORKER_CLOSING, False),
    },
    "worker_done": {
        P._WORKER_EXECUTING: (P._DONE, None),
        P._WORKER_CLOSING: (P._DONE, None),
    },
    "take": {P._READY: (P._TAKEN, PREPARED)},
}
CALLER_TABLE = {
    "leave": {
        P._RUNNING: (P._ORPHANED, None),
        P._READY: (P._CALLER_CLOSING, PREPARED),
    },
    "finalize": {
        P._RUNNING: (P._ORPHANED, None),
        P._READY: (P._STRANDED, PREPARED),
    },
    "finish": {
        P._TAKEN: (P._DONE, None),
        P._CALLER_CLOSING: (P._DONE, None),
    },
}


def call(h, operation):
    if operation == "publish":
        return h.publish(PREPARED)
    if operation == "leave":
        return h.leave(asyncio.CancelledError())
    return getattr(h, operation)()


@pytest.mark.parametrize("state", STATES)
@pytest.mark.parametrize("operation", sorted(WORKER_TABLE))
def test_worker_and_take_operations_in_every_state(operation, state, open_loop):
    h = handoff_in(state, open_loop)
    expected = WORKER_TABLE[operation].get(state, ERR)
    if expected == ERR:
        with pytest.raises(RuntimeError, match=f"handoff: {operation} in state"):
            call(h, operation)
        assert h.state == state  # an illegal call changes nothing
        return
    result = call(h, operation)
    assert (h.state, result) == expected


@pytest.mark.parametrize("state", STATES)
@pytest.mark.parametrize("operation", sorted(CALLER_TABLE))
def test_caller_operations_in_every_state(operation, state, open_loop):
    h = handoff_in(state, open_loop)
    new_state, result = CALLER_TABLE[operation].get(state, (state, None))
    assert call(h, operation) is result
    assert h.state == new_state
    if operation in ("leave", "finalize"):
        assert h.caller_left


def test_publish_after_the_loop_closed_makes_the_worker_close_the_run():
    # H1: nobody can resume a caller on a closed loop.
    loop = asyncio.new_event_loop()
    loop.close()
    h = _Handoff(loop)
    assert h.publish(PREPARED) is False
    assert (h.state, h.interruption) == (P._WORKER_CLOSING, "EventLoopClosed")
    assert h.caller_gone()


def test_leave_records_the_interruption_for_the_worker(open_loop):
    h = _Handoff(open_loop)

    class Stop(BaseException):
        pass

    h.leave(Stop())
    assert (h.state, h.interruption) == (P._ORPHANED, "Stop")
    assert h.caller_gone()


def returns_promptly(fn):
    """Run ``fn`` on a daemon thread; fail (rather than hang) if it blocks."""
    out = []
    t = threading.Thread(target=lambda: out.append(fn()), daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive(), "blocked"
    return out[0]


def test_finalize_never_blocks_on_a_held_lock(open_loop):
    h = handoff_in(P._READY, open_loop)
    with h._lock:  # held, as if by the finalizer's own thread
        assert returns_promptly(h.finalize) is None
    assert h.state == P._READY  # unchanged: the run stays claimed


def test_take_requires_a_published_run(open_loop):
    h = handoff_in(P._READY, open_loop)
    h.prepared = None
    with pytest.raises(RuntimeError):
        h.take()


# --------------------------------------------- forced worker/caller races


def race(worker_first, worker_op, open_loop):
    """Run one worker operation and one ``leave`` in a forced order."""
    h = _Handoff(open_loop)
    first_done = threading.Event()
    out = {}

    def worker():
        if not worker_first:
            assert first_done.wait(5)
        out["worker"] = call(h, worker_op)
        if worker_first:
            first_done.set()

    def caller():
        if worker_first:
            assert first_done.wait(5)
        out["caller"] = h.leave(asyncio.CancelledError())
        if not worker_first:
            first_done.set()

    threads = [threading.Thread(target=worker), threading.Thread(target=caller)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    return h, out


@pytest.mark.parametrize("worker_first", [True, False])
def test_publish_versus_leave_has_exactly_one_closer(worker_first, open_loop):
    h, out = race(worker_first, "publish", open_loop)
    worker_closes = out["worker"] is False
    caller_closes = out["caller"] is PREPARED
    assert worker_closes != caller_closes  # exactly one actor closes the run
    assert caller_closes == worker_first
    assert h.state == (P._CALLER_CLOSING if worker_first else P._WORKER_CLOSING)


@pytest.mark.parametrize("worker_first", [True, False])
def test_keep_versus_leave_never_executes_and_closes(worker_first, open_loop):
    h, out = race(worker_first, "keep", open_loop)
    assert out["caller"] is None  # the caller never closes a sync run
    assert out["worker"] is worker_first  # executes iff it kept it first
    assert h.state == (P._WORKER_EXECUTING if worker_first else P._WORKER_CLOSING)


def test_free_race_publish_versus_leave_always_has_one_closer(open_loop):
    for _ in range(200):
        h = _Handoff(open_loop)
        barrier = threading.Barrier(2)
        out = {}

        def worker(h=h, barrier=barrier, out=out):
            barrier.wait()
            out["worker"] = h.publish(PREPARED)

        def caller(h=h, barrier=barrier, out=out):
            barrier.wait()
            out["caller"] = h.leave(asyncio.CancelledError())

        threads = [threading.Thread(target=worker), threading.Thread(target=caller)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        assert (out["worker"] is False) != (out["caller"] is PREPARED)


# --------------------------------------------------------- job wrappers


class Custom(BaseException):
    pass


KINDS = [
    ValueError("x"),
    Custom(),
    KeyboardInterrupt(),
    SystemExit(3),
    GeneratorExit(),
    asyncio.CancelledError(),
]


@pytest.mark.parametrize("exc", KINDS, ids=lambda e: type(e).__name__)
def test_jobs_return_the_original_exception_object(exc):
    def job():
        raise exc

    result = Pipeline._never_raises(job)
    assert isinstance(result, _JobResult)
    assert result.error is exc


def test_a_job_result_defaults_to_nothing():
    assert _JobResult() == _JobResult(value=None, error=None, prepared=None)


# ------------------------------------------------------- K3 in-step check


def test_inside_the_step_is_not_finalization():
    async def main():
        owner = _task_owner()
        return _outside_own_step(owner)

    assert asyncio.run(main()) is False


def test_another_tasks_step_counts_as_outside():
    async def main():
        owners = []

        async def first():
            owners.append(_task_owner())

        await asyncio.create_task(first())
        return _outside_own_step(owners[0])  # checked from a different Task

    assert asyncio.run(main()) is True


def test_an_unknown_task_counts_as_outside():
    loop = asyncio.new_event_loop()
    try:
        assert _outside_own_step((loop, None)) is True
    finally:
        loop.close()


def test_a_failing_check_counts_as_outside(monkeypatch):
    async def main():
        owner = _task_owner()

        def broken(loop=None):
            raise RuntimeError("teardown")

        monkeypatch.setattr(proxy_module.asyncio, "current_task", broken)
        return _outside_own_step(owner)

    assert asyncio.run(main()) is True


def test_explicit_close_is_classified_as_outside_and_a_raise_as_inside():
    seen = []

    async def coro(raise_it):
        owner = _task_owner()
        try:
            if raise_it:
                raise GeneratorExit
            await asyncio.get_running_loop().create_future()
        except BaseException:
            seen.append(_outside_own_step(owner))
            raise

    with pytest.raises(GeneratorExit):
        asyncio.run(coro(True))
    loop = asyncio.new_event_loop()
    task = loop.create_task(coro(False))
    loop.run_until_complete(asyncio.sleep(0))
    task.get_coro().close()  # an explicit close() outside the Task's step
    task._log_destroy_pending = False  # deliberately abandoned; no GC noise
    loop.close()
    assert seen == [False, True]
