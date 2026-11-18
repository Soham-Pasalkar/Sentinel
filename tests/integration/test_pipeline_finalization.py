"""Coroutine finalization and interpreter exit (K3, K4, H1; owner 2026-11-18).

Each scenario runs in its own interpreter (deadlock-sensitive, and it leaves
a task destroyed while pending). A pending ``evaluate_async`` task is left on
a closed loop, its worker is joined so nothing keeps the coroutine alive, and
the garbage collector then finalizes it **on another thread that holds the
audit store's lock and the guard's lock**. Before the K3/K4 design this
deadlocked: the finalizer tried to take those locks.

Finalization of a pending task is CPython behaviour (garbage collection
closes the coroutine); the tests are skipped elsewhere. Observed locally on
3.11; CI runs them on 3.11, 3.12 and 3.13.
"""

import json
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.implementation.name != "cpython", reason="relies on CPython finalization"
)

SCRIPT = r"""
import asyncio, concurrent.futures, gc, json, os, sys, threading, time
from pathlib import Path
from pydantic import BaseModel, ConfigDict
from sentinel import pipeline as P, proxy as X
from sentinel.audit import AuditLogger
from sentinel.identity import IdentityStore
from sentinel.models import ToolGrant
from sentinel.pipeline import Pipeline
from sentinel.policy import PolicyEngine, SecurityPolicy
from sentinel.proxy import ExecutionProxy, ToolCallGuard, pass_through_filter
from sentinel.registry import ToolRegistry
from sentinel.store import AuditStore

scenario, tmp = sys.argv[1], Path(sys.argv[2])
WAIT = 20

class Args(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str

ws = tmp / "ws"
ws.mkdir()
(ws / "f.txt").write_text("hi")
entered, release = threading.Event(), threading.Event()
calls = []

async def atool(path):
    calls.append("atool")
    entered.set()
    if scenario == "control":
        raise GeneratorExit  # raised by the tool, inside the step
    await asyncio.get_running_loop().create_future()  # never resolves

def stool(path):
    calls.append("stool")
    entered.set()
    assert release.wait(WAIT)
    return "done"

registry = ToolRegistry()
for name, kw in (("atool", {"async_fn": atool}), ("stool", {"sync_fn": stool})):
    registry.register(
        name, arg_schema=Args, destructive=False, path_args=("path",), **kw
    )
identity = IdentityStore(registry, require_credentials=False)
identity.register_agent(
    "ag",
    grants=tuple(
        ToolGrant(tool=t, allowed_path_prefixes=(str(ws),)) for t in ("atool", "stool")
    ),
)
store = AuditStore(tmp / "audit.db")
guard = ToolCallGuard()
pipe = Pipeline(
    registry=registry,
    identity=identity,
    policy=PolicyEngine(SecurityPolicy(version="t")),
    audit=AuditLogger(store),
    proxy=ExecutionProxy(registry, output_filter=pass_through_filter, guard=guard),
)
raw = {
    "agent_id": "ag",
    "session_id": "s",
    "tool": "stool" if scenario == "exit" else "atool",
    "arguments": {"path": str(ws / "f.txt")},
    "tool_call_id": "k",
}
KEY = ("ag", "s", "k")

handoffs, runs = [], []
published = threading.Event()
real_init, real_publish = P._Handoff.__init__, P._Handoff.publish
real_claim = ExecutionProxy.claim

def init(self, loop):
    real_init(self, loop)
    handoffs.append(self)

def publish(self, prepared):
    ok = real_publish(self, prepared)
    published.set()
    return ok

def claim(self, *args, **kwargs):
    run = real_claim(self, *args, **kwargs)
    runs.append(run)
    return run

P._Handoff.__init__, P._Handoff.publish = init, publish
ExecutionProxy.claim = claim

if scenario == "recheck":
    real_reverify = X.reverify

    def gated(*args):
        entered.set()
        assert release.wait(WAIT)
        return real_reverify(*args)

    X.reverify = gated

if scenario in ("ready", "h1"):
    class Detector:
        def analyze(self, request, context):
            entered.set()
            assert release.wait(WAIT)
            return ()

    pipe._detector = Detector()

executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
loop = asyncio.new_event_loop()
loop.set_default_executor(executor)
task = loop.create_task(pipe.evaluate_async(raw))

def run_until(event):
    async def poll():
        deadline = time.monotonic() + WAIT
        while not event.is_set():
            assert time.monotonic() < deadline
            await asyncio.sleep(0.005)
    loop.run_until_complete(poll())

def events():
    return [[r.event_type, r.execution, r.detail] for r in store.read()]

out = {}
if scenario == "control":
    try:
        loop.run_until_complete(task)
    except GeneratorExit:
        out["raised"] = "GeneratorExit"
    out["guard_terminal_at_once"] = guard._entries[KEY] is not None
elif scenario == "exit":
    run_until(entered)
    loop.close()  # no cancellation, no wait: the worker is still in the tool
    # Runs at interpreter exit, before the executor joins its workers.
    threading._register_atexit(release.set)
    print(json.dumps({"exiting": True}))
    sys.exit(0)
else:
    run_until(entered)
    if scenario == "ready":
        release.set()
        assert published.wait(WAIT)  # READY; the loop never runs again
    loop.close()  # the task stays pending; nothing cancels it
    release.set()
    executor.shutdown(wait=True)  # nothing keeps the coroutine alive now
    task._log_destroy_pending = False
    del task

    def collect():
        with store._lock, guard._lock:  # as if mid-insert and mid-claim
            gc.collect()

    t = threading.Thread(target=collect, name="gc-thread")
    t.start()
    t.join(WAIT)
    if t.is_alive():
        print(json.dumps({"deadlock": True}), flush=True)
        os._exit(3)
    out["guard_in_flight_before_drain"] = guard._entries[KEY] is None
    len(guard)  # applies deferred retirements
out["handoff"] = handoffs[0].state
out["run"] = runs[0].state
out["guard_terminal"] = guard._entries[KEY] is not None
out["events"] = events()
out["calls"] = calls
print(json.dumps(out))
"""


def run_scenario(name, tmp_path):
    proc = subprocess.run(  # noqa: S603 - fixed argv: this interpreter, a literal script
        [sys.executable, "-c", SCRIPT, name, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def kinds(out):
    return [e[0] for e in out["events"]]


def test_finalized_while_ready_strands_the_run_without_blocking(tmp_path):
    # T13: the caller is finalized after the worker published the run.
    out = run_scenario("ready", tmp_path)
    assert out["handoff"] == "stranded"
    assert out["run"] == "not_started"  # abandoned without blocking
    assert out["guard_in_flight_before_drain"] and out["guard_terminal"]
    assert kinds(out)[-1] == "EXECUTION_STARTED"  # no write: reads unknown
    assert out["calls"] == []


def test_finalized_during_the_path_recheck_writes_nothing(tmp_path):
    out = run_scenario("recheck", tmp_path)
    assert (out["handoff"], out["run"]) == ("done", "not_started")
    assert out["guard_in_flight_before_drain"] and out["guard_terminal"]
    assert kinds(out)[-1] == "EXECUTION_STARTED"
    assert out["calls"] == []


def test_finalized_while_the_tool_runs_writes_nothing(tmp_path):
    out = run_scenario("tool", tmp_path)
    assert (out["handoff"], out["run"]) == ("done", "interrupted")
    assert out["guard_in_flight_before_drain"] and out["guard_terminal"]
    assert kinds(out)[-1] == "EXECUTION_STARTED"
    assert out["calls"] == ["atool"]


def test_tool_raised_generator_exit_keeps_the_c16_record(tmp_path):
    # Control: inside the step, so not finalization (K3).
    out = run_scenario("control", tmp_path)
    assert out["raised"] == "GeneratorExit"
    assert out["guard_terminal_at_once"]  # retired at once, not deferred
    assert out["run"] == "interrupted"
    last = out["events"][-1]
    assert last[:2] == ["REQUEST_COMPLETED", "unknown"]
    assert "GeneratorExit" in last[2]


def test_loop_closed_before_publication_the_worker_closes_the_run(tmp_path):
    # H1: the worker sees the closed loop and never hands the run over.
    out = run_scenario("h1", tmp_path)
    assert (out["handoff"], out["run"]) == ("done", "not_started")
    assert not out["guard_in_flight_before_drain"]  # retired by the worker
    last = out["events"][-1]
    assert last[:2] == ["REQUEST_COMPLETED", "not_started"]
    assert "EventLoopClosed" in last[2]
    assert out["calls"] == []


def test_interpreter_exit_lets_the_worker_audit_the_sync_tool(tmp_path):
    # The loop is closed while a sync tool runs; at interpreter exit the
    # executor joins its worker, which completes the audit truthfully.
    out = run_scenario("exit", tmp_path)
    assert out == {"exiting": True}
    import sqlite3

    with sqlite3.connect(tmp_path / "audit.db") as conn:
        last = conn.execute(
            "SELECT event_type, execution FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
    assert last == ("REQUEST_COMPLETED", "succeeded")
