"""K4 (owner 2026-11-18): deferred guard retirement and ``abandon_deferred``.

A finalizer may run on a thread that already holds the guard's lock, so it
only queues the key (``SimpleQueue.put``). The next ``claim`` or ``len``
retires it under the lock, starting the D-31 TTL then: never earlier than the
terminal state, and nothing is evicted.
"""

import threading

import pytest

from sentinel.models import DUPLICATE_TOOL_CALL, GUARD_CAPACITY_EXHAUSTED
from sentinel.proxy import ProxyRun, ToolCallGuard

KEY = ("agent", "session", "call-1")


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def guard(clock, capacity=10):
    return ToolCallGuard(ttl_seconds=300.0, capacity=capacity, clock=clock)


def test_deferred_retirement_waits_for_the_next_guard_operation():
    clock = Clock()
    g = guard(clock)
    assert g.claim(KEY) is None
    g.retire_deferred(KEY)
    assert g._entries[KEY] is None  # still in flight: nothing applied yet
    clock.now = 150.0
    assert len(g) == 1  # ``len`` applies the queue
    assert g._entries[KEY] == 450.0  # TTL starts when applied, not earlier


def test_claim_applies_deferred_retirements_and_the_ttl_still_protects():
    clock = Clock()
    g = guard(clock)
    g.claim(KEY)
    g.retire_deferred(KEY)
    clock.now = 200.0
    assert g.claim(KEY) == DUPLICATE_TOOL_CALL  # terminal, but not expired
    assert g._entries[KEY] == 500.0
    clock.now = 500.0
    assert g.claim(KEY) is None  # expired after the full TTL: claimable again


def test_deferred_retirements_free_capacity_after_the_ttl():
    # Availability: finalized runs do not accumulate (G2).
    clock = Clock()
    g = guard(clock, capacity=3)
    keys = [("a", "s", str(i)) for i in range(3)]
    for k in keys:
        assert g.claim(k) is None
        g.retire_deferred(k)
    assert g.claim(("a", "s", "x")) == GUARD_CAPACITY_EXHAUSTED  # within TTL
    clock.now += 300.0
    assert g.claim(("a", "s", "x")) is None


def test_deferred_retirement_of_an_unknown_or_terminal_key_is_ignored():
    clock = Clock()
    g = guard(clock)
    g.claim(KEY)
    g.retire(KEY)  # terminal at 100 + 300
    g.retire_deferred(KEY)
    g.retire_deferred(("no", "such", "key"))
    clock.now = 250.0
    assert len(g) == 1
    assert g._entries == {KEY: 400.0}


@pytest.mark.parametrize("bad", [float("nan"), 50.0])
def test_an_invalid_clock_keeps_deferred_entries_in_flight(bad):
    clock = Clock()
    g = guard(clock)
    g.claim(KEY)
    g.retire_deferred(KEY)
    clock.now = bad  # invalid, or moved backwards (I-16)
    assert len(g) == 1
    assert g._entries[KEY] is None  # fails closed: never expires
    clock.now = 120.0
    assert len(g) == 1
    assert g._entries[KEY] == 420.0  # applied once the clock is valid again


def returns_promptly(fn):
    """Run ``fn`` on a daemon thread; fail (rather than hang) if it blocks."""
    out = []
    t = threading.Thread(target=lambda: out.append(fn()), daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive(), "blocked"
    return out[0]


def test_retire_deferred_never_takes_the_guard_lock():
    g = guard(Clock())
    g.claim(KEY)
    with g._lock:  # as if the finalizer's thread already held it
        returns_promptly(lambda: g.retire_deferred(KEY))


# ------------------------------------------------------- abandon_deferred


def claimed_run(g):
    g.claim(KEY)
    return ProxyRun(guard=g, guard_key=KEY)


def test_abandon_deferred_abandons_a_claimed_run_without_blocking():
    g = guard(Clock())
    run = claimed_run(g)
    with g._lock:  # the guard lock is held: abandon_deferred must not need it
        assert returns_promptly(run.abandon_deferred) is True
    assert run.state == "not_started"
    assert g._entries[KEY] is None
    assert len(g) == 1 and g._entries[KEY] is not None  # retired when applied


def test_abandon_deferred_refuses_a_busy_or_unclaimed_run():
    g = guard(Clock())
    run = claimed_run(g)
    with run._lock:  # busy: give up rather than block
        assert returns_promptly(run.abandon_deferred) is False
    assert run.state == "claimed"
    run.abandon()
    assert run.abandon_deferred() is False  # not claimed any more


def test_abandon_deferred_without_a_guard_entry():
    run = ProxyRun()
    assert run.abandon_deferred() is True
    assert run.state == "not_started"
