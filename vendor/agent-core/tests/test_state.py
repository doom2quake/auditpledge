"""Tests for the state store: lifecycle, concurrency, isolation, durability (no GCP)."""

import threading
import time

import pytest

from agent_core.config import BaseSettings
from agent_core.state import StateStore, signature_of


def _store():
    return StateStore.create(BaseSettings(use_in_memory_state=True))


def test_run_lifecycle_and_data():
    store = _store()
    rid = store.start_run(trigger={"kind": "test"})
    assert store.get(rid)["status"] == "started"
    store.set_status(rid, "investigating")
    store.set_data(rid, "impact", {"dollars_lost": 10054})
    store.append(rid, "actions", {"kind": "alert"})
    doc = store.get(rid)
    assert doc["status"] == "investigating"
    assert doc["data"]["impact"]["dollars_lost"] == 10054
    assert doc["actions"] == [{"kind": "alert"}]


def test_guardrail_audit_trail():
    store = _store()
    rid = store.start_run()
    store.record_guardrail(rid, "ACTION_LIMITER", "blocked", "alert: hourly cap")
    trail = store.get(rid)["guardrails"]
    assert len(trail) == 1
    assert trail[0]["name"] == "ACTION_LIMITER"
    assert trail[0]["outcome"] == "blocked"


def test_recurrence_detection():
    store = _store()
    sig = signature_of("revenue", "EMEA", "drop")
    r1 = store.start_run()
    assert store.detect_recurrence(r1, sig) is None  # first sighting
    r2 = store.start_run()
    rec = store.detect_recurrence(r2, sig)
    assert rec is not None
    assert rec["count"] == 2
    assert r1 in rec["prior_run_ids"]


def test_signature_stable():
    assert signature_of("a", "b") == signature_of("a", "b")
    assert signature_of("a", "b") != signature_of("a", "c")


def test_fail_marks_error():
    store = _store()
    rid = store.start_run()
    store.fail(rid, "boom")
    doc = store.get(rid)
    assert doc["status"] == "error"
    assert doc["error"] == "boom"


# --- concurrency -------------------------------------------------------------

def test_slow_mutation_does_not_lose_a_concurrent_write():
    """Deterministic lost-update probe.

    One writer is held inside its read-modify-write while a second writer runs to
    completion. With an unlocked get/modify/set the first writer's `set` lands
    last and silently erases the second entry; the lock (Firestore: the
    transaction) must make the second writer wait instead.
    """
    store = _store()
    rid = store.start_run()
    entered = threading.Event()

    def _slow(doc):
        entered.set()
        time.sleep(0.25)  # the competing writer runs entirely inside this window
        actions = list(doc.get("actions") or [])
        actions.append({"n": "slow"})
        doc["actions"] = actions
        return doc

    t = threading.Thread(target=store._mutate, args=(rid, _slow))
    t.start()
    assert entered.wait(2)
    store.append(rid, "actions", {"n": "fast"})
    t.join()

    names = sorted(a["n"] for a in store.get(rid)["actions"])
    assert names == ["fast", "slow"]


def test_concurrent_appends_do_not_lose_writes():
    """Read-modify-write under threads: every guardrail decision must survive.

    With an unlocked get/modify/set, two threads read the same document and the
    second `set` drops the first thread's entry.
    """
    store = _store()
    rid = store.start_run()
    threads = [
        threading.Thread(target=store.record_guardrail, args=(rid, f"G{i}", "allowed", str(i)))
        for i in range(40)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    trail = store.get(rid)["guardrails"]
    assert len(trail) == 40
    assert {g["name"] for g in trail} == {f"G{i}" for i in range(40)}


def test_concurrent_mixed_mutations_do_not_lose_writes():
    """An append and a set_data racing on the same run must both land."""
    store = _store()
    rid = store.start_run()
    errors: list[str] = []

    def _append(i: int) -> None:
        store.append(rid, "actions", {"n": i})

    def _set(i: int) -> None:
        store.set_data(rid, f"k{i}", i)

    threads = []
    for i in range(30):
        threads.append(threading.Thread(target=_append, args=(i,)))
        threads.append(threading.Thread(target=_set, args=(i,)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    doc = store.get(rid)
    assert not errors
    assert len(doc["actions"]) == 30
    assert len(doc["data"]) == 30


# --- isolation ---------------------------------------------------------------

def test_get_returns_an_isolated_copy():
    """Mutating a nested value from `get()` must not change stored state.

    Firestore serialises the document, so an in-place edit of a returned list
    would never have reached storage there either; a shallow copy made the local
    backend behave differently from production.
    """
    store = _store()
    rid = store.start_run()
    store.append(rid, "actions", {"kind": "alert"})
    doc = store.get(rid)
    doc["actions"].append({"kind": "ghost"})
    doc["data"]["injected"] = True
    fresh = store.get(rid)
    assert fresh["actions"] == [{"kind": "alert"}]
    assert "injected" not in fresh["data"]


def test_list_and_find_return_isolated_copies():
    store = _store()
    sig = signature_of("x")
    rid = store.start_run()
    store.detect_recurrence(rid, sig)
    listed = store.list()[0]
    listed["guardrails"].append({"name": "ghost"})
    assert store.get(rid)["guardrails"] == []


# --- durability --------------------------------------------------------------

class _DeadBackend:
    durable = True

    def ping(self):
        raise RuntimeError("permission denied on collection")


def test_unreachable_backend_is_reported_as_degraded_not_durable():
    store = StateStore.create(BaseSettings(), backend_factory=_DeadBackend)
    assert store.durable is False
    assert store.degraded is True
    assert "permission denied" in store.degraded_reason
    ready = store.readiness()
    assert ready["durable"] is False and ready["degraded"] is True


def test_require_durable_state_fails_closed():
    settings = BaseSettings(require_durable_state=True)
    with pytest.raises(RuntimeError) as exc:
        StateStore.create(settings, backend_factory=_DeadBackend)
    assert "durable state required" in str(exc.value)


def test_explicit_in_memory_is_not_degraded():
    store = _store()
    assert store.degraded is False
    assert store.durable is False
    assert "opt-in" in store.backend_name


def test_backend_is_verified_with_a_real_call():
    """`create` must exercise the backend, not just construct it."""
    calls: list[str] = []

    class _Backend:
        durable = True

        def ping(self):
            calls.append("ping")

    store = StateStore.create(BaseSettings(), backend_factory=_Backend)
    assert calls == ["ping"]
    assert store.durable is True and store.degraded is False
