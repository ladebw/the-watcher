"""The kill switch: state, termination and trace preservation."""

from __future__ import annotations

import sys

import pytest

from the_watcher import (
    GENESIS_HASH,
    Decision,
    KillState,
    KillSwitch,
    PoEWatcher,
    SessionStatus,
)
from the_watcher.exceptions import KillSwitchError
from the_watcher.runtime import LocalProcess

from conftest import pid_is_alive, wait_for

SLEEP_SCRIPT = "import time; time.sleep(30)"


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------


def test_initial_state_is_armed(clock):
    switch = KillSwitch(clock=clock)
    assert switch.state is KillState.ARMED
    assert switch.armed
    assert not switch.engaged
    assert switch.record is None
    assert switch.reason is None


def test_engage_flips_state_and_records_the_reason(clock):
    switch = KillSwitch(clock=clock)
    record = switch.engage(reason="SANDBOX_BOUNDARY_VIOLATION")

    assert switch.state is KillState.ENGAGED
    assert switch.engaged
    assert not switch.armed
    assert record.reason == "SANDBOX_BOUNDARY_VIOLATION"
    assert record.triggered_at == 1_760_000_000
    assert switch.reason == "SANDBOX_BOUNDARY_VIOLATION"


def test_engage_requires_a_reason(clock):
    switch = KillSwitch(clock=clock)
    with pytest.raises(KillSwitchError):
        switch.engage(reason="   ")
    assert switch.armed


def test_engage_is_idempotent(clock):
    switch = KillSwitch(clock=clock)
    first = switch.engage(reason="FIRST")
    second = switch.engage(reason="SECOND")

    assert first is second
    assert switch.reason == "FIRST"


def test_assert_armed_raises_after_engagement(clock):
    switch = KillSwitch(clock=clock)
    switch.assert_armed()
    switch.engage(reason="DONE")
    with pytest.raises(KillSwitchError):
        switch.assert_armed()


def test_describe_reports_armed_state(clock):
    switch = KillSwitch(clock=clock)
    described = switch.describe()
    assert described == {"state": "ARMED", "reason": None, "triggered_at": None}


def test_describe_reports_engaged_state(clock):
    switch = KillSwitch(clock=clock)
    switch.engage(reason="REASON")
    described = switch.describe()

    assert described["state"] == "ENGAGED"
    assert described["reason"] == "REASON"
    assert described["triggered_at"] == 1_760_000_000
    assert described["triggering_event_hash"] is None


def test_engage_without_target_records_empty_termination(clock):
    switch = KillSwitch(clock=clock)
    assert switch.engage(reason="NO_TARGET").termination == {}


def test_engage_is_safe_for_a_non_terminable_target(clock):
    switch = KillSwitch(clock=clock)
    record = switch.engage(reason="WEIRD_TARGET", target=object())
    assert "error" in record.termination
    assert record.termination["terminated"] == []
    assert switch.engaged


# ---------------------------------------------------------------------------
# Process termination
# ---------------------------------------------------------------------------


def test_engage_terminates_the_target_process(clock):
    process = LocalProcess([sys.executable, "-c", SLEEP_SCRIPT])
    pid = process.start()
    assert wait_for(lambda: pid_is_alive(pid))

    record = KillSwitch(clock=clock).engage(reason="REAL_TERMINATION", target=process)

    assert wait_for(lambda: not pid_is_alive(pid), timeout=15)
    assert record.termination.get("method") != "already_exited"
    assert record.termination.get("terminated")


def test_engage_on_an_already_exited_process_is_clean(clock):
    process = LocalProcess([sys.executable, "-c", "pass"])
    process.start()
    process.wait(timeout=60)

    record = KillSwitch(clock=clock).engage(reason="LATE", target=process)
    assert record.termination["method"] == "already_exited"


def test_terminate_tree_is_idempotent():
    process = LocalProcess([sys.executable, "-c", SLEEP_SCRIPT])
    process.start()

    first = process.terminate_tree()
    second = process.terminate_tree()

    assert first.pid == second.pid
    assert second.method in {"already_exited", "process_group", "taskkill_tree", "root_kill"}


# ---------------------------------------------------------------------------
# Trace integration
# ---------------------------------------------------------------------------


def test_kill_event_starts_the_chain_when_it_is_first():
    watcher = PoEWatcher()
    watcher.kill(reason="FIRST")

    event = watcher.trace[0]
    assert event.event_type == "kill_switch"
    assert event.decision == "KILL"
    assert event.risk == "CRITICAL"
    assert event.previous_hash == GENESIS_HASH
    assert event.verify_hash()


def test_kill_event_links_to_the_previous_event():
    watcher = PoEWatcher()
    watcher.evaluate("file_access", "read", "/tmp/a")
    watcher.kill(reason="SECOND")

    assert len(watcher.trace) == 2
    kill_event = watcher.trace[1]
    assert kill_event.event_type == "kill_switch"
    assert kill_event.previous_hash == watcher.trace[0].event_hash
    assert watcher.verify().valid


def test_kill_event_is_preserved_after_further_attempts():
    watcher = PoEWatcher()
    watcher.kill(reason="PRESERVE_ME")

    watcher.evaluate("file_access", "read", "/tmp/a")
    watcher.evaluate("network_request", "connect", "https://github.com")

    kill_events = [e for e in watcher.trace if e.event_type == "kill_switch"]
    assert len(kill_events) == 1
    assert kill_events[0].reason == "PRESERVE_ME"
    assert watcher.verify().valid


def test_double_kill_writes_a_single_chain_event():
    watcher = PoEWatcher()
    watcher.kill(reason="FIRST")
    watcher.kill(reason="SECOND")

    assert len([e for e in watcher.trace if e.event_type == "kill_switch"]) == 1


def test_sealed_trace_still_verifies_after_a_kill():
    watcher = PoEWatcher()
    watcher.evaluate("file_access", "read", "/tmp/a")
    watcher.kill(reason="SEALED")
    watcher.seal()

    assert watcher.trace.declared_final_hash is not None
    assert watcher.verify().valid


# ---------------------------------------------------------------------------
# Watcher + session integration
# ---------------------------------------------------------------------------


def test_watcher_kill_terminates_the_session_process():
    watcher = PoEWatcher()
    session = watcher.protect([sys.executable, "-c", SLEEP_SCRIPT])
    session.start()
    pid = session.pid
    assert wait_for(lambda: pid_is_alive(pid))

    record = watcher.kill(reason="SESSION_TERMINATION")

    assert wait_for(lambda: not pid_is_alive(pid), timeout=15)
    assert record.reason == "SESSION_TERMINATION"
    assert watcher.killed


def test_kill_preserves_the_trace_after_the_session_closes():
    watcher = PoEWatcher()
    session = watcher.protect([sys.executable, "-c", SLEEP_SCRIPT])
    session.start()

    watcher.kill(reason="PRESERVE")
    session.close()

    assert session.status is SessionStatus.KILLED
    types = [event.event_type for event in watcher.trace]
    assert "kill_switch" in types
    assert "session_end" in types
    assert watcher.verify().valid


def test_killed_watcher_refuses_to_start_a_new_session():
    watcher = PoEWatcher()
    watcher.kill(reason="ALREADY_DEAD")

    session = watcher.protect([sys.executable, "-c", "print('nope')"])
    with pytest.raises(KillSwitchError):
        session.start()


def test_killed_session_blocks_every_subsequent_decision():
    watcher = PoEWatcher()
    watcher.kill(reason="BLOCK_EVERYTHING")

    for event_type, action, resource in (
        ("file_access", "read", "/tmp/a"),
        ("network_request", "connect", "https://github.com"),
        ("tool_request", "invoke", "search"),
    ):
        evaluation = watcher.evaluate(event_type, action, resource)
        assert evaluation.decision is Decision.KILL
        assert evaluation.rule == "session_killed"

    assert watcher.verify().valid


def test_kill_record_is_exposed_for_a_control_plane():
    watcher = PoEWatcher()
    watcher.evaluate("file_access", "read", "/tmp/a")
    triggering_event = watcher.trace[0]
    watcher.kill(reason="CONTROL_PLANE", triggering_event=triggering_event)

    payload = watcher.kill_record.to_dict()
    assert payload["reason"] == "CONTROL_PLANE"
    assert payload["state"] == "ENGAGED"
    assert payload["triggering_event_hash"] == triggering_event.event_hash
    assert "read" in payload["triggering_event_summary"]


def test_kill_record_without_a_triggering_event_has_no_hash():
    watcher = PoEWatcher()
    watcher.kill(reason="OPERATOR")

    payload = watcher.kill_record.to_dict()
    assert payload["triggering_event_hash"] is None
    assert payload["triggering_event_summary"] is None
