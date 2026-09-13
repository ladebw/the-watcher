"""The Watcher: decisions, sessions, trace integration and host signals."""

from __future__ import annotations

import dataclasses
import sys

import pytest

from the_watcher import (
    Decision,
    HostSignal,
    Policy,
    PoEWatcher,
    Risk,
    SessionStatus,
)
from the_watcher.exceptions import KillSwitchError, SessionError

from conftest import pid_is_alive, wait_for

SLEEP_SCRIPT = "import time; time.sleep(30)"


@pytest.fixture()
def watcher(tmp_path):
    return PoEWatcher(
        policy=Policy(workspace_root=str(tmp_path)),
        workspace_root=str(tmp_path),
    )


def event_types(watcher: PoEWatcher) -> list[str]:
    return [event.event_type for event in watcher.trace]


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


def test_normal_actions_are_allowed(watcher, workspace):
    evaluation = watcher.evaluate(
        "file_access", "read", str(workspace / "notes.txt")
    )
    assert evaluation.decision is Decision.ALLOW
    assert evaluation.allowed
    assert not watcher.killed


def test_decisions_are_recorded_in_the_trace(watcher, workspace):
    watcher.evaluate("file_access", "read", str(workspace / "notes.txt"))
    watcher.evaluate("network_request", "connect", "https://github.com")

    assert event_types(watcher) == ["policy_decision", "policy_decision"]
    assert all(event.decision == "ALLOW" for event in watcher.trace)


def test_denied_action_is_recorded_and_does_not_kill():
    watcher = PoEWatcher(
        policy=Policy(allowed_domains=["github.com"]),
        workspace_root=".",
    )
    evaluation = watcher.evaluate(
        "network_request", "connect", "https://unknown-domain.example"
    )

    assert evaluation.decision is Decision.DENY
    assert evaluation.blocked
    assert not watcher.killed
    assert event_types(watcher) == ["policy_decision", "denied_action"]
    assert watcher.trace[1].decision == "DENY"


def test_forbidden_file_access_is_denied():
    watcher = PoEWatcher(
        policy=Policy(forbidden_paths=["/etc/shadow"]), workspace_root="."
    )
    evaluation = watcher.evaluate("file_access", "read", "/etc/shadow")

    assert evaluation.decision is Decision.DENY
    assert evaluation.rule == "forbidden_path"
    assert not watcher.killed


def test_unauthorized_network_action_is_denied():
    watcher = PoEWatcher(policy=Policy(allowed_domains=["github.com"]))
    evaluation = watcher.evaluate(
        "network_request", "connect", "https://evil.example/collect"
    )

    assert evaluation.decision is Decision.DENY
    assert evaluation.rule == "domain_not_allowed"


def test_observe_records_events_without_policy_evaluation(watcher):
    event = watcher.observe("file_access", "read", "/workspace/a.txt")

    assert event.event_type == "file_access"
    assert event.decision == "ALLOW"
    assert len(watcher.trace) == 1


def test_record_false_skips_trace_writes(watcher):
    watcher.evaluate("file_access", "read", "/tmp/a", record=False)
    assert len(watcher.trace) == 0


# ---------------------------------------------------------------------------
# Quarantine and escalation
# ---------------------------------------------------------------------------


def test_quarantined_session_escalates_to_kill():
    watcher = PoEWatcher(
        policy=Policy(
            allowed_domains=["github.com"], unknown_domain=Decision.QUARANTINE
        )
    )

    first = watcher.evaluate("network_request", "connect", "https://unknown.example")
    assert first.decision is Decision.QUARANTINE
    assert watcher.quarantined
    assert not watcher.killed

    second = watcher.evaluate("network_request", "connect", "https://other.example")
    assert second.decision is Decision.KILL
    assert second.rule == "quarantine_escalation"
    assert watcher.killed


def test_quarantine_can_be_triggered_manually():
    watcher = PoEWatcher(policy=Policy(forbidden_paths=["/etc/shadow"]))
    watcher.quarantine(reason="OPERATOR_REVIEW")
    assert watcher.quarantined
    assert "quarantine" in event_types(watcher)

    evaluation = watcher.evaluate("file_access", "read", "/etc/shadow")
    assert evaluation.decision is Decision.KILL
    assert watcher.killed


def test_allowed_actions_still_work_while_quarantined(watcher, workspace):
    watcher.quarantine(reason="REVIEW")
    evaluation = watcher.evaluate(
        "file_access", "read", str(workspace / "notes.txt")
    )
    assert evaluation.decision is Decision.ALLOW
    assert not watcher.killed


# ---------------------------------------------------------------------------
# Host signals (sandbox escape interface)
# ---------------------------------------------------------------------------


def test_tamper_signal_triggers_kill(watcher):
    evaluation = watcher.report_signal(
        HostSignal.WATCHER_TAMPER_ATTEMPT, detail="ptrace on watcher pid"
    )

    assert evaluation.decision is Decision.KILL
    assert watcher.killed
    assert "host_signal" in event_types(watcher)
    assert "kill_switch" in event_types(watcher)


@pytest.mark.parametrize(
    "signal",
    [
        HostSignal.HOST_NAMESPACE_ACCESS,
        HostSignal.FORBIDDEN_SYSCALL,
        HostSignal.PRIVILEGE_ESCALATION,
        HostSignal.PROTECTED_FILE_ACCESS,
        HostSignal.MONITOR_DISABLE_ATTEMPT,
        HostSignal.PERSISTENCE_ATTEMPT,
    ],
)
def test_critical_signals_kill(watcher, signal):
    evaluation = watcher.report_signal(signal)
    assert evaluation.decision is Decision.KILL
    assert evaluation.risk is Risk.CRITICAL
    assert watcher.killed


@pytest.mark.parametrize(
    "signal",
    [HostSignal.UNAUTHORIZED_NETWORK, HostSignal.UNEXPECTED_PROCESS_TREE],
)
def test_non_critical_signals_deny_without_killing(watcher, signal):
    evaluation = watcher.report_signal(signal)
    assert evaluation.decision is Decision.DENY
    assert not watcher.killed


def test_unknown_signal_fails_closed(watcher):
    evaluation = watcher.report_signal("SOMETHING_NEW_FROM_A_MONITOR")
    assert evaluation.decision is Decision.DENY
    assert not watcher.killed


def test_signals_are_recorded_before_the_kill_event(watcher):
    watcher.report_signal(HostSignal.FORBIDDEN_SYSCALL, detail="ptrace")
    types = event_types(watcher)
    assert types.index("host_signal") < types.index("kill_switch")


# ---------------------------------------------------------------------------
# Process reporting
# ---------------------------------------------------------------------------


def test_report_process_records_and_enforces_the_limit():
    watcher = PoEWatcher(policy=Policy(max_processes=10))
    evaluation = watcher.report_process(pid=4242, ppid=100, process_count=25)

    assert evaluation.decision is Decision.DENY
    assert evaluation.rule == "max_processes"
    assert "process_creation" in event_types(watcher)
    assert watcher.trace[0].metadata["process_count"] == 25


# ---------------------------------------------------------------------------
# Kill semantics
# ---------------------------------------------------------------------------


def test_kill_blocks_all_future_actions(watcher):
    watcher.kill(reason="SANDBOX_BOUNDARY_VIOLATION")

    evaluation = watcher.evaluate("file_access", "read", "/tmp/anything")
    assert evaluation.decision is Decision.KILL
    assert evaluation.rule == "session_killed"
    assert evaluation.blocked

    second = watcher.evaluate("network_request", "connect", "https://github.com")
    assert second.decision is Decision.KILL


def test_kill_is_recorded_with_reason_and_risk(watcher):
    watcher.kill(reason="SANDBOX_BOUNDARY_VIOLATION")

    kill_events = [e for e in watcher.trace if e.event_type == "kill_switch"]
    assert len(kill_events) == 1
    event = kill_events[0]
    assert event.decision == "KILL"
    assert event.risk == "CRITICAL"
    assert event.reason == "SANDBOX_BOUNDARY_VIOLATION"


def test_kill_is_idempotent(watcher):
    first = watcher.kill(reason="FIRST")
    second = watcher.kill(reason="SECOND")

    assert first is second
    assert watcher.kill_record.reason == "FIRST"
    assert len([e for e in watcher.trace if e.event_type == "kill_switch"]) == 1


def test_kill_requires_a_reason(watcher):
    with pytest.raises(KillSwitchError):
        watcher.kill(reason="")


def test_state_snapshot_reports_the_kill(watcher):
    watcher.kill(reason="REASON")
    state = watcher.state()

    assert state["killed"] is True
    assert state["kill"]["reason"] == "REASON"
    assert state["kill"]["state"] == "ENGAGED"
    assert state["event_count"] == len(watcher.trace)
    assert state["final_hash"] == watcher.trace.final_hash


def test_policy_and_tripwires_are_read_only_properties(watcher):
    with pytest.raises(AttributeError):
        watcher.policy = Policy()  # type: ignore[misc]
    with pytest.raises(AttributeError):
        watcher.tripwires = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


def test_session_lifecycle_records_start_and_end(watcher):
    with watcher.protect([sys.executable, "-c", "print('ok')"]) as session:
        code = session.wait(timeout=60)

    assert code == 0
    assert session.status is SessionStatus.COMPLETED
    assert "session_start" in event_types(watcher)
    assert "session_end" in event_types(watcher)
    assert watcher.verify().valid


def test_session_captures_a_failing_exit_code(watcher):
    with watcher.protect([sys.executable, "-c", "raise SystemExit(3)"]) as session:
        code = session.wait(timeout=60)

    assert code == 3
    assert session.status is SessionStatus.FAILED


def test_session_cleanup_terminates_a_leftover_process(watcher):
    session = watcher.protect([sys.executable, "-c", SLEEP_SCRIPT])
    session.start()
    pid = session.pid
    assert pid is not None
    assert wait_for(lambda: pid_is_alive(pid))

    session.close()

    assert wait_for(lambda: not pid_is_alive(pid), timeout=15)
    assert session.status is SessionStatus.TERMINATED
    assert "process_termination" in event_types(watcher)


def test_session_kill_terminates_the_protected_process(watcher):
    session = watcher.protect([sys.executable, "-c", SLEEP_SCRIPT])
    session.start()
    pid = session.pid
    assert wait_for(lambda: pid_is_alive(pid))

    watcher.kill(reason="TEST_TERMINATION")

    assert wait_for(lambda: not pid_is_alive(pid), timeout=15)
    assert watcher.killed
    session.close()
    assert session.status is SessionStatus.KILLED


def test_kill_switch_terminates_known_children(watcher, spawner_script):
    command, pid_file = spawner_script
    session = watcher.protect(command)
    session.start()

    if not wait_for(pid_file.exists, timeout=20):
        session.close()
        pytest.skip("child process did not start in time")

    child_pid = int(pid_file.read_text().strip())
    assert wait_for(lambda: pid_is_alive(child_pid), timeout=10)

    watcher.kill(reason="CHILD_TREE_TEST", process=session.process)

    assert wait_for(lambda: not pid_is_alive(child_pid), timeout=15)
    session.close()
    assert "kill_switch" in event_types(watcher)
    assert watcher.verify().valid


def test_protect_requires_a_command(watcher):
    with pytest.raises(SessionError):
        watcher.protect([])


def test_starting_a_session_twice_is_rejected(watcher):
    session = watcher.protect([sys.executable, "-c", "print('ok')"])
    session.start()
    with pytest.raises(SessionError):
        session.start()
    session.close()


def test_missing_executable_raises_session_error(watcher):
    session = watcher.protect(["definitely-not-a-real-binary-xyz"])
    with pytest.raises(SessionError):
        session.start()


# ---------------------------------------------------------------------------
# Trace export
# ---------------------------------------------------------------------------


def test_export_trace_seals_and_verifies(watcher, tmp_path):
    watcher.evaluate("file_access", "read", "/tmp/a")
    path = tmp_path / "trace.json"

    watcher.export_trace(str(path))

    assert watcher.trace.sealed
    assert watcher.verify().valid
    assert path.exists()


def test_tampering_after_export_is_detected(watcher, tmp_path):
    watcher.evaluate("file_access", "read", "/tmp/a")
    watcher.evaluate("file_access", "read", "/tmp/b")
    path = tmp_path / "trace.json"
    watcher.export_trace(str(path))

    from the_watcher import TraceVerifier

    assert TraceVerifier().verify_file(str(path)).valid

    # Mutating the trace afterwards invalidates verification.
    watcher.trace.events[0] = dataclasses.replace(
        watcher.trace.events[0], resource="/tmp/tampered"
    )
    assert not watcher.verify().valid
