"""V2 end-to-end: an external supervisor and a real IPC-protected process."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from the_watcher import Decision, Policy, Tripwire
from the_watcher.ipc.server import ClientContext
from the_watcher.ipc.transport import create_endpoint
from the_watcher.supervisor import SessionState, SupervisoryAction

from conftest import PROJECT_ROOT, pid_is_alive, wait_for


def ctx(**overrides) -> ClientContext:
    base = {
        "session_id": "test-session",
        "connection_id": "test-connection",
        "authenticated": True,
    }
    base.update(overrides)
    return ClientContext(**base)


def events(harness, event_type: str):
    return harness.events_of(event_type)


# ---------------------------------------------------------------------------
# 1-2. Startup order and IPC configuration
# ---------------------------------------------------------------------------


def test_supervisor_starts_before_the_protected_process(harness_factory):
    harness = harness_factory("normal")
    assert harness.wait(timeout=60) == 0

    types = harness.event_types()
    assert types.index("session_created") < types.index("ipc_ready")
    assert types.index("ipc_ready") < types.index("process_started")
    assert types.index("process_started") < types.index("client_connected")

    daemon = harness.daemon
    assert daemon.process.pid is not None
    assert daemon.storage.root
    assert daemon.internal_error == ""


def test_protected_process_is_a_child_of_the_supervisor(harness_factory):
    harness = harness_factory("normal")
    assert harness.wait_until_running(), "session should start"
    supervisor_pid = os.getpid()
    child_pid = harness.daemon.process.pid
    assert child_pid and child_pid != supervisor_pid
    harness.wait(timeout=60)


def test_protected_process_receives_valid_ipc_configuration(harness_factory):
    harness = harness_factory("normal")
    assert harness.wait_until_running()

    env = harness.daemon._child_environment()
    for key in (
        "WATCHER_SESSION_ID",
        "WATCHER_IPC_ENDPOINT",
        "WATCHER_SESSION_TOKEN",
        "WATCHER_PROTOCOL_VERSION",
        "WATCHER_IPC_FAMILY",
        "WATCHER_FAIL_MODE",
    ):
        assert key in env, f"protected process is missing {key}"

    assert env["WATCHER_SESSION_ID"] == harness.daemon.session_id
    assert env["WATCHER_PROTOCOL_VERSION"] == "1"

    # The agent proved the configuration works by authenticating.
    assert harness.wait(timeout=60) == 0
    assert events(harness, "client_authenticated")


def test_protected_process_does_not_receive_supervisor_internals(harness_factory):
    """Policy, storage and tripwire configuration must never be handed over."""
    harness = harness_factory("normal")
    assert harness.wait_until_running()

    # The same check applies to what a *nested* session would inherit.
    env = harness.daemon._child_environment()
    for forbidden in (
        "WATCHER_HOME",
        "WATCHER_STORAGE_ROOT",
        "WATCHER_TRACE_OUT",
        "WATCHER_POLICY_KEY",
        "WATCHER_KILL_TOKEN",
        "WATCHER_POE_KEY",
        "WATCHER_POLICY",
        "WATCHER_TRIPWIRES",
    ):
        assert forbidden not in env, f"{forbidden} must not reach the child"

    # And no path to the authoritative trace.
    assert harness.daemon.storage.root not in json.dumps(env)
    harness.wait(timeout=60)


def test_child_environment_strips_inherited_watcher_variables(tmp_path, monkeypatch):
    from the_watcher.supervisor import DaemonConfig, WatcherDaemon

    monkeypatch.setenv("WATCHER_HOME", "/somewhere/secret")
    monkeypatch.setenv("WATCHER_KILL_TOKEN", "inherited-token")
    monkeypatch.setenv("WATCHER_SESSION_TOKEN", "stale-token")

    daemon = WatcherDaemon(
        DaemonConfig(
            command=[sys.executable, "-c", "pass"],
            storage_root=str(tmp_path / "home"),
            cwd=str(PROJECT_ROOT),
        )
    )
    daemon._prepare()
    daemon._endpoint = create_endpoint(daemon.session_id)

    env = daemon._child_environment()
    assert env["WATCHER_SESSION_TOKEN"] != "stale-token"
    assert "WATCHER_HOME" not in env
    assert "WATCHER_KILL_TOKEN" not in env


def test_child_env_extras_cannot_override_the_session_connection(tmp_path):
    """Explicit pass-through must not be able to break or hijack authentication."""
    from the_watcher.supervisor import DaemonConfig, WatcherDaemon

    daemon = WatcherDaemon(
        DaemonConfig(
            command=[sys.executable, "-c", "pass"],
            storage_root=str(tmp_path / "home"),
            cwd=str(PROJECT_ROOT),
            child_env={
                "WATCHER_SESSION_TOKEN": "attacker-supplied",
                "WATCHER_SESSION_ID": "attacker-session",
                "WATCHER_IPC_ENDPOINT": r"\\.\pipe\attacker",
                "AGENT_MODE": "normal",
            },
        )
    )
    daemon._prepare()
    daemon._endpoint = create_endpoint(daemon.session_id)

    env = daemon._child_environment()
    assert env["WATCHER_SESSION_TOKEN"] == daemon._token
    assert env["WATCHER_SESSION_ID"] == daemon.session_id
    assert env["WATCHER_IPC_ENDPOINT"] == daemon._endpoint.address
    assert env["AGENT_MODE"] == "normal"


# ---------------------------------------------------------------------------
# 12-15. Authoritative policy outcomes
# ---------------------------------------------------------------------------


def test_policy_executes_only_in_the_supervisor(harness_factory):
    harness = harness_factory(
        "forbidden", policy=Policy(forbidden_paths=["/etc/shadow"])
    )
    assert harness.wait(timeout=60) == 0

    decisions = events(harness, "policy_decision")
    assert decisions, "the daemon must record its own policy decision"
    denial = [event for event in decisions if event.decision == "DENY"]
    assert denial, "the daemon must have denied the forbidden read"
    assert denial[0].reason.startswith("path is forbidden by policy")
    assert events(harness, "denied_action")


def test_allow_is_returned_to_the_protected_process(harness_factory):
    harness = harness_factory("normal")
    assert harness.wait(timeout=60) == 0

    decisions = events(harness, "policy_decision")
    assert decisions
    assert all(event.decision == "ALLOW" for event in decisions)
    assert len(decisions) >= 2


def test_deny_is_returned_to_the_protected_process(harness_factory):
    harness = harness_factory(
        "custom",
        policy=Policy(forbidden_paths=["/etc/shadow"]),
        child_env={
            "WATCHER_AGENT_EVENT": "file_access",
            "WATCHER_AGENT_ACTION": "read",
            "WATCHER_AGENT_RESOURCE": "/etc/shadow",
        },
    )
    assert harness.wait(timeout=60) == 0
    assert not harness.daemon.killed
    assert harness.daemon.state is SessionState.COMPLETED

    denial = [e for e in events(harness, "policy_decision") if e.decision == "DENY"]
    assert denial and denial[0].risk == "HIGH"


def test_quarantine_updates_the_session_state(harness_factory):
    harness = harness_factory(
        "custom",
        policy=Policy(
            allowed_domains=["github.com"], unknown_domain=Decision.QUARANTINE
        ),
        child_env={
            "WATCHER_AGENT_EVENT": "network_request",
            "WATCHER_AGENT_ACTION": "connect",
            "WATCHER_AGENT_RESOURCE": "https://unknown.example/exfil",
            "WATCHER_AGENT_LINGER": "0.2",
        },
    )
    assert harness.wait(timeout=60) == 0

    daemon = harness.daemon
    assert events(harness, "quarantine"), "quarantine must be recorded"
    assert daemon.watcher.quarantined

    decisions = events(harness, "policy_decision")
    assert any(e.decision == "QUARANTINE" for e in decisions)

    # Quarantine must be reflected in the session state machine, not only in
    # the trace. The history is the durable evidence, since the process then
    # finishes and the session moves on to a terminal state.
    states = [entry["state"] for entry in daemon.state_snapshot()["history"]]
    assert "QUARANTINED" in states
    assert "COMPLETED" in states
    assert "KILLED" not in states

    # The process was preserved for inspection rather than killed.
    assert not daemon.killed


# ---------------------------------------------------------------------------
# 16-21. External kill authority
# ---------------------------------------------------------------------------


def test_kill_triggers_in_the_external_supervisor(harness_factory):
    harness = harness_factory("tripwire", child_env={"WATCHER_AGENT_LINGER": "2"})
    assert harness.wait(timeout=60) == 137

    daemon = harness.daemon
    assert daemon.killed
    assert daemon.state is SessionState.KILLED
    assert events(harness, "tripwire_activation")
    assert events(harness, "kill_switch")
    assert events(harness, "process_termination")

    record = daemon.watcher.kill_record
    assert record.reason == "TRIPWIRE:fake_root_token"
    assert record.triggering_event_hash


def test_kill_terminates_the_protected_process(harness_factory):
    harness = harness_factory("tripwire", child_env={"WATCHER_AGENT_LINGER": "5"})
    assert harness.wait_until_running()
    pid = harness.daemon.process.pid
    assert pid is not None
    assert wait_for(lambda: pid_is_alive(pid), timeout=20)

    assert harness.wait(timeout=60) == 137
    assert wait_for(lambda: not pid_is_alive(pid), timeout=15)


def test_kill_records_termination_metrics(harness_factory):
    harness = harness_factory("tripwire", child_env={"WATCHER_AGENT_LINGER": "2"})
    assert harness.wait(timeout=60) == 137

    termination = events(harness, "process_termination")[0]
    meta = dict(termination.metadata)
    for field in (
        "kill_started",
        "termination_method",
        "descendant_count",
        "grace_period",
        "forced_termination",
        "termination_result",
    ):
        assert field in meta, f"missing kill metric: {field}"
    assert meta["termination_method"]
    assert "terminated" in meta["termination_result"]


def test_child_processes_are_terminated_with_the_tree(harness_factory, tmp_path):
    pid_file = tmp_path / "child.pid"
    harness = harness_factory(
        "tree",
        child_env={
            "WATCHER_AGENT_PIDFILE": str(pid_file),
            "WATCHER_AGENT_SLEEP": "30",
        },
    )
    assert harness.wait_until_running()

    if not wait_for(pid_file.exists, timeout=25):
        harness.stop("TEST_NO_CHILD")
        harness.wait(timeout=30)
        pytest.skip("child process did not start in time")

    child_pid = int(pid_file.read_text().strip())
    assert wait_for(lambda: pid_is_alive(child_pid), timeout=10)

    harness.daemon.stop("CHILD_TREE_TEST")
    assert harness.wait(timeout=60) == 137

    assert wait_for(lambda: not pid_is_alive(child_pid), timeout=20)
    assert harness.daemon.verify().valid


def test_kill_state_is_irreversible(harness_factory):
    harness = harness_factory("tripwire", child_env={"WATCHER_AGENT_LINGER": "1"})
    assert harness.wait(timeout=60) == 137
    daemon = harness.daemon

    original = daemon.watcher.kill_record.to_dict()
    for _ in range(3):
        daemon.stop("SECOND_ATTEMPT")

    assert daemon.state is SessionState.KILLED
    assert daemon.watcher.kill_record.to_dict()["reason"] == original["reason"]
    assert len(events(harness, "kill_switch")) == 1


def test_protected_process_cannot_reset_kill_state_through_ipc(harness_factory):
    """No IPC message may move a killed session back to a usable state."""
    harness = harness_factory("tripwire", child_env={"WATCHER_AGENT_LINGER": "1"})
    assert harness.wait(timeout=60) == 137
    daemon = harness.daemon
    context = ctx(session_id=daemon.session_id)

    # A kill request cannot un-kill or re-trigger.
    reply = daemon.dispatch("KILL_REQUEST", {"reason": "please stop"}, context)
    assert reply["already_killed"] is True
    assert reply["killed"] is True
    assert daemon.state is SessionState.KILLED

    # An evaluate is answered with KILL, never ALLOW.
    reply = daemon.dispatch(
        "EVALUATE",
        {"event_type": "file_access", "action": "read", "resource": "/tmp/x"},
        context,
    )
    assert reply["decision"] == "KILL"
    assert reply["killed"] is True

    # A client cannot fabricate its way out either.
    reply = daemon.dispatch(
        "EVALUATE",
        {
            "event_type": "file_access",
            "action": "read",
            "resource": "/tmp/x",
            "decision": "ALLOW",
            "risk": "NORMAL",
            "sequence": 0,
        },
        context,
    )
    assert reply["decision"] == "KILL"
    assert len(events(harness, "kill_switch")) == 1


def test_trace_remains_valid_after_a_kill(harness_factory, tmp_path):
    harness = harness_factory(
        "tripwire",
        child_env={"WATCHER_AGENT_LINGER": "2"},
        trace_out=str(tmp_path / "exported.json"),
    )
    assert harness.wait(timeout=60) == 137

    daemon = harness.daemon
    result = daemon.trace.verify()
    assert result.valid, result.signals
    assert daemon.trace.sealed
    assert daemon.trace.to_dict()["final_hash"] == daemon.trace.final_hash


# ---------------------------------------------------------------------------
# 19-24. Storage, timeouts and heartbeats
# ---------------------------------------------------------------------------


def test_trace_storage_is_outside_the_protected_cwd(harness_factory):
    from the_watcher.supervisor import SessionStorage

    harness = harness_factory("normal")
    assert harness.wait(timeout=60) == 0

    daemon = harness.daemon
    assert SessionStorage.is_outside(daemon.storage.root, str(PROJECT_ROOT))
    assert Path(daemon.paths.trace_path).exists()
    assert Path(daemon.paths.metadata_path).exists()
    # The trace is not inside the sandbox's working directory.
    assert PROJECT_ROOT not in Path(daemon.paths.trace_path).parents


def test_storage_inside_the_cwd_is_refused(tmp_path):
    from the_watcher.supervisor import DaemonConfig, WatcherDaemon

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    daemon = WatcherDaemon(
        DaemonConfig(
            command=[sys.executable, "-c", "pass"],
            cwd=str(sandbox),
            storage_root=str(sandbox / ".watcher"),
        )
    )
    exit_code = daemon.run()
    assert exit_code != 0
    assert "StorageError" in daemon.internal_error
    assert daemon.state is SessionState.FAILED


def test_session_timeout_kills_the_process(harness_factory):
    harness = harness_factory(
        "heartbeat",
        child_env={"WATCHER_AGENT_SLEEP": "30"},
        session_timeout=0.8,
    )
    assert harness.wait(timeout=60) == 137

    assert harness.daemon.state is SessionState.KILLED
    assert events(harness, "session_timeout")
    record = harness.daemon.watcher.kill_record
    assert record.reason == "MAX_RUNTIME_EXCEEDED"


def test_heartbeat_timeout_is_detected(harness_factory):
    harness = harness_factory(
        "heartbeat",
        # The client is asked to stay silent, so the supervisor notices.
        child_env={"WATCHER_AGENT_SLEEP": "3", "AGENT_SILENT_HEARTBEAT": "1"},
        heartbeat_interval=0.2,
        heartbeat_timeout=0.6,
        heartbeat_action=SupervisoryAction.RECORD,
        session_timeout=2.5,
    )
    assert harness.wait(timeout=60) == 137

    lost = events(harness, "heartbeat_lost")
    assert lost, "a silent client must be detected"
    assert lost[0].risk == "HIGH"
    assert lost[0].metadata["heartbeats_received"] == 0


def test_heartbeat_can_be_configured_to_quarantine(harness_factory):
    harness = harness_factory(
        "heartbeat",
        child_env={"WATCHER_AGENT_SLEEP": "4", "AGENT_SILENT_HEARTBEAT": "1"},
        heartbeat_interval=0.2,
        heartbeat_timeout=0.6,
        heartbeat_action=SupervisoryAction.QUARANTINE,
        session_timeout=2.0,
    )
    assert harness.wait(timeout=60) == 137

    assert events(harness, "heartbeat_lost")
    assert events(harness, "quarantine")
    assert harness.daemon.watcher.quarantined
    # Quarantine did not kill by itself; the session timeout did.
    kill_reason = harness.daemon.watcher.kill_record.reason
    assert kill_reason == "MAX_RUNTIME_EXCEEDED"


def test_healthy_heartbeat_is_not_reported_as_lost(harness_factory):
    harness = harness_factory(
        "heartbeat",
        child_env={"WATCHER_AGENT_SLEEP": "1.2"},
        heartbeat_interval=0.2,
        heartbeat_timeout=5.0,
    )
    assert harness.wait(timeout=60) == 0
    assert events(harness, "heartbeat_lost") == []


def test_ipc_lost_is_recorded_when_a_client_vanishes(harness_factory):
    harness = harness_factory(
        "crash", child_env={"WATCHER_AGENT_SLEEP": "5"}
    )
    exit_code = harness.wait(timeout=60)
    assert exit_code == 9

    assert events(harness, "client_disconnected")
    assert events(harness, "ipc_lost")
    assert harness.daemon.verify().valid


def test_ipc_lost_action_can_kill(harness_factory):
    harness = harness_factory(
        "crash",
        ipc_lost_action=SupervisoryAction.KILL,
        child_env={"WATCHER_AGENT_SLEEP": "20"},
    )
    exit_code = harness.wait(timeout=60)
    # Either the crash exit code or the kill code is acceptable, depending on
    # whether the disconnect was noticed before the process was reaped.
    assert exit_code in (9, 137)
    assert events(harness, "ipc_lost")


# ---------------------------------------------------------------------------
# 25-29. Exit outcomes and robustness
# ---------------------------------------------------------------------------


def test_normal_exit_produces_completed(harness_factory):
    harness = harness_factory("normal")
    assert harness.wait(timeout=60) == 0

    daemon = harness.daemon
    assert daemon.state is SessionState.COMPLETED
    assert daemon.trace.verify().valid
    metadata = daemon.stats()["metadata"]
    assert metadata["status"] == "COMPLETED"
    assert metadata["exit_code"] == 0
    assert metadata["verification"]["valid"] is True


def test_nonzero_exit_produces_failed(harness_factory):
    harness = harness_factory(
        command=[sys.executable, "-c", "raise SystemExit(3)"]
    )
    assert harness.wait(timeout=60) == 3
    assert harness.daemon.state is SessionState.FAILED
    assert harness.daemon.trace.verify().valid


def test_crashing_process_does_not_crash_the_supervisor(harness_factory):
    harness = harness_factory(
        command=[sys.executable, "-c", "import os; os.abort()"],
    )
    exit_code = harness.wait(timeout=60)
    assert exit_code != 0
    assert harness.daemon.state is SessionState.FAILED
    assert harness.daemon.verify().valid
    assert harness.daemon.internal_error == ""


def test_client_crash_does_not_corrupt_the_trace(harness_factory):
    harness = harness_factory("crash")
    assert harness.wait(timeout=60) == 9
    assert harness.daemon.verify().valid
    # The supervisor recorded the loss of its control channel.
    assert events(harness, "ipc_lost")


def test_storage_failure_is_reported_without_losing_the_session(tmp_path):
    from the_watcher.supervisor import DaemonConfig, WatcherDaemon

    # A file where the sessions directory should be makes storage unusable.
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "sessions").write_text("not a directory", encoding="utf-8")

    daemon = WatcherDaemon(
        DaemonConfig(
            command=[sys.executable, "-c", "pass"],
            storage_root=str(blocked),
            cwd=str(PROJECT_ROOT),
        )
    )
    exit_code = daemon.run()
    assert exit_code != 0
    assert daemon.internal_error
    assert "StorageError" in daemon.internal_error


# ---------------------------------------------------------------------------
# 31. Replay handling at the daemon level
# ---------------------------------------------------------------------------


def test_replayed_evaluate_request_is_not_double_recorded(harness_factory):
    """A replayed request id must not produce a second policy event."""
    from the_watcher.ipc.protocol import MessageType, build_request
    from the_watcher.ipc.transport import CLIENT_RECEIVE_TYPES, connect

    harness = harness_factory(
        "heartbeat", child_env={"WATCHER_AGENT_SLEEP": "6"}
    )
    assert harness.wait_until_running()
    daemon = harness.daemon
    assert wait_for(lambda: daemon.watcher.quarantined is not None)
    assert wait_for(lambda: any(
        e.event_type == "client_authenticated" for e in daemon.trace
    ), timeout=20)

    endpoint = daemon.endpoint
    token = daemon._token  # trusted-side access, same process as the daemon
    limits = daemon._server.limits

    connection = connect(endpoint, timeout=5.0)
    try:
        connection.send(
            build_request(
                MessageType.HELLO,
                {"token": token, "pid": os.getpid(), "protocol_version": 1},
                session_id=daemon.session_id,
            ),
            limits,
        )
        assert connection.receive(limits, allowed_types=CLIENT_RECEIVE_TYPES)["ok"]

        request = build_request(
            MessageType.EVALUATE,
            {"event_type": "file_access", "action": "read", "resource": "/tmp/one"},
            session_id=daemon.session_id,
        )
        decisions_before = len(events(harness, "policy_decision"))

        connection.send(request, limits)
        first = connection.receive(limits, allowed_types=CLIENT_RECEIVE_TYPES)
        decisions_after_first = len(events(harness, "policy_decision"))

        connection.send(request, limits)  # identical request id
        second = connection.receive(limits, allowed_types=CLIENT_RECEIVE_TYPES)
        decisions_after_second = len(events(harness, "policy_decision"))

        assert first["ok"] is True
        assert second["ok"] is False
        assert second["error_code"] == "REPLAYED_REQUEST"

        # A replay must not be evaluated or recorded a second time. The only
        # new event is the protocol-violation entry describing the replay.
        assert decisions_after_first == decisions_before + 1
        assert decisions_after_second == decisions_after_first
        assert events(harness, "ipc_violation")
    finally:
        connection.close()
        harness.wait(timeout=60)


# ---------------------------------------------------------------------------
# 27 (policy-driven kill from a custom request)
# ---------------------------------------------------------------------------


def test_tripwire_kill_from_a_parameterised_request(harness_factory):
    harness = harness_factory(
        "custom",
        policy=Policy(),
        child_env={
            "WATCHER_AGENT_EVENT": "file_access",
            "WATCHER_AGENT_ACTION": "read",
            "WATCHER_AGENT_RESOURCE": "/fake/admin_credentials",
            "WATCHER_AGENT_LINGER": "2",
        },
    )
    assert harness.wait(timeout=60) == 137
    assert harness.daemon.watcher.kill_record.reason == (
        "TRIPWIRE:fake_admin_credentials"
    )


def test_custom_tripwire_registry_is_respected(harness_factory):
    from the_watcher import TripwireRegistry

    registry = TripwireRegistry.default(workspace_root=str(PROJECT_ROOT))
    registry.add(
        Tripwire(
            id="tls_canary",
            description="tls exfiltration canary",
            domains=("exfil.example",),
            event_types=("network_request",),
        )
    )
    harness = harness_factory(
        "custom",
        policy=Policy(),
        tripwires=registry,
        child_env={
            "WATCHER_AGENT_EVENT": "network_request",
            "WATCHER_AGENT_ACTION": "connect",
            "WATCHER_AGENT_RESOURCE": "https://exfil.example/drop",
            "WATCHER_AGENT_LINGER": "2",
        },
    )
    assert harness.wait(timeout=60) == 137
    assert harness.daemon.watcher.kill_record.reason == "TRIPWIRE:tls_canary"
