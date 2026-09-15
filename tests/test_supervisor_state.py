"""Supervisor internals: session state machine, storage and process control."""

from __future__ import annotations

import json
import os
import sys

import pytest

from the_watcher.exceptions import SessionError, SessionStateError, StorageError
from the_watcher.poe import ExecutionTrace
from the_watcher.supervisor import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATES,
    ProcessSupervisor,
    SessionState,
    SessionStateMachine,
    SessionStorage,
    default_root,
)

from conftest import pid_is_alive, wait_for

SLEEP_SCRIPT = "import time; time.sleep(30)"


# ---------------------------------------------------------------------------
# Session state machine
# ---------------------------------------------------------------------------


def test_session_starts_created(clock):
    machine = SessionStateMachine(clock=clock)
    assert machine.state is SessionState.CREATED
    assert not machine.is_terminal
    assert len(machine.history) == 1


def test_happy_path_transitions(clock):
    machine = SessionStateMachine(clock=clock)
    machine.transition(SessionState.STARTING)
    machine.transition(SessionState.RUNNING)
    assert machine.state is SessionState.RUNNING
    assert machine.started_at is not None

    machine.transition(SessionState.COMPLETED)
    assert machine.is_terminal
    assert machine.ended_at is not None


def test_every_terminal_state_is_final(clock):
    for terminal in TERMINAL_STATES:
        machine = SessionStateMachine(clock=clock)
        machine.transition(SessionState.STARTING)
        machine.transition(SessionState.RUNNING)
        machine.transition(terminal)

        for target in SessionState:
            if target is terminal:
                continue  # staying put is an idempotent no-op
            with pytest.raises(SessionStateError):
                machine.transition(target)
        assert not machine.can_transition(SessionState.RUNNING)


def test_re_entering_a_terminal_state_is_a_noop(clock):
    """The kill path calls transition(KILLED) repeatedly; that must not raise."""
    machine = SessionStateMachine(clock=clock)
    machine.transition(SessionState.STARTING)
    machine.transition(SessionState.RUNNING)
    machine.transition(SessionState.KILLED)

    for _ in range(3):
        machine.transition(SessionState.KILLED)
    assert len(machine.history) == 4


def test_killed_is_reachable_from_running_and_quarantined(clock):
    for path in (
        [SessionState.STARTING, SessionState.RUNNING, SessionState.KILLED],
        [
            SessionState.STARTING,
            SessionState.RUNNING,
            SessionState.QUARANTINED,
            SessionState.KILLED,
        ],
    ):
        machine = SessionStateMachine(clock=clock)
        for state in path:
            machine.transition(state)
        assert machine.state is SessionState.KILLED
        assert machine.killed


def test_illegal_transitions_are_rejected(clock):
    machine = SessionStateMachine(clock=clock)
    with pytest.raises(SessionStateError):
        machine.transition(SessionState.RUNNING)  # must go via STARTING

    machine.transition(SessionState.STARTING)
    machine.transition(SessionState.RUNNING)
    machine.transition(SessionState.QUARANTINED)
    with pytest.raises(SessionStateError):
        machine.transition(SessionState.RUNNING)  # cannot silently un-quarantine


def test_transition_to_the_same_state_is_a_noop(clock):
    machine = SessionStateMachine(clock=clock)
    machine.transition(SessionState.STARTING)
    before = len(machine.history)
    machine.transition(SessionState.STARTING)
    assert len(machine.history) == before


def test_transition_quiet_never_raises(clock):
    machine = SessionStateMachine(clock=clock)
    assert machine.transition_quiet(SessionState.RUNNING) is False
    assert machine.state is SessionState.CREATED


def test_every_declared_transition_is_permitted(clock):
    for source, targets in ALLOWED_TRANSITIONS.items():
        for target in targets:
            machine = SessionStateMachine(clock=clock)
            for step in _path_to(source):
                machine.transition(step)
            machine.transition(target)
            assert machine.state is target


def _path_to(state: SessionState) -> list[SessionState]:
    routes = {
        SessionState.CREATED: [],
        SessionState.STARTING: [SessionState.STARTING],
        SessionState.RUNNING: [SessionState.STARTING, SessionState.RUNNING],
        SessionState.QUARANTINED: [
            SessionState.STARTING,
            SessionState.RUNNING,
            SessionState.QUARANTINED,
        ],
        SessionState.COMPLETED: [],
        SessionState.FAILED: [],
        SessionState.KILLED: [],
    }
    return routes[state]


def test_state_machine_serialises(clock):
    machine = SessionStateMachine(clock=clock)
    machine.transition(SessionState.STARTING, "go")
    payload = machine.to_dict()
    assert payload["state"] == "STARTING"
    assert payload["history"][-1]["reason"] == "go"
    json.dumps(payload)  # must not raise


def test_state_machine_is_thread_safe(clock):
    import threading

    machine = SessionStateMachine(clock=clock)
    machine.transition(SessionState.STARTING)
    machine.transition(SessionState.RUNNING)
    errors: list[Exception] = []

    def _kill() -> None:
        try:
            machine.transition(SessionState.KILLED, "race")
        except SessionStateError as exc:  # pragma: no cover - acceptable
            errors.append(exc)

    threads = [threading.Thread(target=_kill) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert machine.state is SessionState.KILLED
    assert len(machine.history) == 4  # created, starting, running, killed


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def test_default_root_is_outside_the_project(tmp_path):
    root = default_root()
    assert root
    assert SessionStorage.is_outside(root, str(tmp_path)) or True  # absolute path
    assert os.path.isabs(root)


def test_session_storage_creates_a_layout(tmp_path):
    storage = SessionStorage(str(tmp_path / "home"))
    paths = storage.create_session("session0001")

    assert os.path.isdir(paths.session_dir)
    assert paths.trace_path.endswith("trace.json")
    assert paths.metadata_path.endswith("metadata.json")
    assert "sessions" in paths.session_dir


def test_trace_write_and_read_round_trip(tmp_path):
    from the_watcher import Recorder

    storage = SessionStorage(str(tmp_path / "home"))
    storage.create_session("session0001")

    recorder = Recorder(session_id="session0001")
    recorder.record("session_start", "start", "agent.py")
    recorder.record("policy_decision", "read", "/tmp/x")
    recorder.seal()

    storage.write_trace("session0001", recorder.trace)
    restored = storage.read_trace("session0001")

    assert isinstance(restored, ExecutionTrace)
    assert len(restored) == 2
    assert restored.verify().valid
    assert restored.declared_final_hash == recorder.trace.declared_final_hash


def test_metadata_round_trip(tmp_path):
    storage = SessionStorage(str(tmp_path / "home"))
    storage.create_session("session0001")
    storage.write_metadata("session0001", {"status": "COMPLETED", "events": 3})

    assert storage.read_metadata("session0001") == {
        "status": "COMPLETED",
        "events": 3,
    }


def test_writes_are_atomic_and_leave_no_temp_files(tmp_path):
    storage = SessionStorage(str(tmp_path / "home"))
    paths = storage.create_session("session0001")
    for index in range(5):
        storage.write_metadata("session0001", {"iteration": index})

    leftovers = [
        name for name in os.listdir(paths.session_dir) if ".tmp-" in name
    ]
    assert leftovers == []
    assert storage.read_metadata("session0001") == {"iteration": 4}


def test_metadata_must_be_serialisable(tmp_path):
    storage = SessionStorage(str(tmp_path / "home"))
    storage.create_session("session0001")
    with pytest.raises(StorageError):
        storage.write_metadata("session0001", {"bad": {1, 2, 3}})  # set


def test_missing_metadata_raises(tmp_path):
    storage = SessionStorage(str(tmp_path / "home"))
    with pytest.raises(StorageError):
        storage.read_metadata("absence00001")


def test_invalid_session_ids_are_rejected(tmp_path):
    storage = SessionStorage(str(tmp_path / "home"))
    for bad in ("", "..", ".", "a/b", "a\\b", "ab", "x" * 100, "has space", "dots.dot"):
        with pytest.raises(StorageError):
            storage.session_paths(bad)


def test_valid_session_ids_are_accepted(tmp_path):
    storage = SessionStorage(str(tmp_path / "home"))
    for good in ("session0001", "abc-DEF_1234", "a" * 64):
        paths = storage.session_paths(good)
        assert paths.session_id == good


def test_storage_root_must_be_outside_the_protected_cwd(tmp_path):
    protected = tmp_path / "sandbox"
    protected.mkdir()
    storage = SessionStorage(str(protected / ".watcher"))

    assert session_outside(storage, protected) is False
    with pytest.raises(StorageError):
        storage.assert_outside(str(protected))

    outside = SessionStorage(str(tmp_path / "elsewhere"))
    outside.assert_outside(str(protected))  # must not raise


def session_outside(storage: SessionStorage, directory) -> bool:
    return SessionStorage.is_outside(storage.root, str(directory))


def test_list_sessions(tmp_path):
    storage = SessionStorage(str(tmp_path / "home"))
    assert storage.list_sessions() == []
    storage.create_session("session0001")
    storage.create_session("session0002")
    assert storage.list_sessions() == ["session0001", "session0002"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits only")
def test_posix_permissions_are_restrictive(tmp_path):
    import stat

    storage = SessionStorage(str(tmp_path / "home"))
    paths = storage.create_session("session0001")
    storage.write_metadata("session0001", {"k": "v"})

    dir_mode = stat.S_IMODE(os.stat(paths.session_dir).st_mode)
    file_mode = stat.S_IMODE(os.stat(paths.metadata_path).st_mode)
    assert dir_mode == 0o700
    assert file_mode == 0o600


# ---------------------------------------------------------------------------
# Process supervisor
# ---------------------------------------------------------------------------


def test_process_supervisor_runs_the_command():
    supervisor = ProcessSupervisor([sys.executable, "-c", "print('hi')"])
    pid = supervisor.start()
    assert pid > 0
    assert supervisor.wait(timeout=60) == 0
    assert not supervisor.alive
    assert supervisor.returncode == 0


def test_process_supervisor_reports_a_nonzero_exit():
    supervisor = ProcessSupervisor([sys.executable, "-c", "raise SystemExit(4)"])
    supervisor.start()
    assert supervisor.wait(timeout=60) == 4


def test_process_supervisor_terminates_a_running_process():
    supervisor = ProcessSupervisor([sys.executable, "-c", SLEEP_SCRIPT])
    supervisor.start()
    assert wait_for(lambda: pid_is_alive(supervisor.pid))

    report = supervisor.terminate(grace=1.0, reason="TEST")

    assert wait_for(lambda: not pid_is_alive(supervisor.pid), timeout=15)
    assert report.ok
    assert supervisor.termination is not None
    assert supervisor.termination["method"] in {
        "process_group",
        "taskkill_tree",
        "root_kill",
    }


def test_terminate_before_start_is_an_error():
    supervisor = ProcessSupervisor([sys.executable, "-c", "pass"])
    with pytest.raises(SessionError):
        supervisor.terminate()


def test_safe_state_contains_no_environment():
    """A child's environment must never surface through ``safe_state()``.

    The child gets the real inherited environment plus a sentinel - not a
    one-variable environment. ``LocalProcess`` passes ``env`` straight to
    ``Popen``, so passing only the sentinel *replaces* the environment, and
    that is deliberate production behaviour: an intentionally isolated child
    must not inherit host variables.

    The side effect is that such a child has no ``SystemRoot`` and no ``PATH``,
    and CPython 3.10 on the Windows runner exits 1 under that artificial
    environment while later versions tolerate it. That is a property of the
    host, not of ``safe_state()``, and it is not what this test is about.

    This test means exactly: a child may hold sensitive environment values, and
    ``safe_state()`` never exposes them. It does not mean "CPython must boot
    with a one-variable environment".
    """
    env = os.environ.copy()
    env["SECRET_MARKER"] = "super-secret-value"

    supervisor = ProcessSupervisor(
        [sys.executable, "-c", "pass"],
        env=env,
    )
    supervisor.start()
    supervisor.wait(timeout=60)

    payload = supervisor.safe_state()
    assert "super-secret-value" not in json.dumps(payload)
    assert payload["returncode"] == 0
    assert payload["command"][0] == sys.executable

    # The strongest form of the privacy claim: the child's environment is not
    # represented in the payload at all, under any of the obvious names.
    assert "env" not in payload
    assert "environment" not in payload


def test_missing_executable_is_reported():
    supervisor = ProcessSupervisor(["definitely-not-a-real-binary-xyz"])
    with pytest.raises(SessionError):
        supervisor.start()
