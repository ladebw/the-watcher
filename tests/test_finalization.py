"""Phase 0 Blocker A: finalisation must never orphan the protected workload.

The defect these tests exist for: ``WatcherDaemon._finalize`` destroyed
containment, drained IPC, recorded lifecycle events and sealed the trace, but
never terminated the workload. On any path that did not already observe an exit
- a supervisor exception, a keyboard interrupt, a signal, or a stop request that
could not kill - the workload survived, detached, while the trace recorded
``"protected process exited with 1"`` for a process that never exited.

The invariant asserted throughout is:

    A session is never finalised or sealed as exited while its protected
    workload is still alive, and no lifecycle event asserts an observation
    that was not made.
"""

from __future__ import annotations

import signal
import sys
import threading

from conftest import PROJECT_ROOT, pid_is_alive, wait_for

#: Long enough that it can never exit on its own during a test.
SLEEPER = [sys.executable, "-c", "import time; time.sleep(120)"]


def _make_daemon(tmp_path, command=SLEEPER, **kwargs):
    from the_watcher.supervisor import DaemonConfig, WatcherDaemon

    config = DaemonConfig(
        command=list(command),
        workspace_root=str(PROJECT_ROOT),
        cwd=str(PROJECT_ROOT),
        storage_root=str(tmp_path / "watcher-home"),
        monitor_interval=0.02,
        **kwargs,
    )
    return WatcherDaemon(config)


def _event_types(daemon) -> list[str]:
    return [event.event_type for event in daemon.trace.events]


def _events_of(daemon, event_type: str):
    return [event for event in daemon.trace.events if event.event_type == event_type]


# ---------------------------------------------------------------------------
# The workload must not survive finalisation
# ---------------------------------------------------------------------------


def test_supervisor_exception_terminates_a_live_workload(tmp_path):
    """A supervisor fault must not leave a detached workload behind.

    ``_watch_process`` is made to raise on its first monitoring iteration, which
    is exactly the shape of a real internal fault: it happens after the workload
    was launched and while it is still running.
    """
    daemon = _make_daemon(tmp_path)

    def boom() -> None:
        raise RuntimeError("simulated supervisor fault")

    daemon._check_heartbeat = boom  # type: ignore[method-assign]

    thread = threading.Thread(target=daemon.run, daemon=True)
    thread.start()
    thread.join(timeout=60)
    assert not thread.is_alive(), "the supervisor thread did not finish"

    pid = daemon.process.pid if daemon.process else None
    assert pid is not None, "the workload should have been launched"
    assert wait_for(lambda: not pid_is_alive(pid), timeout=15), (
        "the protected workload outlived finalisation"
    )

    types = _event_types(daemon)
    assert "shutdown_requested" in types
    assert "termination_initiated" in types
    assert "termination_verified" in types

    # The whole point: no fabricated exit.
    assert "process_exited" not in types, (
        "the trace claims an exit that was never observed"
    )
    assert daemon.state.value == "FAILED"
    assert daemon.trace.verify().valid
    assert "RuntimeError" in daemon.internal_error


def test_direct_finalize_terminates_a_live_workload(tmp_path):
    """Finalising while the workload is alive terminates and verifies it."""
    daemon = _make_daemon(tmp_path)
    daemon._prepare()
    daemon._serve()
    assert daemon.process is not None and daemon.process.alive

    pid = daemon.process.pid
    daemon._finalize(1)

    assert wait_for(lambda: not pid_is_alive(pid), timeout=15), (
        "finalisation left the workload running"
    )
    types = _event_types(daemon)
    assert "shutdown_requested" in types
    assert "termination_initiated" in types
    assert "termination_verified" in types
    assert "process_exited" not in types
    assert daemon.trace.verify().valid

    verified = _events_of(daemon, "termination_verified")[0]
    assert verified.metadata["exit_observed"] is False

    end = _events_of(daemon, "session_end")[0]
    assert end.metadata["exit_observed"] is False
    assert end.metadata["finalization_phase"] == "terminated"


def test_termination_verified_is_not_recorded_when_termination_fails(tmp_path):
    """An unverifiable termination is critical and still claims no exit."""
    daemon = _make_daemon(tmp_path)
    daemon._prepare()
    daemon._serve()

    # Simulate an enforcer/kernel that will not confirm the workload is gone.
    def unverifiable():
        return ({"error": "simulated"}, [424242], False)

    daemon._terminate_workload_now = unverifiable  # type: ignore[method-assign]
    daemon._finalize(1)

    types = _event_types(daemon)
    assert "termination_initiated" in types
    assert "termination_unverified" in types
    assert "termination_verified" not in types
    assert "process_exited" not in types

    unverified = _events_of(daemon, "termination_unverified")[0]
    assert unverified.risk == "CRITICAL"
    assert unverified.decision == "KILL"
    assert unverified.metadata["survivors"] == [424242]

    assert daemon.state.value == "FAILED"
    assert daemon.sealed_verified is True
    assert "could not be verified" in daemon.internal_error


def test_finalize_is_idempotent_with_a_live_workload(tmp_path):
    """Calling finalisation twice must not duplicate events or re-terminate."""
    daemon = _make_daemon(tmp_path)
    daemon._prepare()
    daemon._serve()

    daemon._finalize(1)
    first = [event.event_hash for event in daemon.trace.events]
    exit_code = daemon.exit_code

    daemon._finalize(1)
    second = [event.event_hash for event in daemon.trace.events]

    assert first == second, "the second finalisation appended events"
    assert daemon.exit_code == exit_code
    assert daemon.trace.verify().valid


def test_finalize_without_a_workload_claims_no_exit(tmp_path):
    """A session that failed before launching must not invent an exit."""
    daemon = _make_daemon(tmp_path)
    daemon._prepare()
    # Deliberately never _serve(): nothing was ever launched.
    daemon._finalize(1)

    types = _event_types(daemon)
    assert "process_exited" not in types
    assert "shutdown_requested" not in types
    end = _events_of(daemon, "session_end")[0]
    assert end.metadata["finalization_phase"] == "not_started"
    assert end.metadata["exit_observed"] is False
    assert daemon.trace.verify().valid


def test_normal_exit_is_still_recorded_as_an_observed_exit(tmp_path):
    """The ordinary path must keep its truthful PROCESS_EXITED event."""
    daemon = _make_daemon(tmp_path, command=[sys.executable, "-c", "raise SystemExit(0)"])
    exit_code = daemon.run()

    assert exit_code == 0
    types = _event_types(daemon)
    assert "process_exited" in types
    assert "shutdown_requested" not in types
    exited = _events_of(daemon, "process_exited")[0]
    assert exited.metadata["exit_observed"] is True
    assert exited.metadata["exit_code"] == 0
    assert daemon.state.value == "COMPLETED"
    assert daemon.trace.verify().valid


def test_exit_code_is_never_recorded_when_it_was_not_observed(tmp_path):
    """A clean exit code that was not observed must not produce COMPLETED."""
    daemon = _make_daemon(tmp_path)

    # A workload that never exits, with a caller passing the "clean" code.
    daemon._prepare()
    daemon._serve()
    daemon._finalize(0)

    assert daemon.state.value == "FAILED", (
        "an unobserved exit code 0 was treated as a clean finish"
    )
    assert "process_exited" not in _event_types(daemon)


# ---------------------------------------------------------------------------
# Shutdown and signal paths
# ---------------------------------------------------------------------------


def test_stop_while_alive_leaves_no_survivor(tmp_path):
    """The ordinary stop path still terminates and records the workload."""
    daemon = _make_daemon(tmp_path)
    daemon._prepare()
    daemon._serve()
    pid = daemon.process.pid

    daemon.stop("TEST_STOP")
    daemon._finalize(daemon._watch_process())

    assert wait_for(lambda: not pid_is_alive(pid), timeout=15)
    assert daemon.state.value == "KILLED"
    assert daemon.trace.verify().valid


def test_request_shutdown_performs_a_controlled_kill(tmp_path):
    """A shutdown request becomes an ordinary recorded kill, not a bare exit."""
    daemon = _make_daemon(tmp_path)
    daemon._prepare()
    daemon._serve()
    pid = daemon.process.pid

    daemon.request_shutdown("SIGNAL:SIGTERM")
    assert daemon._quit.is_set()
    exit_code = daemon._watch_process()
    daemon._finalize(exit_code)

    assert wait_for(lambda: not pid_is_alive(pid), timeout=15), (
        "a shutdown request left the workload running"
    )
    types = _event_types(daemon)
    assert "shutdown_requested" in types
    assert daemon.state.value == "KILLED"
    assert daemon.trace.verify().valid

    requested = _events_of(daemon, "shutdown_requested")[0]
    assert requested.metadata["requested_reason"] == "SIGNAL:SIGTERM"


def test_signal_handlers_are_installed_and_restored(tmp_path):
    """The CLI helper routes signals to the daemon and restores the originals."""
    from the_watcher.cli import supervisor_signal_handlers

    daemon = _make_daemon(tmp_path)
    before_int = signal.getsignal(signal.SIGINT)
    before_term = signal.getsignal(signal.SIGTERM)

    with supervisor_signal_handlers(daemon):
        installed_int = signal.getsignal(signal.SIGINT)
        assert installed_int is not before_int
        assert callable(installed_int)
        # Invoke the handler directly: deterministic, and it must not raise or
        # do any real work in the handler frame.
        installed_int(signal.SIGINT, None)
        assert daemon._quit.is_set()
        assert daemon._shutdown_reason == "SIGNAL:SIGINT"

    assert signal.getsignal(signal.SIGINT) is before_int
    assert signal.getsignal(signal.SIGTERM) is before_term


def test_signal_handler_on_a_worker_thread_is_a_no_op(tmp_path):
    """Installing handlers off the main thread must not raise."""
    from the_watcher.cli import supervisor_signal_handlers

    daemon = _make_daemon(tmp_path)
    errors: list[BaseException] = []

    def body() -> None:
        try:
            with supervisor_signal_handlers(daemon):
                pass
        except BaseException as exc:  # noqa: BLE001 - the test asserts emptiness
            errors.append(exc)

    thread = threading.Thread(target=body)
    thread.start()
    thread.join(timeout=10)
    assert errors == []


# ---------------------------------------------------------------------------
# Trace truthfulness
# ---------------------------------------------------------------------------


def test_shutdown_vocabulary_never_asserts_an_unobserved_exit(tmp_path):
    """Every lifecycle event in a terminated session describes an observation."""
    daemon = _make_daemon(tmp_path)
    daemon._prepare()
    daemon._serve()
    daemon._finalize(1)

    allowed = {
        "session_created",
        "ipc_ready",
        "process_started",
        "shutdown_requested",
        "termination_initiated",
        "termination_verified",
        "process_termination",
        "session_end",
        "trace_sealed",
        "client_connected",
        "client_authenticated",
        "client_disconnected",
        "ipc_lost",
        "heartbeat",
    }
    for event in daemon.trace.events:
        if event.event_type in ("session_end", "trace_sealed"):
            continue
        assert event.event_type in allowed, (
            f"unexpected lifecycle event in a terminated session: {event.event_type}"
        )

    sealed = _events_of(daemon, "trace_sealed")[0]
    # The count describes the trace as sealed, including this event.
    assert sealed.metadata["event_count"] == len(daemon.trace.events)
