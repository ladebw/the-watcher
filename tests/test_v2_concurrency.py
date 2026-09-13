"""Concurrency: deterministic sequencing and the kill-race invariant.

These tests exist because the promise "the external supervisor is
authoritative" is only meaningful if it holds under load. They drive the real
daemon over real IPC from several threads at once.
"""

from __future__ import annotations

import os
import threading

import pytest

from the_watcher.ipc.protocol import IpcLimits, MessageType, build_request
from the_watcher.ipc.transport import CLIENT_RECEIVE_TYPES, connect

CONNECTIONS = 4
REQUESTS_PER_CONNECTION = 50

#: Event types that represent an action the protected process asked to perform.
CLIENT_ACTION_EVENTS = frozenset(
    {
        "policy_decision",
        "denied_action",
        "file_access",
        "file_modification",
        "network_request",
        "api_request",
        "tool_request",
        "model_call",
        "shell_command",
        "process_creation",
    }
)


def make_limits():
    return IpcLimits(
        max_connections_per_session=CONNECTIONS + 4,
        request_timeout=30.0,
        max_message_bytes=256 * 1024,
    )


def auth_connection(daemon):
    """Open an authenticated raw connection to the running daemon."""
    limits = daemon._server.limits  # trusted-side access, same process
    connection = connect(daemon.endpoint, timeout=10.0)
    connection.send(
        build_request(
            MessageType.HELLO,
            {"token": daemon._token, "pid": os.getpid(), "protocol_version": 1},
            session_id=daemon.session_id,
        ),
        limits,
    )
    response = connection.receive(limits, allowed_types=CLIENT_RECEIVE_TYPES)
    assert response["ok"] is True, response
    return connection


def evaluate(connection, daemon, event_type, action, resource):
    limits = daemon._server.limits
    connection.send(
        build_request(
            MessageType.EVALUATE,
            {"event_type": event_type, "action": action, "resource": resource},
            session_id=daemon.session_id,
        ),
        limits,
    )
    return connection.receive(limits, allowed_types=CLIENT_RECEIVE_TYPES)


def run_threads(targets):
    threads = [threading.Thread(target=target, daemon=True) for target in targets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    assert all(not thread.is_alive() for thread in threads), "a worker thread hung"


# ---------------------------------------------------------------------------
# Dense, gap-free sequencing under concurrency
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("concurrency", [1, 4])
def test_concurrent_events_receive_dense_unique_sequences(harness_factory, concurrency):
    harness = harness_factory(
        "heartbeat",
        child_env={"WATCHER_AGENT_SLEEP": "40"},
        limits=make_limits(),
    )
    assert harness.wait_until_running(), "session should start"
    daemon = harness.daemon

    connections = [auth_connection(daemon) for _ in range(concurrency)]
    responses: list[dict] = []
    failures: list[BaseException] = []
    lock = threading.Lock()

    def worker(connection, count):
        for _ in range(count):
            try:
                response = evaluate(
                    connection, daemon, "file_access", "read", "/tmp/concurrent"
                )
            except BaseException as exc:  # noqa: BLE001 - reported to the test
                with lock:
                    failures.append(exc)
                return
            with lock:
                responses.append(response)

    per_worker = max(1, REQUESTS_PER_CONNECTION // concurrency)
    run_threads(
        [lambda c=connection: worker(c, per_worker) for connection in connections]
    )

    for connection in connections:
        connection.close()

    assert failures == []
    accepted = [response for response in responses if response.get("ok")]
    assert len(accepted) == per_worker * concurrency

    # Every accepted request produced exactly one decision.
    decisions = [e for e in daemon.trace if e.event_type == "policy_decision"]
    assert len(decisions) == len(accepted)
    assert all(e.decision == "ALLOW" for e in decisions)

    # Sequence numbers are dense, unique and in order.
    sequences = [event.sequence for event in daemon.trace]
    assert sequences == list(range(len(sequences)))

    # No duplicate event hashes, and the chain is intact.
    hashes = [event.event_hash for event in daemon.trace]
    assert len(set(hashes)) == len(hashes)
    assert daemon.verify().valid

    # Every event's predecessor link is correct.
    previous = None
    for event in daemon.trace:
        if previous is not None:
            assert event.previous_hash == previous.event_hash
        assert event.previous_hash == (
            previous.event_hash if previous else "0" * 64
        )
        previous = event

    daemon.stop("STRESS_DONE")
    assert harness.wait(timeout=60) == 137
    assert daemon.verify().valid


def test_concurrent_events_do_not_break_the_hash_chain(harness_factory):
    """A heavier burst, asserting only the chain invariants."""
    harness = harness_factory(
        "heartbeat",
        child_env={"WATCHER_AGENT_SLEEP": "40"},
        limits=make_limits(),
    )
    assert harness.wait_until_running()
    daemon = harness.daemon

    connections = [auth_connection(daemon) for _ in range(CONNECTIONS)]
    errors: list[BaseException] = []
    lock = threading.Lock()

    def worker(connection):
        for _ in range(REQUESTS_PER_CONNECTION):
            try:
                evaluate(connection, daemon, "tool_request", "invoke", "search")
            except BaseException as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)
                return

    run_threads([lambda c=connection: worker(c) for connection in connections])
    for connection in connections:
        connection.close()

    assert errors == []
    sequences = [event.sequence for event in daemon.trace]
    assert len(sequences) == len(set(sequences))
    assert sequences == list(range(len(sequences)))
    assert daemon.verify().valid

    daemon.stop("STRESS_DONE")
    assert harness.wait(timeout=60) == 137
    result = daemon.verify()
    assert result.valid, result.signals


# ---------------------------------------------------------------------------
# Kill race
# ---------------------------------------------------------------------------


def test_kill_race_never_authorises_a_later_action(harness_factory):
    """Once the kill is decided, no later privileged action may be ALLOWed.

    A tripwire evaluation runs concurrently with a burst of allowed actions.
    Whatever order the daemon serialises them in, every client-action event
    recorded *after* the kill switch fires must be a KILL.
    """
    harness = harness_factory(
        "heartbeat",
        child_env={"WATCHER_AGENT_SLEEP": "40"},
        limits=make_limits(),
    )
    assert harness.wait_until_running()
    daemon = harness.daemon

    connections = [auth_connection(daemon) for _ in range(CONNECTIONS)]
    responses: list[dict] = []
    lock = threading.Lock()
    stop = threading.Event()

    def killer():
        connection = connections[0]
        try:
            response = evaluate(
                connection, daemon, "file_access", "read", "/fake/root_token"
            )
        except BaseException:  # noqa: BLE001 - the kill may sever the connection
            return
        with lock:
            responses.append(response)

    def normal(connection):
        for _ in range(500):
            if stop.is_set():
                return
            try:
                response = evaluate(
                    connection, daemon, "file_access", "read", "/tmp/race"
                )
            except BaseException:  # noqa: BLE001 - expected once killed
                return
            with lock:
                responses.append(response)

    # Sustained traffic first, so the kill genuinely races live requests.
    normal_threads = [
        threading.Thread(target=normal, args=(connection,), daemon=True)
        for connection in connections[1:]
    ]
    for thread in normal_threads:
        thread.start()

    from conftest import wait_for

    assert wait_for(
        lambda: any(
            event.event_type == "policy_decision" and event.decision == "ALLOW"
            for event in daemon.trace
        ),
        timeout=15,
    ), "traffic should be flowing before the kill"

    killer_thread = threading.Thread(target=killer, daemon=True)
    killer_thread.start()
    killer_thread.join(30)

    # Keep hammering briefly after the kill so post-kill attempts are recorded.
    from time import sleep

    sleep(0.2)
    stop.set()
    for thread in normal_threads:
        thread.join(30)
    for connection in connections:
        connection.close()

    daemon.stop("RACE_TEARDOWN")
    assert harness.wait(timeout=60) == 137
    assert daemon.killed

    trace = daemon.trace
    kill_indexes = [
        index for index, event in enumerate(trace) if event.event_type == "kill_switch"
    ]
    assert len(kill_indexes) == 1, "exactly one kill event may be recorded"
    kill_index = kill_indexes[0]

    # The race must have been real: actions were allowed before the kill.
    allowed_before = [
        event
        for event in trace[:kill_index]
        if event.event_type in CLIENT_ACTION_EVENTS and event.decision == "ALLOW"
    ]
    assert allowed_before, "the race produced no pre-kill allows"

    after = list(trace[kill_index + 1 :])
    post_kill_attempts = [
        event for event in after if event.event_type in CLIENT_ACTION_EVENTS
    ]
    assert post_kill_attempts, "no post-kill attempts were recorded"

    offenders = [event for event in post_kill_attempts if event.decision != "KILL"]
    assert offenders == [], (
        "these events authorised an action after the kill: "
        + ", ".join(event.summary() for event in offenders)
    )

    # And no client ever received an ALLOW after the kill was decided.
    assert all(
        response["payload"]["decision"] == "KILL"
        for response in responses
        if response.get("ok") and response["payload"].get("killed")
    )

    assert daemon.verify().valid


def test_kill_race_with_many_concurrent_requests(harness_factory):
    """Re-run the race with a wider burst to shake out ordering luck."""
    for _ in range(3):
        harness = harness_factory(
            "heartbeat",
            child_env={"WATCHER_AGENT_SLEEP": "40"},
            limits=make_limits(),
        )
        assert harness.wait_until_running()
        daemon = harness.daemon

        connections = [auth_connection(daemon) for _ in range(CONNECTIONS)]

        def killer(connection=connections[0], target=daemon):
            try:
                evaluate(connection, target, "file_access", "read", "/fake/root_token")
            except BaseException:  # noqa: BLE001
                pass

        def normal(connection, target=daemon):
            for _ in range(20):
                try:
                    evaluate(
                        connection,
                        target,
                        "network_request",
                        "connect",
                        "https://github.com",
                    )
                except BaseException:  # noqa: BLE001
                    return

        run_threads(
            [killer]
            + [lambda c=connection: normal(c) for connection in connections[1:]]
        )
        for connection in connections:
            connection.close()

        daemon.stop("RACE_TEARDOWN")
        assert harness.wait(timeout=60) == 137

        trace = daemon.trace
        kill_index = next(
            index
            for index, event in enumerate(trace)
            if event.event_type == "kill_switch"
        )
        for event in trace[kill_index + 1 :]:
            if event.event_type in CLIENT_ACTION_EVENTS:
                assert event.decision == "KILL", event.summary()
        assert daemon.verify().valid
