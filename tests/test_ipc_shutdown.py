"""IPC shutdown: refusing new writers, draining, and an explicit failure.

The defect these cover: ``IpcServer.stop()`` joined its worker threads only
until a deadline and then gave up, so the supervisor could seal the trace while
a worker was still appending. The append landed after the seal, leaving
``compute_final_hash()`` different from ``declared_final_hash``, and
verification reported ``INVALID_FINAL_TRACE_HASH`` on a trace nobody had
tampered with.

Two independent guarantees are tested here because either alone is
insufficient:

* the server must refuse to *start* a new authoritative write once draining
  begins, and must know when the ones in flight have finished; and
* the trace itself must refuse appends once sealed, so a straggler write can
  never corrupt the declared hash even if the drain is not clean.
"""

from __future__ import annotations

import contextlib
import os
import threading
import time

import pytest

from the_watcher.exceptions import IpcDrainTimeout
from the_watcher.ipc.protocol import (
    ErrorCode,
    IpcLimits,
    MessageType,
    build_request,
)
from the_watcher.ipc.server import IpcServer, ServerState
from the_watcher.ipc.transport import (
    CLIENT_RECEIVE_TYPES,
    IpcListener,
    connect,
    create_endpoint,
)

SESSION_ID = "shutdowntest1"
TOKEN = "shutdown-test-token-must-never-be-logged"

LIMITS = IpcLimits(handshake_timeout=3.0, request_timeout=3.0, idle_poll=0.05)

#: Generous relative to the drain timeouts under test, so a slow machine does
#: not turn "the writer finished" into a failure.
SETTLE = 5.0


def wait_for(predicate, timeout: float = SETTLE, interval: float = 0.01) -> bool:
    """Poll ``predicate`` until it is true or the timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


class BlockingHandler:
    """A handler that holds one request open until it is released.

    This is what an in-flight authoritative writer looks like from the
    server's point of view: mid-``dispatch``, with an append still to come.
    """

    def __init__(self, release: threading.Event) -> None:
        self.release = release
        self.entered = threading.Event()
        self.dispatched: list[str] = []

    def session_snapshot(self) -> dict:
        return {
            "state": "RUNNING",
            "heartbeat": {
                "interval": 0,
                "timeout": 0,
                "required": False,
                "action": "record",
            },
        }

    def dispatch(self, message_type: str, payload: dict, context) -> dict:
        self.dispatched.append(message_type)
        self.entered.set()
        self.release.wait(30.0)
        return {"acknowledged": True}

    def on_client_connected(self, context) -> None:
        pass

    def on_client_authenticated(self, context) -> None:
        pass

    def on_client_disconnected(self, context, reason) -> None:
        pass

    def on_protocol_violation(self, code, detail, context) -> None:
        pass

    def on_handler_error(self, kind, detail, context) -> None:
        pass


@contextlib.contextmanager
def running_server(handler):
    """A started server on a private endpoint, torn down without raising."""
    endpoint = create_endpoint(SESSION_ID)
    listener = IpcListener(endpoint)
    server = IpcServer(listener, SESSION_ID, TOKEN, handler, LIMITS).start()
    try:
        yield server, endpoint
    finally:
        # drain() rather than stop(): a teardown must not mask a test failure
        # by raising from the cleanup path itself.
        server.drain(timeout=3.0)


def authenticated_client(endpoint):
    connection = connect(endpoint, timeout=5.0)
    connection.send(
        build_request(
            MessageType.HELLO,
            {"token": TOKEN, "pid": os.getpid(), "protocol_version": 1},
            session_id=SESSION_ID,
        ),
        LIMITS,
    )
    connection.receive(LIMITS, allowed_types=CLIENT_RECEIVE_TYPES)
    return connection


def start_request(connection) -> None:
    connection.send(
        build_request(
            MessageType.EVALUATE,
            {"kind": "tool_request", "action": "invoke", "resource": "search"},
            session_id=SESSION_ID,
        ),
        LIMITS,
    )


def test_a_started_server_is_running():
    handler = BlockingHandler(threading.Event())
    with running_server(handler) as (server, _endpoint):
        assert server.state is ServerState.RUNNING
        assert server.running
        assert server.active_writers == 0


def test_drain_waits_for_an_in_flight_writer():
    """Draining must not report success while a handler is still working."""
    release = threading.Event()
    handler = BlockingHandler(release)

    with running_server(handler) as (server, endpoint):
        connection = authenticated_client(endpoint)
        start_request(connection)
        assert handler.entered.wait(SETTLE), "the handler never started"
        assert server.active_writers == 1

        outcome: dict = {}

        def drain() -> None:
            outcome["result"] = server.drain(timeout=10.0)

        drainer = threading.Thread(target=drain, name="test-drain")
        drainer.start()

        assert wait_for(lambda: server.state is ServerState.DRAINING), (
            "the server never entered DRAINING"
        )
        # Still holding the in-flight writer, so the drain cannot be finished.
        assert drainer.is_alive(), "drain returned while a writer was active"
        assert server.active_writers == 1

        # Let the writer finish; only now may the drain complete.
        release.set()
        drainer.join(10)
        assert not drainer.is_alive()

        result = outcome["result"]
        assert result.drained is True
        assert result.forced is False
        assert result.active_writers == 0
        assert result.remaining_workers == ()
        assert server.state is ServerState.STOPPED
        assert server.active_writers == 0


def test_a_request_arriving_during_drain_is_refused_not_dispatched():
    """Once draining, no new authoritative write may begin."""
    release = threading.Event()
    handler = BlockingHandler(release)

    with running_server(handler) as (server, endpoint):
        # Two authenticated connections: the second is already accepted, so it
        # can still send while the server is draining.
        holder = authenticated_client(endpoint)
        late = authenticated_client(endpoint)

        start_request(holder)
        assert handler.entered.wait(SETTLE), "the handler never started"
        dispatched_before = len(handler.dispatched)

        drainer = threading.Thread(target=lambda: server.drain(timeout=10.0))
        drainer.start()
        assert wait_for(lambda: server.state is ServerState.DRAINING)

        # A new request on the already-accepted connection must be refused.
        start_request(late)
        response = late.receive(LIMITS, allowed_types=CLIENT_RECEIVE_TYPES)

        assert response.get("type") == MessageType.ERROR.value, response
        assert response.get("error_code") == ErrorCode.NOT_READY.value, response
        assert response.get("ok") is False, response
        assert len(handler.dispatched) == dispatched_before, (
            "a new handler was started after draining began"
        )

        release.set()
        drainer.join(10)
        assert not drainer.is_alive()


def test_stop_raises_instead_of_giving_up_quietly():
    """A writer that will not drain must become an explicit failure."""
    release = threading.Event()  # deliberately never set during the drain
    handler = BlockingHandler(release)

    with running_server(handler) as (server, endpoint):
        connection = authenticated_client(endpoint)
        try:
            start_request(connection)
            assert handler.entered.wait(SETTLE), "the handler never started"

            with pytest.raises(IpcDrainTimeout) as excinfo:
                server.stop(timeout=0.5)

            # The failure names the straggler rather than being anonymous.
            assert excinfo.value.remaining, "the timeout named no worker"
            assert "drain" in str(excinfo.value).lower()
            assert not server.running
            assert server.active_writers == 1
        finally:
            release.set()

        # Once the writer is released the server can finish.
        assert wait_for(lambda: server.active_writers == 0, timeout=10.0)


def test_drain_reports_forced_when_the_deadline_expires():
    """A drain that has to force transports shut must say so."""
    release = threading.Event()
    handler = BlockingHandler(release)

    with running_server(handler) as (server, endpoint):
        connection = authenticated_client(endpoint)
        try:
            start_request(connection)
            assert handler.entered.wait(SETTLE), "the handler never started"

            result = server.drain(timeout=0.4)

            assert result.drained is False
            assert result.forced is True
            assert result.active_writers == 1
            assert result.remaining_workers, "no straggler was reported"
        finally:
            release.set()

        assert wait_for(lambda: server.active_writers == 0, timeout=10.0)


def test_drain_is_idempotent_and_cannot_start_new_writers():
    """A second drain returns immediately and never restarts the server."""
    handler = BlockingHandler(threading.Event())

    with running_server(handler) as (server, _endpoint):
        first = server.drain(timeout=2.0)
        assert first.drained is True

        second = server.drain(timeout=2.0)
        assert second.drained is True
        assert second.elapsed == 0.0

        assert server.state is ServerState.STOPPED
        assert not server.running
        assert server.active_writers == 0
