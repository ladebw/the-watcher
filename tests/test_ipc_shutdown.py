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


# ---------------------------------------------------------------------------
# The shutdown invariant, made deterministic
# ---------------------------------------------------------------------------
#
# The defect these cover: ``drain()`` closed the accepted transports at the
# instant it entered DRAINING, while a writer was still mid-append. A request
# arriving in that window raced the teardown, so the client saw
# ``ConnectionResetError`` instead of the ``NOT_READY`` refusal it was entitled
# to. Which of the two it got depended purely on scheduling.
#
# These tests do not wait and hope. They hold the drain open with a
# synchronization primitive the test owns - an in-flight writer parked on an
# ``Event`` - so the drain window is provably still open at the moment the late
# request is sent, and then assert which half of the invariant applies.


class StateRecordingHandler(BlockingHandler):
    """Records the server state observed at the moment of each dispatch."""

    def __init__(self, release: threading.Event, server_ref: list) -> None:
        super().__init__(release)
        self._server_ref = server_ref
        self.states_at_dispatch: list[str] = []

    def dispatch(self, message_type: str, payload: dict, context) -> dict:
        server = self._server_ref[0]
        self.states_at_dispatch.append(server.state.value if server else "no-server")
        return super().dispatch(message_type, payload, context)


def test_no_request_is_dispatched_once_draining_has_begun():
    """The invariant, asserted from inside the handler.

    Recording the server state at the instant ``dispatch`` runs is what makes
    "never dispatched after draining starts" checkable rather than inferred: if
    any dispatch is ever observed while DRAINING, the state recorded here says
    so, whatever the client saw.
    """
    server_ref: list = []
    release = threading.Event()
    handler = StateRecordingHandler(release, server_ref)

    with running_server(handler) as (server, endpoint):
        server_ref.append(server)
        holder = authenticated_client(endpoint)
        late = authenticated_client(endpoint)

        start_request(holder)
        assert handler.entered.wait(SETTLE), "the handler never started"
        dispatched_before = len(handler.dispatched)

        drainer = threading.Thread(target=lambda: server.drain(timeout=10.0))
        drainer.start()
        assert wait_for(lambda: server.state is ServerState.DRAINING)

        start_request(late)
        response = late.receive(LIMITS, allowed_types=CLIENT_RECEIVE_TYPES)
        assert response.get("type") == MessageType.ERROR.value, response
        assert response.get("error_code") == ErrorCode.NOT_READY.value, response

        # Nothing new was dispatched...
        assert len(handler.dispatched) == dispatched_before
        # ...and everything that *was* dispatched happened while RUNNING.
        assert handler.states_at_dispatch == [ServerState.RUNNING.value], (
            f"a request was dispatched while draining: {handler.states_at_dispatch}"
        )

        release.set()
        drainer.join(10)
        assert not drainer.is_alive()


def test_a_request_arriving_during_drain_is_refused_not_reset():
    """A racing request gets a refusal frame, never a connection reset.

    Deterministic by construction: the in-flight writer is held open by this
    test, so the drain cannot reach the point where it closes transports. The
    assertions on ``active_writers`` and ``drainer.is_alive()`` prove the window
    was still open when the late request was written - so a pass here cannot be
    the result of winning a race.
    """
    release = threading.Event()
    handler = BlockingHandler(release)

    with running_server(handler) as (server, endpoint):
        holder = authenticated_client(endpoint)
        late = authenticated_client(endpoint)

        start_request(holder)
        assert handler.entered.wait(SETTLE), "the handler never started"

        drainer = threading.Thread(target=lambda: server.drain(timeout=10.0))
        drainer.start()
        assert wait_for(lambda: server.state is ServerState.DRAINING)

        # The window is open by construction: a writer is still in flight, so
        # the drain is parked before the teardown step and cannot have closed
        # this connection.
        assert server.active_writers == 1, "the in-flight writer was not counted"
        assert drainer.is_alive(), "the drain completed while a writer was active"

        start_request(late)
        # A well-formed refusal, not a transport error. If the transport had
        # been torn down this would raise IpcTransportError instead.
        response = late.receive(LIMITS, allowed_types=CLIENT_RECEIVE_TYPES)
        assert response.get("type") == MessageType.ERROR.value, response
        assert response.get("error_code") == ErrorCode.NOT_READY.value, response
        assert response.get("ok") is False, response

        release.set()
        drainer.join(10)
        assert not drainer.is_alive()


def test_every_request_arriving_during_drain_is_refused():
    """All of them, not just the first: refusal must not be a one-shot."""
    release = threading.Event()
    handler = BlockingHandler(release)

    with running_server(handler) as (server, endpoint):
        holder = authenticated_client(endpoint)
        late_one = authenticated_client(endpoint)
        late_two = authenticated_client(endpoint)

        start_request(holder)
        assert handler.entered.wait(SETTLE), "the handler never started"
        dispatched_before = len(handler.dispatched)

        drainer = threading.Thread(target=lambda: server.drain(timeout=10.0))
        drainer.start()
        assert wait_for(lambda: server.state is ServerState.DRAINING)

        for index, connection in enumerate((late_one, late_two)):
            assert server.active_writers == 1, "the drain window closed early"
            start_request(connection)
            response = connection.receive(LIMITS, allowed_types=CLIENT_RECEIVE_TYPES)
            assert response.get("type") == MessageType.ERROR.value, (index, response)
            assert response.get("error_code") == ErrorCode.NOT_READY.value, (
                index,
                response,
            )

        assert len(handler.dispatched) == dispatched_before, (
            "a request was dispatched after draining began"
        )

        release.set()
        drainer.join(10)
        assert not drainer.is_alive()


def test_a_request_admitted_before_draining_completes_normally():
    """The other half of the invariant, and the one that is easy to get wrong.

    A request that claimed a writer while the server was still RUNNING must be
    allowed to finish and to receive its reply. The writer claim therefore has
    to outlive the response being written: releasing it at the end of
    ``dispatch`` let the drain see "no active writers", close the transport, and
    destroy the reply to a request nobody had refused.
    """
    release = threading.Event()
    handler = BlockingHandler(release)

    with running_server(handler) as (server, endpoint):
        connection = authenticated_client(endpoint)
        start_request(connection)
        assert handler.entered.wait(SETTLE), "the handler never started"
        assert server.active_writers == 1

        drainer = threading.Thread(target=lambda: server.drain(timeout=10.0))
        drainer.start()
        assert wait_for(lambda: server.state is ServerState.DRAINING)

        # The request was admitted before draining, so it finishes normally.
        release.set()

        response = connection.receive(LIMITS, allowed_types=CLIENT_RECEIVE_TYPES)
        assert response.get("type") == MessageType.RESPONSE.value, response
        assert response.get("ok") is True, response

        drainer.join(10)
        assert not drainer.is_alive()
        assert server.active_writers == 0


# ---------------------------------------------------------------------------
# The refusal boundary: a NOT_READY frame in flight must not be cut
# ---------------------------------------------------------------------------
#
# ``_begin_write`` returns False for a request that arrives while DRAINING, so
# that request holds no *writer* claim. Its NOT_READY frame is still on the wire
# though, and while nothing accounted for that send the drain could observe
# ``active_writers == 0``, conclude it was finished, and close the transport
# underneath the reply - reproducing the original reset at a narrower boundary.
#
# Refusals now hold a *response* claim, and the drain closes the claim window
# and waits for it before tearing anything down. These tests pin that boundary.
#
# They are deterministic rather than lucky. ``GatedListener`` parks ``drain()``
# in its accept-thread join with DRAINING already set and the refusal window
# still open, and ``GatedConnection`` holds the refusal send itself. The test
# therefore *knows* the order of events instead of hoping for it - there is no
# sleep, no retry, and no reliance on an admitted request keeping the drain
# alive.


class GatedConnection:
    """Wraps a server-side connection so the test can observe and hold it."""

    def __init__(self, inner, arm: threading.Event, release: threading.Event) -> None:
        self._inner = inner
        self._arm = arm
        self._release = release
        self.send_started = threading.Event()
        #: Set if the *server* closes this transport. This is the witness for
        #: "teardown did not run while a reply was mid-write": with response
        #: accounting the drain cannot reach its close step, so this stays unset
        #: for as long as a claim is held.
        self.close_started = threading.Event()

    def send(self, message, limits) -> None:
        if self._arm.is_set():
            self.send_started.set()
            self._release.wait(30.0)
        return self._inner.send(message, limits)

    def close(self) -> None:
        self.close_started.set()
        return self._inner.close()

    def __getattr__(self, name):
        return getattr(self._inner, name)


class GatedListener:
    """Wraps a listener so the test can hold ``accept`` open.

    Blocking the accept loop parks ``drain()`` in its accept-thread join, which
    happens with DRAINING already set and the refusal window still open. That is
    what lets the test establish a refusal *before* the drain reaches its
    teardown step, without a sleep and without an admitted writer holding the
    drain open.
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.arm = threading.Event()
        self.release = threading.Event()
        self.holding = threading.Event()
        #: Set while the accept loop is blocked inside the real ``accept``.
        #: Waiting on this before arming is what makes the parking deterministic:
        #: if the loop has not yet re-entered ``accept`` when the drain sets
        #: ``_stopping``, it exits in the normal way and never reaches the gate.
        self.waiting = threading.Event()
        self.conn_arm = threading.Event()
        self.conn_release = threading.Event()
        self.connections: list[GatedConnection] = []

    @property
    def endpoint(self):
        return self._inner.endpoint

    def accept(self):
        self.waiting.set()
        try:
            connection = self._inner.accept()
        finally:
            self.waiting.clear()
        wrapped = GatedConnection(connection, self.conn_arm, self.conn_release)
        self.connections.append(wrapped)
        if self.arm.is_set() and not self.release.is_set():
            # Hand control to the test before returning to the accept loop, so
            # the loop cannot observe _stopping and finish the drain.
            self.holding.set()
            self.release.wait(30.0)
        return wrapped

    def close(self):
        self._inner.close()


@contextlib.contextmanager
def gated_server(handler):
    """A started server whose accept loop and response sends the test controls."""
    endpoint = create_endpoint(SESSION_ID)
    listener = GatedListener(IpcListener(endpoint))
    server = IpcServer(listener, SESSION_ID, TOKEN, handler, LIMITS).start()

    def _release_everything() -> None:
        listener.release.set()
        listener.conn_release.set()

    try:
        yield server, endpoint, listener
    finally:
        _release_everything()
        server.drain(timeout=3.0)


def _parked_drain(server, listener, timeout: float = 30.0):
    """Start a drain and return it once it is parked with the window open.

    The accept loop is confirmed to be blocked inside ``accept`` *before* the
    drain starts, so that setting ``_stopping`` cannot make it exit by the normal
    path and skip the gate. Without that ordering the parking - and therefore the
    whole test - would depend on how far the accept loop happened to get.
    """
    assert wait_for(listener.waiting.is_set), (
        "the accept loop is not parked in accept()"
    )
    listener.arm.set()

    drainer = threading.Thread(target=lambda: server.drain(timeout=timeout))
    drainer.start()
    assert wait_for(lambda: server.state is ServerState.DRAINING), (
        "the server never entered DRAINING"
    )
    assert wait_for(listener.holding.is_set), "the accept loop was never parked"
    return drainer


def test_a_refusal_send_in_flight_is_never_cut_by_the_teardown():
    """The exact boundary: zero writers, one refusal being written.

    Steps: enter DRAINING with no admitted writers; hold the accept loop so the
    drain cannot reach its teardown; send a late request; hold its refusal
    ``send`` half-written; then let the drain proceed and prove that it waits
    for that frame rather than closing the transport under it.
    """
    handler = BlockingHandler(threading.Event())
    with gated_server(handler) as (server, endpoint, listener):
        late = authenticated_client(endpoint)
        # Capture the client's own server-side connection now: the drain's
        # wake-probe is accepted later and would otherwise be the newest entry.
        late_wrapper = listener.connections[-1]

        listener.conn_arm.set()
        drainer = _parked_drain(server, listener)

        # No admitted writer at all: the drain has nothing else to wait for, so
        # the refusal claim is the only thing that can keep it from tearing down.
        assert server.active_writers == 0
        assert server.active_responses == 0

        start_request(late)
        assert wait_for(late_wrapper.send_started.is_set), (
            "the refusal was never written"
        )

        # The refusal holds a claim even though nothing was dispatched.
        assert server.active_writers == 0, "a refused request must not dispatch"
        assert server.active_responses == 1, (
            "the refusal frame holds no in-flight claim, so the drain could cut it"
        )

        # Let the drain run. It must not close the transport while that frame is
        # still being written.
        listener.release.set()

        # Observe the negative: were refusal sends unaccounted for, the drain
        # would reach its teardown within microseconds of the accept join
        # returning, so this window only has to give it the chance to do so.
        # Asserting on the close itself - rather than on elapsed time - is what
        # makes it a statement about ordering.
        assert not wait_for(late_wrapper.close_started.is_set, timeout=0.5), (
            "the drain closed the transport while a refusal frame was in flight"
        )
        assert server.active_responses == 1, "the claim was released too early"
        assert late_wrapper.closed is False, "the transport was closed under the reply"
        assert drainer.is_alive(), "the drain finished with a response in flight"

        listener.conn_release.set()

        # A complete NOT_READY frame proves the transport outlived the send.
        response = late.receive(LIMITS, allowed_types=CLIENT_RECEIVE_TYPES)
        assert response.get("type") == MessageType.ERROR.value, response
        assert response.get("error_code") == ErrorCode.NOT_READY.value, response
        assert response.get("ok") is False, response

        drainer.join(10)
        assert not drainer.is_alive()
        assert server.active_responses == 0
        assert server.state is ServerState.STOPPED


def test_concurrent_refusal_sends_are_all_accounted_for():
    """Every in-flight refusal holds its own claim, not just the first."""
    handler = BlockingHandler(threading.Event())
    with gated_server(handler) as (server, endpoint, listener):
        first = authenticated_client(endpoint)
        second = authenticated_client(endpoint)
        wrappers = list(listener.connections)
        assert len(wrappers) == 2, wrappers

        listener.conn_arm.set()
        drainer = _parked_drain(server, listener)

        assert server.active_writers == 0

        start_request(first)
        start_request(second)

        assert wait_for(
            lambda: all(wrapper.send_started.is_set() for wrapper in wrappers)
        ), "both refusals should be in flight"
        assert server.active_responses == 2, (
            f"expected two in-flight refusals, saw {server.active_responses}"
        )

        listener.release.set()
        assert not wait_for(
            lambda: any(wrapper.close_started.is_set() for wrapper in wrappers),
            timeout=0.5,
        ), "the drain closed a transport while refusal frames were in flight"
        assert server.active_responses == 2, "a claim was released too early"
        assert drainer.is_alive()

        listener.conn_release.set()

        for connection in (first, second):
            response = connection.receive(LIMITS, allowed_types=CLIENT_RECEIVE_TYPES)
            assert response.get("type") == MessageType.ERROR.value, response
            assert response.get("error_code") == ErrorCode.NOT_READY.value, response

        drainer.join(10)
        assert not drainer.is_alive()
        assert server.active_responses == 0
