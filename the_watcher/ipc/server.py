"""Authenticated local IPC server.

Responsibilities, and nothing else:

* bind a local-only endpoint and accept connections;
* refuse connections beyond the per-session limit;
* require an authenticated ``HELLO`` carrying the session token before any
  other message is honoured;
* bound every message (size, depth, string length, item count) before it
  reaches the daemon;
* drop replayed request ids;
* hand valid requests to the daemon's handler and return its response.

The server holds no policy, no trace and no kill logic. It is the *transport*
half of the trust boundary; the daemon is the *authority* half.
"""

from __future__ import annotations

import enum
import hmac
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..exceptions import IpcDrainTimeout, IpcTransportError, ProtocolError
from .protocol import (
    CLIENT_MESSAGE_TYPES,
    ErrorCode,
    IpcLimits,
    MessageType,
    build_error,
    build_response,
    sanitize_text,
)
from .transport import IpcConnection, IpcListener, LocalEndpoint

__all__ = ["ClientContext", "DrainOutcome", "IpcServer", "ServerState"]

#: How long :meth:`IpcServer.drain` waits for authoritative writers by default.
#: Bounded on purpose: a wedged worker must not be able to hang the Watcher.
DEFAULT_DRAIN_TIMEOUT = 5.0


class ServerState(str, enum.Enum):
    """Lifecycle of the IPC transport.

    ``RUNNING`` accepts work. ``DRAINING`` refuses to start a new handler but
    lets the ones already in flight finish. ``STOPPED`` means every worker is
    gone and no further authoritative write can occur.
    """

    NEW = "NEW"
    RUNNING = "RUNNING"
    DRAINING = "DRAINING"
    STOPPED = "STOPPED"


@dataclass(frozen=True)
class DrainOutcome:
    """What happened when the authoritative writers were drained."""

    drained: bool
    forced: bool
    active_writers: int
    remaining_workers: tuple[str, ...]
    elapsed: float

    def describe(self) -> str:
        if self.drained:
            return f"all IPC writers stopped in {self.elapsed:.3f}s"
        return (
            f"IPC drain timed out after {self.elapsed:.3f}s with "
            f"{self.active_writers} writer(s) mid-append and "
            f"{len(self.remaining_workers)} worker(s) alive: "
            f"{', '.join(self.remaining_workers) or 'none named'}"
        )

#: Handshake fields that are safe to copy into the audit trail.  Anything else
#: a client sends about itself is discarded: unvalidated client strings would
#: otherwise be a way to smuggle arbitrary content (including a token) into the
#: trace.
_SAFE_CLIENT_FIELDS = ("python", "platform", "runtime")


def _safe_client_info(info: Any) -> dict[str, Any]:
    """Reduce client-supplied handshake metadata to a bounded allowlist."""
    if not isinstance(info, Mapping):
        return {}
    safe: dict[str, Any] = {}
    for key in _SAFE_CLIENT_FIELDS:
        if key not in info:
            continue
        value = info[key]
        if isinstance(value, str):
            safe[key] = sanitize_text(value, 64)
        elif isinstance(value, bool):
            safe[key] = value
        elif isinstance(value, (int, float)):
            safe[key] = value
    return safe


@dataclass
class ClientContext:
    """Identity of one connected client, for lifecycle records."""

    session_id: str
    connection_id: str
    client_pid: "int | None" = None
    client_version: "int | None" = None
    client_info: Mapping[str, Any] = field(default_factory=dict)
    authenticated: bool = False
    connected_at: int = 0
    authenticated_at: "int | None" = None
    requests_served: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Safe, token-free description of the client."""
        return {
            "connection_id": self.connection_id,
            "client_pid": self.client_pid,
            "client_version": self.client_version,
            "client_info": dict(self.client_info),
            "connected_at": self.connected_at,
            "requests_served": self.requests_served,
        }


class IpcServer:
    """Accept loop, authentication and request dispatch."""

    def __init__(
        self,
        listener: IpcListener,
        session_id: str,
        token: str,
        handler: Any,
        limits: "IpcLimits | None" = None,
        clock: "Any | None" = None,
    ) -> None:
        if not token:
            raise IpcTransportError("an IPC server requires a session token")

        self._listener = listener
        self._endpoint: LocalEndpoint = listener.endpoint
        self._session_id = session_id
        self._token = token
        self._handler = handler
        self._limits = limits or IpcLimits()
        self._limits.validate()
        self._clock = clock or time.time

        self._stopping = threading.Event()
        #: Set at the end of :meth:`drain`, once no further request can be
        #: admitted. A worker keys its read loop off *this* rather than
        #: ``_stopping``: during a drain a request is refused, not dropped, so
        #: the connection must stay answerable until the drain is over.
        self._drained = threading.Event()
        self._threads_lock = threading.Lock()
        #: Guards the authoritative-writer count. Shares the thread lock so a
        #: state change and a writer claim cannot interleave.
        self._writers_cv = threading.Condition(self._threads_lock)
        self._state = ServerState.NEW
        #: Handlers currently inside ``dispatch``. Non-zero means an event may
        #: still be appended, so sealing is not yet safe.
        self._writers = 0
        #: Response frames currently being written, including ``NOT_READY``
        #: refusals. This is deliberately *not* the same counter as ``_writers``:
        #: a refusal dispatched nothing, so it holds no writer claim, but its
        #: frame is on the wire and tearing the transport down mid-send
        #: truncates it. Transport teardown waits for this to reach zero.
        self._responses = 0
        #: Set by the drain once it has stopped waiting for writers, so that no
        #: new response claim can be taken between the final check and the
        #: teardown. Without it, a refusal could begin in that gap and be cut.
        self._claims_closed = False
        self._connections: dict[str, IpcConnection] = {}
        self._contexts: dict[str, ClientContext] = {}
        self._accept_thread: "threading.Thread | None" = None
        self._workers: list[threading.Thread] = []
        self._started = False
        self._rejected_connections = 0
        self._protocol_violations = 0
        self._replayed_requests = 0
        # Bounded, insertion-ordered, shared across connections so a request id
        # cannot be replayed on a second connection either.
        self._replay_cache: "OrderedDict[str, bool]" = OrderedDict()

    # -- accessors -------------------------------------------------------

    @property
    def endpoint(self) -> LocalEndpoint:
        return self._endpoint

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def limits(self) -> IpcLimits:
        return self._limits

    @property
    def state(self) -> ServerState:
        return self._state

    @property
    def running(self) -> bool:
        return self._state is ServerState.RUNNING

    @property
    def active_writers(self) -> int:
        """Handlers currently mid-append. Must be zero before sealing."""
        with self._writers_cv:
            return self._writers

    @property
    def active_responses(self) -> int:
        """Response frames currently being written, refusals included.

        Every admitted request holds one of these for its whole
        request/response cycle, and every ``NOT_READY`` refusal holds one for
        the duration of its send. The drain waits for this to reach zero before
        it closes any transport, which is what stops teardown from racing a
        reply that is halfway out.
        """
        with self._writers_cv:
            return self._responses

    @property
    def connection_count(self) -> int:
        with self._threads_lock:
            return len(self._connections)

    @property
    def authenticated_count(self) -> int:
        with self._threads_lock:
            return sum(1 for context in self._contexts.values() if context.authenticated)

    def stats(self) -> dict[str, Any]:
        """Token-free counters for the session metadata."""
        return {
            "rejected_connections": self._rejected_connections,
            "protocol_violations": self._protocol_violations,
            "replayed_requests": self._replayed_requests,
            "connections": self.connection_count,
        }

    def client_contexts(self) -> list[dict[str, Any]]:
        with self._threads_lock:
            return [context.to_dict() for context in self._contexts.values()]

    # -- lifecycle -------------------------------------------------------

    def start(self) -> "IpcServer":
        if self._started:
            return self
        self._started = True
        self._state = ServerState.RUNNING
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="watcher-ipc-accept", daemon=True
        )
        self._accept_thread.start()
        return self

    def _wake_accept(self) -> None:
        """Unblock a pending ``accept()``.

        On Windows ``accept`` has no timeout, so the portable way to wake it is
        a throwaway connection.
        """
        try:
            from .transport import connect as _connect

            probe = _connect(self._endpoint, timeout=0.5)
            probe.close()
        except Exception:  # noqa: BLE001 - best effort, never fatal
            pass

    def drain(self, timeout: float = DEFAULT_DRAIN_TIMEOUT) -> DrainOutcome:
        """Stop accepting work and wait for every authoritative writer to go.

        The sequence is the point of the method:

        1. move to ``DRAINING`` under the writer condition, so no *new* handler
           can start and therefore no new append can begin;
        2. wake and join the accept loop, so no new connection can arrive;
        3. wait for the in-flight writers to finish — **before** any transport is
           touched, so a request that arrives during the drain is still answered
           with a deterministic refusal rather than racing the teardown;
        4. close the refusal window and wait for the responses already in flight
           — including ``NOT_READY`` frames — to be written, so teardown can
           never truncate a reply;
        5. release the parked workers and close the accepted transports, which
           unblocks a worker sitting in a read;
        6. wait for the workers to exit — their teardown is what records
           ``client_disconnected``, and a live worker could still be doing it;
        7. wait once more for the in-flight writer count to reach zero.

        The cutover, stated as rules rather than as a sequence, because these
        are the properties a caller depends on:

        * while the response-claim window is open, a request that arrives on an
          already-established connection while DRAINING receives a complete
          ``NOT_READY`` frame, and is never dispatched;
        * the window is closed atomically under the writer condition, so once it
          is closed no further response claim is admitted - a frame cannot begin
          in the gap between the final check and the teardown;
        * teardown then waits for the responses already claimed to be written,
          bounded by the drain deadline, so an in-flight reply is never
          truncated;
        * a request is never dispatched after ``DRAINING`` begins: admission is
          decided in exactly one place, ``_begin_write``, under the same
          condition that performs the transition, so a request racing it has one
          outcome or the other and never both.

        Steps 4 and 6 are both required: a worker can be alive without writing,
        and a writer can be mid-append on a worker that is about to exit. Only
        when both are clear is it safe to seal the trace.

        Step 3 preceding step 5 is what makes the shutdown race-free. Closing the
        transports is what unblocks a worker parked in a read, but doing it at
        the instant draining began - while a writer was still mid-append -
        destroyed the very connection a client needs in order to be refused, so a
        request arriving in that window raced the teardown and observed a
        connection reset instead of ``NOT_READY``. A connection that is still
        open can refuse deterministically; one that has been closed can only
        drop. Step 4 closes the same hole for refusals: those frames are on the
        wire too, and they hold a response claim so teardown must wait for them.

        Bounded and non-raising: an unclean drain is reported through
        :class:`DrainOutcome` so that :meth:`stop` can turn it into an explicit
        failure and the supervisor can decide what to record. A wedge is never
        allowed to hang the Watcher.
        """
        started = time.monotonic()
        deadline = started + max(0.0, timeout)

        with self._writers_cv:
            if self._state is ServerState.STOPPED:
                self._drained.set()
                return DrainOutcome(True, False, 0, (), 0.0)
            self._state = ServerState.DRAINING
            self._stopping.set()
            connections = list(self._connections.values())
            self._connections.clear()

        self._wake_accept()

        accept_thread = self._accept_thread
        if accept_thread is not None and accept_thread.is_alive():
            accept_thread.join(max(0.0, min(timeout, 2.0)))

        # Only the accept loop registers workers, so once it has stopped the
        # set below is final.
        with self._writers_cv:
            workers = list(self._workers)
            self._workers.clear()
            connections.extend(self._connections.values())
            self._connections.clear()

        # Wait for the in-flight writers before closing anything, so that a
        # request arriving during the drain is answered instead of reset. The
        # condition releases the lock while waiting, so ``_begin_write`` can
        # still admit/refuse in parallel - and refuses, because the state is
        # already DRAINING.
        try:
            with self._writers_cv:
                while self._writers > 0:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    self._writers_cv.wait(min(remaining, 0.25))

            # Writers are done, so the window in which a request can be *refused*
            # is about to close. Shut it under the same lock, and then wait for
            # the responses already being written - refusals included - to
            # finish. Closing the claim window before the final check is what
            # removes the last gap: a claim can no longer be taken between
            # observing zero and tearing the transports down.
            with self._writers_cv:
                self._claims_closed = True
                while self._responses > 0:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    self._writers_cv.wait(min(remaining, 0.25))
        finally:
            # Whatever happened above, no further request will be answered, so
            # the parked workers must be released rather than left waiting for
            # work that can never be admitted.
            self._drained.set()

        for connection in connections:
            try:
                connection.close()
            except Exception:  # noqa: BLE001
                pass

        # Join outside the condition: _end_write() needs the same lock to
        # decrement the writer count, so holding it here would deadlock.
        for worker in workers:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if worker.is_alive():
                worker.join(remaining)

        with self._writers_cv:
            while self._writers > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._writers_cv.wait(min(remaining, 0.25))
            active = self._writers

        remaining_workers = tuple(w.name for w in workers if w.is_alive())
        drained = active == 0 and not remaining_workers
        forced = False

        if not drained:
            # Force the transports shut so a wedged worker cannot hold the
            # session open. This is not what keeps the trace sound — the
            # sealed-append guard in the PoE layer is — but it bounds the
            # damage and gets the worker to exit.
            forced = True
            for connection in connections:
                try:
                    connection.close()
                except Exception:  # noqa: BLE001
                    pass
            grace = min(0.5, max(0.0, deadline - time.monotonic()))
            if grace > 0:
                for worker in workers:
                    if worker.is_alive():
                        worker.join(grace)

        try:
            self._listener.close()
        except Exception:  # noqa: BLE001
            pass

        with self._writers_cv:
            active = self._writers
            remaining_workers = tuple(w.name for w in workers if w.is_alive())
            drained = active == 0 and not remaining_workers
            if drained:
                self._state = ServerState.STOPPED

        return DrainOutcome(
            drained=drained,
            forced=forced,
            active_writers=active,
            remaining_workers=remaining_workers,
            elapsed=time.monotonic() - started,
        )

    def stop(self, timeout: float = DEFAULT_DRAIN_TIMEOUT) -> DrainOutcome:
        """Drain, and refuse to pretend a dirty shutdown was a clean one.

        Raises :class:`IpcDrainTimeout` when a writer is still active past the
        deadline. Returning quietly would let the caller proceed to seal a
        trace that a worker could still be appending to.
        """
        outcome = self.drain(timeout)
        if not outcome.drained:
            raise IpcDrainTimeout(
                f"IPC drain did not complete: {outcome.describe()}",
                list(outcome.remaining_workers),
            )
        return outcome

    # -- accept loop -----------------------------------------------------

    def _accept_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                connection = self._listener.accept()
            except IpcTransportError:
                if self._stopping.is_set():
                    break
                continue
            except Exception:  # noqa: BLE001 - the listener is gone
                break

            if self._stopping.is_set():
                connection.close()
                break

            with self._threads_lock:
                at_capacity = (
                    len(self._connections) >= self._limits.max_connections_per_session
                )
                if not at_capacity:
                    connection_id = uuid.uuid4().hex
                    self._connections[connection_id] = connection
                    self._contexts[connection_id] = ClientContext(
                        session_id=self._session_id,
                        connection_id=connection_id,
                        connected_at=int(self._clock()),
                    )
                else:
                    self._rejected_connections += 1

            if at_capacity:
                self._reject(connection, ErrorCode.TOO_MANY_CONNECTIONS)
                continue

            worker = threading.Thread(
                target=self._serve_connection,
                args=(connection_id, connection),
                name=f"watcher-ipc-{connection_id[:8]}",
                daemon=True,
            )
            with self._threads_lock:
                self._workers.append(worker)
            worker.start()

    def _reject(self, connection: IpcConnection, code: ErrorCode) -> None:
        try:
            connection.send(
                build_error(None, code, "connection refused"), self._limits
            )
        except Exception:  # noqa: BLE001
            pass
        connection.close()

    # -- per-connection handling -----------------------------------------

    def _serve_connection(self, connection_id: str, connection: IpcConnection) -> None:
        with self._threads_lock:
            context = self._contexts[connection_id]

        reason = "closed"
        try:
            self._call_hook("on_client_connected", context)

            if not self._handshake(connection, context):
                return

            reason = "client_closed"
            # This loop deliberately keys off ``_drained`` rather than
            # ``_stopping``.
            #
            # Draining is a state in which requests are *refused*, not a state
            # in which the connection vanishes. Exiting here as soon as
            # ``_stopping`` was set meant a request that arrived moments after
            # the drain began was dropped along with the socket instead of being
            # answered - and whether a client saw the ``NOT_READY`` refusal or a
            # connection reset depended purely on where this worker happened to
            # be when the transition landed. Staying parked until the drain is
            # actually over makes the outcome deterministic: every request that
            # arrives while the connection is open reaches ``_begin_write`` and
            # receives exactly one answer.
            while not self._drained.is_set():
                if not connection.poll(self._limits.idle_poll):
                    continue
                self._serve_one(connection, context)

        except ProtocolError as exc:
            self._protocol_violations += 1
            self._call_hook(
                "on_protocol_violation",
                exc.code,
                sanitize_text(str(exc)),
                context,
            )
            try:
                connection.send(
                    build_error(None, exc.code, "request rejected"), self._limits
                )
            except Exception:  # noqa: BLE001
                pass
            reason = f"protocol_violation:{exc.code}"
        except IpcTransportError:
            reason = "transport_error"
        except Exception as exc:  # noqa: BLE001 - never let a client kill the daemon
            reason = f"internal_error:{type(exc).__name__}"
        finally:
            connection.close()
            with self._threads_lock:
                self._connections.pop(connection_id, None)
                self._contexts.pop(connection_id, None)
            self._call_hook("on_client_disconnected", context, reason)

    def _handshake(self, connection: IpcConnection, context: ClientContext) -> bool:
        """Require an authenticated HELLO before anything else."""
        if not connection.poll(self._limits.handshake_timeout):
            return False

        message = connection.receive(
            self._limits,
            allowed_types=CLIENT_MESSAGE_TYPES,
            require_request_id=False,
        )
        if message.get("type") != MessageType.HELLO.value:
            raise ProtocolError(
                ErrorCode.UNAUTHENTICATED, "first message must be HELLO"
            )

        payload = message.get("payload") or {}
        session_id = message.get("session_id")
        if session_id is not None and session_id != self._session_id:
            raise ProtocolError(ErrorCode.SESSION_MISMATCH, "unknown session")

        if not self._token_matches(payload.get("token")):
            raise ProtocolError(ErrorCode.BAD_TOKEN, "authentication failed")

        context.authenticated = True
        context.authenticated_at = int(self._clock())
        context.client_pid = payload.get("pid") if isinstance(payload.get("pid"), int) else None
        context.client_version = (
            payload.get("protocol_version")
            if isinstance(payload.get("protocol_version"), int)
            else None
        )
        info = payload.get("client")
        context.client_info = _safe_client_info(info)

        self._call_hook("on_client_authenticated", context)

        snapshot = self._call_hook("session_snapshot") or {}
        connection.send(
            build_response(
                message.get("request_id"),
                {
                    "session_id": self._session_id,
                    "protocol_version": 1,
                    "state": snapshot.get("state", "RUNNING"),
                    "heartbeat": snapshot.get("heartbeat", {}),
                    "server_time": int(self._clock()),
                },
            ),
            self._limits,
        )
        return True

    def _token_matches(self, candidate: Any) -> bool:
        if not isinstance(candidate, str) or not candidate:
            return False
        # compare_digest rejects non-ASCII strings, so screen first.
        if not candidate.isascii():
            return False
        return hmac.compare_digest(candidate, self._token)

    def _serve_one(self, connection: IpcConnection, context: ClientContext) -> None:
        try:
            message = connection.receive(
                self._limits,
                allowed_types=CLIENT_MESSAGE_TYPES,
                require_request_id=True,
            )
        except ProtocolError as exc:
            self._protocol_violations += 1
            self._call_hook("on_protocol_violation", exc.code, sanitize_text(str(exc)), context)
            try:
                connection.send(
                    build_error(None, exc.code, "request rejected"), self._limits
                )
            except Exception:  # noqa: BLE001
                pass
            if exc.fatal:
                # The frame was not fully drained, so the next "message" would
                # be the tail of this one. Refuse to resynchronise.
                connection.close()
                raise IpcTransportError(
                    f"fatal protocol violation: {exc.code}"
                ) from exc
            return

        message_type = message["type"]
        request_id = message.get("request_id")
        session_id = message.get("session_id")

        if session_id is not None and session_id != self._session_id:
            connection.send(
                build_error(request_id, ErrorCode.SESSION_MISMATCH, "unknown session"),
                self._limits,
            )
            return

        if message_type == MessageType.HELLO.value:
            connection.send(
                build_error(request_id, ErrorCode.BAD_REQUEST, "already authenticated"),
                self._limits,
            )
            return

        if not self._remember_request(context, request_id):
            self._replayed_requests += 1
            self._call_hook(
                "on_protocol_violation",
                ErrorCode.REPLAYED_REQUEST.value,
                f"duplicate request_id {sanitize_text(request_id, 40)}",
                context,
            )
            connection.send(
                build_error(
                    request_id, ErrorCode.REPLAYED_REQUEST, "duplicate request id"
                ),
                self._limits,
            )
            return

        payload = message.get("payload") or {}
        if not self._begin_write():
            # Draining. Refusing here is what guarantees that no *new*
            # authoritative write can start once shutdown has begun. The reply
            # goes out under its own in-flight claim so the drain cannot cut it.
            self._send_refusal(connection, request_id)
            return

        # The writer claim is held for the whole request/response cycle, not
        # merely across ``dispatch``. Releasing it before the reply was written
        # let the drain observe "no active writers", close the transport, and
        # destroy the reply to a request that had legitimately been admitted -
        # the other half of the shutdown race, landing on a client that did
        # nothing wrong. "Admitted before draining" must mean "completes
        # normally", which is only true if the claim outlives the send.
        try:
            try:
                result = self._handler.dispatch(message_type, payload, context)
            except ProtocolError as exc:
                connection.send(
                    build_error(request_id, exc.code, "request rejected"), self._limits
                )
                return
            except Exception as exc:  # noqa: BLE001
                # Never leak internals to the client; the daemon logs internally.
                self._call_hook(
                    "on_handler_error",
                    type(exc).__name__,
                    sanitize_text(str(exc)),
                    context,
                )
                connection.send(
                    build_error(
                        request_id, ErrorCode.INTERNAL_ERROR, "internal error"
                    ),
                    self._limits,
                )
                return

            context.requests_served += 1
            connection.send(
                build_response(
                    request_id, result if isinstance(result, Mapping) else {}
                ),
                self._limits,
            )
        finally:
            self._end_write()

    def _begin_write(self) -> bool:
        """Claim the right to run one authoritative handler, or refuse.

        Returns ``False`` once the server is draining. Counting writers — as
        opposed to inferring safety from thread liveness — is what makes
        "no active authoritative writer before seal" a property the shutdown
        can actually check.

        The admitted request also takes a *response* claim, because the drain
        has to wait for the reply to be written and not merely for the handler to
        return; otherwise it can close the transport under its own reply.
        """
        with self._writers_cv:
            if self._state is not ServerState.RUNNING or self._claims_closed:
                return False
            self._writers += 1
            self._responses += 1
            return True

    def _end_write(self) -> None:
        with self._writers_cv:
            self._writers -= 1
            self._responses -= 1
            self._writers_cv.notify_all()

    def _send_refusal(self, connection: IpcConnection, request_id: "str | None") -> None:
        """Write a ``NOT_READY`` refusal under an in-flight response claim.

        A refusal dispatched nothing, so it takes no *writer* claim. It does
        have to reach the client in one piece, though, and without a claim the
        drain could observe no writers, conclude it was finished, and close the
        transport underneath a frame that was halfway out — the same
        client-visible reset this path exists to remove, just at a narrower
        boundary.

        If the claim window has already closed then the teardown has begun, and
        no frame is written at all: a clean close is a better answer than a
        truncated one.
        """
        with self._writers_cv:
            if self._claims_closed:
                return
            self._responses += 1
        try:
            connection.send(
                build_error(
                    request_id,
                    ErrorCode.NOT_READY,
                    "server is shutting down",
                ),
                self._limits,
            )
        except Exception:  # noqa: BLE001
            pass
        finally:
            with self._writers_cv:
                self._responses -= 1
                self._writers_cv.notify_all()

    def _remember_request(self, context: ClientContext, request_id: "str | None") -> bool:
        """Return ``False`` for a replayed request id."""
        if not request_id:
            return True
        cache = self._replay_cache
        if request_id in cache:
            return False
        cache[request_id] = True
        while len(cache) > self._limits.replay_cache_size:
            cache.popitem(last=False)
        return True

    # -- hooks -----------------------------------------------------------

    def _call_hook(self, name: str, *args: Any) -> Any:
        hook = getattr(self._handler, name, None)
        if hook is None:
            return None
        try:
            return hook(*args)
        except Exception:  # noqa: BLE001 - a broken hook must not kill the server
            return None

    def __repr__(self) -> str:
        return (
            f"<IpcServer {self._endpoint.display} "
            f"connections={self.connection_count} running={self.running}>"
        )
