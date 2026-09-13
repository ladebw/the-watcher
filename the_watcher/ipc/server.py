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

import hmac
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..exceptions import IpcTransportError, ProtocolError
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

__all__ = ["ClientContext", "IpcServer"]

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
        self._threads_lock = threading.Lock()
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
    def running(self) -> bool:
        return self._started and not self._stopping.is_set()

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
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="watcher-ipc-accept", daemon=True
        )
        self._accept_thread.start()
        return self

    def stop(self, timeout: float = 2.0) -> None:
        """Stop accepting, drop clients and release the endpoint."""
        if self._stopping.is_set():
            return
        self._stopping.set()

        # Unblock a pending accept() deterministically: on Windows the accept
        # call has no timeout, so we wake it with a throwaway connection.
        try:
            from .transport import connect as _connect

            probe = _connect(self._endpoint, timeout=0.5)
            probe.close()
        except Exception:  # noqa: BLE001 - best effort, never fatal
            pass

        thread = self._accept_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout)

        with self._threads_lock:
            connections = list(self._connections.values())
            self._connections.clear()
            workers = list(self._workers)
            self._workers.clear()

        for connection in connections:
            connection.close()

        # Wait for connection threads to finish. This matters for correctness:
        # a worker records lifecycle events (client_disconnected), and the
        # daemon must be sure no further event can be appended before it seals
        # the trace. Without this join, a late worker could append after the
        # seal and invalidate the declared final hash.
        deadline = time.monotonic() + max(0.0, timeout)
        for worker in workers:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if worker.is_alive():
                worker.join(remaining)

        self._listener.close()

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
            while not self._stopping.is_set():
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
                "on_handler_error", type(exc).__name__, sanitize_text(str(exc)), context
            )
            connection.send(
                build_error(request_id, ErrorCode.INTERNAL_ERROR, "internal error"),
                self._limits,
            )
            return

        context.requests_served += 1
        connection.send(
            build_response(request_id, result if isinstance(result, Mapping) else {}),
            self._limits,
        )

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
