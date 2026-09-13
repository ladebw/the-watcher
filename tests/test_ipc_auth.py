"""IPC authentication, connection limits and replay protection."""

from __future__ import annotations

import contextlib
import os


from the_watcher.exceptions import IpcTransportError, ProtocolError
from the_watcher.ipc.protocol import (
    ErrorCode,
    IpcLimits,
    MessageType,
    build_request,
)
from the_watcher.ipc.server import IpcServer
from the_watcher.ipc.transport import (
    CLIENT_RECEIVE_TYPES,
    IpcListener,
    connect,
    create_endpoint,
)

SESSION_ID = "authtest001"
TOKEN = "test-token-value-that-must-never-be-logged"

LIMITS = IpcLimits(handshake_timeout=3.0, request_timeout=3.0)


class StubHandler:
    """Minimal handler so the server can be tested without a daemon."""

    def __init__(self) -> None:
        self.connected: list[str] = []
        self.authenticated: list[str] = []
        self.disconnected: list[tuple[str, str]] = []
        self.violations: list[tuple[str, str]] = []
        self.requests: list[tuple[str, dict]] = []

    def session_snapshot(self) -> dict:
        return {
            "state": "RUNNING",
            "heartbeat": {"interval": 0, "timeout": 0, "required": False, "action": "record"},
        }

    def dispatch(self, message_type: str, payload: dict, context) -> dict:
        self.requests.append((message_type, dict(payload)))
        if message_type == MessageType.EVALUATE.value:
            return {"decision": "ALLOW", "risk": "NORMAL", "reason": "stub", "rule": "stub"}
        return {"acknowledged": True}

    def on_client_connected(self, context) -> None:
        self.connected.append(context.connection_id)

    def on_client_authenticated(self, context) -> None:
        self.authenticated.append(context.connection_id)

    def on_client_disconnected(self, context, reason) -> None:
        self.disconnected.append((context.connection_id, reason))

    def on_protocol_violation(self, code, detail, context) -> None:
        self.violations.append((code, detail))


@contextlib.contextmanager
def running_server(handler=None, limits=LIMITS, token=TOKEN, session_id=SESSION_ID):
    handler = handler or StubHandler()
    endpoint = create_endpoint(session_id)
    listener = IpcListener(endpoint)
    server = IpcServer(listener, session_id, token, handler, limits).start()
    try:
        yield server, endpoint, handler
    finally:
        server.stop()


def open_client(endpoint):
    return connect(endpoint, timeout=5.0)


def send_hello(connection, *, token=TOKEN, session_id=SESSION_ID, limits=LIMITS, **extra):
    payload = {"pid": os.getpid(), "protocol_version": 1}
    if token is not None:
        payload["token"] = token
    payload.update(extra)
    connection.send(
        build_request(MessageType.HELLO, payload, session_id=session_id), limits
    )
    return read_response(connection, limits)


def read_response(connection, limits=LIMITS):
    """Read one server message, tolerating a closed connection."""
    try:
        return connection.receive(limits, allowed_types=CLIENT_RECEIVE_TYPES)
    except (IpcTransportError, ProtocolError):
        return None


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------


def test_correct_token_authenticates():
    with running_server() as (server, endpoint, handler):
        connection = open_client(endpoint)
        try:
            response = send_hello(connection)
            assert response is not None
            assert response["ok"] is True
            assert response["payload"]["session_id"] == SESSION_ID
            assert response["payload"]["protocol_version"] == 1
            assert len(handler.authenticated) == 1
        finally:
            connection.close()


def test_wrong_token_is_rejected():
    with running_server() as (server, endpoint, handler):
        connection = open_client(endpoint)
        try:
            response = send_hello(connection, token="not-the-right-token")
            assert response is not None
            assert response["ok"] is False
            assert response["error_code"] == ErrorCode.BAD_TOKEN.value
            assert handler.authenticated == []
            assert handler.requests == []
        finally:
            connection.close()


def test_missing_token_is_rejected():
    with running_server() as (server, endpoint, handler):
        connection = open_client(endpoint)
        try:
            response = send_hello(connection, token=None)
            assert response is not None
            assert response["ok"] is False
            assert response["error_code"] == ErrorCode.BAD_TOKEN.value
            assert handler.authenticated == []
        finally:
            connection.close()


def test_non_ascii_token_is_rejected_without_crashing():
    """A non-ASCII candidate must not make compare_digest raise."""
    with running_server() as (server, endpoint, handler):
        connection = open_client(endpoint)
        try:
            response = send_hello(connection, token="\u00fc\u00f6\u00e4" * 4)
            assert response is not None
            assert response["ok"] is False
            assert response["error_code"] == ErrorCode.BAD_TOKEN.value
        finally:
            connection.close()


def test_token_is_never_echoed_back():
    with running_server() as (server, endpoint, handler):
        connection = open_client(endpoint)
        try:
            response = send_hello(connection)
            assert TOKEN not in repr(response)
            connection.send(
                build_request(
                    MessageType.SESSION_STATUS, {}, session_id=SESSION_ID
                ),
                LIMITS,
            )
            follow_up = read_response(connection)
            assert TOKEN not in repr(follow_up)
        finally:
            connection.close()


def test_session_id_mismatch_is_rejected():
    with running_server() as (server, endpoint, handler):
        connection = open_client(endpoint)
        try:
            response = send_hello(connection, session_id="othersess01")
            assert response is not None
            assert response["ok"] is False
            assert response["error_code"] == ErrorCode.SESSION_MISMATCH.value
        finally:
            connection.close()


def test_first_message_must_be_hello():
    with running_server() as (server, endpoint, handler):
        connection = open_client(endpoint)
        try:
            connection.send(
                build_request(
                    MessageType.EVALUATE,
                    {"event_type": "file_access", "action": "read"},
                    session_id=SESSION_ID,
                ),
                LIMITS,
            )
            response = read_response(connection)
            assert response is not None
            assert response["ok"] is False
            assert response["error_code"] == ErrorCode.UNAUTHENTICATED.value
            assert handler.requests == []
        finally:
            connection.close()


def test_client_info_is_reduced_to_an_allowlist():
    """Client-supplied metadata must not become an arbitrary channel into the trace."""
    with running_server() as (server, endpoint, handler):
        connection = open_client(endpoint)
        try:
            response = send_hello(
                connection,
                client={
                    "python": "3.14.3",
                    "platform": "win32",
                    "token": TOKEN,
                    "secret_note": "arbitrary client string",
                    "nested": {"deep": "value"},
                },
            )
            assert response["ok"] is True

            contexts = server.client_contexts()
            assert len(contexts) == 1
            info = contexts[0]["client_info"]
            assert info["python"] == "3.14.3"
            assert info["platform"] == "win32"
            assert "secret_note" not in info
            assert "nested" not in info
            assert "token" not in info
            assert TOKEN not in repr(server.client_contexts())
        finally:
            connection.close()


def test_authenticated_client_can_issue_requests():
    with running_server() as (server, endpoint, handler):
        connection = open_client(endpoint)
        try:
            assert send_hello(connection)["ok"] is True
            connection.send(
                build_request(
                    MessageType.EVALUATE,
                    {"event_type": "file_access", "action": "read"},
                    session_id=SESSION_ID,
                ),
                LIMITS,
            )
            response = read_response(connection)
            assert response["ok"] is True
            assert response["payload"]["decision"] == "ALLOW"
            assert handler.requests[-1][0] == "EVALUATE"
        finally:
            connection.close()


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------


def test_duplicate_request_id_is_rejected():
    with running_server() as (server, endpoint, handler):
        connection = open_client(endpoint)
        try:
            assert send_hello(connection)["ok"] is True

            request = build_request(
                MessageType.HEARTBEAT, {}, session_id=SESSION_ID
            )
            connection.send(request, LIMITS)
            first = read_response(connection)
            assert first["ok"] is True

            connection.send(request, LIMITS)  # identical request_id
            second = read_response(connection)
            assert second["ok"] is False
            assert second["error_code"] == ErrorCode.REPLAYED_REQUEST.value
        finally:
            connection.close()


def test_distinct_request_ids_are_all_served():
    with running_server() as (server, endpoint, handler):
        connection = open_client(endpoint)
        try:
            assert send_hello(connection)["ok"] is True
            for _ in range(10):
                connection.send(
                    build_request(MessageType.HEARTBEAT, {}, session_id=SESSION_ID),
                    LIMITS,
                )
                assert read_response(connection)["ok"] is True
            assert len(handler.requests) == 10
        finally:
            connection.close()


# ---------------------------------------------------------------------------
# Connection limits
# ---------------------------------------------------------------------------


def test_connection_limit_is_enforced():
    limits = IpcLimits(
        handshake_timeout=3.0, request_timeout=3.0, max_connections_per_session=1
    )
    with running_server(limits=limits) as (server, endpoint, handler):
        first = open_client(endpoint)
        try:
            assert send_hello(first, limits=limits)["ok"] is True

            second = open_client(endpoint)
            try:
                response = read_response(second, limits)
                # Either an explicit refusal or an immediate close is correct;
                # what matters is that the second client is not served.
                if response is not None:
                    assert response["ok"] is False
                    assert response["error_code"] in {
                        ErrorCode.TOO_MANY_CONNECTIONS.value,
                        ErrorCode.BAD_TOKEN.value,
                    }
            finally:
                second.close()

            assert server.stats()["rejected_connections"] >= 1
        finally:
            first.close()


def test_protocol_violations_are_reported_to_the_handler():
    limits = IpcLimits(handshake_timeout=3.0, max_message_bytes=2048)
    with running_server(limits=limits) as (server, endpoint, handler):
        connection = open_client(endpoint)
        try:
            # A well-formed HELLO, then an oversized frame.
            assert send_hello(connection, limits=limits)["ok"] is True
            connection.send(
                build_request(
                    MessageType.EVENT,
                    {"event_type": "tool_request", "action": "big", "resource": "x" * 20000},
                    session_id=SESSION_ID,
                ),
                IpcLimits(),
            )
            # The server refuses the frame; it either returns an error or drops
            # the connection, but it must not be desynchronised by the leftovers.
            response = read_response(connection, limits)
            if response is not None:
                assert response["ok"] is False
        finally:
            connection.close()

        import time

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not handler.violations:
            time.sleep(0.02)

    assert handler.violations, "oversized frame should be reported as a violation"
    assert any(code == "MESSAGE_TOO_LARGE" for code, _ in handler.violations)


def test_server_stop_releases_the_endpoint():
    with running_server() as (server, endpoint, handler):
        assert server.running
    assert not server.running
