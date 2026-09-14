"""Local IPC transport: endpoint choice, framing, limits and pickle-freedom."""

from __future__ import annotations

import contextlib
import os
import pathlib
import threading

import pytest

from the_watcher.exceptions import IpcTransportError, ProtocolError
from the_watcher.ipc.protocol import IpcLimits, MessageType, build_request
from the_watcher.ipc.transport import (
    PIPE_PREFIX,
    IpcListener,
    connect,
    create_endpoint,
    default_family,
)

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]


@contextlib.contextmanager
def ipc_pair(session_id: str = "testsession", limits: "IpcLimits | None" = None):
    """Yield (server_connection, client_connection, limits)."""
    limits = limits or IpcLimits(handshake_timeout=3.0, request_timeout=3.0)
    endpoint = create_endpoint(session_id)
    listener = IpcListener(endpoint)
    accepted: dict = {}

    def _accept() -> None:
        try:
            accepted["connection"] = listener.accept()
        except Exception as exc:  # noqa: BLE001
            accepted["error"] = exc

    thread = threading.Thread(target=_accept, daemon=True)
    thread.start()
    client = connect(endpoint, timeout=5.0)
    thread.join(5)

    assert "error" not in accepted, accepted.get("error")
    server = accepted.get("connection")
    assert server is not None
    try:
        yield server, client, limits
    finally:
        for connection in (server, client):
            try:
                connection.close()
            except Exception:  # noqa: BLE001
                pass
        listener.close()


# ---------------------------------------------------------------------------
# Endpoint selection
# ---------------------------------------------------------------------------


def test_default_family_is_a_local_family():
    family = default_family()
    assert family in {"AF_PIPE", "AF_UNIX"}
    if os.name == "nt":
        assert family == "AF_PIPE"
    else:
        assert family == "AF_UNIX"


def test_no_tcp_transport_is_implemented():
    """A loopback TCP fallback must not exist: the daemon is local-only."""
    source = (PROJECT_ROOT / "the_watcher" / "ipc" / "transport.py").read_text(
        encoding="utf-8"
    )
    assert "AF_INET" not in source
    assert "127.0.0.1" not in source
    assert "localhost" not in source


def test_no_pickle_is_used_by_the_transport():
    """Nothing crossing the boundary may be deserialised as a Python object."""
    banned = (
        "import pickle",
        "from pickle",
        "pickle.load",
        "pickle.dump",
        "import marshal",
        "from marshal",
        "marshal.load",
        "yaml.load",
        "eval(",
        "exec(",
    )
    for name in ("transport.py", "protocol.py", "server.py", "client.py"):
        source = (PROJECT_ROOT / "the_watcher" / "ipc" / name).read_text(encoding="utf-8")
        for token in banned:
            assert token not in source, f"{name} must not use {token!r}"


def test_named_pipe_endpoint_names_are_namespaced():
    endpoint = create_endpoint("abcdef123456")
    assert endpoint.family == default_family()
    if os.name == "nt":
        assert endpoint.address.startswith(PIPE_PREFIX)
    assert "the-watcher" in endpoint.address
    assert endpoint.display.startswith(("pipe:", "unix:"))


def test_endpoints_are_unique_per_session():
    first = create_endpoint("sessionaaa")
    second = create_endpoint("sessionaaa")
    assert first.address != second.address


def test_invalid_session_id_is_rejected():
    with pytest.raises(IpcTransportError):
        create_endpoint("bad session id")


def test_unsupported_family_is_rejected():
    with pytest.raises(IpcTransportError):
        create_endpoint("goodsession", family="AF_INET")


# ---------------------------------------------------------------------------
# Framing round trips
# ---------------------------------------------------------------------------


def test_message_round_trip_over_the_local_endpoint():
    with ipc_pair() as (server, client, limits):
        client.send({**build_request(MessageType.HEARTBEAT, {}, "testsession")}, limits)
        received = server.receive(limits)
        assert received["type"] == "HEARTBEAT"
        assert received["version"] == 1


def test_unicode_survives_the_round_trip():
    with ipc_pair() as (server, client, limits):
        client.send(
            build_request(
                MessageType.EVENT,
                {"event_type": "tool_request", "action": "invoke", "resource": "caf\u00e9 \u2713"},
                "testsession",
            ),
            limits,
        )
        assert server.receive(limits)["payload"]["resource"] == "caf\u00e9 \u2713"


def test_many_messages_preserve_order():
    with ipc_pair() as (server, client, limits):
        for index in range(25):
            client.send(
                build_request(
                    MessageType.EVENT,
                    {"event_type": "tool_request", "action": f"call-{index}"},
                    "testsession",
                ),
                limits,
            )
        actions = [server.receive(limits)["payload"]["action"] for _ in range(25)]
        assert actions == [f"call-{index}" for index in range(25)]


def test_peer_disconnect_is_reported_as_a_transport_error():
    with ipc_pair() as (server, client, limits):
        client.close()
        assert server.poll(2.0) in (False, True)
        with pytest.raises((IpcTransportError, ProtocolError)):
            server.receive(limits)


# ---------------------------------------------------------------------------
# Limits on the wire
# ---------------------------------------------------------------------------


def test_sender_refuses_to_exceed_its_own_message_limit():
    limits = IpcLimits(max_message_bytes=1024)
    with ipc_pair(limits=limits) as (server, client, limits):
        with pytest.raises(ProtocolError) as excinfo:
            client.send(
                build_request(
                    MessageType.EVENT,
                    {"event_type": "tool_request", "action": "big", "resource": "x" * 5000},
                    "testsession",
                ),
                limits,
            )
        assert excinfo.value.code == "MESSAGE_TOO_LARGE"


def test_receiver_refuses_an_oversized_frame_without_crashing():
    """A hostile peer cannot make the daemon allocate an unbounded message.

    The frame must exceed the *receiver's* limit but still fit in the pipe's
    kernel buffer. A frame larger than that buffer deadlocks the test rather
    than exercising the receiver: the sender blocks inside ``send_bytes`` with
    a partially written frame, the receiver reads the length prefix, refuses
    the frame *without draining its body*, and the sender is left writing into
    a pipe nobody will ever read again. On Windows that pending overlapped
    write waits forever, which is what hung CI for 95 minutes.

    Exceeding the limit by better than 2x keeps the assertion identical while
    making the send unbounded-block-free on every platform.
    """
    strict = IpcLimits(max_message_bytes=1024, handshake_timeout=3.0)
    permissive = IpcLimits()

    with ipc_pair(limits=strict) as (server, client, _):
        # The client is not bound by the server's limit, so it can send a frame
        # the server must reject. ~2 KB against a 1 KB limit: refused, but far
        # below the ~8 KB pipe buffer, so this write always completes.
        client.send(
            build_request(
                MessageType.EVENT,
                {"event_type": "tool_request", "action": "big", "resource": "x" * 2000},
                "testsession",
            ),
            permissive,
        )
        with pytest.raises(ProtocolError) as excinfo:
            server.receive(strict)
        assert excinfo.value.code == "MESSAGE_TOO_LARGE"


def test_connect_to_a_missing_endpoint_fails_within_the_timeout():
    import time

    endpoint = create_endpoint("nosuchsession")
    started = time.monotonic()
    with pytest.raises(IpcTransportError):
        connect(endpoint, timeout=1.0)
    assert time.monotonic() - started < 10.0
