"""A deliberately malformed IPC peer, used by exactly one test.

``test_ipc_auth.py`` needs a client that authenticates successfully and then
sends a frame larger than the server's ``max_message_bytes``. Doing that inside
the pytest process is what hung Windows CI for 95 minutes.

The sequence that hangs is:

1. the sender writes a frame far larger than the pipe's kernel buffer, so
   ``multiprocessing``'s ``send_bytes`` blocks part-way through;
2. the server reads the four-byte length prefix, refuses the frame *without
   draining its body* (the stream is already out of sync, so draining would be
   pointless), sends an error back and closes the pipe;
3. the sender is now blocked writing into a pipe that nobody will ever read
   again. On Windows that pending write is an overlapped ``WriteFile`` waiting
   in ``WaitForMultipleObjects(..., INFINITE)``, which never returns.

Nothing in that is a Watcher defect: the *server* behaves exactly as it should,
and a hostile peer is welcome to wedge itself. What is a defect is letting a
test process become the thing that never finishes.

So the malformed client runs as its own process. The test asserts on what the
server recorded - which is the only thing that was ever in question - and
bounds, then kills, this process.

All output is JSON lines, matching ``ipc_agent.py``, so the parent can see how
far the peer got before it was stopped.
"""

from __future__ import annotations

import json
import os
import sys


def emit(**fields: object) -> None:
    print(json.dumps(fields, sort_keys=True), flush=True)


def main() -> int:
    from the_watcher.ipc.client import (
        ENV_ENDPOINT,
        ENV_FAMILY,
        ENV_SESSION_ID,
        ENV_TOKEN,
    )
    from the_watcher.ipc.protocol import IpcLimits, MessageType, build_request
    from the_watcher.ipc.transport import (
        CLIENT_RECEIVE_TYPES,
        connect,
        endpoint_from_values,
    )

    session_id = os.environ[ENV_SESSION_ID]
    token = os.environ[ENV_TOKEN]
    oversize = int(os.environ.get("WATCHER_MALFORMED_OVERSIZE", "20000"))

    # The peer's own limit is the permissive default, so the frame passes the
    # client-side guard and reaches the server, whose limit is much smaller.
    # That mismatch is the whole point: it models a peer that does not honour
    # the protocol it was given.
    permissive = IpcLimits()

    endpoint = endpoint_from_values(
        os.environ[ENV_ENDPOINT],
        os.environ.get(ENV_FAMILY),
        session_id,
    )
    connection = connect(endpoint, timeout=5.0)
    try:
        connection.send(
            build_request(
                MessageType.HELLO,
                {"token": token, "pid": os.getpid(), "protocol_version": 1},
                session_id=session_id,
            ),
            permissive,
        )
        connection.receive(permissive, allowed_types=CLIENT_RECEIVE_TYPES)
        emit(event="authenticated")

        emit(event="oversize_send_started", payload_bytes=oversize)
        connection.send(
            build_request(
                MessageType.EVENT,
                {
                    "event_type": "tool_request",
                    "action": "big",
                    "resource": "x" * oversize,
                },
                session_id=session_id,
            ),
            permissive,
        )
        emit(event="oversize_send_finished")
    except BaseException as exc:  # noqa: BLE001
        # BrokenPipeError, IpcTransportError and a closed connection are all
        # valid outcomes for a peer the server has just thrown off. The parent
        # does not treat any of them as a test failure.
        emit(
            event="peer_failure",
            error=type(exc).__name__,
            detail=str(exc)[:200],
        )
        return 2
    finally:
        connection.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
