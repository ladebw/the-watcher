"""A protected agent that talks to the external Watcher over local IPC.

This is the V2 shape of an agent: it holds **no** policy, no tripwires, no
trace and no kill switch. It asks the external supervisor for a decision and
obeys it.

Run it under the supervisor::

    watcher run --allow-domain github.com \
                --forbid-path /etc/shadow \
                -- python examples/v2_agent.py

Scenarios are selected with ``WATCHER_AGENT_MODE``:

``normal``      one allowed action, then exit          (expect ALLOW)
``forbidden``   a forbidden path                        (expect DENY, not executed)
``tripwire``    touch a canary                          (expect KILL from the supervisor)
``forge``       send daemon-owned fields                (expect them to be ignored)
``disconnect``  close the link, then keep going         (expect fail-closed DENY)
``heartbeat``   connect and stay quiet                  (expect HEARTBEAT_LOST)
"""

from __future__ import annotations

import json
import os
import sys
import time

from the_watcher.ipc import WatcherClient

WORKSPACE = os.environ.get("WATCHER_AGENT_WORKSPACE", os.getcwd())


def emit(**fields: object) -> None:
    """Print a JSON line so the run is easy to inspect and script against."""
    print(json.dumps(fields, sort_keys=True), flush=True)


def request(client: WatcherClient, event_type: str, action: str, resource: str):
    """Ask the supervisor, then honour the answer."""
    decision = client.evaluate(event_type, action, resource)
    emit(event="decision", event_type=event_type, resource=resource, **decision.to_dict())
    if decision.allowed:
        emit(event="executed", resource=resource, note="the agent performs the action")
    else:
        emit(
            event="refused",
            resource=resource,
            rule=decision.rule,
            note="the agent must not perform the action",
        )
    return decision


def scenario_normal(client: WatcherClient) -> None:
    request(client, "model_call", "invoke", "local-model")
    request(client, "network_request", "connect", "https://github.com/ladebw/AAIP")


def scenario_forbidden(client: WatcherClient) -> None:
    decision = request(client, "file_access", "read", "/etc/shadow")
    emit(event="checked", executed=decision.allowed)


def scenario_tripwire(client: WatcherClient) -> None:
    request(client, "file_access", "read", "/fake/root_token")
    # The supervisor is about to terminate this process tree.
    time.sleep(float(os.environ.get("WATCHER_AGENT_LINGER", "2")))
    request(client, "file_access", "read", os.path.join(WORKSPACE, "notes.txt"))


def scenario_forge() -> dict:
    """Send fields only the supervisor may set, over the raw protocol.

    The typed client would reject these as unexpected arguments, so this
    deliberately talks to the socket directly. The point is to show that the
    *daemon* discards them: the answer still comes from its own policy, and the
    recorded event carries the daemon's sequence and hash.
    """
    from the_watcher.ipc.protocol import IpcLimits, MessageType, build_request
    from the_watcher.ipc.transport import (
        CLIENT_RECEIVE_TYPES,
        connect,
        endpoint_from_values,
    )

    session_id = os.environ["WATCHER_SESSION_ID"]
    limits = IpcLimits()
    endpoint = endpoint_from_values(
        os.environ["WATCHER_IPC_ENDPOINT"],
        os.environ.get("WATCHER_IPC_FAMILY"),
        session_id,
    )
    connection = connect(endpoint, timeout=5.0)
    try:
        connection.send(
            build_request(
                MessageType.HELLO,
                {
                    "token": os.environ["WATCHER_SESSION_TOKEN"],
                    "pid": os.getpid(),
                    "protocol_version": 1,
                },
                session_id=session_id,
            ),
            limits,
        )
        connection.receive(limits, allowed_types=CLIENT_RECEIVE_TYPES)

        connection.send(
            build_request(
                MessageType.EVALUATE,
                {
                    "event_type": "file_access",
                    "action": "read",
                    "resource": os.path.join(WORKSPACE, "notes.txt"),
                    # Everything below is the daemon's to decide, not ours.
                    "sequence": 999,
                    "timestamp": 1,
                    "previous_hash": "f" * 64,
                    "event_hash": "f" * 64,
                    "final_hash": "f" * 64,
                    "decision": "DENY",
                    "risk": "CRITICAL",
                },
                session_id=session_id,
            ),
            limits,
        )
        response = connection.receive(limits, allowed_types=CLIENT_RECEIVE_TYPES)
        return dict(response.get("payload") or {})
    finally:
        connection.close()


def scenario_disconnect(client: WatcherClient) -> None:
    emit(event="disconnecting")
    client.close(notify=False)

    decision = client.evaluate("file_access", "read", "/etc/shadow")
    emit(event="decision", resource="/etc/shadow", **decision.to_dict())
    emit(
        event="fail_closed_check",
        blocked=decision.blocked,
        note="an unreachable Watcher must not be treated as permission",
    )


def main() -> int:
    mode = os.environ.get("WATCHER_AGENT_MODE", "normal")

    if mode == "forge":
        emit(event="forged_response", response=scenario_forge())
        return 0

    client = WatcherClient.from_environment()
    emit(
        event="connected",
        session_id=client.session_id,
        fail_mode=client.fail_mode.value,
        heartbeat=client.handshake_info().get("heartbeat", {}),
    )

    try:
        if mode == "normal":
            scenario_normal(client)
        elif mode == "forbidden":
            scenario_forbidden(client)
        elif mode == "tripwire":
            scenario_tripwire(client)
        elif mode == "disconnect":
            scenario_disconnect(client)
        elif mode == "heartbeat":
            time.sleep(float(os.environ.get("WATCHER_AGENT_SLEEP", "10")))
        else:
            emit(event="error", reason=f"unknown mode {mode!r}")
            return 2
    finally:
        client.close()

    emit(event="finished", mode=mode)
    return 0


if __name__ == "__main__":
    sys.exit(main())
