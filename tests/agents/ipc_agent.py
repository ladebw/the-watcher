"""A well-behaved V2 agent: talks to the external Watcher over IPC.

Driven by ``WATCHER_AGENT_MODE`` so one script covers the example scenarios:

* ``normal``   — request an allowed action, then finish
* ``forbidden``— request a forbidden path (expect DENY) and do not execute
* ``tripwire`` — touch a canary (expect KILL from the daemon)
* ``forge``    — try to supply daemon-owned fields (they are ignored)
* ``disconnect``— close the link and continue anyway (fail-closed)

All output is printed as JSON lines so it is easy to assert on in tests.
"""

from __future__ import annotations

import json
import os
import sys
import time

from the_watcher.ipc import WatcherClient


def emit(**fields: object) -> None:
    print(json.dumps(fields, sort_keys=True), flush=True)


def _raw_evaluate(payload: dict) -> dict:
    """Send a hand-built EVALUATE message, bypassing the typed client.

    Used to prove that the daemon ignores client-supplied ``sequence``,
    ``event_hash``, ``decision`` and friends.
    """
    from the_watcher.ipc.protocol import (
        IpcLimits,
        MessageType,
        build_request,
    )
    from the_watcher.ipc.transport import (
        CLIENT_RECEIVE_TYPES,
        connect,
        endpoint_from_values,
    )

    session_id = os.environ["WATCHER_SESSION_ID"]
    token = os.environ["WATCHER_SESSION_TOKEN"]
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
                {"token": token, "pid": os.getpid(), "protocol_version": 1},
                session_id=session_id,
            ),
            limits,
        )
        connection.receive(limits, allowed_types=CLIENT_RECEIVE_TYPES)

        connection.send(
            build_request(MessageType.EVALUATE, payload, session_id=session_id),
            limits,
        )
        response = connection.receive(limits, allowed_types=CLIENT_RECEIVE_TYPES)
        return dict(response.get("payload") or {})
    finally:
        connection.close()


def main() -> int:
    mode = os.environ.get("WATCHER_AGENT_MODE", "normal")
    workspace = os.environ.get("WATCHER_AGENT_WORKSPACE", ".")

    # The supervisor owns WATCHER_HEARTBEAT_INTERVAL and deliberately cannot be
    # overridden, so a test that needs a *silent* client asks the client itself
    # to stop heartbeating.
    overrides: dict = {}
    if os.environ.get("AGENT_SILENT_HEARTBEAT") == "1":
        overrides["heartbeat_interval"] = 0.0

    client = WatcherClient.from_environment(**overrides)
    emit(event="ready", mode=mode, connected=client.connected,
         heartbeat=client.handshake_info().get("heartbeat", {}))

    if mode == "normal":
        decision = client.evaluate("file_access", "read", os.path.join(workspace, "notes.txt"))
        emit(event="decision", step="allowed_read", **decision.to_dict())
        if decision.allowed:
            emit(event="executed", step="allowed_read")

        decision = client.evaluate("network_request", "connect", "https://github.com/repo")
        emit(event="decision", step="allowed_network", **decision.to_dict())

    elif mode == "forbidden":
        decision = client.evaluate("file_access", "read", "/etc/shadow")
        emit(event="decision", step="forbidden_read", **decision.to_dict())
        if decision.allowed:
            emit(event="executed", step="forbidden_read")
        else:
            emit(event="refused", step="forbidden_read", reason=decision.reason)

    elif mode == "tripwire":
        decision = client.evaluate("file_access", "read", "/fake/root_token")
        emit(event="decision", step="tripwire", **decision.to_dict())
        # Keep running briefly so the supervisor's kill is observable.
        time.sleep(float(os.environ.get("WATCHER_AGENT_SLEEP", "0.5")))
        after = client.evaluate("file_access", "read", os.path.join(workspace, "notes.txt"))
        emit(event="decision", step="after_kill", **after.to_dict())
        time.sleep(float(os.environ.get("WATCHER_AGENT_LINGER", "10")))

    elif mode == "forge":
        # Send daemon-owned fields over the raw protocol. The typed client API
        # would reject these as unexpected kwargs, so this deliberately bypasses
        # it: the point is to prove the *daemon* ignores them.
        forged = {
            "event_type": "file_access",
            "action": "read",
            "resource": os.path.join(workspace, "notes.txt"),
            "sequence": 999,
            "timestamp": 1,
            "previous_hash": "f" * 64,
            "event_hash": "f" * 64,
            "final_hash": "f" * 64,
            "decision": "DENY",
            "risk": "CRITICAL",
        }
        response = _raw_evaluate(forged)
        emit(event="forged_response", response=response)

    elif mode == "disconnect":
        emit(event="disconnecting")
        client.close(notify=False)
        time.sleep(float(os.environ.get("WATCHER_AGENT_SLEEP", "0.2")))
        decision = client.evaluate("file_access", "read", "/etc/shadow")
        emit(event="decision", step="after_disconnect", **decision.to_dict())
        if decision.blocked:
            emit(event="refused", step="after_disconnect", reason=decision.reason)

    elif mode == "custom":
        # Flexible mode: the driving test chooses the request.
        decision = client.evaluate(
            os.environ.get("WATCHER_AGENT_EVENT", "network_request"),
            os.environ.get("WATCHER_AGENT_ACTION", "connect"),
            os.environ.get("WATCHER_AGENT_RESOURCE", ""),
        )
        emit(event="decision", step="custom", **decision.to_dict())
        if decision.allowed:
            emit(event="executed", step="custom")
        else:
            emit(event="refused", step="custom", reason=decision.reason)
        linger = float(os.environ.get("WATCHER_AGENT_LINGER", "0"))
        if linger:
            time.sleep(linger)

    elif mode == "crash":
        # One legitimate request, then die without saying goodbye.
        decision = client.evaluate(
            "file_access", "read", os.path.join(workspace, "notes.txt")
        )
        emit(event="decision", step="pre_crash", **decision.to_dict())
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(9)

    elif mode == "tree":
        # Spawn a child so the supervisor's tree termination can be observed.
        import subprocess

        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"]
        )
        emit(event="child_spawned", child_pid=child.pid)
        pid_file = os.environ.get("WATCHER_AGENT_PIDFILE")
        if pid_file:
            with open(pid_file, "w", encoding="utf-8") as handle:
                handle.write(str(child.pid))
        time.sleep(float(os.environ.get("WATCHER_AGENT_SLEEP", "20")))

    elif mode == "heartbeat":
        interval = float(os.environ.get("WATCHER_AGENT_SLEEP", "10"))
        emit(event="sleeping", seconds=interval)
        time.sleep(interval)

    else:
        emit(event="error", reason=f"unknown mode {mode!r}")
        return 2

    client.close()
    emit(event="done", mode=mode)
    return 0


if __name__ == "__main__":
    sys.exit(main())
