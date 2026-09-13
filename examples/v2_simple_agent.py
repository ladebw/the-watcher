"""Minimal worker used by the V2 examples.

It performs only ordinary work, so a protected run of it completes with a
valid, empty-of-incidents trace::

    watcher run -- python examples/v2_simple_agent.py
"""

from __future__ import annotations

import sys

from the_watcher.ipc import WatcherClient


def main() -> int:
    client = WatcherClient.from_environment()
    print(f"[worker] connected to the Watcher: {client.connected}", flush=True)
    print(f"[worker] session: {client.session_id}", flush=True)

    for step in range(3):
        decision = client.evaluate("tool_request", "invoke", "local_compute")
        verdict = "allowed" if decision.allowed else f"blocked ({decision.rule})"
        print(f"[worker] step {step + 1}: {verdict}", flush=True)
        if decision.blocked:
            print("[worker] refusing to continue", flush=True)
            return 1

    client.close()
    print("[worker] done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
