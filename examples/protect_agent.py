"""Protect a separate process, using the context-manager API.

    python examples/protect_agent.py

The Watcher starts the worker, records the session, verifies the chain and
writes the trace to ``traces/protected-session.json``.
"""

from __future__ import annotations

import sys

from the_watcher import Policy, Watcher


def main() -> int:
    watcher = Watcher(
        policy=Policy(
            allowed_domains=["github.com"],
            forbidden_paths=["/etc/shadow", "~/.ssh"],
            max_processes=10,
            max_runtime_seconds=60,
        )
    )

    # Start the worker and wait for it. `protect` records session_start,
    # running the process under the Watcher's policy and tripwires.
    with watcher.protect([sys.executable, "examples/worker.py"]) as session:
        exit_code = session.wait(timeout=60)

    print()
    print("exit code   :", exit_code)
    print("status      :", session.status.value)
    print("events      :", len(session.trace))
    print("killed      :", watcher.killed)
    print("verification:", session.trace.verify())
    print()

    print("session trace:")
    for event in session.trace:
        print("  ", event.summary())

    path = watcher.export_trace("traces/protected-session.json")
    print()
    print("trace written to:", path)
    return 0 if not watcher.killed else 1


if __name__ == "__main__":
    sys.exit(main())
