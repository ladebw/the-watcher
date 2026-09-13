"""A deliberately ordinary agent, used to demonstrate The Watcher.

It performs one allowed action, one denied action, then touches a tripwire.
Run it under the Watcher:

    watcher run --allow-domain github.com -- python examples/agent.py

Or evaluate its actions programmatically - see ``examples/protect_agent.py``.
"""

from __future__ import annotations

import sys

from the_watcher import Policy, PoEWatcher


def attempt(watcher: PoEWatcher, event_type: str, action: str, resource: str) -> None:
    evaluation = watcher.evaluate(event_type, action, resource)
    verdict = "ALLOWED" if evaluation.allowed else "BLOCKED"
    print(f"[agent] {verdict:8s} {event_type:16s} {resource}")
    print(f"[agent]          -> {evaluation}")
    if evaluation.allowed:
        print("[agent]          action executed")
    else:
        print("[agent]          action refused by the Watcher")


def main() -> int:
    watcher = PoEWatcher(
        policy=Policy(
            allowed_domains=["github.com"],
            forbidden_paths=["/etc/shadow", "~/.ssh"],
        )
    )

    print("[agent] starting a benign task")
    attempt(watcher, "model_call", "invoke", "local-model")

    print("[agent] trying to reach the allow-listed domain")
    attempt(watcher, "network_request", "connect", "https://github.com/ladebw/AAIP")

    print("[agent] trying to reach an unlisted domain")
    attempt(watcher, "network_request", "connect", "https://exfil.example/collect")

    print("[agent] reading a forbidden file")
    attempt(watcher, "file_access", "read", "/etc/shadow")

    print("[agent] touching a canary tripwire")
    attempt(watcher, "file_access", "read", "/fake/root_token")

    print("[agent] attempting one more action after the kill switch")
    attempt(watcher, "network_request", "connect", "https://github.com")

    print()
    print("[agent] session state:", watcher.state())
    print("[agent] trace verification:", watcher.verify())
    for event in watcher.trace:
        print(f"[agent]   {event.summary()}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
