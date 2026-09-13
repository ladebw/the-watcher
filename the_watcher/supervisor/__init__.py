"""The external Watcher supervisor.

Trusted side of V2. Everything here runs *outside* the protected process:

* :class:`WatcherDaemon` — per-session supervisor and the single authority for
  policy, tripwires, the PoE trace, the kill switch and process control.
* :class:`SessionStateMachine` — explicit, terminal-safe lifecycle.
* :class:`SessionStorage` — authoritative trace storage outside the sandbox.
* :class:`ProcessSupervisor` — owns the protected process as a child.

Usage::

    from the_watcher.supervisor import DaemonConfig, WatcherDaemon

    daemon = WatcherDaemon(DaemonConfig(command=["python", "agent.py"]))
    exit_code = daemon.run()
"""

from __future__ import annotations

from .process_supervisor import ProcessSupervisor
from .session import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATES,
    SessionState,
    SessionStateMachine,
    StateTransition,
)
from .storage import SessionPaths, SessionStorage, default_root
from .daemon import (
    KILLED_EXIT_CODE,
    DaemonConfig,
    SupervisoryAction,
    WatcherDaemon,
)

__all__ = [
    "WatcherDaemon",
    "DaemonConfig",
    "SupervisoryAction",
    "KILLED_EXIT_CODE",
    "SessionState",
    "SessionStateMachine",
    "StateTransition",
    "TERMINAL_STATES",
    "ALLOWED_TRANSITIONS",
    "SessionStorage",
    "SessionPaths",
    "default_root",
    "ProcessSupervisor",
]
