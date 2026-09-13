"""Linux kernel primitives used by the containment backends.

Every module in this package is **standard library only** and imports nothing
from the rest of :mod:`the_watcher`. That is not a style preference: the
supervisor copies ``exec_guard.py`` and its three siblings into a read-only
directory inside the sandbox, where they are executed as the last trusted act
before the untrusted workload starts. Keeping them dependency-free means the
sandbox never needs the Watcher package on its filesystem.

The modules are imported normally by the supervisor for testing, and executed
as standalone scripts by the guard.
"""

from __future__ import annotations

__all__ = [
    "seccomp_filter",
    "landlock_ruleset",
    "resource_limits",
    "exec_guard",
]
