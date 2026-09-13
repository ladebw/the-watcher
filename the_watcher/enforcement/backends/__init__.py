"""Containment backends.

``namespaces`` is the default: rootless user/PID/mount/network namespaces plus
Landlock, seccomp, capability drop and rlimits. ``docker`` exists for hosts
with a container runtime and refuses anything it cannot guarantee.

Both implement :class:`~the_watcher.enforcement.base.Enforcer` and both fail
closed: an unavailable backend raises, it never silently downgrades.
"""

from __future__ import annotations

__all__ = ["NamespaceEnforcer", "DockerEnforcer"]


def __getattr__(name: str):  # pragma: no cover - import cost only
    if name == "NamespaceEnforcer":
        from .namespaces import NamespaceEnforcer

        return NamespaceEnforcer
    if name == "DockerEnforcer":
        from .docker import DockerEnforcer

        return DockerEnforcer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
