"""OS-enforced containment (V3).

V2 decided *what* an agent may do and recorded the decision. V3 makes the
kernel that decision: a denial is an ``EPERM``/``EACCES``/``ENOENT`` from the
operating system, not a message from the Watcher that the agent is free to
ignore.

Layering::

    profile.py       declarative containment policy + preset profiles
    capabilities.py  what this host can actually enforce (probed, not assumed)
    procfs.py        trusted-side observation of namespaces and processes
    base.py          Enforcer contract, lifecycle states, evidence records
    linux/           stdlib-only kernel primitives + the in-sandbox guard
    backends/        namespace and container implementations

Two properties are load-bearing:

1. **The guard modules are stdlib-only and free of intra-package imports.**
   They are copied into a read-only directory inside the sandbox, so the
   protected environment never gains access to the Watcher's own code,
   configuration or storage.
2. **Nothing degrades silently.** A capability that cannot be enforced raises
   :class:`~the_watcher.exceptions.EnforcementUnavailable` before any workload
   starts. There is no "best effort" containment mode.
"""

from __future__ import annotations

from .base import (
    TERMINAL_CONTAINMENT_STATES,
    ContainmentState,
    ContainmentUnit,
    EnforcementEvidence,
    EnforcementMode,
    Enforcer,
    SandboxSpec,
    TerminationOutcome,
    select_backend,
)
from .capabilities import (
    BackendAvailability,
    HostCapabilities,
    clear_capability_cache,
    detect_capabilities,
)
from .declared import (
    NEVER_OVERRIDABLE,
    Enforcement,
    FieldEnforcement,
    enforcement_report,
    refusals,
    report_summary,
    require_honourable,
    unhonoured,
    unsupported_summary,
)
from .profile import (
    PROFILE_PRESETS,
    ContainmentProfile,
    FilesystemPolicy,
    NetworkMode,
    ProcessPolicy,
    ResourcePolicy,
    SyscallPolicy,
    get_preset,
)

__all__ = [
    # contract
    "Enforcer",
    "EnforcementMode",
    "ContainmentState",
    "TERMINAL_CONTAINMENT_STATES",
    "ContainmentUnit",
    "EnforcementEvidence",
    "SandboxSpec",
    "TerminationOutcome",
    "select_backend",
    # profile
    "ContainmentProfile",
    "FilesystemPolicy",
    "ProcessPolicy",
    "ResourcePolicy",
    "SyscallPolicy",
    "NetworkMode",
    "PROFILE_PRESETS",
    "get_preset",
    # host probing
    "HostCapabilities",
    "BackendAvailability",
    "detect_capabilities",
    "clear_capability_cache",
    # declared versus enforced
    "Enforcement",
    "FieldEnforcement",
    "NEVER_OVERRIDABLE",
    "enforcement_report",
    "unhonoured",
    "refusals",
    "require_honourable",
    "report_summary",
    "unsupported_summary",
]


def __getattr__(name: str):  # pragma: no cover - convenience only
    """Expose the backends lazily so importing the package stays cheap."""
    if name in ("NamespaceEnforcer", "DockerEnforcer"):
        from .backends.docker import DockerEnforcer
        from .backends.namespaces import NamespaceEnforcer

        return {"NamespaceEnforcer": NamespaceEnforcer, "DockerEnforcer": DockerEnforcer}[
            name
        ]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
