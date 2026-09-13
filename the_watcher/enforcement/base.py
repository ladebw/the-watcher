"""The enforcement contract.

Watcher core talks to an :class:`Enforcer`, never to a container runtime or a
Linux syscall. That keeps the trust boundary explicit and lets a new backend
be added without touching the daemon.

The lifecycle is::

    capabilities()            can this host enforce anything?
    prepare(profile)          validate + fail closed BEFORE launching
    launch(spec)              start the contained workload
    inspect(unit)             ask the kernel what is actually true
    isolate_network(unit)     cut egress before termination
    terminate(unit, grace)    destroy the whole containment unit
    verify_empty(unit)        prove nothing survived

Every method that could weaken protection raises rather than degrading.
"""

from __future__ import annotations

import abc
import enum
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from ..exceptions import EnforcementUnavailable
from ..runtime import LocalProcess
from .capabilities import HostCapabilities, detect_capabilities
from .procfs import NamespaceIds, find_processes_in_namespace
from .profile import ContainmentProfile

__all__ = [
    "EnforcementMode",
    "ContainmentState",
    "TERMINAL_CONTAINMENT_STATES",
    "EnforcementEvidence",
    "TerminationOutcome",
    "SandboxSpec",
    "ContainmentUnit",
    "Enforcer",
    "select_backend",
]


class EnforcementMode(str, enum.Enum):
    """Whether the workload is OS-contained or merely supervised."""

    OFF = "off"
    ENFORCED = "enforced"


class ContainmentState(str, enum.Enum):
    """Lifecycle of a containment unit."""

    UNPREPARED = "UNPREPARED"
    PREPARED = "PREPARED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    ISOLATING = "ISOLATING"
    TERMINATING = "TERMINATING"
    TERMINATED = "TERMINATED"
    FAILED = "FAILED"
    #: Protected processes survived termination. Always treated as critical.
    KILL_FAILED = "KILL_FAILED"


TERMINAL_CONTAINMENT_STATES: frozenset[ContainmentState] = frozenset(
    {ContainmentState.TERMINATED, ContainmentState.FAILED, ContainmentState.KILL_FAILED}
)


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnforcementEvidence:
    """What the kernel/runtime reports about a running unit.

    This is deliberately *observed*, not asserted: the sandbox is asked to
    describe itself by reading ``/proc`` from the trusted side (or the
    container runtime's own report), and any mismatch between the profile and
    reality is listed in ``problems`` and fails verification.
    """

    backend: str
    verified: bool
    uid_on_host: "int | None" = None
    uid_inside_namespace: "int | None" = None
    capabilities_effective: str = ""
    capabilities_on_host: str = ""
    no_new_privs: bool = False
    seccomp_mode: "int | None" = None
    landlock_abi: "int | None" = None
    namespaces: Mapping[str, str] = field(default_factory=dict)
    cgroup: "str | None" = None
    read_only_root: bool = False
    network_isolated: bool = False
    network_interfaces: tuple[str, ...] = ()
    process_count: int = 0
    problems: tuple[str, ...] = ()
    checked_at: int = field(default_factory=lambda: int(time.time()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "verified": self.verified,
            "uid_on_host": self.uid_on_host,
            "uid_inside_namespace": self.uid_inside_namespace,
            "capabilities_effective": self.capabilities_effective,
            "capabilities_on_host": self.capabilities_on_host,
            "no_new_privs": self.no_new_privs,
            "seccomp_mode": self.seccomp_mode,
            "landlock_abi": self.landlock_abi,
            "namespaces": dict(self.namespaces),
            "cgroup": self.cgroup,
            "read_only_root": self.read_only_root,
            "network_isolated": self.network_isolated,
            "network_interfaces": list(self.network_interfaces),
            "process_count": self.process_count,
            "problems": list(self.problems),
            "checked_at": self.checked_at,
        }

    def summary(self) -> str:
        parts = [
            f"{self.backend}",
            f"uid(host)={self.uid_on_host}",
            f"caps={self.capabilities_effective or '?'}",
            f"nnp={'yes' if self.no_new_privs else 'no'}",
            f"seccomp={self.seccomp_mode}",
            f"landlock={self.landlock_abi}",
            f"ro_root={'yes' if self.read_only_root else 'no'}",
            f"net_isolated={'yes' if self.network_isolated else 'no'}",
            f"procs={self.process_count}",
        ]
        if self.problems:
            parts.append("problems=" + "; ".join(self.problems))
        return " ".join(parts)


@dataclass(frozen=True)
class TerminationOutcome:
    """Outcome of destroying a containment unit."""

    state: ContainmentState
    method: str
    terminated: tuple[int, ...] = ()
    remaining: tuple[int, ...] = ()
    forced: bool = False
    network_isolated: bool = False
    duration_seconds: float = 0.0
    report: "Mapping[str, Any] | None" = None
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.state is ContainmentState.TERMINATED and not self.remaining

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "method": self.method,
            "terminated": list(self.terminated),
            "remaining": list(self.remaining),
            "forced": self.forced,
            "network_isolated": self.network_isolated,
            "duration_seconds": self.duration_seconds,
            "ok": self.ok,
            "error": self.error,
            "report": dict(self.report) if self.report else None,
        }


# ---------------------------------------------------------------------------
# Spec and unit
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxSpec:
    """Everything a backend needs to build the sandbox for one session."""

    command: tuple[str, ...]
    profile: ContainmentProfile
    workspace_host: str
    workspace_inner: str = "/workspace"
    #: Supervisor-owned directory holding the IPC socket. Mounted read-only
    #: into the sandbox; nothing else from the supervisor is exposed.
    control_dir_host: "str | None" = None
    control_dir_inner: str = "/run/the-watcher"
    cwd_inner: "str | None" = None
    environment: Mapping[str, str] = field(default_factory=dict)
    #: Extra read-only roots the workload needs (e.g. an interpreter prefix).
    extra_read_paths: tuple[str, ...] = ()
    unit_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": list(self.command),
            "profile": self.profile.to_dict(),
            "workspace_host": self.workspace_host,
            "workspace_inner": self.workspace_inner,
            "control_dir_host": self.control_dir_host,
            "control_dir_inner": self.control_dir_inner,
            "cwd_inner": self.cwd_inner,
            "environment": dict(self.environment),
            "extra_read_paths": list(self.extra_read_paths),
            "unit_key": self.unit_key,
        }

    @property
    def read_paths(self) -> tuple[str, ...]:
        paths = list(self.profile.filesystem.allow_read)
        paths.extend(self.extra_read_paths)
        return tuple(dict.fromkeys(paths))

    @property
    def write_paths(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(self.profile.filesystem.allow_write))


@dataclass
class ContainmentUnit:
    """A launched containment unit and everything needed to audit it."""

    unit_key: str
    backend: str
    profile_digest: str
    process: "LocalProcess | None" = None
    host_pid: "int | None" = None
    state: ContainmentState = ContainmentState.UNPREPARED
    namespaces: NamespaceIds = field(default_factory=lambda: NamespaceIds(values={}))
    control_dir_inner: "str | None" = None
    workspace_inner: str = "/workspace"
    started_at: "int | None" = None
    evidence: "EnforcementEvidence | None" = None
    termination: "TerminationOutcome | None" = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def alive(self) -> bool:
        return self.process is not None and self.process.alive

    @property
    def returncode(self) -> "int | None":
        return self.process.returncode if self.process is not None else None

    @property
    def user_namespace(self) -> "str | None":
        """The namespace that identifies this unit's processes."""
        return self.namespaces.user or self.namespaces.pid

    def refresh_namespaces(self) -> None:
        if self.host_pid:
            from .procfs import read_namespaces as _read

            self.namespaces = _read(self.host_pid)

    def to_dict(self) -> dict[str, Any]:
        return {
            "unit_key": self.unit_key,
            "backend": self.backend,
            "profile_digest": self.profile_digest,
            "host_pid": self.host_pid,
            "state": self.state.value,
            "namespaces": self.namespaces.to_dict(),
            "control_dir_inner": self.control_dir_inner,
            "workspace_inner": self.workspace_inner,
            "started_at": self.started_at,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "termination": self.termination.to_dict() if self.termination else None,
            "metadata": dict(self.metadata),
        }


# ---------------------------------------------------------------------------
# The interface
# ---------------------------------------------------------------------------


class Enforcer(abc.ABC):
    """Backend contract. Implementations must fail closed."""

    backend_name: str = "abstract"

    def __init__(self, capabilities: "HostCapabilities | None" = None) -> None:
        self._capabilities = capabilities

    # -- capabilities ----------------------------------------------------

    @property
    def capabilities(self) -> HostCapabilities:
        if self._capabilities is None:
            self._capabilities = detect_capabilities()
        return self._capabilities

    @abc.abstractmethod
    def prepare(self, profile: ContainmentProfile, spec: "SandboxSpec | None" = None) -> None:
        """Validate configuration. Raises before anything is launched."""

    # -- lifecycle -------------------------------------------------------

    def plan(self, spec: SandboxSpec) -> dict[str, Any]:
        """Inner paths the backend will use for ``spec``, *before* launching.

        The daemon needs the in-sandbox control path in order to tell the
        protected process where the IPC socket will appear, and the sandbox
        path before anything is started. Backends that relocate nothing
        return the spec's own values.
        """
        return {
            "workspace_host": spec.workspace_host,
            "workspace_inner": spec.workspace_inner,
            "control_inner": spec.control_dir_inner if spec.control_dir_host else None,
            "cwd_inner": spec.cwd_inner or spec.workspace_inner,
        }

    @abc.abstractmethod
    def launch(self, spec: SandboxSpec) -> ContainmentUnit:
        """Start the contained workload."""

    @abc.abstractmethod
    def inspect(self, unit: ContainmentUnit) -> EnforcementEvidence:
        """Observe what is actually enforced."""

    @abc.abstractmethod
    def isolate_network(self, unit: ContainmentUnit) -> tuple[bool, str]:
        """Cut network egress before termination. Returns ``(ok, detail)``."""

    @abc.abstractmethod
    def terminate(self, unit: ContainmentUnit, grace: float = 2.0) -> TerminationOutcome:
        """Destroy the whole containment unit."""

    def verify_empty(self, unit: ContainmentUnit) -> tuple[bool, list[int]]:
        """Return ``(is_empty, surviving_pids)`` using trusted-side /proc.

        Default implementation keys on the unit's user/pid namespace, which is
        what makes a sandbox identifiable from outside. Backends may override.
        """
        namespace = unit.user_namespace
        if not namespace:
            return False, []
        kind = "user" if unit.namespaces.user else "pid"
        survivors = find_processes_in_namespace(namespace, kind=kind)
        return (not survivors), survivors

    # -- helpers ---------------------------------------------------------

    def require_available(self) -> None:
        availability = self.capabilities.backend(self.backend_name)
        if availability is None or not availability.available:
            detail = availability.detail if availability else "backend not recognised"
            raise EnforcementUnavailable(
                f"containment backend {self.backend_name!r} is unavailable: {detail}"
            )

    def __repr__(self) -> str:
        return f"<{type(self).__name__} backend={self.backend_name}>"


def select_backend(
    profile: ContainmentProfile,
    capabilities: "HostCapabilities | None" = None,
    runtime_root: "str | None" = None,
) -> Enforcer:
    """Return the enforcer for ``profile.backend``, or raise.

    ``auto`` prefers the namespace backend because it needs no daemon, then
    falls back to a container runtime. An explicit backend that is unavailable
    is an error — never a silent downgrade.
    """
    from .backends.docker import DockerEnforcer
    from .backends.namespaces import NamespaceEnforcer

    caps = capabilities or detect_capabilities()
    requested = (profile.backend or "auto").lower()

    candidates: Sequence[str]
    if requested == "auto":
        candidates = ("namespaces", "docker")
    elif requested in ("namespaces", "namespace", "linux"):
        candidates = ("namespaces",)
    elif requested in ("docker", "container"):
        candidates = ("docker",)
    else:
        raise EnforcementUnavailable(
            f"unknown containment backend {profile.backend!r}"
        )

    factories: dict[str, Callable[..., Enforcer]] = {
        "namespaces": NamespaceEnforcer,
        "docker": DockerEnforcer,
    }
    details: list[str] = []

    for name in candidates:
        availability = caps.backend(name)
        if availability is not None and availability.available:
            return factories[name](caps, runtime_root=runtime_root)
        details.append(f"{name}: {availability.detail if availability else 'unavailable'}")

    raise EnforcementUnavailable(
        "no containment backend can enforce this profile on this host ("
        + "; ".join(details)
        + "). V3 enforced mode requires Linux with unprivileged user "
        "namespaces and seccomp; on Windows run it inside WSL2 or a Linux VM."
    )
