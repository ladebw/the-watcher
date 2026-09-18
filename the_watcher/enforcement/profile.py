"""Containment profiles.

A profile is the *complete, deterministic, serialisable* description of the
isolation a workload will run under. Because it is deterministic it can be
hashed, and that digest is what gets committed into the Proof of Execution at
session start — so a trace can later prove which protection configuration was
actually active.

Profiles are validated eagerly and refuse dangerous configuration. A profile
that asks for a privileged container or for the Docker socket is not
"downgraded"; it is rejected.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace
from typing import Any, Mapping

from ..exceptions import ContainmentRefused
from ..poe.canonical import canonical_bytes, sha256_hex

__all__ = [
    "NetworkMode",
    "FilesystemPolicy",
    "SyscallPolicy",
    "ProcessPolicy",
    "ResourcePolicy",
    "ContainmentProfile",
    "PROFILE_PRESETS",
    "DANGEROUS_CAPABILITIES",
    "DEFAULT_READ_ROOTS",
]


class NetworkMode(str, enum.Enum):
    """How much network a protected workload gets."""

    NONE = "none"
    RESTRICTED = "restricted"
    OPEN = "open"


#: Fields inside each profile section that must be tuples, so that a loaded
#: profile is equal to the one it was serialised from and cannot be mutated
#: through a list held by a frozen dataclass.
_TUPLE_FIELDS: "Mapping[str, tuple[str, ...]]" = {
    "filesystem": ("allow_read", "allow_write"),
    "syscalls": (),
    "processes": (),
    "resources": (),
}

#: Every key a profile may contain. Anything else is refused rather than
#: ignored, so a typo cannot silently leave a default in force.
_PROFILE_KEYS: "frozenset[str]" = frozenset(
    {
        "name",
        "backend",
        "filesystem",
        "syscalls",
        "processes",
        "resources",
        "network",
        "allowed_networks",
        "drop_all_capabilities",
        "add_capabilities",
        "no_new_privileges",
        "allow_privileged",
        "allow_dangerous_capabilities",
        "allow_docker_socket",
        "allow_reduced_protection",
    }
)


#: Capabilities that are never granted to an ordinary protected workload.
DANGEROUS_CAPABILITIES: frozenset[str] = frozenset(
    {
        "CAP_SYS_ADMIN",
        "CAP_SYS_PTRACE",
        "CAP_NET_ADMIN",
        "CAP_SYS_MODULE",
        "CAP_SYS_BOOT",
        "CAP_SYS_RAWIO",
        "CAP_SYS_TIME",
        "CAP_MAC_ADMIN",
        "CAP_AUDIT_CONTROL",
        "CAP_SYSLOG",
        "CAP_DAC_READ_SEARCH",
        "CAP_SETFCAP",
    }
)

#: Runtime roots a Python workload needs to read. Deliberately explicit rather
#: than "all of /etc": Landlock is an allow-list, so anything unnamed is denied.
DEFAULT_READ_ROOTS: tuple[str, ...] = (
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/opt",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/localtime",
    "/etc/hosts",
    "/etc/environment",
    # Landlock rejects device nodes as rule targets (EINVAL), so /dev is
    # granted as a directory. Write access is not granted, and the nodes
    # themselves are owned by unmapped root, so they stay unreadable.
    "/dev",
    "/proc",
    "/sys/devices/system/cpu",
)


@dataclass(frozen=True)
class FilesystemPolicy:
    """Landlock allow-list plus mount policy.

    ``allow_read`` and ``allow_write`` are *allow-lists*: the kernel denies
    everything they do not name. Landlock cannot express a deny rule.
    """

    allow_read: tuple[str, ...] = DEFAULT_READ_ROOTS
    allow_write: tuple[str, ...] = ("/workspace", "/tmp")
    workspace: str = "/workspace"
    read_only_root: bool = True
    tmpfs_size_mb: int = 64
    landlock_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow_read": list(self.allow_read),
            "allow_write": list(self.allow_write),
            "workspace": self.workspace,
            "read_only_root": self.read_only_root,
            "tmpfs_size_mb": self.tmpfs_size_mb,
            "landlock_required": self.landlock_required,
        }


@dataclass(frozen=True)
class SyscallPolicy:
    """Which syscall classes seccomp blocks, and how."""

    profile: str = "watcher-default"
    block_namespace_manipulation: bool = True
    block_mount: bool = True
    block_ptrace: bool = True
    block_kernel_modules: bool = True
    block_bpf: bool = True
    block_reboot: bool = True
    block_keyring: bool = True
    block_raw_io: bool = True
    block_kexec: bool = True
    block_swap: bool = True
    block_perf: bool = True
    #: Deny namespace-creating *flags* on the legacy ``clone`` syscall while
    #: leaving ``clone`` itself callable, so threads and ordinary process
    #: creation keep working. Without this, ``clone(CLONE_NEWUSER|…)`` creates
    #: child namespaces even though ``unshare``/``setns``/``clone3`` are blocked.
    block_clone_namespaces: bool = True
    errno_name: str = "EPERM"

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "block_namespace_manipulation": self.block_namespace_manipulation,
            "block_mount": self.block_mount,
            "block_ptrace": self.block_ptrace,
            "block_kernel_modules": self.block_kernel_modules,
            "block_bpf": self.block_bpf,
            "block_reboot": self.block_reboot,
            "block_keyring": self.block_keyring,
            "block_raw_io": self.block_raw_io,
            "block_kexec": self.block_kexec,
            "block_swap": self.block_swap,
            "block_perf": self.block_perf,
            "block_clone_namespaces": self.block_clone_namespaces,
            "errno_name": self.errno_name,
        }


@dataclass(frozen=True)
class ProcessPolicy:
    """Process-count and handle ceilings."""

    max_processes: int = 32
    max_open_files: int = 512
    max_stack_mb: int = 8

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_processes": self.max_processes,
            "max_open_files": self.max_open_files,
            "max_stack_mb": self.max_stack_mb,
        }


@dataclass(frozen=True)
class ResourcePolicy:
    """External ceilings. ``None`` means "not configured", never "unlimited
    by accident" — the backend records exactly what it applied.

    ``cpus`` defaults to ``None`` deliberately. No backend other than the
    container runtime can enforce a CPU rate without cgroup v2, so a non-``None``
    default would put a value in the profile digest that nothing implemented -
    the exact "declared but not enforced" defect V4 Phase 0 removes.
    """

    memory_mb: "int | None" = 512
    cpus: "float | None" = None
    max_runtime_seconds: "float | None" = None
    max_file_size_mb: int = 256
    max_core_dump_mb: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "memory_mb": self.memory_mb,
            "cpus": self.cpus,
            "max_runtime_seconds": self.max_runtime_seconds,
            "max_file_size_mb": self.max_file_size_mb,
            "max_core_dump_mb": self.max_core_dump_mb,
        }


@dataclass(frozen=True)
class ContainmentProfile:
    """The full containment configuration for one session."""
    name: str = "research-strict"
    backend: str = "auto"

    filesystem: FilesystemPolicy = field(default_factory=FilesystemPolicy)
    syscalls: SyscallPolicy = field(default_factory=SyscallPolicy)
    processes: ProcessPolicy = field(default_factory=ProcessPolicy)
    resources: ResourcePolicy = field(default_factory=ResourcePolicy)

    network: NetworkMode = NetworkMode.NONE
    #: CIDRs permitted in RESTRICTED mode. V3 does not claim DNS-based
    #: filtering: only addresses and prefixes, or a controlled proxy.
    allowed_networks: tuple[str, ...] = ()

    drop_all_capabilities: bool = True
    add_capabilities: tuple[str, ...] = ()
    no_new_privileges: bool = True

    #: Research escape hatches. Both are refused unless explicitly enabled,
    #: and enabling them is recorded in the trace as a reduced-protection run.
    allow_privileged: bool = False
    allow_dangerous_capabilities: bool = False
    allow_docker_socket: bool = False

    #: Explicit acknowledgement that the session may run **without** a resource
    #: control the selected backend cannot apply (for example a CPU ceiling on a
    #: backend with no cgroup quota). Without it, an explicitly requested but
    #: unenforceable ceiling is refused before the workload is launched. It never
    #: covers the settings that describe the trust boundary itself - a network
    #: mode, capability handling or ``no_new_privs`` - because accepting those
    #: would mean recording a posture the kernel does not implement.
    allow_reduced_protection: bool = False

    # -- serialisation ---------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "backend": self.backend,
            "filesystem": self.filesystem.to_dict(),
            "syscalls": self.syscalls.to_dict(),
            "processes": self.processes.to_dict(),
            "resources": self.resources.to_dict(),
            "network": self.network.value,
            "allowed_networks": list(self.allowed_networks),
            "drop_all_capabilities": self.drop_all_capabilities,
            "add_capabilities": list(self.add_capabilities),
            "no_new_privileges": self.no_new_privileges,
            "allow_privileged": self.allow_privileged,
            "allow_dangerous_capabilities": self.allow_dangerous_capabilities,
            "allow_docker_socket": self.allow_docker_socket,
            "allow_reduced_protection": self.allow_reduced_protection,
        }

    #: Fields that must be tuples. A loaded profile must be *equal* to the
    #: built-in one it was serialised from, and a frozen dataclass holding a
    #: list is not really frozen: the list can be mutated, so the recorded
    #: digest could stop describing the configuration actually in force.
    #: Declared at module scope because anything annotated inside a dataclass
    #: body becomes a field.

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ContainmentProfile":
        if not isinstance(data, Mapping):
            raise ContainmentRefused("containment profile must be a mapping")
        payload = dict(data)

        # An unrecognised key is refused rather than ignored. A typo in a
        # containment profile would otherwise silently leave the default in
        # place while the operator believed they had changed it.
        unknown = sorted(set(payload) - _PROFILE_KEYS)
        if unknown:
            raise ContainmentRefused(
                "unknown containment profile key(s): "
                + ", ".join(unknown)
                + "; known keys: "
                + ", ".join(sorted(_PROFILE_KEYS))
            )

        def _section(key: str, factory):
            section = payload.get(key)
            if section is None:
                return factory()
            if not isinstance(section, Mapping):
                raise ContainmentRefused(f"profile section {key!r} must be a mapping")
            normalised = dict(section)
            for name in _TUPLE_FIELDS.get(key, ()):
                if name in normalised and isinstance(normalised[name], list):
                    normalised[name] = tuple(normalised[name])
            try:
                return factory(**normalised)
            except TypeError as exc:
                raise ContainmentRefused(f"invalid {key} section: {exc}") from exc

        try:
            network = NetworkMode(str(payload.get("network", "none")).lower())
        except ValueError as exc:
            raise ContainmentRefused(
                f"invalid network mode: {payload.get('network')!r}"
            ) from exc

        profile = cls(
            name=str(payload.get("name", "research-strict")),
            backend=str(payload.get("backend", "auto")),
            filesystem=_section("filesystem", FilesystemPolicy),
            syscalls=_section("syscalls", SyscallPolicy),
            processes=_section("processes", ProcessPolicy),
            resources=_section("resources", ResourcePolicy),
            network=network,
            allowed_networks=tuple(payload.get("allowed_networks") or ()),
            drop_all_capabilities=bool(payload.get("drop_all_capabilities", True)),
            add_capabilities=tuple(payload.get("add_capabilities") or ()),
            no_new_privileges=bool(payload.get("no_new_privileges", True)),
            allow_privileged=bool(payload.get("allow_privileged", False)),
            allow_dangerous_capabilities=bool(
                payload.get("allow_dangerous_capabilities", False)
            ),
            allow_docker_socket=bool(payload.get("allow_docker_socket", False)),
            allow_reduced_protection=bool(
                payload.get("allow_reduced_protection", False)
            ),
        )
        profile.validate()
        return profile

    def replace(self, **changes: Any) -> "ContainmentProfile":
        """Return a validated copy with ``changes`` applied."""
        updated = replace(self, **changes)
        updated.validate()
        return updated

    @classmethod
    def from_file(cls, path: str) -> "ContainmentProfile":
        """Load a profile from a JSON file.

        Only the fields present are overridden; everything else keeps its
        default. A file that names a privileged or otherwise unsafe setting is
        still refused by :meth:`validate` — loading a file is not a way to
        bypass the safety checks.
        """
        import json
        import pathlib

        text = pathlib.Path(path).read_text(encoding="utf-8")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON: {exc}") from exc
        if not isinstance(payload, Mapping):
            raise ValueError("a containment profile file must contain a JSON object")
        return cls.from_dict(payload)

    # -- identity --------------------------------------------------------

    def digest(self) -> str:
        """Stable SHA-256 of the effective configuration.

        Recorded in the Proof of Execution at session start so the trace
        proves *which* containment was active. Contains no secrets: a profile
        is configuration, not credentials.
        """
        return sha256_hex(canonical_bytes(self.to_dict()))

    # -- validation ------------------------------------------------------

    def validate(self) -> None:
        """Refuse dangerous or incoherent configuration. Fail closed."""
        if self.allow_privileged:
            raise ContainmentRefused(
                "a privileged container is never allowed for a protected "
                "workload; remove allow_privileged"
            )
        if self.allow_docker_socket:
            raise ContainmentRefused(
                "the container runtime socket must never be mounted into a "
                "protected workload; remove allow_docker_socket"
            )

        granted = {name.upper() for name in self.add_capabilities}
        dangerous = granted & DANGEROUS_CAPABILITIES
        if dangerous and not self.allow_dangerous_capabilities:
            raise ContainmentRefused(
                "refusing dangerous capabilities without the explicit research "
                "override: " + ", ".join(sorted(dangerous))
            )

        if self.drop_all_capabilities and granted and not self.allow_dangerous_capabilities:
            # Adding capabilities back on top of CAP_DROP=ALL is legitimate as
            # long as none of them are dangerous; the check above covers that.
            pass

        if self.network is NetworkMode.RESTRICTED and not self.allowed_networks:
            raise ContainmentRefused(
                "network mode 'restricted' requires at least one allowed "
                "network (CIDR or address)"
            )

        if self.processes.max_processes < 1:
            raise ContainmentRefused("max_processes must be >= 1")
        if self.resources.memory_mb is not None and self.resources.memory_mb < 16:
            raise ContainmentRefused("memory_mb must be >= 16 when set")
        if self.resources.cpus is not None and self.resources.cpus <= 0:
            raise ContainmentRefused("cpus must be > 0 when set")
        if self.filesystem.tmpfs_size_mb < 1:
            raise ContainmentRefused("tmpfs_size_mb must be >= 1")

    @property
    def is_reduced_protection(self) -> bool:
        """``True`` when the effective posture is weaker than the strict baseline.

        This is deliberately broader than "a research override was set": a
        probe that silently reports full protection because it only looked for
        the explicit escape hatches would be misleading. Anything that weakens
        containment counts, so it can be recorded in the trace as such.
        """
        return bool(
            self.allow_privileged
            or self.allow_dangerous_capabilities
            or self.add_capabilities
            or not self.drop_all_capabilities
            or not self.no_new_privileges
            or not self.filesystem.read_only_root
            or self.network is not NetworkMode.NONE
        )

    def reduced_protection_reasons(self) -> tuple[str, ...]:
        """Which specific settings weaken the posture, for the audit trail."""
        reasons: list[str] = []
        if self.allow_privileged:
            reasons.append("allow_privileged")
        if self.allow_dangerous_capabilities:
            reasons.append("allow_dangerous_capabilities")
        if self.add_capabilities:
            reasons.append(f"add_capabilities={','.join(self.add_capabilities)}")
        if not self.drop_all_capabilities:
            reasons.append("drop_all_capabilities=false")
        if not self.no_new_privileges:
            reasons.append("no_new_privileges=false")
        if not self.filesystem.read_only_root:
            reasons.append("read_only_root=false")
        if self.network is not NetworkMode.NONE:
            reasons.append(f"network={self.network.value}")
        return tuple(reasons)

    def summary(self) -> str:
        caps = "all dropped" if self.drop_all_capabilities else "not dropped"
        if self.add_capabilities:
            caps = f"dropped, then +{','.join(self.add_capabilities)}"
        return (
            f"{self.name}: backend={self.backend} network={self.network.value} "
            f"root={'ro' if self.filesystem.read_only_root else 'rw'} "
            f"caps=({caps}) nnp={self.no_new_privileges} "
            f"pids<={self.processes.max_processes} "
            f"mem={self.resources.memory_mb or '-'}MB cpus={self.resources.cpus or '-'}"
        )


#: Named presets. ``research-strict`` is the default for enforced runs.
PROFILE_PRESETS: dict[str, ContainmentProfile] = {
    "research-strict": ContainmentProfile(),
    "research-net": ContainmentProfile(
        name="research-net",
        network=NetworkMode.RESTRICTED,
        allowed_networks=("10.0.0.0/8",),
    ),
    "dev": ContainmentProfile(
        name="dev",
        network=NetworkMode.OPEN,
        filesystem=FilesystemPolicy(
            workspace="/workspace", read_only_root=False, tmpfs_size_mb=256
        ),
        processes=ProcessPolicy(max_processes=128),
        resources=ResourcePolicy(memory_mb=2048, cpus=2.0),
    ),
}


def get_preset(name: str) -> ContainmentProfile:
    """Return a named preset, or raise if it does not exist."""
    try:
        return PROFILE_PRESETS[name]
    except KeyError as exc:
        raise ContainmentRefused(
            f"unknown containment profile {name!r}; "
            f"known profiles: {', '.join(sorted(PROFILE_PRESETS))}"
        ) from exc
