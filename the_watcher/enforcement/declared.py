"""Declared versus enforced containment configuration.

A profile is a *declaration*. What the kernel actually enforces is a different
thing, and the gap between them is where a security product quietly lies to its
user. Three gaps existed in V3 and are named here:

* ``resources.cpus`` was printed by ``summary()`` and hashed into the profile
  digest, and no backend except Docker ever consumed it;
* ``no_new_privileges``, ``drop_all_capabilities`` and ``add_capabilities`` were
  read by nothing - the guard always set ``no_new_privs`` and always cleared
  every capability, so a profile could declare a posture the kernel did not
  implement;
* ``network=open`` was treated as a containment *failure* by the health check,
  so an explicitly declared posture could never complete a session.

This module produces an explicit, per-field, per-backend verdict:

``ENFORCED``
    The declared value is what the operating system enforces.
``PARTIALLY_ENFORCED``
    A real mechanism enforces something close to, but not exactly, the declared
    value (``RLIMIT_AS`` bounds address space, not resident memory).
``UNSUPPORTED``
    Nothing enforces it. The declared value has no effect.
``REFUSED``
    Nothing enforces it *and* proceeding would misrepresent the session or
    silently break the workload, so the backend refuses before launch.

The governing invariant:

    No configuration value may be presented as enforced configuration while the
    selected backend silently ignores it.

So ``UNSUPPORTED`` is never silent: it appears in the enforcement report, which
is recorded in the Proof of Execution beside the profile digest, and it is
reported by ``watcher doctor``. ``REFUSED`` stops the session before the
workload is launched.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from ..exceptions import ContainmentRefused
from .profile import ContainmentProfile, NetworkMode

__all__ = [
    "Enforcement",
    "FieldEnforcement",
    "SUPPORTED_BACKENDS",
    "NEVER_OVERRIDABLE",
    "enforcement_report",
    "unhonoured",
    "refusals",
    "require_honourable",
    "report_summary",
    "unsupported_summary",
]


class Enforcement(str, enum.Enum):
    """How faithfully a backend implements a declared setting."""

    ENFORCED = "ENFORCED"
    PARTIALLY_ENFORCED = "PARTIALLY_ENFORCED"
    UNSUPPORTED = "UNSUPPORTED"
    REFUSED = "REFUSED"


@dataclass(frozen=True)
class FieldEnforcement:
    """One declared setting, and what actually happens to it."""

    field: str
    status: Enforcement
    declared: Any = None
    enforced: Any = None
    mechanism: str = ""
    detail: str = ""

    @property
    def honoured(self) -> bool:
        return self.status in (Enforcement.ENFORCED, Enforcement.PARTIALLY_ENFORCED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "status": self.status.value,
            "declared": self.declared,
            "enforced": self.enforced,
            "mechanism": self.mechanism,
            "detail": self.detail,
        }


#: Backends this module knows how to describe.
SUPPORTED_BACKENDS = ("namespaces", "docker")

#: Mechanism notes for the syscall categories the filter is actually built from.
_SYSCALL_CATEGORIES: Mapping[str, str] = {
    "block_namespace_manipulation": "unshare/setns/clone3",
    "block_mount": "mount and the new mount API",
    "block_ptrace": "ptrace and process_vm_*",
    "block_kernel_modules": "init_module/finit_module/delete_module",
    "block_bpf": "bpf, io_uring and userfaultfd",
    "block_reboot": "reboot and the kexec family",
    "block_keyring": "keyring syscalls",
    "block_raw_io": "iopl/ioperm, privileged_system and swap",
    "block_perf": "perf_event_open",
}


def _defaults() -> ContainmentProfile:
    return ContainmentProfile()


def _norm(backend: str) -> str:
    name = (backend or "auto").lower()
    if name in ("docker", "container"):
        return "docker"
    return "namespaces"


# ---------------------------------------------------------------------------
# The classification table
# ---------------------------------------------------------------------------


def _namespaces_report(profile: ContainmentProfile) -> list[FieldEnforcement]:
    """Every declared setting, judged against what the guard really does."""
    fs = profile.filesystem
    sys_ = profile.syscalls
    proc = profile.processes
    res = profile.resources
    report: list[FieldEnforcement] = []

    report.append(
        FieldEnforcement(
            field="filesystem.allow_read",
            status=Enforcement.ENFORCED,
            declared=list(fs.allow_read),
            enforced=list(fs.allow_read),
            mechanism="Landlock allow-list",
            detail=(
                "Landlock is an allow-list, so everything it does not name is "
                "denied by the kernel"
            ),
        )
    )
    report.append(
        FieldEnforcement(
            field="filesystem.allow_write",
            status=Enforcement.ENFORCED,
            declared=list(fs.allow_write),
            enforced=list(fs.allow_write),
            mechanism="Landlock allow-list",
        )
    )
    report.append(
        FieldEnforcement(
            field="filesystem.read_only_root",
            status=Enforcement.ENFORCED,
            declared=fs.read_only_root,
            enforced=fs.read_only_root,
            mechanism="bind remount MS_RDONLY",
        )
    )
    report.append(
        FieldEnforcement(
            field="filesystem.tmpfs_size_mb",
            status=Enforcement.ENFORCED,
            declared=fs.tmpfs_size_mb,
            enforced=fs.tmpfs_size_mb,
            mechanism="tmpfs size= mount option",
        )
    )
    report.append(
        FieldEnforcement(
            field="filesystem.landlock_required",
            status=Enforcement.ENFORCED,
            declared=fs.landlock_required,
            enforced=fs.landlock_required,
            mechanism="prepare() refuses the session when Landlock is unavailable",
        )
    )

    for flag, note in _SYSCALL_CATEGORIES.items():
        declared = bool(getattr(sys_, flag, True))
        report.append(
            FieldEnforcement(
                field=f"syscalls.{flag}",
                status=Enforcement.ENFORCED,
                declared=declared,
                enforced=declared,
                mechanism=f"seccomp-bpf denylist ({note})",
                detail="" if declared else "declared off, so these syscalls are allowed",
            )
        )

    for dead in ("block_kexec", "block_swap"):
        declared = bool(getattr(sys_, dead, True))
        effective = bool(
            sys_.block_reboot if dead == "block_kexec" else sys_.block_raw_io
        )
        report.append(
            FieldEnforcement(
                field=f"syscalls.{dead}",
                status=Enforcement.PARTIALLY_ENFORCED,
                declared=declared,
                enforced=effective,
                mechanism="seccomp-bpf denylist (via a broader category)",
                detail=(
                    "this flag has no independent effect: kexec syscalls are "
                    "governed by block_reboot and swap syscalls by block_raw_io"
                ),
            )
        )

    # Namespace creation through the legacy clone syscall. ``clone`` is not in
    # the denylist, because blocking it outright would break threads and
    # ordinary process creation; this is the argument-aware rule that closes the
    # gap instead.
    block_clone = bool(getattr(sys_, "block_clone_namespaces", True))
    report.append(
        FieldEnforcement(
            field="syscalls.block_clone_namespaces",
            status=Enforcement.ENFORCED if block_clone else Enforcement.UNSUPPORTED,
            declared=block_clone,
            enforced=block_clone,
            mechanism="seccomp-bpf argument mask on clone(2) flags",
            detail=""
            if block_clone
            else (
                "declared off, so a workload can create child namespaces with "
                "clone(CLONE_NEWUSER|CLONE_NEWPID|...); the survivor scan is "
                "then the only thing that would notice a nested descendant"
            ),
        )
    )

    report.append(
        FieldEnforcement(
            field="processes.max_processes",
            status=Enforcement.PARTIALLY_ENFORCED,
            declared=proc.max_processes,
            enforced=proc.max_processes,
            mechanism="RLIMIT_NPROC plus a measured per-uid baseline",
            detail=(
                "RLIMIT_NPROC counts every process of this uid on the host, not "
                "just this unit, so the ceiling is applied as a budget above the "
                "measured baseline rather than as an exact unit limit"
            ),
        )
    )
    report.append(
        FieldEnforcement(
            field="processes.max_open_files",
            status=Enforcement.ENFORCED,
            declared=proc.max_open_files,
            enforced=proc.max_open_files,
            mechanism="RLIMIT_NOFILE",
        )
    )
    report.append(
        FieldEnforcement(
            field="processes.max_stack_mb",
            status=Enforcement.ENFORCED,
            declared=proc.max_stack_mb,
            enforced=proc.max_stack_mb,
            mechanism="RLIMIT_STACK",
        )
    )

    report.append(
        FieldEnforcement(
            field="resources.memory_mb",
            status=Enforcement.PARTIALLY_ENFORCED if res.memory_mb is not None
            else Enforcement.ENFORCED,
            declared=res.memory_mb,
            enforced=res.memory_mb,
            mechanism="RLIMIT_AS (address space)" if res.memory_mb is not None
            else "not configured",
            detail=(
                "RLIMIT_AS bounds virtual address space, not resident memory, so "
                "a workload can be refused for mapping memory it never uses"
            )
            if res.memory_mb is not None
            else "",
        )
    )
    if res.cpus is None:
        report.append(
            FieldEnforcement(
                field="resources.cpus",
                status=Enforcement.ENFORCED,
                declared=None,
                enforced=None,
                mechanism="not configured",
            )
        )
    else:
        report.append(
            FieldEnforcement(
                field="resources.cpus",
                status=Enforcement.REFUSED,
                declared=res.cpus,
                enforced=None,
                mechanism="no CPU quota mechanism on this backend",
                detail=(
                    "enforcing a CPU rate needs cgroup v2 cpu.max, which this "
                    "backend does not use. An explicitly requested CPU ceiling "
                    "is refused before launch rather than accepted and ignored; "
                    "a profile may opt in to running without it by setting "
                    "allow_reduced_protection, which is recorded in the trace"
                ),
            )
        )
    report.append(
        FieldEnforcement(
            field="resources.max_runtime_seconds",
            status=Enforcement.ENFORCED,
            declared=res.max_runtime_seconds,
            enforced=res.max_runtime_seconds,
            mechanism="RLIMIT_CPU",
            detail="" if res.max_runtime_seconds is not None else "not configured",
        )
    )
    report.append(
        FieldEnforcement(
            field="resources.max_file_size_mb",
            status=Enforcement.ENFORCED,
            declared=res.max_file_size_mb,
            enforced=res.max_file_size_mb,
            mechanism="RLIMIT_FSIZE",
        )
    )
    report.append(
        FieldEnforcement(
            field="resources.max_core_dump_mb",
            status=Enforcement.ENFORCED,
            declared=res.max_core_dump_mb,
            enforced=res.max_core_dump_mb,
            mechanism="RLIMIT_CORE",
        )
    )

    if profile.network is NetworkMode.NONE:
        report.append(
            FieldEnforcement(
                field="network",
                status=Enforcement.ENFORCED,
                declared=profile.network.value,
                enforced=profile.network.value,
                mechanism="private network namespace with no uplink",
            )
        )
    elif profile.network is NetworkMode.OPEN:
        report.append(
            FieldEnforcement(
                field="network",
                status=Enforcement.ENFORCED,
                declared=profile.network.value,
                enforced=profile.network.value,
                mechanism="no network namespace is created",
                detail=(
                    "the declared posture is applied faithfully and provides no "
                    "egress restriction; the session is recorded as reduced "
                    "protection"
                ),
            )
        )
    else:
        report.append(
            FieldEnforcement(
                field="network",
                status=Enforcement.REFUSED,
                declared=profile.network.value,
                enforced=None,
                mechanism="no rootless egress filter exists",
                detail=(
                    "a faithful egress allow-list needs host network privileges; "
                    "a user-space or DNS-only filter would not be OS enforcement"
                ),
            )
        )

    report.append(
        FieldEnforcement(
            field="drop_all_capabilities",
            status=Enforcement.ENFORCED
            if profile.drop_all_capabilities
            else Enforcement.REFUSED,
            declared=profile.drop_all_capabilities,
            enforced=True,
            mechanism="capset + PR_CAPBSET_DROP for every capability",
            detail=""
            if profile.drop_all_capabilities
            else (
                "the guard always clears the effective, permitted and "
                "inheritable sets and drops the bounding set, so a profile that "
                "asks to keep capabilities cannot be honoured"
            ),
        )
    )
    report.append(
        FieldEnforcement(
            field="add_capabilities",
            status=Enforcement.REFUSED
            if profile.add_capabilities
            else Enforcement.ENFORCED,
            declared=list(profile.add_capabilities),
            enforced=[],
            mechanism="no capability is ever added back",
            detail=(
                "the guard clears every capability after the mounts and never "
                "restores one, so a granted capability would be silently dropped "
                "and the workload would fail with EACCES"
            )
            if profile.add_capabilities
            else "",
        )
    )
    report.append(
        FieldEnforcement(
            field="no_new_privileges",
            status=Enforcement.ENFORCED
            if profile.no_new_privileges
            else Enforcement.REFUSED,
            declared=profile.no_new_privileges,
            enforced=True,
            mechanism="PR_SET_NO_NEW_PRIVS before Landlock and seccomp",
            detail=""
            if profile.no_new_privileges
            else (
                "the guard always sets no_new_privs, so a profile declaring it "
                "false describes a posture the kernel does not implement"
            ),
        )
    )
    if profile.allowed_networks:
        report.append(
            FieldEnforcement(
                field="allowed_networks",
                status=Enforcement.REFUSED,
                declared=list(profile.allowed_networks),
                enforced=[],
                mechanism="no egress filter",
                detail="only meaningful with network=restricted, which is refused",
            )
        )
    else:
        report.append(
            FieldEnforcement(
                field="allowed_networks",
                status=Enforcement.ENFORCED,
                declared=[],
                enforced=[],
                mechanism="not configured",
            )
        )
    return report


#: Settings the container backend maps onto real runtime flags.
_CONTAINER_ENFORCED: Mapping[str, str] = {
    "filesystem.read_only_root": "--read-only",
    "resources.memory_mb": "--memory (cgroup memory.max, exact)",
    "resources.cpus": "--cpus (cgroup cpu.max, exact)",
    "processes.max_processes": "--pids-limit (cgroup pids.max, exact)",
    "network": "container networking mode",
}


def _docker_report(profile: ContainmentProfile) -> list[FieldEnforcement]:
    """The container backend applies a much smaller part of a profile.

    A setting this backend applies is ``ENFORCED`` here even when the namespace
    backend refuses it: ``resources.cpus`` is a real ``--cpus`` flag, so a CPU
    ceiling that the rootless backend must refuse is honoured by this one.
    """
    report: list[FieldEnforcement] = []
    for entry in _namespaces_report(profile):
        if entry.field == "network":
            # Both backends refuse restricted egress, for the same reason.
            report.append(entry)
            continue
        if entry.field in _CONTAINER_ENFORCED:
            if entry.field == "resources.cpus" and profile.resources.cpus is None:
                report.append(
                    FieldEnforcement(
                        field=entry.field,
                        status=Enforcement.ENFORCED,
                        declared=None,
                        enforced=None,
                        mechanism="not configured",
                    )
                )
                continue
            report.append(
                FieldEnforcement(
                    field=entry.field,
                    status=Enforcement.ENFORCED,
                    declared=entry.declared,
                    enforced=entry.enforced,
                    mechanism=_CONTAINER_ENFORCED[entry.field],
                )
            )
            continue
        report.append(
            FieldEnforcement(
                field=entry.field,
                status=Enforcement.UNSUPPORTED,
                declared=entry.declared,
                enforced=None,
                mechanism="not applied by the container backend",
                detail=entry.detail
                or (
                    "the container backend does not read this setting, so the "
                    "workload gets the runtime's own default rather than the "
                    "declared value"
                ),
            )
        )
    return report


def enforcement_report(
    profile: ContainmentProfile, backend: str
) -> tuple[FieldEnforcement, ...]:
    """The per-field verdict for ``profile`` on ``backend``."""
    if _norm(backend) == "docker":
        return tuple(_docker_report(profile))
    return tuple(_namespaces_report(profile))


def unhonoured(
    profile: ContainmentProfile, backend: str
) -> tuple[FieldEnforcement, ...]:
    """Every setting the backend does not honour."""
    return tuple(
        entry for entry in enforcement_report(profile, backend) if not entry.honoured
    )


def refusals(
    profile: ContainmentProfile, backend: str
) -> tuple[FieldEnforcement, ...]:
    """Every setting that must stop the session before launch."""
    return tuple(
        entry
        for entry in enforcement_report(profile, backend)
        if entry.status is Enforcement.REFUSED
    )


#: Settings whose semantics describe the trust boundary itself, and which an
#: explicit reduced-protection opt-in may therefore **never** waive. Accepting
#: ``no_new_privileges=false`` or ``network=restricted`` would not mean "running
#: without a control"; it would mean recording a posture the operating system
#: does not implement, which is the one thing this module exists to prevent.
NEVER_OVERRIDABLE: frozenset[str] = frozenset(
    {
        "network",
        "no_new_privileges",
        "drop_all_capabilities",
        "add_capabilities",
        "allowed_networks",
    }
)


def require_honourable(
    profile: ContainmentProfile,
    backend: str,
    allow_reduced_protection: bool = False,
) -> tuple[FieldEnforcement, ...]:
    """Refuse the session when a declared setting cannot be honoured.

    The rule this enforces is the difference between *silence* and *intent*:

    * **not specified** - no ceiling was asked for, so running without one is
      correct and nothing is raised;
    * **explicitly specified but unsupported** - the operator asked for a
      control this backend cannot apply. The session is refused **before the
      workload is launched**, because proceeding would record a constraint that
      nothing implements.

    ``allow_reduced_protection`` is the explicit, recorded opt-in for a caller
    who has decided to run without such a control (for example a CPU ceiling on
    a backend that has no cgroup quota). It never covers the settings in
    :data:`NEVER_OVERRIDABLE`, whose whole meaning is the posture itself. The
    profile's own ``allow_reduced_protection`` field is always honoured, so a
    caller cannot accidentally refuse a profile that already recorded the
    acknowledgement.

    Returns the settings that were waived, so the caller can record them.
    """
    accepted = allow_reduced_protection or profile.allow_reduced_protection
    defaults = _defaults()
    waivable: list[FieldEnforcement] = []
    blockers: list[FieldEnforcement] = []

    for entry in refusals(profile, backend):
        if entry.field == "network" or _declared_explicitly(profile, defaults, entry.field):
            if entry.field in NEVER_OVERRIDABLE:
                blockers.append(entry)
            elif accepted:
                waivable.append(entry)
            else:
                blockers.append(entry)

    if blockers:
        detail = "; ".join(
            f"{entry.field}={entry.declared!r}: {entry.detail}" for entry in blockers
        )
        hint = (
            ""
            if any(entry.field in NEVER_OVERRIDABLE for entry in blockers)
            else (
                " Pass --allow-reduced-protection (or set "
                "allow_reduced_protection in the profile) to accept running "
                "without it; the waiver is recorded in the Proof of Execution."
            )
        )
        raise ContainmentRefused(
            f"the {backend} containment backend cannot honour this profile, so it "
            "would be recorded as enforced configuration that nothing implements "
            f"({detail}).{hint}"
        )
    return tuple(waivable)


def _declared_explicitly(
    profile: ContainmentProfile, defaults: ContainmentProfile, field: str
) -> bool:
    """Whether ``field`` differs from the profile's own default."""
    if field == "network":
        # ``restricted`` is never a default and is always refused.
        return True
    if "." in field:
        section, name = field.split(".", 1)
        try:
            return getattr(getattr(profile, section), name) != getattr(
                getattr(defaults, section), name
            )
        except AttributeError:  # pragma: no cover - defensive
            return False
    try:
        return getattr(profile, field) != getattr(defaults, field)
    except AttributeError:  # pragma: no cover - defensive
        return False


def report_summary(report: "Iterable[FieldEnforcement]") -> dict[str, Any]:
    """A compact, JSON-safe summary for the trace and for ``doctor``."""
    entries = list(report)
    counts: dict[str, int] = {status.value: 0 for status in Enforcement}
    for entry in entries:
        counts[entry.status.value] += 1
    return {
        "counts": counts,
        "fields": [entry.to_dict() for entry in entries],
    }


def unsupported_summary(profile: ContainmentProfile, backend: str) -> dict[str, Any]:
    """The unhonoured settings, split by whether they were explicitly declared."""
    defaults = _defaults()
    entries = unhonoured(profile, backend)
    return {
        "backend": backend,
        "unhonoured": [entry.to_dict() for entry in entries],
        "declared_but_unhonoured": [
            entry.to_dict()
            for entry in entries
            if _declared_explicitly(profile, defaults, entry.field)
        ],
    }
