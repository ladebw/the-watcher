"""Host capability detection.

V3 is Linux-only, and this module exists so that fact is *reported* rather
than discovered by a workload silently running with less protection than was
asked for.

Every probe here is a real check: namespaces are read from ``/proc``, seccomp
is verified by actually installing a filter in a throwaway child, Landlock by
calling its syscall, and ``unshare --map-root-user`` by running it.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

__all__ = [
    "BackendAvailability",
    "HostCapabilities",
    "detect_capabilities",
    "clear_capability_cache",
]

SYS_LANDLOCK_CREATE_RULESET = 444
LANDLOCK_CREATE_RULESET_VERSION = 1

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

_AUDIT_ARCH_X86_64 = 0xC000003E
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_KILL_PROCESS = 0x80000000

_PROBE_TIMEOUT = 15.0
_cached: "HostCapabilities | None" = None


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


@dataclass(frozen=True)
class BackendAvailability:
    """Whether one enforcement backend can be used on this host."""

    name: str
    available: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "available": self.available, "detail": self.detail}


@dataclass(frozen=True)
class HostCapabilities:
    """What this host can actually enforce."""

    os_name: str
    is_linux: bool
    kernel_release: str
    arch: str

    user_namespaces: bool = False
    pid_namespaces: bool = False
    mount_namespaces: bool = False
    network_namespaces: bool = False
    ipc_namespaces: bool = False
    uts_namespaces: bool = False
    cgroup_namespaces: bool = False

    seccomp_available: bool = False
    seccomp_detail: str = ""
    landlock_abi: "int | None" = None
    cgroup_version: "int | None" = None
    cgroup_controllers: tuple[str, ...] = ()

    unshare_binary: "str | None" = None
    unprivileged_userns_ok: bool = False
    unprivileged_userns_detail: str = ""

    docker_binary: "str | None" = None
    podman_binary: "str | None" = None
    container_runtime_detail: str = ""

    backends: tuple[BackendAvailability, ...] = ()
    problems: tuple[str, ...] = ()
    checked_at: int = 0

    # -- derived ---------------------------------------------------------

    @property
    def namespaces_available(self) -> bool:
        return (
            self.user_namespaces
            and self.pid_namespaces
            and self.mount_namespaces
            and self.network_namespaces
        )

    @property
    def enforced_mode_available(self) -> bool:
        """``True`` when at least one backend can enforce containment."""
        return any(backend.available for backend in self.backends)

    @property
    def available_backends(self) -> tuple[str, ...]:
        return tuple(backend.name for backend in self.backends if backend.available)

    def backend(self, name: str) -> "BackendAvailability | None":
        for backend in self.backends:
            if backend.name == name:
                return backend
        return None

    # -- serialisation ---------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "os_name": self.os_name,
            "is_linux": self.is_linux,
            "kernel_release": self.kernel_release,
            "arch": self.arch,
            "user_namespaces": self.user_namespaces,
            "pid_namespaces": self.pid_namespaces,
            "mount_namespaces": self.mount_namespaces,
            "network_namespaces": self.network_namespaces,
            "ipc_namespaces": self.ipc_namespaces,
            "uts_namespaces": self.uts_namespaces,
            "cgroup_namespaces": self.cgroup_namespaces,
            "seccomp_available": self.seccomp_available,
            "seccomp_detail": self.seccomp_detail,
            "landlock_abi": self.landlock_abi,
            "cgroup_version": self.cgroup_version,
            "cgroup_controllers": list(self.cgroup_controllers),
            "unshare_binary": self.unshare_binary,
            "unprivileged_userns_ok": self.unprivileged_userns_ok,
            "unprivileged_userns_detail": self.unprivileged_userns_detail,
            "docker_binary": self.docker_binary,
            "podman_binary": self.podman_binary,
            "container_runtime_detail": self.container_runtime_detail,
            "backends": [backend.to_dict() for backend in self.backends],
            "problems": list(self.problems),
            "checked_at": self.checked_at,
        }

    # -- reporting -------------------------------------------------------

    def doctor_report(self) -> str:
        """Human-readable capability report (`watcher doctor`)."""
        yes = lambda flag: "yes" if flag else "no"  # noqa: E731

        lines = ["The Watcher - containment capabilities", ""]
        lines.append(f"Host platform:         {self.os_name} ({self.arch})")
        lines.append(f"Kernel:                {self.kernel_release or 'n/a'}")
        lines.append("")

        if not self.is_linux:
            lines.append("Linux:                 no")
            lines.append("")
            lines.append("V3 enforced mode:      UNAVAILABLE")
            lines.append("  Reason: Linux enforcement backend required")
            lines.append("  V2 external supervisor remains available on this platform.")
            lines.append("")
            lines.append(
                "  On Windows, run V3 inside WSL2, a Linux container environment,"
            )
            lines.append("  or a Linux VM and invoke the Watcher from there.")
            if self.problems:
                lines.append("")
                lines.append("Notes:")
                for problem in self.problems:
                    lines.append(f"  - {problem}")
            return "\n".join(lines)

        lines.append("Linux:                 yes")
        lines.append(f"Namespaces:            {yes(self.namespaces_available)}")
        lines.append(f"  user namespace:      {yes(self.user_namespaces)}")
        lines.append(f"  pid namespace:       {yes(self.pid_namespaces)}")
        lines.append(f"  mount namespace:     {yes(self.mount_namespaces)}")
        lines.append(f"  network namespace:   {yes(self.network_namespaces)}")
        lines.append(
            f"  unprivileged userns: {yes(self.unprivileged_userns_ok)}"
            + (f"  ({self.unprivileged_userns_detail})" if self.unprivileged_userns_detail else "")
        )
        lines.append(
            f"Seccomp:               {yes(self.seccomp_available)}"
            + (f"  ({self.seccomp_detail})" if self.seccomp_detail else "")
        )
        lines.append(
            "Landlock ABI:          "
            + (str(self.landlock_abi) if self.landlock_abi else "unavailable")
        )
        lines.append(
            "cgroups:               "
            + (f"v{self.cgroup_version}" if self.cgroup_version else "unavailable")
        )
        if self.cgroup_controllers:
            lines.append(
                "  controllers:         " + ",".join(self.cgroup_controllers[:8])
            )
        lines.append("")

        lines.append("Enforcement backends:")
        for backend in self.backends:
            lines.append(
                f"  {backend.name:<20} {'AVAILABLE' if backend.available else 'unavailable'}"
                f"  {backend.detail}"
            )
        lines.append("")

        lines.append(
            "V3 enforced mode:      "
            + ("AVAILABLE" if self.enforced_mode_available else "UNAVAILABLE")
        )
        if not self.enforced_mode_available:
            lines.append("  Reason: " + (self.problems[0] if self.problems else "unknown"))

        if self.problems:
            lines.append("")
            lines.append("Notes:")
            for problem in self.problems:
                lines.append(f"  - {problem}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------


def _probe_namespaces() -> dict[str, bool]:
    kinds = ("user", "pid", "mnt", "net", "ipc", "uts", "cgroup")
    result: dict[str, bool] = {}
    for kind in kinds:
        result[kind] = os.path.exists(f"/proc/self/ns/{kind}")
    return result


def _probe_seccomp() -> tuple[bool, str]:
    """Verify seccomp by installing a real filter in a throwaway child."""
    program = (
        _SockFilter(code=0x20, jt=0, jf=0, k=4),  # ld arch
        _SockFilter(code=0x15, jt=1, jf=0, k=_AUDIT_ARCH_X86_64),  # jeq
        _SockFilter(code=0x06, jt=0, jf=0, k=_SECCOMP_RET_KILL_PROCESS),
        _SockFilter(code=0x06, jt=0, jf=0, k=_SECCOMP_RET_ALLOW),
    )
    array = (_SockFilter * len(program))(*program)
    fprog = _SockFprog(len=len(program), filter=array)

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - child
        os.close(read_fd)
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            message = "seccomp filter installed"
            code = 0
            if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
                code, message = 1, f"prctl(no_new_privs) failed: errno {ctypes.get_errno()}"
            elif libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog)) != 0:
                code, message = 1, f"prctl(set_seccomp) failed: errno {ctypes.get_errno()}"
        except BaseException as exc:  # noqa: BLE001
            code, message = 1, f"{type(exc).__name__}: {exc}"
        os.write(write_fd, message.encode()[:200])
        os.close(write_fd)
        os._exit(code)

    os.close(write_fd)
    detail = os.read(read_fd, 256).decode("utf-8", "replace")
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    ok = os.waitstatus_to_exitcode(status) == 0
    return ok, detail if detail else ("seccomp filter installed" if ok else "unavailable")


def _probe_landlock() -> "int | None":
    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except OSError:
        return None
    ctypes.set_errno(0)
    result = libc.syscall(
        SYS_LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION
    )
    if result >= 0:
        return int(result)
    if ctypes.get_errno() == errno.ENOSYS:
        return None
    return None


def _probe_cgroups() -> tuple["int | None", tuple[str, ...]]:
    controllers_path = "/sys/fs/cgroup/cgroup.controllers"
    if os.path.exists(controllers_path):
        try:
            with open(controllers_path, "r", encoding="utf-8") as handle:
                controllers = tuple(handle.read().split())
        except OSError:
            controllers = ()
        return 2, controllers
    if os.path.exists("/proc/cgroups"):
        return 1, ()
    return None, ()


def _probe_unprivileged_userns(unshare: "str | None") -> tuple[bool, str]:
    if not unshare:
        return False, "unshare not installed"
    try:
        completed = subprocess.run(
            [unshare, "--user", "--map-root-user", "--", "true"],
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{type(exc).__name__}"
    if completed.returncode == 0:
        return True, "unshare --user --map-root-user works"
    detail = (completed.stderr or completed.stdout or "").strip().splitlines()
    return False, detail[0] if detail else f"exit {completed.returncode}"


def _probe_container_runtime(
    docker: "str | None", podman: "str | None"
) -> tuple[bool, str]:
    candidates = [name for name in (docker, podman) if name]
    if not candidates:
        return False, "no container runtime found on PATH"
    for binary in candidates:
        try:
            completed = subprocess.run(
                [binary, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=_PROBE_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"{type(exc).__name__} probing {os.path.basename(binary)}"
        if completed.returncode == 0:
            return True, f"{os.path.basename(binary)} daemon reachable"
        detail = (completed.stderr or "").strip().splitlines()
        return False, f"{os.path.basename(binary)}: {detail[0] if detail else 'daemon not reachable'}"
    return False, "no usable container runtime"


def detect_capabilities(refresh: bool = False) -> HostCapabilities:
    """Probe the host. Results are cached for the process lifetime."""
    global _cached  # noqa: PLW0603 - deliberate process-wide cache
    if _cached is not None and not refresh:
        return _cached

    import time

    is_linux = sys.platform.startswith("linux") and os.path.isdir("/proc/self/ns")
    namespaces = _probe_namespaces() if is_linux else {}
    problems: list[str] = []

    seccomp_available = False
    seccomp_detail = "requires Linux"
    landlock_abi: "int | None" = None
    cgroup_version: "int | None" = None
    cgroup_controllers: tuple[str, ...] = ()

    if is_linux:
        seccomp_available, seccomp_detail = _probe_seccomp()
        landlock_abi = _probe_landlock()
        cgroup_version, cgroup_controllers = _probe_cgroups()

        if not seccomp_available:
            problems.append(
                "seccomp filters cannot be installed: syscall enforcement "
                "is unavailable on this host"
            )
        if landlock_abi is None:
            problems.append(
                "Landlock is unavailable: filesystem enforcement falls back to "
                "mount isolation and a read-only root only"
            )

    unshare_binary = shutil.which("unshare") if is_linux else None
    userns_ok = False
    userns_detail = "requires Linux"
    if is_linux:
        userns_ok, userns_detail = _probe_unprivileged_userns(unshare_binary)

    docker_binary = shutil.which("docker")
    podman_binary = shutil.which("podman")
    runtime_ok, runtime_detail = (False, "requires Linux")
    if is_linux:
        runtime_ok, runtime_detail = _probe_container_runtime(docker_binary, podman_binary)

    # -- backend availability -------------------------------------------
    namespaces_reasons: list[str] = []
    if not is_linux:
        namespaces_reasons.append("requires Linux")
    if not unshare_binary:
        namespaces_reasons.append("unshare not installed")
    if not userns_ok:
        namespaces_reasons.append(f"unprivileged user namespaces: {userns_detail}")
    for kind in ("pid", "mnt", "net"):
        if not namespaces.get(kind):
            namespaces_reasons.append(f"{kind} namespace unavailable")
    if not seccomp_available:
        namespaces_reasons.append("seccomp unavailable")

    namespaces_backend = BackendAvailability(
        name="namespaces",
        available=not namespaces_reasons,
        detail=(
            "user+pid+mnt+net+ipc+uts namespaces, seccomp, "
            f"landlock ABI {landlock_abi}" if not namespaces_reasons else "; ".join(namespaces_reasons)
        ),
    )

    docker_reasons: list[str] = []
    if not is_linux:
        docker_reasons.append("requires Linux")
    if not docker_binary and not podman_binary:
        docker_reasons.append("no docker or podman binary on PATH")
    elif not runtime_ok:
        docker_reasons.append(runtime_detail)

    docker_backend = BackendAvailability(
        name="docker",
        available=not docker_reasons,
        detail=runtime_detail if not docker_reasons else "; ".join(docker_reasons),
    )

    capabilities = HostCapabilities(
        os_name=platform.system().lower(),
        is_linux=is_linux,
        kernel_release=platform.release(),
        arch=platform.machine(),
        user_namespaces=bool(namespaces.get("user")),
        pid_namespaces=bool(namespaces.get("pid")),
        mount_namespaces=bool(namespaces.get("mnt")),
        network_namespaces=bool(namespaces.get("net")),
        ipc_namespaces=bool(namespaces.get("ipc")),
        uts_namespaces=bool(namespaces.get("uts")),
        cgroup_namespaces=bool(namespaces.get("cgroup")),
        seccomp_available=seccomp_available,
        seccomp_detail=seccomp_detail,
        landlock_abi=landlock_abi,
        cgroup_version=cgroup_version,
        cgroup_controllers=cgroup_controllers,
        unshare_binary=unshare_binary,
        unprivileged_userns_ok=userns_ok,
        unprivileged_userns_detail=userns_detail,
        docker_binary=docker_binary,
        podman_binary=podman_binary,
        container_runtime_detail=runtime_detail,
        backends=(namespaces_backend, docker_backend),
        problems=tuple(problems),
        checked_at=int(time.time()),
    )

    _cached = capabilities
    return capabilities


def clear_capability_cache() -> None:
    """Drop the cached probe result (used by tests)."""
    global _cached  # noqa: PLW0603
    _cached = None
