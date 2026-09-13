"""seccomp-bpf filter construction.

Standard library only, and free of intra-package imports, because this file is
copied verbatim into the sandbox and imported by the exec guard as well as
being used by the supervisor for validation.

Architecture handling
---------------------
The filter **validates the syscall ABI first** and kills the process on a
mismatch. A filter that compared only syscall numbers would be meaningless on
a different architecture, since the numbers are per-ABI. Syscall numbers for
every supported architecture are therefore kept in explicit tables.

Return action
-------------
Blocked syscalls return ``EPERM`` rather than a kill, so a workload that
probes a dangerous operation gets a normal ``PermissionError`` instead of
dying. That also makes the denial observable and recordable as
``OS_ENFORCEMENT_DENIED`` rather than a crash.

``SECCOMP_RET_USER_NOTIF``
--------------------------
Dynamic, argument-inspecting mediation is *not* used by default. It requires
careful (and TOCTOU-prone) pointer handling, and the supervisor would become a
syscall broker on the critical path. The constant and the plumbing are defined
here so a future backend can adopt it behind an explicit profile flag; see
``docs`` in the README for the limitations of argument inspection.
"""

from __future__ import annotations

import ctypes
import errno
import platform
from typing import Any

# -- prctl ------------------------------------------------------------------
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# -- seccomp return actions -------------------------------------------------
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_TRAP = 0x00030000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_USER_NOTIF = 0x7FC00000
SECCOMP_RET_LOG = 0x7FFC0000
SECCOMP_RET_ALLOW = 0x7FFF0000

# -- bpf instruction encoding ----------------------------------------------
BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06

LD_W_ABS = BPF_LD | BPF_W | BPF_ABS
JMP_JEQ_K = BPF_JMP | BPF_JEQ | BPF_K
RET_K = BPF_RET | BPF_K

#: ``struct seccomp_data`` field offsets.
OFFSET_NR = 0
OFFSET_ARCH = 4

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

#: Audit architecture value per ``platform.machine()``.
ARCH_BY_MACHINE = {
    "x86_64": AUDIT_ARCH_X86_64,
    "amd64": AUDIT_ARCH_X86_64,
    "aarch64": AUDIT_ARCH_AARCH64,
    "arm64": AUDIT_ARCH_AARCH64,
}

#: Syscall categories. Each maps a category name to {syscall name: number}.
#: Numbers are per-architecture and must come from these tables, never from a
#: guess.
_X86_64 = {
    "namespace_manipulation": {
        "unshare": 272,
        "setns": 308,
        "clone3": 435,
    },
    "mount_operations": {
        "mount": 165,
        "umount2": 166,
        "pivot_root": 155,
        "chroot": 161,
        "move_mount": 429,
        "open_tree": 428,
        "fsopen": 430,
        "fsconfig": 431,
        "fsmount": 432,
        "fspick": 433,
        "mount_setattr": 442,
    },
    "ptrace": {
        "ptrace": 101,
        "process_vm_readv": 310,
        "process_vm_writev": 311,
    },
    "kernel_modules": {
        "init_module": 175,
        "finit_module": 313,
        "delete_module": 176,
    },
    "bpf": {"bpf": 321},
    "reboot": {
        "reboot": 169,
        "kexec_load": 246,
        "kexec_file_load": 320,
    },
    "keyring": {
        "add_key": 248,
        "request_key": 249,
        "keyctl": 250,
    },
    "raw_io": {
        "iopl": 172,
        "ioperm": 173,
        "open_by_handle_at": 304,
        "name_to_handle_at": 303,
    },
    "privileged_system": {
        "acct": 163,
        "quotactl": 179,
        "settimeofday": 164,
        "clock_settime": 227,
        "adjtimex": 159,
        "sethostname": 170,
        "setdomainname": 171,
        "syslog": 103,
        "personality": 135,
        "vhangup": 153,
    },
    "swap": {
        "swapon": 167,
        "swapoff": 168,
    },
    "perf": {"perf_event_open": 298},
    "io_uring": {
        "io_uring_setup": 425,
        "io_uring_enter": 426,
        "io_uring_register": 427,
    },
    "userfaultfd": {"userfaultfd": 323},
}

_AARCH64 = {
    "namespace_manipulation": {"unshare": 97, "setns": 268, "clone3": 435},
    "mount_operations": {
        "mount": 40,
        "umount2": 39,
        "pivot_root": 41,
        "chroot": 51,
        "move_mount": 429,
        "open_tree": 428,
        "fsopen": 430,
        "fsconfig": 431,
        "fsmount": 432,
        "fspick": 433,
        "mount_setattr": 442,
    },
    "ptrace": {"ptrace": 117, "process_vm_readv": 270, "process_vm_writev": 271},
    "kernel_modules": {"init_module": 105, "finit_module": 273, "delete_module": 106},
    "bpf": {"bpf": 280},
    "reboot": {"reboot": 142, "kexec_load": 104, "kexec_file_load": 294},
    "keyring": {"add_key": 217, "request_key": 218, "keyctl": 219},
    "raw_io": {"open_by_handle_at": 265, "name_to_handle_at": 264},
    "privileged_system": {
        "acct": 89,
        "quotactl": 60,
        "settimeofday": 170,
        "clock_settime": 112,
        "adjtimex": 171,
        "sethostname": 161,
        "setdomainname": 162,
        "syslog": 116,
        "personality": 92,
        "vhangup": 58,
    },
    "swap": {"swapon": 224, "swapoff": 225},
    "perf": {"perf_event_open": 241},
    "io_uring": {"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427},
    "userfaultfd": {"userfaultfd": 282},
}

SYSCALL_TABLES: dict[int, dict[str, dict[str, int]]] = {
    AUDIT_ARCH_X86_64: _X86_64,
    AUDIT_ARCH_AARCH64: _AARCH64,
}

#: Policy attribute name -> syscall category it controls.
CATEGORY_FLAGS = {
    "namespace_manipulation": "block_namespace_manipulation",
    "mount_operations": "block_mount",
    "ptrace": "block_ptrace",
    "kernel_modules": "block_kernel_modules",
    "bpf": "block_bpf",
    "reboot": "block_reboot",
    "keyring": "block_keyring",
    "raw_io": "block_raw_io",
    "privileged_system": "block_raw_io",
    "swap": "block_raw_io",
    "perf": "block_perf",
    "io_uring": "block_bpf",
    "userfaultfd": "block_bpf",
    "kexec": "block_kexec",
}


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


def current_arch() -> int:
    machine = platform.machine().lower()
    try:
        return ARCH_BY_MACHINE[machine]
    except KeyError as exc:
        raise RuntimeError(
            f"unsupported architecture for seccomp: {machine!r}. "
            "Refusing to install a filter whose syscall numbers would be wrong."
        ) from exc


def errno_for(name: str) -> int:
    value = getattr(errno, name, None)
    if not isinstance(value, int):
        return errno.EPERM
    return value


def blocked_syscalls(policy: Any, arch: "int | None" = None) -> dict[str, int]:
    """Return ``{syscall name: number}`` blocked by ``policy`` for ``arch``.

    Raises for an architecture with no syscall table rather than emitting a
    filter that cannot be correct.
    """
    resolved = arch if arch is not None else current_arch()
    try:
        table = SYSCALL_TABLES[resolved]
    except KeyError as exc:
        raise RuntimeError(f"no seccomp syscall table for arch {resolved:#x}") from exc

    blocked: dict[str, int] = {}
    for category, numbers in table.items():
        flag = CATEGORY_FLAGS.get(category)
        if flag is None:
            continue
        if category == "kexec":
            enabled = getattr(policy, "block_kexec", True)
        else:
            enabled = getattr(policy, flag, True)
        if enabled:
            blocked.update(numbers)
    return blocked


def build_program(policy: Any, arch: "int | None" = None) -> list[tuple[int, int, int, int]]:
    """Build the BPF program as ``(code, jt, jf, k)`` tuples.

    Layout::

        ld  arch
        jeq AUDIT_ARCH, +1, 0
        ret KILL_PROCESS            (wrong ABI -> die, never allow)
        ld  nr
        for each blocked syscall:
            jeq number, 0, +1
            ret ERRNO|errno
        ret ALLOW
    """
    resolved = arch if arch is not None else current_arch()
    error = errno_for(getattr(policy, "errno_name", "EPERM"))
    blocked = blocked_syscalls(policy, resolved)

    program: list[tuple[int, int, int, int]] = [
        (LD_W_ABS, 0, 0, OFFSET_ARCH),
        (JMP_JEQ_K, 1, 0, resolved),
        (RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        (LD_W_ABS, 0, 0, OFFSET_NR),
    ]
    for number in sorted(set(blocked.values())):
        program.append((JMP_JEQ_K, 0, 1, number))
        program.append((RET_K, 0, 0, SECCOMP_RET_ERRNO | error))
    program.append((RET_K, 0, 0, SECCOMP_RET_ALLOW))
    return program


def program_to_ctypes(program: list[tuple[int, int, int, int]]) -> _SockFprog:
    array = (_SockFilter * len(program))(
        *[_SockFilter(code=c, jt=jt, jf=jf, k=k) for c, jt, jf, k in program]
    )
    return _SockFprog(len=len(program), filter=array)


def install(policy: Any, arch: "int | None" = None) -> dict[str, Any]:
    """Set ``no_new_privs`` and install the filter on the calling process.

    Irreversible and inherited across ``execve``. Must be called after any
    privileged setup (mounts) and after Landlock.
    """
    program = build_program(policy, arch)
    fprog = program_to_ctypes(program)
    libc = ctypes.CDLL(None, use_errno=True)

    ctypes.set_errno(0)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise RuntimeError(f"prctl(PR_SET_NO_NEW_PRIVS) failed: {errno.errorcode.get(err, err)}")

    ctypes.set_errno(0)
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog)) != 0:
        err = ctypes.get_errno()
        raise RuntimeError(f"prctl(PR_SET_SECCOMP) failed: {errno.errorcode.get(err, err)}")

    blocked = blocked_syscalls(policy, arch)
    return {
        "enabled": True,
        "arch": f"0x{(arch if arch is not None else current_arch()):x}",
        "instructions": len(program),
        "blocked_count": len(blocked),
        "blocked_syscalls": sorted(blocked),
        "action": "ERRNO",
        "errno_name": getattr(policy, "errno_name", "EPERM"),
    }
