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
BPF_ALU = 0x04
BPF_AND = 0x50
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06

LD_W_ABS = BPF_LD | BPF_W | BPF_ABS
ALU_AND_K = BPF_ALU | BPF_AND | BPF_K
JMP_JEQ_K = BPF_JMP | BPF_JEQ | BPF_K
RET_K = BPF_RET | BPF_K

#: ``struct seccomp_data`` field offsets. Verified against
#: ``/usr/include/linux/seccomp.h`` and by ``offsetof`` on the build host:
#: ``nr`` at 0, ``arch`` at 4, ``instruction_pointer`` at 8, ``args`` at 16,
#: each argument 64 bits, so ``args[0]`` is the low word at 16 and the high
#: word at 20. The layout is UAPI and identical on every supported
#: architecture; only the syscall *numbers* are per-arch.
OFFSET_NR = 0
OFFSET_ARCH = 4
OFFSET_ARG0_LOW = 16
OFFSET_ARG0_HIGH = 20

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

#: Audit architecture value per ``platform.machine()``.
ARCH_BY_MACHINE = {
    "x86_64": AUDIT_ARCH_X86_64,
    "amd64": AUDIT_ARCH_X86_64,
    "aarch64": AUDIT_ARCH_AARCH64,
    "arm64": AUDIT_ARCH_AARCH64,
}

# ---------------------------------------------------------------------------
# clone() namespace flags
# ---------------------------------------------------------------------------
#
# ``clone`` is the one syscall that must stay *allowed* while a specific set of
# its flags must not be. Denying the syscall outright would break threads and
# process creation, which every supported workload needs, so the filter
# inspects the flags argument instead.
#
# These values are UAPI constants from ``<linux/sched.h>``: they are identical
# on every architecture, which is why only the syscall *number* has to be
# per-arch. Audited against the real header rather than transcribed from
# memory.

#: Low 32 bits of the ``clone`` flags argument that create a namespace.
CLONE_NEWTIME = 0x00000080  # sits inside the CSIGNAL byte, but is never a signal
CLONE_NEWNS = 0x00020000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000

#: Every namespace-creating bit in the low word. Computed from the constants
#: above so a value can never drift from the definition.
CLONE_NAMESPACE_FLAGS = (
    CLONE_NEWTIME
    | CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET
)  # == 0x7E020080

#: Flags that live *above* bit 31 and are therefore in the high word:
#: ``CLONE_CLEAR_SIGHAND`` (0x1_00000000) and ``CLONE_INTO_CGROUP``
#: (0x2_00000000). Both are clone3-era flags; legacy ``clone`` rejects them
#: with ``EINVAL``, but denying them here is the fail-closed direction and
#: costs one comparison. Only these two bits are masked, so a sign-extended
#: negative ``int`` flags value (as some libc wrappers pass) is still allowed.
CLONE_HIGH_FLAGS = 0x3

#: A 32-bit word of all ones: what a negative ``int`` flags value looks like in
#: the high word once sign-extended to 64 bits. ``CLONE_IO`` is 0x80000000, and
#: a libc wrapper that takes ``int flags`` sign-extends it, so this form must
#: stay allowed or the rule would break a legitimate caller.
SIGN_EXTENDED_WORD = 0xFFFFFFFF

#: Flags deliberately *not* treated as namespace creation, with the reasoning
#: recorded so a future reader does not have to re-derive it:
#:
#: ``CLONE_NEWUSER`` and friends above are the complete set defined by the
#: kernel. ``CLONE_NEWTIME`` is included even though legacy ``clone`` cannot
#: actually use it (the low byte carries the exit signal and 0x80 is not a
#: valid signal), so the rule stays correct if that ever changes.
NON_NAMESPACE_CLONE_FLAGS = (
    "CLONE_VM",
    "CLONE_FS",
    "CLONE_FILES",
    "CLONE_SIGHAND",
    "CLONE_THREAD",
    "CLONE_SYSVSEM",
    "CLONE_SETTLS",
    "CLONE_PARENT_SETTID",
    "CLONE_CHILD_CLEARTID",
    "CLONE_CHILD_SETTID",
    "CLONE_VFORK",
    "CLONE_PARENT",
    "CLONE_PIDFD",
    "CLONE_PTRACE",
    "CLONE_DETACHED",
    "CLONE_UNTRACED",
    "CLONE_IO",
    "SIGCHLD",
)

#: ``syscall name -> (argument index, low mask, high mask)``. Every entry means
#: "allow this syscall unless one of these bits is set in this argument". The
#: syscall itself is looked up in the ``clone_guard`` category of the syscall
#: tables, which is deliberately absent from ``CATEGORY_FLAGS`` so that the
#: syscall is never blocked outright.
ARGUMENT_GUARDS: dict[str, tuple[int, int, int]] = {
    "clone": (0, CLONE_NAMESPACE_FLAGS, CLONE_HIGH_FLAGS),
}

#: The syscall table category used only for guard number lookup.
CLONE_GUARD_CATEGORY = "clone_guard"

#: Syscalls that must report ``ENOSYS`` rather than ``EPERM``.
#:
#: ``clone3`` is the load-bearing case, and getting this wrong breaks every
#: threaded workload. glibc's ``__clone_internal`` tries ``clone3`` first and
#: falls back to the legacy ``clone`` syscall **only when ``clone3`` fails with
#: ``ENOSYS``**; any other errno is taken as a real refusal. Returning ``EPERM``
#: here therefore made ``pthread_create`` fail inside the sandbox with
#: "can't start new thread" - measured, not theorised, on glibc 2.39.
#:
#: ``ENOSYS`` is also the more honest answer for this syscall: the filter is
#: making it appear unavailable, and the runtime's documented fallback then
#: takes the legacy ``clone`` path, where the namespace flags are guarded
#: separately. No protection is lost - ``clone3`` still cannot create a
#: namespace, and ``unshare``/``setns`` still return ``EPERM``.
DENIAL_ERRNO_OVERRIDES: dict[str, str] = {"clone3": "ENOSYS"}


def syscall_denials(policy: Any, arch: "int | None" = None) -> dict[str, tuple[int, int]]:
    """``syscall name -> (number, errno value)`` for every whole-syscall denial."""
    resolved = arch if arch is not None else current_arch()
    default = errno_for(getattr(policy, "errno_name", "EPERM"))
    denials: dict[str, tuple[int, int]] = {}
    for name, number in blocked_syscalls(policy, resolved).items():
        override = DENIAL_ERRNO_OVERRIDES.get(name)
        denials[name] = (number, errno_for(override) if override else default)
    return denials

#: Syscall categories. Each maps a category name to {syscall name: number}.
#: Numbers are per-architecture and must come from these tables, never from a
#: guess.
_X86_64 = {
    "namespace_manipulation": {
        "unshare": 272,
        "setns": 308,
        "clone3": 435,
    },
    # Lookup-only category: ``blocked_syscalls`` skips any category that is not
    # in ``CATEGORY_FLAGS``, so ``clone`` stays callable while its flags
    # argument is inspected by the guard below. Verified against
    # ``/usr/include/x86_64-linux-gnu/asm/unistd_64.h``: __NR_clone == 56.
    "clone_guard": {"clone": 56},
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
    # Lookup-only; see the x86_64 table. Verified against
    # ``/usr/include/asm-generic/unistd.h``: __NR_clone == 220.
    "clone_guard": {"clone": 220},
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


def argument_guards(policy: Any, arch: "int | None" = None) -> dict[str, dict[str, int]]:
    """The syscalls that are allowed *conditionally*, and on what condition.

    Returns ``{syscall: {"arg": i, "low_mask": m, "high_mask": h}}`` for the
    guards that are enabled by ``policy``. A guard means "allow this syscall
    unless one of these bits is set in this argument" - used for ``clone``,
    where denying the syscall outright would break threads and process
    creation.
    """
    resolved = arch if arch is not None else current_arch()
    table = SYSCALL_TABLES.get(resolved)
    if table is None:
        raise RuntimeError(f"no seccomp syscall table for arch {resolved:#x}")

    enabled = bool(getattr(policy, "block_clone_namespaces", True))
    guards: dict[str, dict[str, int]] = {}
    if not enabled:
        return guards
    guard_table = table.get(CLONE_GUARD_CATEGORY, {})
    for name, (index, low_mask, high_mask) in ARGUMENT_GUARDS.items():
        if name in guard_table:
            guards[name] = {"arg": index, "low_mask": low_mask, "high_mask": high_mask}
    return guards


def build_program(policy: Any, arch: "int | None" = None) -> list[tuple[int, int, int, int]]:
    """Build the BPF program as ``(code, jt, jf, k)`` tuples.

    Layout::

        ld  arch
        jeq AUDIT_ARCH, +1, 0
        ret KILL_PROCESS                  (wrong ABI -> die, never allow)
        ld  nr
        for each blocked syscall:         (whole-syscall denials)
            jeq number, 0, +1
            ret ERRNO|errno
        for each argument guard:          (conditional denials, e.g. clone)
            ld  nr
            jeq number, 0, +4
            ld  args[i] low
            and low_mask
            jeq 0, +1, 0
            ret ERRNO|errno
        ret ALLOW

    The guard block is self-contained and begins by reloading the syscall
    number, because the ``and`` leaves the accumulator holding the masked
    argument rather than ``nr``. Without that reload, a guard that falls
    through would leave the next comparison testing the wrong value.

    Argument inspection is safe here in a way that ``SECCOMP_RET_USER_NOTIF``
    mediation is not: the flags argument is a *value*, not a pointer, so there
    is no TOCTOU window and no supervisor round trip.
    """
    resolved = arch if arch is not None else current_arch()
    error = errno_for(getattr(policy, "errno_name", "EPERM"))
    table = SYSCALL_TABLES[resolved]
    guards = argument_guards(policy, resolved)

    # One errno per syscall number; ``clone3`` reports ENOSYS so that glibc's
    # documented fallback to legacy ``clone`` happens (see
    # ``DENIAL_ERRNO_OVERRIDES``).
    by_number: dict[int, int] = {}
    for _name, (number, err) in syscall_denials(policy, resolved).items():
        by_number.setdefault(number, err)

    guarded_numbers = {
        table[CLONE_GUARD_CATEGORY][name]
        for name in guards
        if name in table.get(CLONE_GUARD_CATEGORY, {})
    }

    program: list[tuple[int, int, int, int]] = [
        (LD_W_ABS, 0, 0, OFFSET_ARCH),
        (JMP_JEQ_K, 1, 0, resolved),
        (RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        (LD_W_ABS, 0, 0, OFFSET_NR),
    ]

    # Whole-syscall denials.
    for number in sorted(n for n in by_number if n not in guarded_numbers):
        program.append((JMP_JEQ_K, 0, 1, number))
        program.append((RET_K, 0, 0, SECCOMP_RET_ERRNO | by_number[number]))

    # Conditional denials: the syscall is allowed unless the masked bits are set.
    for name in sorted(guards):
        guard = guards[name]
        number = table[CLONE_GUARD_CATEGORY][name]
        low_offset = OFFSET_ARG0_LOW + 8 * int(guard["arg"])
        high_offset = OFFSET_ARG0_HIGH + 8 * int(guard["arg"])

        # Low word: deny when any namespace-creating bit is present.
        #   [0] ld nr
        #   [1] jeq N, 0, 4      (not clone -> skip the 4-instruction block)
        #   [2] ld args[i] low
        #   [3] and low_mask
        #   [4] jeq 0, 1, 0      (no namespace bit -> skip the denial)
        #   [5] ret ERRNO
        program.append((LD_W_ABS, 0, 0, OFFSET_NR))
        program.append((JMP_JEQ_K, 0, 4, number))
        program.append((LD_W_ABS, 0, 0, low_offset))
        program.append((ALU_AND_K, 0, 0, int(guard["low_mask"])))
        program.append((JMP_JEQ_K, 1, 0, 0))
        program.append((RET_K, 0, 0, SECCOMP_RET_ERRNO | error))

        if int(guard["high_mask"]):
            # High word: the clone3-era flags live above bit 31, but a *sign
            # extended* negative int flags value sets every high bit too, and
            # that is legitimate - ``CLONE_IO`` is 0x80000000 and some libc
            # wrappers pass it as a negative ``int``. Denying all-ones would
            # break such a caller, so the pure sign-extension form is allowed
            # and anything else with those bits set is denied.
            #   [0] ld nr
            #   [1] jeq N, 0, 6
            #   [2] ld args[i] high
            #   [3] and high_mask
            #   [4] jeq 0, 3, 0          (no clone3-era bit -> allow)
            #   [5] ld args[i] high
            #   [6] jeq 0xFFFFFFFF, 1, 0 (pure sign extension -> allow)
            #   [7] ret ERRNO
            program.append((LD_W_ABS, 0, 0, OFFSET_NR))
            program.append((JMP_JEQ_K, 0, 6, number))
            program.append((LD_W_ABS, 0, 0, high_offset))
            program.append((ALU_AND_K, 0, 0, int(guard["high_mask"])))
            program.append((JMP_JEQ_K, 3, 0, 0))
            program.append((LD_W_ABS, 0, 0, high_offset))
            program.append((JMP_JEQ_K, 1, 0, SIGN_EXTENDED_WORD))
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
    guards = argument_guards(policy, arch)
    denials = syscall_denials(policy, arch)
    return {
        "enabled": True,
        "arch": f"0x{(arch if arch is not None else current_arch()):x}",
        "instructions": len(program),
        "blocked_count": len(blocked),
        "blocked_syscalls": sorted(blocked),
        "denial_errno": {
            name: errno.errorcode.get(err, str(err))
            for name, (_number, err) in sorted(denials.items())
        },
        "argument_guards": {
            name: {
                "arg": guard["arg"],
                "low_mask": f"0x{guard['low_mask']:08x}",
                "high_mask": f"0x{guard['high_mask']:08x}",
            }
            for name, guard in guards.items()
        },
        "action": "ERRNO",
        "errno_name": getattr(policy, "errno_name", "EPERM"),
    }
