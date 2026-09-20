"""The argument-aware seccomp rule for ``clone``.

``unshare``, ``setns`` and ``clone3`` are denied outright, but ``clone`` cannot
be: Python threads and every ordinary subprocess go through it. Linux validation
proved that ``clone(CLONE_NEWUSER | CLONE_NEWPID | …)`` therefore succeeded
inside the sandbox and created a nested descendant that outlived its ancestor.

The fix is an argument-aware rule: allow ``clone`` unless its flags argument
carries a namespace-creating bit. This module tests that rule **without needing
Linux**, by interpreting the emitted BPF program. That matters because the
program is built from hand-assembled jump offsets, and a wrong offset would
either let the escape through or break threading - neither of which is visible
from a passing integration test alone.

The mask itself is pinned against the real ``<linux/sched.h>`` UAPI constants,
audited on the build host rather than transcribed from memory.
"""

from __future__ import annotations

import errno

import pytest

from the_watcher.enforcement.linux import seccomp_filter as sf
from the_watcher.enforcement.profile import SyscallPolicy

X86_64 = sf.AUDIT_ARCH_X86_64
AARCH64 = sf.AUDIT_ARCH_AARCH64
OTHER_ARCH = 0xC00000F3

#: UAPI values, audited from /usr/include/linux/sched.h.
UAPI = {
    "CLONE_NEWTIME": 0x00000080,
    "CLONE_NEWNS": 0x00020000,
    "CLONE_NEWCGROUP": 0x02000000,
    "CLONE_NEWUTS": 0x04000000,
    "CLONE_NEWIPC": 0x08000000,
    "CLONE_NEWUSER": 0x10000000,
    "CLONE_NEWPID": 0x20000000,
    "CLONE_NEWNET": 0x40000000,
}

#: Ordinary clone flags that must keep working. Audited from the same header.
ORDINARY = {
    "SIGCHLD": 17,
    "CLONE_VM": 0x00000100,
    "CLONE_FS": 0x00000200,
    "CLONE_FILES": 0x00000400,
    "CLONE_SIGHAND": 0x00000800,
    "CLONE_THREAD": 0x00010000,
    "CLONE_SYSVSEM": 0x00040000,
    "CLONE_SETTLS": 0x00080000,
    "CLONE_PARENT_SETTID": 0x00100000,
    "CLONE_CHILD_CLEARTID": 0x00200000,
    "CLONE_CHILD_SETTID": 0x01000000,
    "CLONE_VFORK": 0x00004000,
    "CLONE_PARENT": 0x00008000,
    "CLONE_PIDFD": 0x00001000,
    "CLONE_IO": 0x80000000,
}

CLONE_NR = {"x86_64": 56, "aarch64": 220}


def _run_program(program, *, nr: int, arch: int, args=(0, 0, 0, 0, 0, 0)) -> int:
    """Interpret the classic-BPF subset that ``build_program`` emits.

    Supports exactly the four opcodes the builder uses, which is enough to
    verify the control flow *and* the jump offsets.
    """
    accumulator = 0
    pc = 0

    def load(offset: int) -> int:
        if offset == sf.OFFSET_NR:
            return nr
        if offset == sf.OFFSET_ARCH:
            return arch
        if sf.OFFSET_ARG0_LOW <= offset < sf.OFFSET_ARG0_LOW + 48:
            delta = offset - sf.OFFSET_ARG0_LOW
            index = delta // 8
            # Each argument is 64 bits: byte 0 is the low 32-bit word, byte 4
            # the high one. ``seccomp_data.args`` is always 64-bit wide.
            word = (delta % 8) // 4
            value = int(args[index]) & 0xFFFFFFFFFFFFFFFF
            return (value >> (32 * word)) & 0xFFFFFFFF
        raise AssertionError(f"program loaded an unexpected offset: {offset}")

    for _ in range(10000):
        code, jt, jf, k = program[pc]
        if code == sf.LD_W_ABS:
            accumulator = load(k)
            pc += 1
        elif code == sf.ALU_AND_K:
            accumulator &= k
            pc += 1
        elif code == sf.JMP_JEQ_K:
            pc += (jt if accumulator == k else jf) + 1
        elif code == sf.RET_K:
            return k
        else:  # pragma: no cover - the builder emits nothing else
            raise AssertionError(f"unexpected opcode {code:#x}")
    raise AssertionError("the program did not terminate")


def _verdict(program, *, nr, arch, args=(0, 0, 0, 0, 0, 0)) -> str:
    action = _run_program(program, nr=nr, arch=arch, args=args)
    if action == sf.SECCOMP_RET_ALLOW:
        return "ALLOW"
    if action == sf.SECCOMP_RET_KILL_PROCESS:
        return "KILL"
    if action & 0xFFFF0000 == sf.SECCOMP_RET_ERRNO:
        err = action & 0x0000FFFF
        return f"ERRNO:{errno.errorcode.get(err, err)}"
    return f"0x{action:08x}"


# ---------------------------------------------------------------------------
# the mask
# ---------------------------------------------------------------------------


def test_the_namespace_mask_matches_the_uapi_constants():
    """Pinned so a value can never drift from the kernel's definitions."""
    assert sf.CLONE_NEWTIME == UAPI["CLONE_NEWTIME"]
    assert sf.CLONE_NEWNS == UAPI["CLONE_NEWNS"]
    assert sf.CLONE_NEWCGROUP == UAPI["CLONE_NEWCGROUP"]
    assert sf.CLONE_NEWUTS == UAPI["CLONE_NEWUTS"]
    assert sf.CLONE_NEWIPC == UAPI["CLONE_NEWIPC"]
    assert sf.CLONE_NEWUSER == UAPI["CLONE_NEWUSER"]
    assert sf.CLONE_NEWPID == UAPI["CLONE_NEWPID"]
    assert sf.CLONE_NEWNET == UAPI["CLONE_NEWNET"]


def test_the_mask_is_exactly_the_union_of_the_namespace_flags():
    expected = 0
    for value in UAPI.values():
        expected |= value
    assert sf.CLONE_NAMESPACE_FLAGS == expected
    # Audited value: CLONE_NEWTIME contributes the 0x80 byte, everything else
    # sits in the top byte-and-a-bit.
    assert sf.CLONE_NAMESPACE_FLAGS == 0x7E020080


@pytest.mark.parametrize("name", sorted(UAPI))
def test_every_namespace_flag_is_inside_the_mask(name):
    assert UAPI[name] & sf.CLONE_NAMESPACE_FLAGS == UAPI[name]


@pytest.mark.parametrize("name", sorted(ORDINARY))
def test_no_ordinary_clone_flag_is_inside_the_mask(name):
    """A mask that caught these would break threads or process creation."""
    assert ORDINARY[name] & sf.CLONE_NAMESPACE_FLAGS == 0, (
        f"{name} must stay allowed but is masked"
    )


def test_the_high_word_mask_covers_the_clone3_era_flags():
    """CLONE_CLEAR_SIGHAND and CLONE_INTO_CGROUP live above bit 31."""
    assert sf.CLONE_HIGH_FLAGS == 0x3
    assert (0x100000000 >> 32) & sf.CLONE_HIGH_FLAGS
    assert (0x200000000 >> 32) & sf.CLONE_HIGH_FLAGS


# ---------------------------------------------------------------------------
# the syscall stays callable
# ---------------------------------------------------------------------------


def test_clone_is_not_in_the_whole_syscall_denylist():
    """Blocking clone outright would break every supported workload."""
    blocked = sf.blocked_syscalls(SyscallPolicy(), X86_64)
    assert "clone" not in blocked
    assert "unshare" in blocked
    assert "setns" in blocked
    assert "clone3" in blocked


def test_the_guard_is_reported_for_each_supported_architecture():
    for machine, arch in (("x86_64", X86_64), ("aarch64", AARCH64)):
        guards = sf.argument_guards(SyscallPolicy(), arch)
        assert "clone" in guards, machine
        assert guards["clone"]["low_mask"] == sf.CLONE_NAMESPACE_FLAGS
        assert guards["clone"]["high_mask"] == sf.CLONE_HIGH_FLAGS
        assert guards["clone"]["arg"] == 0


def test_the_guard_can_be_declared_off_and_then_does_nothing():
    policy = SyscallPolicy(block_clone_namespaces=False)
    assert sf.argument_guards(policy, X86_64) == {}
    program = sf.build_program(policy, X86_64)
    assert _verdict(program, nr=CLONE_NR["x86_64"], arch=X86_64,
                    args=(UAPI["CLONE_NEWUSER"],)) == "ALLOW"


# ---------------------------------------------------------------------------
# the rule, verified by interpreting the program
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("machine,arch", [("x86_64", X86_64), ("aarch64", AARCH64)])
def test_threads_and_ordinary_clone_are_allowed(machine, arch):
    program = sf.build_program(SyscallPolicy(), arch)
    clone = CLONE_NR[machine]

    # fork(2): clone(SIGCHLD)
    assert _verdict(program, nr=clone, arch=arch, args=(ORDINARY["SIGCHLD"],)) == "ALLOW"

    # vfork(2)
    assert (
        _verdict(
            program,
            nr=clone,
            arch=arch,
            args=(ORDINARY["CLONE_VM"] | ORDINARY["CLONE_VFORK"] | ORDINARY["SIGCHLD"],),
        )
        == "ALLOW"
    )

    # pthread_create: the full thread flag set glibc uses.
    thread_flags = (
        ORDINARY["CLONE_VM"]
        | ORDINARY["CLONE_FS"]
        | ORDINARY["CLONE_FILES"]
        | ORDINARY["CLONE_SIGHAND"]
        | ORDINARY["CLONE_THREAD"]
        | ORDINARY["CLONE_SYSVSEM"]
        | ORDINARY["CLONE_SETTLS"]
        | ORDINARY["CLONE_PARENT_SETTID"]
        | ORDINARY["CLONE_CHILD_CLEARTID"]
    )
    assert _verdict(program, nr=clone, arch=arch, args=(thread_flags,)) == "ALLOW"

    # Every ordinary flag together, plus a valid exit signal.
    everything = ORDINARY["SIGCHLD"]
    for name, value in ORDINARY.items():
        if name != "SIGCHLD":
            everything |= value
    assert _verdict(program, nr=clone, arch=arch, args=(everything,)) == "ALLOW"

    # A sign-extended negative int flags value (as some libc wrappers pass for
    # the 0x80000000 CLONE_IO bit) must still be allowed.
    signed = 0xFFFFFFFF80000000
    assert _verdict(program, nr=clone, arch=arch, args=(signed,)) == "ALLOW"


@pytest.mark.parametrize("machine,arch", [("x86_64", X86_64), ("aarch64", AARCH64)])
@pytest.mark.parametrize("name", sorted(UAPI))
def test_every_namespace_flag_is_denied_on_clone(machine, arch, name):
    program = sf.build_program(SyscallPolicy(), arch)
    verdict = _verdict(
        program, nr=CLONE_NR[machine], arch=arch, args=(UAPI[name],)
    )
    assert verdict == "ERRNO:EPERM", f"{name} was not denied on {machine}: {verdict}"


@pytest.mark.parametrize("machine,arch", [("x86_64", X86_64), ("aarch64", AARCH64)])
def test_a_namespace_flag_mixed_with_ordinary_flags_is_still_denied(machine, arch):
    """The realistic attack combines namespace bits with a valid signal."""
    program = sf.build_program(SyscallPolicy(), arch)
    flags = (
        UAPI["CLONE_NEWUSER"]
        | UAPI["CLONE_NEWPID"]
        | UAPI["CLONE_NEWNS"]
        | UAPI["CLONE_NEWIPC"]
        | UAPI["CLONE_NEWUTS"]
        | ORDINARY["SIGCHLD"]
    )
    assert _verdict(program, nr=CLONE_NR[machine], arch=arch, args=(flags,)) == (
        "ERRNO:EPERM"
    )


@pytest.mark.parametrize("high", [0x100000000, 0x200000000, 0x300000000])
def test_clone3_era_high_flags_are_denied(high):
    program = sf.build_program(SyscallPolicy(), X86_64)
    assert _verdict(program, nr=CLONE_NR["x86_64"], arch=X86_64, args=(high,)) == (
        "ERRNO:EPERM"
    )


def test_the_existing_denials_are_unchanged():
    """The rule must not weaken what was already blocked."""
    program = sf.build_program(SyscallPolicy(), X86_64)
    for nr, name in ((272, "unshare"), (308, "setns")):
        assert _verdict(program, nr=nr, arch=X86_64) == "ERRNO:EPERM", name
    # clone3 is denied too, but with ENOSYS on purpose: glibc's
    # __clone_internal falls back to legacy clone *only* on ENOSYS, so
    # returning EPERM here made pthread_create fail inside the sandbox.
    assert _verdict(program, nr=435, arch=X86_64) == "ERRNO:ENOSYS"
    # Ordinary syscalls pass.
    for nr in (0, 1, 2, 60, 257, 262):
        assert _verdict(program, nr=nr, arch=X86_64) == "ALLOW", nr


def test_clone3_reports_enosys_so_glibc_can_fall_back():
    """The errno matters: EPERM breaks threads, ENOSYS makes them work.

    This is the difference between a filter that closes an escape and a filter
    that breaks every threaded workload. glibc tries clone3 first and falls back
    to clone only when it sees ENOSYS.
    """
    for arch in (X86_64, AARCH64):
        denials = sf.syscall_denials(SyscallPolicy(), arch)
        assert denials["clone3"][1] == errno.ENOSYS
        assert denials["unshare"][1] == errno.EPERM
        assert denials["setns"][1] == errno.EPERM
        assert sf.DENIAL_ERRNO_OVERRIDES == {"clone3": "ENOSYS"}


def test_the_install_report_names_the_errno_per_syscall():
    """A trace must show both what is denied and how it is refused."""
    policy = SyscallPolicy()
    denials = sf.syscall_denials(policy, X86_64)
    assert errno.errorcode[denials["clone3"][1]] == "ENOSYS"
    guards = sf.argument_guards(policy, X86_64)
    assert guards["clone"]["low_mask"] == 0x7E020080


def test_a_foreign_abi_is_still_killed():
    """The arch check stays first: a foreign ABI must never be allowed."""
    program = sf.build_program(SyscallPolicy(), X86_64)
    assert _verdict(program, nr=1, arch=OTHER_ARCH) == "KILL"


def test_the_program_still_fits_the_kernel_instruction_budget():
    """BPF filters are capped at 4096 instructions; the guard must not blow it."""
    for arch in (X86_64, AARCH64):
        program = sf.build_program(SyscallPolicy(), arch)
        assert len(program) < 4096, len(program)


def test_the_guard_is_recorded_in_the_install_report():
    """The trace must be able to show the rule that is actually in force."""
    policy = SyscallPolicy()
    guards = sf.argument_guards(policy, X86_64)
    assert guards["clone"]["low_mask"] == 0x7E020080
    # install() reports the same structure; check the shape it will emit.
    program = sf.build_program(policy, X86_64)
    assert any(
        code == sf.ALU_AND_K and k == sf.CLONE_NAMESPACE_FLAGS
        for code, _jt, _jf, k in program
    )
    assert any(
        code == sf.ALU_AND_K and k == sf.CLONE_HIGH_FLAGS
        for code, _jt, _jf, k in program
    )
