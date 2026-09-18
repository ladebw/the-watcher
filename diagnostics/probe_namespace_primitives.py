#!/usr/bin/env python3
"""Probe which namespace-creating primitives the kernel and seccomp permit.

Run from the repository root::

    python diagnostics/probe_namespace_primitives.py
    python diagnostics/probe_namespace_primitives.py --hard-case MARKER --hold 30

Why this exists
---------------

``verify_empty`` decides whether a containment unit is really gone by matching
processes against the unit's identity. That identity is built from namespace
inode equality *and* from live ancestry to the launch-time roots. Both
assumptions can be defeated by a descendant that creates **child** namespaces:
its ``ns/user`` and ``ns/pid`` inode values then differ from the unit's, and if
its ancestor also exits it is no longer obviously reachable by ancestry.

The V3 seccomp profile blocks ``unshare``, ``setns`` and ``clone3``. It does
**not** block the legacy ``clone`` syscall, which can carry the same namespace
flags. This probe answers, empirically and on the running host:

* which of those primitives actually succeed,
* which errno the kernel or the filter returns when they do not,
* and, in ``--hard-case`` mode, whether a nested descendant can outlive the
  ancestor that created it.

The output is JSON on stdout so a test can assert on it, and it is readable
enough to paste into a security review. It never modifies the host: every
namespace it creates is discarded when the process exits.

Exit code is 0 whenever the probe ran, regardless of what it found. A failing
probe would be indistinguishable from a probe that discovered a blocked
primitive, and the *findings* are the point.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import platform
import sys
import tempfile
import time
from typing import Any

__all__ = ["main", "probe_all"]

CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWCGROUP = 0x02000000
SIGCHLD = 17

SYS_CLONE3 = 435

#: How long a spawned child holds itself alive, so a caller can observe it.
DEFAULT_HOLD = 20

libc = ctypes.CDLL(None, use_errno=True)

#: The child entry point must be a real C function whose frame never returns
#: into the Python interpreter. A ``clone`` child did not go through
#: ``fork()``, so the interpreter's state (notably the GIL the parent held when
#: it called ``clone``) is a copy that cannot safely be re-entered: a
#: ``ctypes`` callback there deadlocks or crashes, and the child dies at once -
#: which would make an escape look impossible for the wrong reason.
#:
#: So the child body is a few bytes of machine code in an executable page: sit
#: in ``pause(2)`` until a signal arrives. It touches no Python state at all,
#: and the parent kills it explicitly when the observation window closes.
_PAUSE_LOOP_X86_64 = bytes(
    [
        0xB8, 0x22, 0x00, 0x00, 0x00,  # mov eax, 34   (SYS_pause)
        0x0F, 0x05,  # syscall
        0xEB, 0xF9,  # jmp -7        (back to the mov)
    ]
)

_child_stub_page: "int | None" = None


def _pause_stub() -> "int | None":
    """Return the address of an executable ``pause`` loop, or ``None``.

    ``None`` means this architecture's opcodes are not known here, which is
    reported as a limitation rather than guessed at.
    """
    global _child_stub_page
    if _child_stub_page is not None:
        return _child_stub_page
    if platform.machine().lower() not in ("x86_64", "amd64"):
        return None

    PROT_READ, PROT_WRITE, PROT_EXEC = 1, 2, 4
    MAP_PRIVATE, MAP_ANONYMOUS = 0x02, 0x20
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_long,
    ]
    page = libc.mmap(
        None,
        4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    )
    if not page or page == ctypes.c_void_p(-1).value:
        return None
    ctypes.memmove(page, _PAUSE_LOOP_X86_64, len(_PAUSE_LOOP_X86_64))
    _child_stub_page = int(page)
    return _child_stub_page


def _errno_name(value: int) -> str:
    return errno.errorcode.get(value, str(value))


def _namespace_links(pid: int) -> dict[str, Any]:
    """Read ``/proc/<pid>/ns/*`` for ``pid``, reporting refusals honestly."""
    result: dict[str, Any] = {}
    for kind in ("user", "pid", "mnt", "net"):
        try:
            result[kind] = os.readlink(f"/proc/{pid}/ns/{kind}")
        except OSError as exc:
            result[kind] = f"<{_errno_name(exc.errno or 0)}>"
    return result


def _ppid_of(pid: int) -> "int | None":
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as handle:
            data = handle.read()
    except OSError:
        return None
    close = data.rfind(")")
    if close == -1:
        return None
    fields = data[close + 2 :].split()
    try:
        return int(fields[1])
    except (IndexError, ValueError):
        return None


# ---------------------------------------------------------------------------
# individual primitives
# ---------------------------------------------------------------------------


def _fork_collect(work: Any) -> dict[str, Any]:
    """Run ``work`` in a forked child and return its JSON-able result.

    A pipe is deliberately **not** used to carry the result. A namespace-creating
    ``clone`` copies the file descriptor table into the child, so a paused clone
    child would hold the pipe's write end open forever and the parent's
    ``read()`` would never see EOF - the probe would hang with no output, which
    is indistinguishable from "the primitive was blocked". A file has no such
    liveness dependency.
    """
    path = tempfile.mktemp(prefix="watcher-probe-", suffix=".json")
    pid = os.fork()
    if pid == 0:  # pragma: no cover - child process
        try:
            result = work()
        except BaseException as exc:  # noqa: BLE001 - reported, never raised
            result = {"error": f"{type(exc).__name__}: {exc}"}
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(result, handle)
        except OSError:
            pass
        os._exit(0)

    os.waitpid(pid, 0)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {"error": "no-result"}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _try_unshare(flag: int) -> dict[str, Any]:
    """Attempt ``unshare(flag)`` in a forked child so the parent is untouched."""

    def work() -> dict[str, Any]:
        ctypes.set_errno(0)
        rc = libc.unshare(ctypes.c_int(flag))
        return {"rc": rc, "errno": ctypes.get_errno()}

    outcome = _fork_collect(work)
    if "error" in outcome:
        return {"attempted": True, "ok": False, "errno_name": outcome["error"]}
    return {
        "attempted": True,
        "ok": outcome["rc"] == 0,
        "errno": outcome["errno"],
        "errno_name": _errno_name(outcome["errno"]),
    }


class _CloneArgs(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("pidfd", ctypes.c_uint64),
        ("child_tid", ctypes.c_uint64),
        ("parent_tid", ctypes.c_uint64),
        ("exit_signal", ctypes.c_uint64),
        ("stack", ctypes.c_uint64),
        ("stack_size", ctypes.c_uint64),
        ("tls", ctypes.c_uint64),
        ("set_tid", ctypes.c_uint64),
        ("set_tid_size", ctypes.c_uint64),
        ("cgroup", ctypes.c_uint64),
    ]


def _try_clone3() -> dict[str, Any]:
    """Attempt the modern ``clone3`` syscall with a minimal argument block."""

    def work() -> dict[str, Any]:
        args = _CloneArgs()
        args.flags = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS
        args.exit_signal = SIGCHLD
        ctypes.set_errno(0)
        rc = libc.syscall(
            ctypes.c_long(SYS_CLONE3),
            ctypes.byref(args),
            ctypes.c_size_t(ctypes.sizeof(args)),
        )
        err = ctypes.get_errno()
        if rc == 0:
            # We are the new child of a raw syscall clone. Never continue in the
            # interpreter here: leave immediately.
            libc._exit(ctypes.c_int(0))
        return {"rc": rc, "errno": err}

    outcome = _fork_collect(work)
    if "error" in outcome:
        return {"attempted": True, "ok": False, "errno_name": outcome["error"]}
    return {
        "attempted": True,
        "ok": outcome["rc"] > 0,
        "errno": outcome["errno"],
        "errno_name": _errno_name(outcome["errno"]),
    }


def legacy_clone_nested(flags: int) -> tuple[int, int]:
    """Call legacy ``clone`` with namespace flags. Returns ``(pid, errno)``.

    ``pid > 0`` means a child was created that now lives in child namespaces.
    ``pid <= 0`` means the kernel or the seccomp filter refused; ``errno`` says
    which.
    """
    stub = _pause_stub()
    if stub is None:
        return -1, errno.ENOSYS

    libc.clone.restype = ctypes.c_long
    libc.clone.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
    ]
    libc.malloc.restype = ctypes.c_void_p
    libc.malloc.argtypes = [ctypes.c_size_t]

    size = 1 << 20
    stack = libc.malloc(ctypes.c_size_t(size))
    if not stack:
        return -1, errno.ENOMEM
    # The stack grows down on x86, so hand over the top of the block.
    top = ctypes.c_void_p(stack + size - 64)
    ctypes.set_errno(0)
    pid = libc.clone(ctypes.c_void_p(stub), top, ctypes.c_int(flags), None)
    return int(pid), ctypes.get_errno()


def _kill_quietly(pid: "int | None") -> None:
    """Best-effort cleanup so a probe never leaks a held-open child."""
    if not pid or pid <= 0:
        return
    try:
        os.kill(int(pid), 9)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# the probes
# ---------------------------------------------------------------------------


def probe_all(hold: int = DEFAULT_HOLD) -> dict[str, Any]:
    """Attempt every namespace-creating primitive and report the outcome."""
    findings: dict[str, Any] = {
        "arch": platform.machine(),
        "pid": os.getpid(),
        "uid": os.getuid(),
        "pid_namespace": _namespace_links(os.getpid()).get("pid"),
        "user_namespace": _namespace_links(os.getpid()).get("user"),
        "seccomp_mode": _seccomp_mode(),
        "primitives": {},
    }

    findings["primitives"]["unshare_newuser"] = _try_unshare(CLONE_NEWUSER)
    findings["primitives"]["unshare_newpid"] = _try_unshare(CLONE_NEWPID)
    findings["primitives"]["unshare_newns"] = _try_unshare(CLONE_NEWNS)
    findings["primitives"]["clone3"] = _try_clone3()

    flags = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | SIGCHLD
    pid, err = legacy_clone_nested(flags)
    nested: dict[str, Any] = {
        "attempted": True,
        "flags": flags,
        "ok": pid > 0,
        "errno": err,
        "errno_name": _errno_name(err),
        "child_pid": pid if pid > 0 else None,
    }
    if pid > 0:
        time.sleep(0.2)
        nested["child_namespaces"] = _namespace_links(pid)
        nested["child_ppid"] = _ppid_of(pid)
        nested["parent_namespaces"] = _namespace_links(os.getpid())
        nested["child_inode_differs"] = {
            kind: nested["child_namespaces"].get(kind)
            != nested["parent_namespaces"].get(kind)
            for kind in ("user", "pid", "mnt")
        }
        nested["child_state"] = _state_of(pid)
        _kill_quietly(pid)
    findings["primitives"]["legacy_clone_nested"] = nested
    return findings


def _state_of(pid: int) -> "str | None":
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as handle:
            data = handle.read()
    except OSError:
        return None
    close = data.rfind(")")
    if close == -1:
        return None
    fields = data[close + 2 :].split()
    return fields[0] if fields else None


def _seccomp_mode() -> "int | None":
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("Seccomp:"):
                    return int(line.split(":", 1)[1].strip())
    except (OSError, ValueError):
        return None
    return None


def run_hard_case(marker: str, hold: int = DEFAULT_HOLD) -> int:
    """Create a nested descendant, let its ancestor exit, then hold it open.

    The lifecycle under test::

        sandbox init  ->  descendant  ->  nested descendant (new user+PID ns)
                      ->  ancestor exits  ->  nested child reparented, still alive

    The nested child is written to ``marker`` as JSON so a host-side test can
    observe it while it is alive. The child is killed when the hold expires, so
    the probe never leaks a process.
    """
    flags = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | SIGCHLD
    payload: dict[str, Any] = {
        "sandbox_pid": os.getpid(),
        "sandbox_namespaces": _namespace_links(os.getpid()),
        "flags": flags,
        "ancestor_exited": False,
        "nested": None,
    }

    # The ancestor hands its record back through a file, not a pipe: the paused
    # clone child inherits the file descriptor table, so a pipe's write end
    # would never close and the parent would block forever.
    ancestor_record = marker + ".ancestor.json"
    if os.path.exists(ancestor_record):
        os.unlink(ancestor_record)

    ancestor = os.fork()
    if ancestor == 0:  # pragma: no cover - child process
        pid, err = legacy_clone_nested(flags)
        record = {
            "ancestor_pid": os.getpid(),
            "clone_pid": pid if pid > 0 else None,
            "clone_errno": err,
            "clone_errno_name": _errno_name(err),
            "ok": pid > 0,
        }
        if pid > 0:
            time.sleep(0.2)
            record["child_namespaces"] = _namespace_links(pid)
            record["child_ppid"] = _ppid_of(pid)
            record["child_state"] = _state_of(pid)
        try:
            with open(ancestor_record, "w", encoding="utf-8") as handle:
                json.dump(record, handle)
        except OSError:
            pass
        # The ancestor exits immediately, leaving the nested child behind.
        os._exit(0)

    os.waitpid(ancestor, 0)
    payload["ancestor_exited"] = True

    try:
        with open(ancestor_record, "r", encoding="utf-8") as handle:
            record = json.load(handle)
    except (OSError, ValueError):
        record = {"ok": False, "clone_errno_name": "no-record"}
    payload["nested"] = record

    child_pid = record.get("clone_pid")
    if child_pid:
        time.sleep(0.3)
        payload["nested_reparented_to"] = _ppid_of(child_pid)
        payload["nested_state_after_ancestor_exit"] = _state_of(child_pid)
        payload["nested_alive_after_ancestor_exit"] = _state_of(child_pid) not in (
            None,
            "Z",
        )
        payload["nested_live_namespaces"] = _namespace_links(child_pid)

    with open(marker, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)

    # Hold the sandbox init open so the unit stays observable, then clean up.
    time.sleep(hold)
    _kill_quietly(child_pid)
    return 0


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", metavar="FILE", help="write the report here too")
    parser.add_argument(
        "--hard-case",
        metavar="MARKER",
        help="run the nested-ancestor-exit lifecycle and write findings to MARKER",
    )
    parser.add_argument(
        "--hold",
        type=int,
        default=DEFAULT_HOLD,
        help=f"seconds a spawned child stays alive (default {DEFAULT_HOLD})",
    )
    args = parser.parse_args(argv)

    if args.hard_case:
        return run_hard_case(args.hard_case, args.hold)

    findings = probe_all(args.hold)
    text = json.dumps(findings, indent=2, sort_keys=True)
    print(text)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
