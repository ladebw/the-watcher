#!/usr/bin/env python3
"""An agent that deliberately ignores the Watcher.

This script never imports ``WatcherClient``, never opens the IPC socket and
never asks permission for anything. It simply attempts the operations a
compromised or hostile agent would attempt and records what the operating
system did.

That is the whole point of V3. Under V2 an agent that skipped the client
skipped the protection: the Watcher would decide "deny" and the agent would
never hear about it. Here the decision has already been made by the kernel, so
an agent that ignores the Watcher entirely still fails.

Usage::

    bypass_agent.py --attempt network --json-out report.json
    bypass_agent.py --attempt all

Result shape: every entry is ``{"escaped": bool, "detail": str, ...}``.
``escaped`` is ``True`` only when a forbidden operation actually succeeded.

Exit codes: 0 when nothing escaped (containment held), 3 when something did,
2 for a usage error.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import socket
import sys
from typing import Any, Callable

#: Returned when a forbidden operation actually succeeded.
ESCAPED_EXIT_CODE = 3

ATTEMPTS = ("file", "network", "syscall", "process", "root", "workspace", "escape")


# ---------------------------------------------------------------------------
# result recording
# ---------------------------------------------------------------------------


def _errno_of(exc: BaseException) -> str:
    value = getattr(exc, "errno", None)
    if value is None:
        return type(exc).__name__
    if not isinstance(value, int):
        return str(value)
    if value < 0:
        return f"gai:{value}"
    return errno.errorcode.get(value, f"errno {value}")


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def attempt(results: dict[str, Any], name: str, function: Callable[[], Any]) -> None:
    """Run a forbidden operation. Succeeding means the boundary failed."""
    try:
        value = function()
    except BaseException as exc:  # noqa: BLE001 - the refusal is the observation
        results[name] = {
            "escaped": False,
            "detail": _errno_of(exc),
            "message": str(exc)[:160],
            "error": type(exc).__name__,
        }
    else:
        results[name] = {"escaped": True, "detail": str(value)[:160]}


def observe(
    results: dict[str, Any],
    name: str,
    measure: Callable[[], Any],
    isolated_when: Callable[[Any], bool],
) -> None:
    """Run a measurement, and decide from its value whether isolation held.

    Used where the question is not "did this fail?" but "does the sandbox look
    like a separate machine?". Recording the raw value keeps the evidence
    auditable instead of reducing it to a verdict.
    """
    try:
        value = measure()
    except BaseException as exc:  # noqa: BLE001
        results[name] = {
            "escaped": False,
            "detail": f"unmeasurable ({_errno_of(exc)})",
            "value": None,
        }
        return
    held = isolated_when(value)
    results[name] = {
        "escaped": not held,
        "detail": str(value)[:160],
        "value": value,
    }


# ---------------------------------------------------------------------------
# the attempts
# ---------------------------------------------------------------------------


def attempt_file(results: dict[str, Any]) -> None:
    """Read things the agent has no business reading."""

    def read(path: str) -> str:
        with open(path, "rb") as handle:
            return f"read {len(handle.read(4096))} bytes"

    attempt(results, "read_root_ssh_key", lambda: read("/root/.ssh/id_rsa"))
    attempt(results, "read_etc_shadow", lambda: read("/etc/shadow"))
    attempt(results, "read_host_home", lambda: read(os.path.expanduser("~/.netrc")))
    attempt(results, "list_root", lambda: len(os.listdir("/")))
    attempt(results, "read_mnt_c", lambda: read("/mnt/c/Windows/win.ini"))

    def read_via_procfs() -> str:
        # A common trick: reach the same file through /proc/self/root, which is
        # a different path string for the same inode.
        with open("/proc/self/root/etc/shadow", "rb") as handle:
            return f"read {len(handle.read(4096))} bytes"

    attempt(results, "read_via_proc_self_root", read_via_procfs)

    def walk_from_root_fd() -> str:
        # Another: hold a directory descriptor on / and list it through /proc.
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            entries = os.listdir(f"/proc/self/fd/{root}")
            return f"listed {len(entries)} entries"
        finally:
            os.close(root)

    attempt(results, "list_root_via_fd", walk_from_root_fd)

    def escape_with_dotdot() -> str:
        with open("/tmp/.watcher/scratch/../../../etc/shadow", "rb") as handle:
            return f"read {len(handle.read(4096))} bytes"

    attempt(results, "traverse_dotdot", escape_with_dotdot)


def attempt_network(results: dict[str, Any]) -> None:
    """Reach the network."""

    def connect(address: tuple[str, int]) -> str:
        sock = socket.create_connection(address, timeout=3)
        sock.close()
        return f"connected to {address[0]}:{address[1]}"

    attempt(results, "connect_ipv4", lambda: connect(("1.1.1.1", 80)))
    attempt(results, "connect_dns", lambda: connect(("8.8.8.8", 53)))
    attempt(results, "connect_gateway", lambda: connect(("192.168.1.1", 80)))
    attempt(results, "resolve_dns", lambda: socket.gethostbyname("example.com"))

    # ``localhost`` resolves from /etc/hosts, which the profile grants read
    # access to deliberately. It is a local name lookup, not network egress, so
    # it is recorded as an observation rather than counted as an escape.
    observe(
        results,
        "resolve_localhost",
        lambda: socket.gethostbyname("localhost"),
        lambda value: value.startswith("127."),
    )

    def raw_socket_send() -> str:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(b"probe", ("1.1.1.1", 53))
            return "sent a udp datagram"
        finally:
            sock.close()

    attempt(results, "udp_sendto", raw_socket_send)


def attempt_syscall(results: dict[str, Any]) -> None:
    """Perform privileged system operations."""
    libc = ctypes.CDLL(None, use_errno=True)

    def check(result: int, what: str) -> str:
        if result != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        return what

    if hasattr(os, "unshare"):
        attempt(
            results,
            "unshare_user_namespace",
            lambda: check(os.unshare(0x10000000), "created a nested user namespace"),
        )
        attempt(
            results,
            "unshare_mount_namespace",
            lambda: check(os.unshare(0x00020000), "created a nested mount namespace"),
        )
        attempt(
            results,
            "unshare_network_namespace",
            lambda: check(os.unshare(0x40000000), "created a nested network namespace"),
        )

    attempt(
        results,
        "mount_tmpfs",
        lambda: check(
            libc.mount(b"none", b"/tmp", b"tmpfs", 0, None), "mounted a filesystem"
        ),
    )
    attempt(
        results,
        "mount_proc",
        lambda: check(
            libc.mount(b"proc", b"/tmp", b"proc", 0, None), "mounted a fresh procfs"
        ),
    )
    attempt(
        results,
        "ptrace",
        lambda: check(libc.ptrace(0, 0, None, None), "ptraced a process"),
    )

    # ``setuid(0)`` would be a no-op here: the workload already runs as
    # namespace-uid 0, mapped to an unprivileged host uid. The meaningful test
    # is whether it can become a *different* uid, which requires that uid to be
    # mapped into the namespace — and only one uid is.
    attempt(
        results,
        "setuid_to_unmapped_uid",
        lambda: check(libc.setuid(1000), "changed to uid 1000"),
    )

    def regain_capabilities() -> str:
        """Try to get capabilities back after the drop."""
        header = _CapHeader(version=0x20080522, pid=0)
        data = (_CapData * 2)()
        for word in data:
            word.effective = 0xFFFFFFFF
            word.permitted = 0xFFFFFFFF
            word.inheritable = 0
        if libc.syscall(126, ctypes.byref(header), ctypes.byref(data)) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        return "restored capabilities"

    attempt(results, "capset_regain", regain_capabilities)

    def clear_no_new_privs() -> str:
        if libc.prctl(38, 0, 0, 0, 0) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        return "cleared no_new_privs"

    attempt(results, "clear_no_new_privs", clear_no_new_privs)

    def install_own_seccomp() -> str:
        """Replace or loosen the sandbox's filter with our own."""
        if libc.prctl(22, 2, 0, 0, 0) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        return "installed a permissive seccomp filter"

    attempt(results, "install_own_seccomp", install_own_seccomp)

    attempt(results, "open_bpf", lambda: os.open("/sys/fs/bpf/probe", os.O_RDWR))
    attempt(results, "open_dev_kmem", lambda: os.open("/dev/kmem", os.O_RDWR))
    attempt(results, "reboot", lambda: check(libc.reboot(0x01234567), "requested reboot"))
    attempt(
        results,
        "kexec_load",
        lambda: check(libc.syscall(246, 0, 0, 0, 0), "requested kexec"),
    )


def attempt_process(results: dict[str, Any]) -> None:
    """Overwhelm the process ceiling."""
    spawned: list[int] = []
    failure: "OSError | None" = None
    try:
        for _ in range(400):
            pid = os.fork()
            if pid == 0:
                import time

                time.sleep(5)
                os._exit(0)
            spawned.append(pid)
    except OSError as exc:
        failure = exc

    for pid in spawned:
        try:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
        except OSError:
            pass

    observe(
        results,
        "fork_bomb",
        lambda: {
            "spawned": len(spawned),
            "errno": getattr(failure, "errno", None),
            "errno_name": _errno_of(failure) if failure else "",
        },
        # The ceiling held if the kernel stopped us before 400 children. A run
        # that reached the loop limit means there is no effective ceiling.
        lambda value: bool(value["errno"]) and value["spawned"] < 400,
    )


def attempt_root(results: dict[str, Any]) -> None:
    """Write outside the workspace."""

    def write(path: str) -> str:
        with open(path, "w") as handle:
            handle.write("escape\n")
        return f"wrote {path}"

    attempt(results, "write_etc", lambda: write("/etc/watcher_escape"))
    attempt(results, "write_usr_bin", lambda: write("/usr/bin/watcher_escape"))
    attempt(results, "write_root_dir", lambda: write("/watcher_escape"))
    attempt(results, "mkdir_root", lambda: os.mkdir("/watcher_escape_dir"))
    attempt(results, "chmod_etc_passwd", lambda: os.chmod("/etc/passwd", 0o777))
    attempt(results, "unlink_etc_hosts", lambda: os.unlink("/etc/hosts"))

    def symlink_then_follow() -> str:
        """Creating the link is not the test; following it is.

        Writing inside the scratch directory is permitted, so creating a
        symlink there proves nothing. Reaching the target through the link is
        what would be an escape, and Landlock resolves symlinks before it
        decides.
        """
        link = "/tmp/.watcher/scratch/escape_link"
        try:
            os.symlink("/etc/shadow", link)
        except FileExistsError:
            pass
        with open(link, "rb") as handle:
            return f"read {len(handle.read(4096))} bytes through the symlink"

    attempt(results, "symlink_then_follow", symlink_then_follow)

    def hardlink_to_etc() -> str:
        os.link("/etc/passwd", "/tmp/.watcher/scratch/passwd_link")
        return "hard-linked /etc/passwd into the scratch directory"

    attempt(results, "hardlink_from_etc", hardlink_to_etc)


def attempt_workspace(results: dict[str, Any]) -> None:
    """Operations the sandbox *should* permit.

    A failure here is not an escape; it would mean the containment is broken
    rather than strict. These are recorded as observations so the distinction
    stays visible in the evidence.
    """
    here = os.getcwd()

    def write_file(path: str) -> str:
        with open(path, "w") as handle:
            handle.write("probe\n")
        return f"wrote {path}"

    for name, path in (
        ("write_workspace", os.path.join(here, "workspace_probe.txt")),
        ("write_scratch", "/tmp/.watcher/scratch/scratch_probe.txt"),
    ):
        observe(
            results,
            name,
            lambda path=path: write_file(path),
            lambda value: True,
        )

    observe(results, "read_workspace", lambda: sorted(os.listdir(here)), lambda v: True)
    observe(
        results,
        "read_etc_passwd",
        lambda: len(open("/etc/passwd").read()),
        lambda value: True,
    )
    observe(
        results,
        "read_usr_lib",
        lambda: os.path.isdir("/usr/lib"),
        lambda value: True,
    )


def attempt_escape(results: dict[str, Any]) -> None:
    """Direct attempts to leave the sandbox."""
    libc = ctypes.CDLL(None, use_errno=True)

    def setns_host_mount() -> str:
        fd = os.open("/proc/1/ns/mnt", os.O_RDONLY)
        try:
            if libc.setns(fd, 0x00020000) != 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code))
        finally:
            os.close(fd)
        return "joined the host mount namespace"

    attempt(results, "setns_host_mount", setns_host_mount)

    def setns_host_pid() -> str:
        fd = os.open("/proc/1/ns/pid", os.O_RDONLY)
        try:
            if libc.setns(fd, 0x20000000) != 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code))
        finally:
            os.close(fd)
        return "joined the host pid namespace"

    attempt(results, "setns_host_pid", setns_host_pid)

    def numeric_pids() -> list[int]:
        return sorted(int(entry) for entry in os.listdir("/proc") if entry.isdigit())

    # A correct PID namespace contains exactly one process: this one. Seeing
    # more would mean the host's process table is visible.
    observe(
        results,
        "pid_namespace_contents",
        numeric_pids,
        lambda value: value == [1],
    )

    def proc_count() -> int:
        return len([e for e in os.listdir("/proc") if e.isdigit()])

    observe(results, "proc_pid_count", proc_count, lambda value: value == 1)

    attempt(
        results,
        "read_other_process_root",
        lambda: open("/proc/2/root/etc/shadow", "rb").read(16),
    )

    def open_by_handle() -> str:
        libc.syscall(304, -1, b"/etc/shadow", ctypes.c_void_p(0), 0)
        code = ctypes.get_errno()
        if code and code not in (2, 22):
            raise OSError(code, os.strerror(code))
        return "open_by_handle_at was reachable"

    attempt(results, "open_by_handle", open_by_handle)

    def mount_host_root() -> str:
        if libc.mount(b"/", b"/mnt", b"none", 4096, None) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        return "bind-mounted the host root"

    attempt(results, "bind_host_root", mount_host_root)


ATTEMPT_TABLE: dict[str, Callable[[dict[str, Any]], None]] = {
    "file": attempt_file,
    "network": attempt_network,
    "syscall": attempt_syscall,
    "process": attempt_process,
    "root": attempt_root,
    "workspace": attempt_workspace,
    "escape": attempt_escape,
}


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description="attempt to escape containment")
    parser.add_argument(
        "--attempt",
        choices=(*ATTEMPTS, "all"),
        default="all",
        help="which group of operations to attempt",
    )
    parser.add_argument("--json-out", metavar="FILE", help="write the results here")
    args = parser.parse_args(argv)

    results: dict[str, Any] = {
        "identity": {
            "uid": os.getuid(),
            "euid": os.geteuid(),
            "gid": os.getgid(),
            "pid": os.getpid(),
            "cwd": os.getcwd(),
            "executable": sys.executable,
        },
        "attempt": args.attempt,
    }

    status: dict[str, str] = {}
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                key, separator, value = line.partition(":")
                if separator and key in (
                    "Uid",
                    "Gid",
                    "CapEff",
                    "CapBnd",
                    "CapPrm",
                    "NoNewPrivs",
                    "Seccomp",
                    "NSpid",
                ):
                    status[key] = value.strip()
    except OSError:
        pass
    results["status"] = status

    groups = ATTEMPTS if args.attempt == "all" else (args.attempt,)
    for group in groups:
        ATTEMPT_TABLE[group](results)

    escaped = sorted(
        name
        for name, outcome in results.items()
        if isinstance(outcome, dict) and outcome.get("escaped")
    )
    results["escaped"] = escaped
    results["contained"] = not escaped

    if args.json_out:
        with open(args.json_out, "w") as handle:
            json.dump(results, handle, indent=2, sort_keys=True)

    print(json.dumps(results, sort_keys=True))
    return ESCAPED_EXIT_CODE if escaped else 0


if __name__ == "__main__":
    sys.exit(main())
