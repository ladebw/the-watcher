"""Trusted-side inspection of other processes through ``/proc``.

Used for two things V3 must not take on faith:

* **evidence** — what the kernel actually reports for a running unit (uid,
  capabilities, ``NoNewPrivs``, seccomp mode, namespace ids);
* **verification** — proving a containment unit is really gone after a kill,
  by looking for any process that still shares its namespaces.

The protected workload is never asked about any of this.
"""

from __future__ import annotations

import errno
import os
from dataclasses import dataclass
from typing import Any

__all__ = [
    "NamespaceIds",
    "read_status",
    "read_namespaces",
    "process_ids",
    "process_state",
    "caught_signals",
    "catches_signal",
    "find_processes_in_namespace",
    "pid_exists",
    "namespace_inode",
    "child_pids",
    "filesystem_type",
    "read_network_interfaces",
    "read_network_routes",
]

NS_KINDS = ("cgroup", "ipc", "mnt", "net", "pid", "pid_for_children", "time", "user", "uts")


@dataclass(frozen=True)
class NamespaceIds:
    """Namespace identifiers for one process, as ``kind -> inode``."""

    values: dict[str, str]

    def get(self, kind: str) -> "str | None":
        return self.values.get(kind)

    @property
    def user(self) -> "str | None":
        return self.values.get("user")

    @property
    def pid(self) -> "str | None":
        return self.values.get("pid")

    def to_dict(self) -> dict[str, str]:
        return dict(self.values)


def read_status(pid: int) -> dict[str, str]:
    """Return ``/proc/<pid>/status`` as a mapping. Empty when unreadable."""
    fields: dict[str, str] = {}
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as handle:
            for line in handle:
                key, separator, value = line.partition(":")
                if separator:
                    fields[key.strip()] = value.strip()
    except OSError:
        return {}
    return fields


def read_namespaces(pid: int) -> NamespaceIds:
    """Return the namespace inode identifiers of ``pid``."""
    values: dict[str, str] = {}
    for kind in NS_KINDS:
        try:
            values[kind] = os.readlink(f"/proc/{pid}/ns/{kind}")
        except OSError:
            continue
    return NamespaceIds(values=values)


def namespace_inode(pid: int, kind: str) -> "str | None":
    """Return e.g. ``user:[4026531837]`` for a process, or ``None``."""
    try:
        return os.readlink(f"/proc/{pid}/ns/{kind}")
    except OSError:
        return None


def process_ids() -> list[int]:
    """Every numeric pid currently visible in ``/proc``."""
    try:
        entries = os.listdir("/proc")
    except OSError:
        return []
    return sorted(int(entry) for entry in entries if entry.isdigit())


def caught_signals(pid: int) -> int:
    """Bit mask of signals the process has installed a handler for.

    ``SigCgt`` from ``/proc/<pid>/status``. Used to decide whether a graceful
    SIGTERM can possibly be delivered, because the answer changes the kill
    path materially (see ``NamespaceEnforcer.terminate``).
    """
    status = read_status(pid)
    value = status.get("SigCgt")
    if not value:
        return 0
    try:
        return int(value, 16)
    except ValueError:
        return 0


def catches_signal(pid: int, signum: int) -> bool:
    """Whether ``pid`` has a handler installed for ``signum`` (1-based)."""
    if signum < 1:
        return False
    return bool(caught_signals(pid) & (1 << (signum - 1)))


def process_state(pid: int) -> str:
    """The single-letter state from ``/proc/<pid>/stat`` (``''`` if unknown)."""
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as handle:
            data = handle.read()
    except OSError:
        return ""
    # "<pid> (<comm>) <state> ..."; comm may contain spaces and parentheses,
    # so split after the final ')'.
    close = data.rfind(")")
    if close == -1:
        return ""
    fields = data[close + 2 :].split()
    return fields[0] if fields else ""


def find_processes_in_namespace(
    namespace: str,
    kind: str = "user",
    exclude: "set[int] | None" = None,
    live_only: bool = True,
) -> list[int]:
    """Pids whose ``kind`` namespace equals ``namespace``.

    This is the trusted-side answer to "is the containment unit really empty?".
    A sandbox's user namespace is effectively its identity, so finding no
    process carrying it is strong evidence the unit is gone.

    ``live_only`` excludes zombies by default. A zombie has released its
    resources and cannot execute another instruction, so counting one as a
    survivor would report a failed kill for a unit that is in fact gone —
    a false alarm is as much of a lie as a false reassurance. Zombies are
    still visible through ``process_state`` when a caller wants them.
    """
    if not namespace:
        return []
    skip = exclude or set()
    found: list[int] = []
    for pid in process_ids():
        if pid in skip:
            continue
        if namespace_inode(pid, kind) != namespace:
            continue
        if live_only and process_state(pid) == "Z":
            continue
        found.append(pid)
    return found


def read_network_interfaces(pid: int) -> tuple[str, ...]:
    """Network interfaces in ``pid``'s network namespace, read from outside.

    ``/proc/<pid>/net/dev`` is rendered from the *process's* network
    namespace, so a second network namespace shows only ``lo`` and no
    counters. That is host-side evidence of isolation — the workload is never
    asked whether it is isolated.
    """
    names: list[str] = []
    try:
        with open(f"/proc/{pid}/net/dev", "r", encoding="utf-8") as handle:
            for index, line in enumerate(handle):
                if index == 0:
                    continue  # header
                name, _, rest = line.partition(":")
                if not rest:
                    continue
                names.append(name.strip())
    except OSError:
        return ()
    return tuple(names)


def read_network_routes(pid: int) -> tuple[str, ...]:
    """Routing table entries in ``pid``'s network namespace.

    An isolated namespace has no default route, which is the actual reason
    egress fails. Recording it turns "network=none" from a claim into an
    observation.
    """
    routes: list[str] = []
    try:
        with open(f"/proc/{pid}/net/route", "r", encoding="utf-8") as handle:
            for index, line in enumerate(handle):
                if index == 0:
                    continue
                entry = line.split()
                if len(entry) >= 8:
                    routes.append(f"{entry[0]}/{entry[7]}")
    except OSError:
        return ()
    return tuple(routes)


def child_pids(pid: int) -> tuple[int, ...]:
    """Direct children of ``pid``, from ``/proc/<pid>/task/<pid>/children``.

    ``unshare --pid --fork`` creates the PID namespace in the launcher and
    then forks: the launcher stays in the old PID namespace while the child
    becomes the namespace init. The child is therefore the only process that
    carries the full sandbox state, and the supervisor has to be able to find
    it in order to inspect anything meaningful.
    """
    try:
        with open(
            f"/proc/{pid}/task/{pid}/children", "r", encoding="utf-8"
        ) as handle:
            return tuple(int(token) for token in handle.read().split() if token)
    except (OSError, ValueError):
        return ()


def filesystem_type(path: str) -> str:
    """Filesystem type backing ``path``, from ``/proc/self/mountinfo``.

    Used only to make refusal messages concrete: the actual decision about
    whether enforcement works is made by probing, not by this string.
    """
    target = os.path.realpath(path)
    best_mount = ""
    best_type = "unknown"
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as handle:
            for line in handle:
                fields = line.split()
                try:
                    separator = fields.index("-")
                except ValueError:
                    continue
                if len(fields) < separator + 2:
                    continue
                mount_point = fields[4]
                # mountinfo escapes spaces as \040.
                mount_point = mount_point.replace("\\040", " ")
                if target == mount_point or target.startswith(mount_point.rstrip("/") + "/"):
                    if len(mount_point) >= len(best_mount):
                        best_mount = mount_point
                        best_type = fields[separator + 1]
    except OSError:
        return "unknown"
    return best_type


def pid_exists(pid: int) -> bool:
    """Return ``True`` when the pid is live (or a zombie we cannot reap)."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        return exc.errno != errno.ESRCH
    return True


def read_cgroup(pid: int) -> "str | None":
    """Return the cgroup v2 path of ``pid``, if any."""
    try:
        with open(f"/proc/{pid}/cgroup", "r", encoding="utf-8") as handle:
            for line in handle:
                # cgroup v2 format: "0::/path"
                parts = line.strip().split(":", 2)
                if len(parts) == 3 and parts[0] == "0":
                    return parts[2] or "/"
    except OSError:
        return None
    return None


def read_cmdline(pid: int, limit: int = 512) -> str:
    """Return a printable rendering of ``/proc/<pid>/cmdline``."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as handle:
            raw = handle.read(limit)
    except OSError:
        return ""
    text = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    return text


def describe_process(pid: int) -> dict[str, Any]:
    """A compact, token-free description of one process."""
    status = read_status(pid)
    return {
        "pid": pid,
        "uid": status.get("Uid", "").split()[0] if status.get("Uid") else None,
        "capabilities": status.get("CapEff"),
        "no_new_privs": status.get("NoNewPrivs"),
        "seccomp": status.get("Seccomp"),
        "command": read_cmdline(pid, 160),
    }
