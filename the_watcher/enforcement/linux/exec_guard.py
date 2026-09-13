#!/usr/bin/env python3
"""In-sandbox launch guard: applies enforcement, then execs the workload.

This script runs **inside** the namespaces, as the last trusted code before the
untrusted workload starts. It is deliberately:

* **standalone** — it imports only the standard library plus its sibling
  files, all of which are copied into a read-only directory for this session.
  It never imports ``the_watcher``, so the sandbox needs no access to the
  Watcher package, its configuration or its storage;
* **one-way** — every step reduces privilege and cannot be undone;
* **fail-closed** — if a required step fails it reports the failure and exits
  without exec'ing the workload, so the supervisor can refuse the session.

Order matters and is enforced: mounts need namespace-local capabilities,
Landlock needs ``no_new_privs``, and seccomp would block Landlock's own
syscalls if it were installed first. Capabilities are dropped last.
"""

from __future__ import annotations

import base64
import ctypes
import errno
import json
import os
import sys
from typing import Any

EXIT_OK = 0
EXIT_SETUP_FAILED = 70
EXIT_EXEC_FAILED = 71

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18

PR_CAPBSET_DROP = 24
LINUX_CAPABILITY_VERSION_3 = 0x20080522
SYS_CAPSET = 126

libc = ctypes.CDLL(None, use_errno=True)


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def _errno_name(err: int) -> str:
    return errno.errorcode.get(err, str(err))


def _import_siblings() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)


# ---------------------------------------------------------------------------
# mounts
# ---------------------------------------------------------------------------


def _mount(
    source: "str | None",
    target: str,
    fstype: "str | None" = None,
    flags: int = 0,
    data: "str | None" = None,
) -> None:
    ctypes.set_errno(0)
    result = libc.mount(
        source.encode() if source else None,
        target.encode(),
        fstype.encode() if fstype else None,
        ctypes.c_ulong(flags),
        data.encode() if data else None,
    )
    if result != 0:
        err = ctypes.get_errno()
        raise RuntimeError(f"mount({source!r} -> {target!r}) failed: {_errno_name(err)}")


def _ensure_dir(path: str) -> None:
    """Create a mount point, reporting why it failed if it cannot be made.

    A rootless user namespace cannot create directories on filesystems owned
    by uids that are not mapped into it, so this can genuinely fail. The
    failure is propagated instead of being swallowed, because a mount with no
    mount point fails later with a confusing ``ENOENT``.
    """
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(
            f"cannot create mount point {path!r}: "
            f"{_errno_name(exc.errno or 0)}"
        ) from exc


def apply_mounts(plan: list[dict], problems: list[str]) -> list[str]:
    """Apply the supervisor-supplied mount plan.

    The plan is generated from the profile by the supervisor; it is never
    taken from agent input. Each entry records whether it was applied.
    """
    applied: list[str] = []

    for entry in plan:
        kind = entry.get("kind")
        target = entry.get("target") or ""
        optional = bool(entry.get("optional"))

        try:
            if kind == "private":
                _mount(None, entry.get("target", "/"), None, MS_REC | MS_PRIVATE)
                applied.append("private:/")
                continue

            if kind == "bind":
                source = entry["source"]
                if not os.path.exists(source):
                    if optional:
                        problems.append(f"bind source missing (optional): {source}")
                        continue
                    raise RuntimeError(f"bind source missing: {source}")
                _ensure_dir(target)
                _mount(source, target, None, MS_BIND | MS_REC)
                if entry.get("read_only"):
                    _mount(None, target, None, MS_REMOUNT | MS_BIND | MS_RDONLY)
                applied.append(f"bind:{source}->{target}")
                continue

            if kind == "tmpfs":
                _ensure_dir(target)
                options = entry.get("options") or "size=64m,mode=1777"
                _mount("tmpfs", target, "tmpfs", MS_NOSUID | MS_NODEV, options)
                applied.append(f"tmpfs:{target}")
                continue

            if kind == "read_only_root":
                _mount(None, entry.get("target", "/"), None, MS_REMOUNT | MS_BIND | MS_RDONLY)
                applied.append("read_only_root:/")
                continue

            problems.append(f"unknown mount kind: {kind!r}")
        except (OSError, RuntimeError) as exc:
            if optional:
                problems.append(f"optional mount {kind} on {target}: {exc}")
                continue
            raise

    return applied


# ---------------------------------------------------------------------------
# capabilities
# ---------------------------------------------------------------------------


def drop_capabilities() -> dict[str, Any]:
    """Clear every capability and drop the bounding set.

    The bounding set is dropped **first**: ``PR_CAPBSET_DROP`` requires
    ``CAP_SETPCAP``, which is gone once the effective and permitted sets are
    cleared.
    """
    dropped = 0
    bounding_failures: list[int] = []
    for capability in range(0, 64):
        ctypes.set_errno(0)
        if libc.prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) == 0:
            dropped += 1
        else:
            # EINVAL simply means the capability number does not exist on this
            # kernel; anything else is recorded.
            err = ctypes.get_errno()
            if err != errno.EINVAL:
                bounding_failures.append(capability)

    header = _CapHeader(version=LINUX_CAPABILITY_VERSION_3, pid=0)
    data = (_CapData * 2)()
    for word in data:
        word.effective = 0
        word.permitted = 0
        word.inheritable = 0

    ctypes.set_errno(0)
    result = libc.syscall(SYS_CAPSET, ctypes.byref(header), ctypes.byref(data))
    if result != 0:
        raise RuntimeError(f"capset failed: {_errno_name(ctypes.get_errno())}")

    status = _self_status()
    return {
        "effective_cleared": status.get("CapEff") == "0000000000000000",
        "cap_eff_inside": status.get("CapEff"),
        "cap_bnd_inside": status.get("CapBnd"),
        "bounding_set_dropped": dropped,
        "bounding_set_failures": bounding_failures,
    }


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------


def emit(report: dict, report_fd: int) -> None:
    """Send the report to the supervisor over the inherited pipe."""
    payload = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if report_fd >= 0:
        try:
            os.write(report_fd, payload)
        except OSError:
            pass


def _self_status() -> dict[str, Any]:
    """Read our own ``/proc/self/status`` from inside the namespaces.

    ``CapEff``, ``NoNewPrivs`` and ``Seccomp`` are global process attributes,
    so the supervisor can also verify them from outside. Reporting them from
    inside as well means a mismatch between the two views is itself evidence
    that something in between interfered.
    """
    wanted = {
        "Uid",
        "Gid",
        "CapEff",
        "CapBnd",
        "CapPrm",
        "NoNewPrivs",
        "Seccomp",
        "Seccomp_filters",
    }
    status: dict[str, Any] = {}
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as handle:
            for line in handle:
                key, _, value = line.partition(":")
                if key in wanted:
                    status[key] = value.strip()
    except OSError:
        pass
    return status


def main(argv: list[str]) -> int:
    _import_siblings()

    if "--" not in argv:
        print("exec_guard: missing '--' before the command", file=sys.stderr)
        return EXIT_SETUP_FAILED

    separator = argv.index("--")
    options = argv[1:separator]
    command = argv[separator + 1 :]

    spec_b64 = ""
    report_fd = -1
    index = 0
    while index < len(options):
        if options[index] == "--spec-b64" and index + 1 < len(options):
            spec_b64 = options[index + 1]
            index += 2
        elif options[index] == "--report-fd" and index + 1 < len(options):
            report_fd = int(options[index + 1])
            index += 2
        else:
            index += 1

    report: dict[str, Any] = {"ok": False, "pid": os.getpid(), "problems": [], "steps": []}

    if not command:
        report["problems"].append("no command supplied")
        emit(report, report_fd)
        return EXIT_SETUP_FAILED

    try:
        spec = json.loads(base64.b64decode(spec_b64).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        report["problems"].append(f"spec decode failed: {type(exc).__name__}")
        emit(report, report_fd)
        return EXIT_SETUP_FAILED

    # Imported here so a failure to locate the sibling modules is reported
    # through the same channel as every other setup failure.
    try:
        import landlock_ruleset  # type: ignore
        import resource_limits  # type: ignore
        import seccomp_filter  # type: ignore
    except ImportError as exc:  # pragma: no cover - packaging fault
        report["problems"].append(f"cannot import guard modules: {exc}")
        emit(report, report_fd)
        return EXIT_SETUP_FAILED

    problems: list[str] = report["problems"]

    try:
        # 1. mounts (needs namespace-local capabilities)
        mounts = apply_mounts(spec.get("mounts") or [], problems)
        report["mounts"] = mounts
        report["steps"].append("mounts")

        # 2. resource ceilings
        limits = resource_limits.apply_limits(
            spec.get("processes") or {}, spec.get("resources") or {}
        )
        report["limits"] = limits["applied"]
        problems.extend(limits["problems"])
        report["steps"].append("rlimits")

        # 3. Landlock allow-list (before seccomp: it needs its own syscalls)
        landlock = landlock_ruleset.apply_allowlist(
            spec.get("read_paths") or [],
            spec.get("write_paths") or [],
            abi=spec.get("landlock_abi"),
            require=bool(spec.get("landlock_required", True)),
        )
        report["landlock"] = landlock
        report["steps"].append("landlock")

        # 4. seccomp (sets no_new_privs as a side effect)
        seccomp = seccomp_filter.install(_PolicyView(spec.get("syscalls") or {}))
        report["seccomp"] = seccomp
        report["steps"].append("seccomp")

        # 5. drop the namespace-local capabilities we used for the mounts
        capabilities = drop_capabilities()
        report["capabilities"] = capabilities
        report["steps"].append("capabilities_dropped")

        # Re-read the inner view after the drop: this is what the workload
        # will inherit, so it is the value the supervisor cross-checks.
        inner = _self_status()
        report["status_inside"] = inner
        report["uid_inside"] = int(inner["Uid"].split()[0]) if inner.get("Uid") else None
        report["gid_inside"] = int(inner["Gid"].split()[0]) if inner.get("Gid") else None
        if inner.get("CapEff") != "0000000000000000":
            problems.append(f"capabilities survive inside the sandbox: {inner.get('CapEff')}")
        if inner.get("NoNewPrivs") != "1":
            problems.append("no_new_privs is not set inside the sandbox")

    except (OSError, RuntimeError) as exc:
        problems.append(f"{type(exc).__name__}: {exc}")
        emit(report, report_fd)
        return EXIT_SETUP_FAILED

    # Report success before exec'ing: after this point the process is the
    # untrusted workload and must not be trusted to report anything.
    report["ok"] = not report["problems"]
    report["command"] = command
    emit(report, report_fd)
    if report_fd >= 0:
        try:
            os.close(report_fd)
        except OSError:
            pass

    cwd = spec.get("cwd_inner")
    if cwd:
        try:
            os.chdir(cwd)
        except OSError as exc:
            print(f"exec_guard: cannot chdir to {cwd}: {exc}", file=sys.stderr)
            return EXIT_EXEC_FAILED

    # The supervisor's environment is the base; the spec adds the workload's
    # own variables. Replacing outright would leave the workload with no PATH
    # and no HOME.
    environment = dict(os.environ)
    environment.update(
        {str(k): str(v) for k, v in (spec.get("environment") or {}).items()}
    )
    try:
        os.execvpe(command[0], list(command), environment)
    except OSError as exc:
        print(f"exec_guard: cannot execute {command[0]!r}: {exc}", file=sys.stderr)
        return EXIT_EXEC_FAILED


class _PolicyView:
    """Adapt the JSON syscall section to the attribute access the filter uses."""

    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def __getattr__(self, name: str) -> Any:
        if name == "errno_name":
            return self._payload.get("errno_name", "EPERM")
        return bool(self._payload.get(name, True))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
