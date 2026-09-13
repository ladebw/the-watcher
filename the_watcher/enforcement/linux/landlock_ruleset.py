"""Landlock ruleset construction.

Standard library only and free of intra-package imports, because this file is
copied into the sandbox and imported by the exec guard.

**Landlock is an allow-list.** A path-beneath rule grants access; it cannot
deny. ``landlock_add_rule`` with ``allowed_access == 0`` is rejected by the
kernel with ``ENOMSG`` ("useless rule"), because denying by default is already
the behaviour. So the effective policy is: name what the workload legitimately
needs, and everything else becomes unreachable.

Scope limits, stated honestly: Landlock mediates filesystem access by
path-beneath rules. It does not mediate network access, does not mediate
processes, and cannot restrict access to already-open file descriptors
obtained before the ruleset was applied. Anything relying on it must apply it
before ``execve`` and must not rely on it for anything outside its scope.
"""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import subprocess
import sys
from typing import Any, Iterable

SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446

LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1

PR_SET_NO_NEW_PRIVS = 38

# -- filesystem access rights ------------------------------------------------
ACCESS_EXECUTE = 1 << 0
ACCESS_WRITE_FILE = 1 << 1
ACCESS_READ_FILE = 1 << 2
ACCESS_READ_DIR = 1 << 3
ACCESS_REMOVE_DIR = 1 << 4
ACCESS_REMOVE_FILE = 1 << 5
ACCESS_MAKE_CHAR = 1 << 6
ACCESS_MAKE_DIR = 1 << 7
ACCESS_MAKE_REG = 1 << 8
ACCESS_MAKE_SOCK = 1 << 9
ACCESS_MAKE_FIFO = 1 << 10
ACCESS_MAKE_BLOCK = 1 << 11
ACCESS_MAKE_SYM = 1 << 12
ACCESS_REFER = 1 << 13  # ABI 2
ACCESS_TRUNCATE = 1 << 14  # ABI 3
ACCESS_IOCTL_DEV = 1 << 15  # ABI 5+

#: Highest access bit defined by each ABI. Requesting a bit the running kernel
#: does not know fails the whole ruleset with EINVAL, so the mask is ABI-aware.
ABI_MAX_BIT = {1: 12, 2: 13, 3: 14, 4: 14, 5: 15, 6: 15}

#: Reading a file or traversing a directory.
READ_RIGHTS = ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR
#: Everything needed to create, modify and remove files.
WRITE_RIGHTS = (
    READ_RIGHTS
    | ACCESS_WRITE_FILE
    | ACCESS_REMOVE_DIR
    | ACCESS_REMOVE_FILE
    | ACCESS_MAKE_CHAR
    | ACCESS_MAKE_DIR
    | ACCESS_MAKE_REG
    | ACCESS_MAKE_SOCK
    | ACCESS_MAKE_FIFO
    | ACCESS_MAKE_BLOCK
    | ACCESS_MAKE_SYM
    | ACCESS_REFER
    | ACCESS_TRUNCATE
)

#: Access bits the kernel accepts for a **regular file**. Anything outside
#: this set (READ_DIR, the MAKE_*/REMOVE_* family, REFER) makes
#: ``landlock_add_rule`` fail with EINVAL for a file, so a rule that targets a
#: file must be masked down to this. Verified against the running kernel.
FILE_RIGHTS = (
    ACCESS_EXECUTE
    | ACCESS_WRITE_FILE
    | ACCESS_READ_FILE
    | ACCESS_TRUNCATE
)

#: Access bits valid for a **directory**, i.e. everything.
DIR_RIGHTS = READ_RIGHTS | ACCESS_WRITE_FILE | (
    ACCESS_REMOVE_DIR
    | ACCESS_REMOVE_FILE
    | ACCESS_MAKE_CHAR
    | ACCESS_MAKE_DIR
    | ACCESS_MAKE_REG
    | ACCESS_MAKE_SOCK
    | ACCESS_MAKE_FIFO
    | ACCESS_MAKE_BLOCK
    | ACCESS_MAKE_SYM
    | ACCESS_REFER
    | ACCESS_TRUNCATE
)


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    # The kernel declares this struct packed.
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def probe_abi() -> "int | None":
    """Return the supported Landlock ABI version, or ``None``."""
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
    return None


def access_mask_for_abi(abi: int) -> int:
    highest = ABI_MAX_BIT.get(abi, 12)
    mask = 0
    for bit in range(highest + 1):
        mask |= 1 << bit
    return mask


def apply_allowlist(
    read_paths: Iterable[str],
    write_paths: Iterable[str],
    abi: "int | None" = None,
    require: bool = True,
) -> dict[str, Any]:
    """Restrict the calling process to ``read_paths`` / ``write_paths``.

    Irreversible; inherited across ``execve``; never shared with the parent.
    Raises :class:`RuntimeError` when ``require`` is set and Landlock cannot be
    applied — a silently unprotected sandbox would be worse than no sandbox.
    """
    resolved = abi if abi is not None else probe_abi()
    if resolved is None:
        if require:
            raise RuntimeError("Landlock is unavailable on this kernel")
        return {"enabled": False, "reason": "landlock unavailable"}

    handled = access_mask_for_abi(resolved)
    libc = ctypes.CDLL(None, use_errno=True)

    ruleset = _RulesetAttr(handled_access_fs=handled)
    ctypes.set_errno(0)
    ruleset_fd = libc.syscall(
        SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0
    )
    if ruleset_fd < 0:
        err = ctypes.get_errno()
        raise RuntimeError(
            f"landlock_create_ruleset failed: {errno.errorcode.get(err, err)}"
        )

    grants: dict[str, int] = {}
    for path in read_paths:
        if path:
            grants[path] = grants.get(path, 0) | (READ_RIGHTS & handled)
    for path in write_paths:
        if path:
            grants[path] = grants.get(path, 0) | (WRITE_RIGHTS & handled)

    applied: list[str] = []
    skipped: list[dict] = []
    masked: list[dict] = []
    try:
        for path, allowed in sorted(grants.items()):
            if not allowed:
                skipped.append({"path": path, "reason": "no access bits for this ABI"})
                continue
            target = os.path.realpath(path)
            try:
                info = os.stat(target)
            except OSError as exc:
                skipped.append(
                    {"path": path, "reason": f"missing ({errno.errorcode.get(exc.errno or 0, '')})"}
                )
                continue
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                # Landlock only accepts directories and regular files as rule
                # targets: it answers EINVAL for device nodes, FIFOs and
                # sockets. A device such as /dev/null therefore has to be
                # covered by a rule on its parent directory instead.
                skipped.append(
                    {"path": path, "reason": "unsupported object type (not a file or directory)"}
                )
                continue

            effective = allowed
            if not stat.S_ISDIR(info.st_mode):
                # Masked per object type. The kernel rejects bits that do not
                # apply to the object (READ_DIR and the MAKE_*/REMOVE_* set on
                # a regular file) with EINVAL, which would fail the whole
                # ruleset rather than just this rule.
                effective = allowed & FILE_RIGHTS
                if effective != allowed:
                    masked.append(
                        {
                            "path": path,
                            "type": "file",
                            "applied": effective,
                            "dropped": allowed & ~effective,
                        }
                    )
                if not effective:
                    skipped.append(
                        {"path": path, "reason": "no access bits apply to a regular file"}
                    )
                    continue
            try:
                parent_fd = os.open(target, os.O_PATH | os.O_CLOEXEC)
            except OSError as exc:
                skipped.append(
                    {"path": path, "reason": f"cannot open ({errno.errorcode.get(exc.errno or 0, '')})"}
                )
                continue
            try:
                rule = _PathBeneathAttr(allowed_access=effective, parent_fd=parent_fd)
                ctypes.set_errno(0)
                added = libc.syscall(
                    SYS_LANDLOCK_ADD_RULE,
                    ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.byref(rule),
                    0,
                )
                if added < 0:
                    err = ctypes.get_errno()
                    raise RuntimeError(
                        f"landlock_add_rule({path}) failed: "
                        f"{errno.errorcode.get(err, err)}"
                    )
                applied.append(path)
            finally:
                os.close(parent_fd)

        # no_new_privs is a precondition for restrict_self.
        ctypes.set_errno(0)
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            err = ctypes.get_errno()
            raise RuntimeError(
                f"prctl(PR_SET_NO_NEW_PRIVS) failed: {errno.errorcode.get(err, err)}"
            )

        ctypes.set_errno(0)
        if libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0:
            err = ctypes.get_errno()
            raise RuntimeError(
                f"landlock_restrict_self failed: {errno.errorcode.get(err, err)}"
            )
    finally:
        os.close(ruleset_fd)

    return {
        "enabled": True,
        "abi": resolved,
        "handled_access_fs": handled,
        "granted_paths": applied,
        "skipped_paths": skipped,
        "masked_paths": masked,
        "read_paths": sorted({p for p in read_paths if p}),
        "write_paths": sorted({p for p in write_paths if p}),
    }


#: Filesystem types where Landlock path rules may be accepted by the kernel
#: and then not honoured when the process actually touches the file.
#:
#: This list exists because a *functional probe was not enough*. Measured on
#: WSL2 (kernel 6.6.87.2-microsoft-standard-WSL2), probing individual
#: directories on the same 9p mount gave:
#:
#:     /mnt/c                              OK  OK  OK
#:     /mnt/c/Users                        OK  OK  OK
#:     /mnt/c/Users/DELL                   OK  OK  OK
#:     /mnt/c/Users/DELL/Desktop           OK  OK  OK
#:     /mnt/c/.../the watcher              OK  OK  OK
#:     /mnt/c/.../the watcher/_v3smoke     DENY DENY DENY
#:
#: Six directories, one filesystem, two answers, each stable across repeats.
#: Landlock keys rules by inode and walks the file's ancestors to match them;
#: on these filesystems that identity is not stable enough for the walk. The
#: practical consequence is that a probe of one path says nothing about
#: another, so a workspace on one of these filesystems must be refused rather
#: than tested. Unreliable enforcement is not enforcement.
UNRELIABLE_FILESYSTEMS: frozenset[str] = frozenset(
    {
        "9p",
        "v9fs",
        "drvfs",
        "virtiofs",
        "cifs",
        "smb3",
        "nfs",
        "nfs4",
        "afs",
        "ceph",
        "fuse",
        "fuseblk",
    }
)

#: Filesystem types where Landlock is known to behave correctly. Anything not
#: listed here still has to pass :func:`probe_path_access`.
RELIABLE_FILESYSTEMS: frozenset[str] = frozenset(
    {"ext4", "ext3", "ext2", "xfs", "btrfs", "tmpfs", "ramfs", "overlay", "zfs", "f2fs"}
)


_PROBE_SCRIPT = r"""
import errno
import os
import sys

import landlock_ruleset as ll

path = sys.argv[1]
try:
    ll.apply_allowlist([path], [path], abi=ll.probe_abi(), require=True)
    os.listdir(path)
except OSError as exc:
    print("d" + errno.errorcode.get(exc.errno or 0, str(exc.errno)))
except Exception as exc:  # noqa: BLE001 - reported as text
    print("e" + type(exc).__name__)
else:
    print("ok")
"""


def probe_path_access(path: str) -> tuple[bool, str]:
    """Does a Landlock allow-list actually grant access to ``path``?

    This is verified behaviour rather than a filesystem-type guess. On a
    native Linux filesystem the answer is yes. On WSL's ``/mnt/c`` (a 9p /
    drvfs mount) it is **no**: the kernel accepts the rule and then denies
    access anyway, because Landlock keys rules on inode identity and that
    filesystem does not supply one stable enough for the ancestor walk.

    Measured on one 9p mount, six directories gave two different answers
    (five ``OK``, one ``DENY``), each stable across repeats. That is why the
    backend gates on the filesystem type first and only probes types it does
    not recognise: a probe of one path cannot vouch for another, and
    unreliable enforcement is not enforcement.

    The test runs in a subprocess because Landlock cannot be undone, and
    because forking a multi-threaded process is unsafe — which a supervisor
    embedding the Watcher in a larger application may well be.
    """
    if not path or not os.path.isdir(path):
        return False, "path is not an existing directory"

    module_dir = os.path.dirname(os.path.abspath(__file__))
    environment = dict(os.environ)
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        module_dir if not existing else module_dir + os.pathsep + existing
    )

    try:
        completed = subprocess.run(
            [sys.executable, "-c", _PROBE_SCRIPT, path],
            capture_output=True,
            text=True,
            timeout=30,
            env=environment,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"cannot run the Landlock probe: {type(exc).__name__}: {exc}"

    verdict = (completed.stdout or "").strip().splitlines()
    result = verdict[-1] if verdict else ""

    if result == "ok":
        return True, "a Landlock allow-list grants access"
    if result.startswith("d"):
        return False, f"Landlock denied a path it had been granted ({result[1:]})"
    if result.startswith("e"):
        return False, f"the Landlock probe failed ({result[1:]})"
    return False, (
        "the Landlock probe produced no usable result "
        f"({result or 'empty'}; stderr: {(completed.stderr or '').strip()[:160]})"
    )
