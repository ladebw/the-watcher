#!/usr/bin/env python3
"""Determine which Landlock access masks the kernel accepts per object type.

Why this exists
---------------
``landlock_add_rule`` answers ``EINVAL`` when the requested access bits do not
apply to the target object, and one bad rule fails the *whole* ruleset. In
particular ``LANDLOCK_ACCESS_FS_READ_DIR`` is rejected for a regular file, so a
single allow-list containing both directories and files must mask its bits per
object type. That constraint is what ``landlock_ruleset.FILE_RIGHTS`` encodes.

Measured on kernel 6.6.87.2-microsoft-standard-WSL2 (Landlock ABI 3)::

    /etc/environment   file   RF=OK  EXEC=OK  EXEC|RF=OK  EXEC|RF|RD=EINVAL  RD=EINVAL
    /usr               dir    RF=OK  EXEC=OK  EXEC|RF=OK  EXEC|RF|RD=OK      RD=OK
    /dev               dir    RF=OK  EXEC=OK  EXEC|RF=OK  EXEC|RF|RD=OK      RD=OK

Run it on a new kernel before trusting those numbers.
"""

import ctypes
import errno
import os
import stat
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from the_watcher.enforcement.linux import landlock_ruleset as ll  # noqa: E402

libc = ctypes.CDLL(None, use_errno=True)


class Attr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


def try_rule(path, mask):
    a = Attr(handled_access_fs=mask)
    rfd = libc.syscall(
        ll.SYS_LANDLOCK_CREATE_RULESET,
        ctypes.byref(a),
        ctypes.c_size_t(ctypes.sizeof(a)),
        ctypes.c_uint32(0),
    )
    if rfd < 0:
        return f"create_ruleset {errno.errorcode.get(ctypes.get_errno(), '?')}"
    try:
        pfd = os.open(os.path.realpath(path), os.O_PATH | os.O_CLOEXEC)
        try:
            rule = ll._PathBeneathAttr(allowed_access=mask, parent_fd=pfd)
            ctypes.set_errno(0)
            r = libc.syscall(
                ll.SYS_LANDLOCK_ADD_RULE,
                rfd,
                ll.LANDLOCK_RULE_PATH_BENEATH,
                ctypes.byref(rule),
                0,
            )
            if r < 0:
                return errno.errorcode.get(ctypes.get_errno(), "?")
            return "OK"
        finally:
            os.close(pfd)
    finally:
        os.close(rfd)


MASKS = [
    ("RF", ll.ACCESS_READ_FILE),
    ("EXEC", ll.ACCESS_EXECUTE),
    ("EXEC|RF", ll.ACCESS_EXECUTE | ll.ACCESS_READ_FILE),
    ("EXEC|RF|RD", ll.ACCESS_EXECUTE | ll.ACCESS_READ_FILE | ll.ACCESS_READ_DIR),
    ("RD", ll.ACCESS_READ_DIR),
]

for path in ["/etc/environment", "/etc/ld.so.cache", "/usr/bin/python3", "/usr", "/dev"]:
    try:
        st = os.stat(os.path.realpath(path))
    except OSError as exc:
        print(f"{path:<22} stat failed: {exc}")
        continue
    if stat.S_ISDIR(st.st_mode):
        kind = "dir"
    elif stat.S_ISREG(st.st_mode):
        kind = "file"
    else:
        kind = "other"
    row = "  ".join(f"{label}={try_rule(path, mask)}" for label, mask in MASKS)
    print(f"{path:<22} {kind:<6} {row}")
