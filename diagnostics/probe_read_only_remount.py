"""Does a read-only remount of / also make a bind submount read-only?

Why this exists
---------------
V3 exposes the workspace by bind-mounting it onto itself and then remounting
``/`` read-only. That only works because ``MS_REMOUNT|MS_BIND|MS_RDONLY``
changes *that one mount* rather than the underlying superblock. Measured, with
the workspace as a bind submount::

    remount flags: MS_REMOUNT|MS_BIND|MS_RDONLY
      workspace source dir         EROFS
      bind submount of source      WRITABLE
      /etc (root mount)            EROFS
      /usr (root mount)            EROFS

The plain ``MS_REMOUNT|MS_RDONLY`` form fails with ``EPERM`` inside a rootless
user namespace, so the bind form is both the correct choice and the only one
available. If a future kernel changes this, every sandbox's workspace becomes
read-only and the change will show up here first.

Run::

    unshare --user --map-root-user --mount -- python3 diagnostics/probe_read_only_remount.py bind
"""

import ctypes
import errno
import os
import sys

libc = ctypes.CDLL(None, use_errno=True)
MS_RDONLY = 1
MS_BIND = 4096


def mount(source, target, flags):
    ctypes.set_errno(0)
    r = libc.mount(
        source.encode() if source else None,
        target.encode(),
        None,
        ctypes.c_ulong(flags),
        None,
    )
    if r != 0:
        return errno.errorcode.get(ctypes.get_errno(), "?")
    return "OK"


def write_probe(path, label):
    target = os.path.join(path, "probe.txt")
    try:
        with open(target, "w") as handle:
            handle.write("x")
        os.unlink(target)
        print(f"  {label:<28} WRITABLE")
    except OSError as exc:
        print(f"  {label:<28} {errno.errorcode.get(exc.errno)}")


base = "/tmp/ro_probe"
src = os.path.join(base, "src")
dst = os.path.join(base, "dst")
scratch_src = os.path.join(base, "scratchsrc")
scratch_dst = os.path.join(base, "scratchdst")
for path in (src, dst, scratch_src, scratch_dst):
    os.makedirs(path, exist_ok=True)

print("bind submount on the SAME filesystem as /:", os.stat(src).st_dev == os.stat("/").st_dev)
print("bind:", mount(src, dst, MS_BIND))

print("tmpfs bind:", mount("tmpfs", scratch_src, 0) if False else "skipped")

mode = sys.argv[1] if len(sys.argv) > 1 else "bind"
if mode == "plain":
    print("remount flags: MS_REMOUNT|MS_RDONLY")
    print("remount:", mount(None, "/", 32 | MS_RDONLY))
else:
    print("remount flags: MS_REMOUNT|MS_BIND|MS_RDONLY")
    print("remount:", mount(None, "/", 32 | MS_BIND | MS_RDONLY))

write_probe(src, "workspace source dir")
write_probe(dst, "bind submount of source")
write_probe("/etc", "/etc (root mount)")
write_probe("/usr", "/usr (root mount)")
