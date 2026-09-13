#!/usr/bin/env bash
# Which namespace mapping gives enough privilege to build a mount tree?
#
# Why this exists
# ---------------
# The sandbox has to mount things (a private /, the workspace, a scratch
# tmpfs, a read-only /), and mounting needs CAP_SYS_ADMIN. The question is how
# an unprivileged process obtains a capability that applies to those mounts
# without ever holding real host privilege.
#
# Three variants are measured:
#
#   A. `unshare --user`              uid 65534 inside, CapEff 0     -> mounts fail
#   B. `unshare --user --map-root-user`  uid 0 inside, full caps    -> mounts work
#   C. `--map-users` with two entries     needs newuidmap, absent   -> unavailable
#
# Variant B is what the enforcement backend uses. Note what it does *not*
# claim: uid 0 inside is namespace-local and maps to the unprivileged host uid,
# so `EnforcementEvidence` records both `uid_inside_namespace` (0) and
# `uid_on_host` (1000) and never describes the workload as "non-root inside".
#
# The last two steps are the interesting ones: writing to /etc must fail, and
# the probe prints the errno so the failure can be attributed (EROFS proves the
# read-only remount, EACCES would only prove a permission check).
#
# Run:  bash diagnostics/probe_namespace_mapping.sh

set -u

echo "=== util-linux unshare ==="
unshare --version

echo
echo "=== mapping options supported ==="
unshare --help 2>&1 | grep -Ei "map-root-user|map-users|map-groups|keep-caps" || echo "(none found)"

echo
echo "=== variant A: unshare --user (identity/default) ==="
unshare --user --pid --fork --mount --net -- python3 -c "
import os
st = dict(l.split(':',1) for l in open('/proc/self/status') if ':' in l)
print('  uid inside :', os.getuid(), 'euid:', os.geteuid())
print('  CapEff     :', st.get('CapEff','?').strip())
"

echo
echo "=== variant B: unshare --user --map-root-user ==="
unshare --user --map-root-user --pid --fork --mount --net -- python3 -c "
import os, ctypes
st = dict(l.split(':',1) for l in open('/proc/self/status') if ':' in l)
print('  uid inside :', os.getuid(), 'euid:', os.geteuid())
print('  CapEff     :', st.get('CapEff','?').strip())
libc = ctypes.CDLL(None, use_errno=True)
MS_REC=16384; MS_PRIVATE=1<<18
r = libc.mount(b'none', b'/', None, ctypes.c_ulong(MS_REC|MS_PRIVATE), None)
print('  make-private r=', r, 'errno', ctypes.get_errno())
r = libc.mount(b'tmpfs', b'/tmp', b'tmpfs', ctypes.c_ulong(0), b'size=32m')
print('  tmpfs /tmp   r=', r, 'errno', ctypes.get_errno())
r = libc.mount(None, b'/', None, ctypes.c_ulong(32|4096|1), None)
print('  remount / ro r=', r, 'errno', ctypes.get_errno())
try:
    open('/etc/should-fail.txt','w').write('x'); print('  write /etc   : SUCCEEDED (not read-only!)')
except OSError as e:
    print('  write /etc   : denied errno', e.errno)
try:
    open('/tmp/ok.txt','w').write('x'); print('  write /tmp   : allowed')
except OSError as e:
    print('  write /tmp   : denied errno', e.errno)
"
echo "  (variant B exit: $?)"

echo
echo "=== variant C: --map-users two entries ==="
unshare --user --map-users=1000,0,1 --map-users=65534,1,1 --pid --fork --mount -- python3 -c "
import os
st = dict(l.split(':',1) for l in open('/proc/self/status') if ':' in l)
print('  uid inside :', os.getuid(), 'euid:', os.geteuid())
print('  CapEff     :', st.get('CapEff','?').strip())
print('  uid_map    :', open('/proc/self/uid_map').read().strip().replace(chr(10),' | '))
" 2>&1 | sed 's/^/  /'

echo
echo "=== does setuid to a mapped non-root uid work? ==="
unshare --user --map-users=1000,0,1 --map-users=65534,1,1 --pid --fork --mount -- python3 -c "
import os, ctypes
libc = ctypes.CDLL(None, use_errno=True)
r = libc.setresgid(1,1,1); print('  setresgid ->', r, ctypes.get_errno())
r = libc.setresuid(1,1,1); print('  setresuid ->', r, ctypes.get_errno())
print('  uid now    :', os.getuid())
st = dict(l.split(':',1) for l in open('/proc/self/status') if ':' in l)
print('  CapEff     :', st.get('CapEff','?').strip())
" 2>&1 | sed 's/^/  /'
