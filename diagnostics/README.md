# Diagnostics

Scripts that measure the platform and the repository itself, rather than the
Watcher's behaviour. They exist because several decisions in the Linux
enforcement layer were made from measurements that a test suite cannot
re-derive: a test can assert *"Landlock rules are masked per object type"*, but
it cannot explain why that is required or warn you when a new kernel changes
the answer.

None of these are part of the test suite. Run them by hand.

## Platform probes

| Script | Question it answers |
| --- | --- |
| `probe_namespace_mapping.sh` | Which namespace mapping gives an unprivileged process enough privilege to build a mount tree? |
| `probe_landlock_mask.py` | Which access bits does `landlock_add_rule` accept for a regular file, a directory and a device node? |
| `probe_landlock_reach.py` | Are Landlock path rules actually honoured, across several paths and repeated runs? |
| `probe_read_only_remount.py` | Does making `/` read-only also make a bind submount read-only? |
| `check_landlock_reach.sh` | Quick version of the reach question for a single path. |

## Release hygiene

| Script | Purpose |
| --- | --- |
| `check_code_hygiene.py` | Leftover debug output, stale TODOs, commented-out code, bare `except:` |
| `check_text_hygiene.py` | Encoding damage, non-UTF-8 files, tabs, trailing whitespace |
| `secret_scan.py` | Credential-like strings, separating fixtures from live keys |
| `show_benchmark.py` | Prints the headline numbers from a benchmark result file |

## The findings these produced

### Namespace mapping: `--map-root-user` is required

Measured on WSL2:

| Variant | uid inside | `CapEff` | Mounts |
| --- | --- | --- | --- |
| `unshare --user` | 65534 | `0` | fail |
| `unshare --user --map-root-user` | 0 | `000001ffffffffff` | work |
| `--map-users` with two entries | — | — | unavailable: no `newuidmap` |

The consequence is recorded honestly rather than papered over: uid 0 *inside*
maps to the unprivileged host uid, so `EnforcementEvidence` carries both
`uid_inside_namespace` (0) and `uid_on_host` (1000), and nothing anywhere
claims the workload runs as non-root inside.

### `READ_DIR` is rejected for regular files

`landlock_add_rule` returns `EINVAL` when the requested bits do not apply to
the target object, and one bad rule fails the whole ruleset:

```
/etc/environment   file   RF=OK  EXEC=OK  EXEC|RF=OK  EXEC|RF|RD=EINVAL  RD=EINVAL
/usr               dir    RF=OK  EXEC=OK  EXEC|RF=OK  EXEC|RF|RD=OK      RD=OK
/dev               dir    RF=OK  EXEC=OK  EXEC|RF=OK  EXEC|RF|RD=OK      RD=OK
```

This is what `landlock_ruleset.FILE_RIGHTS` encodes. It is also why `/dev/null`
cannot be named directly — device nodes are rejected as rule targets — so `/dev`
is granted as a directory instead. Run `probe_landlock_mask.py` on a new kernel
before trusting those numbers.

### Landlock is not reliably honoured on 9p/drvfs filesystems

On WSL2, probing six directories at increasing depth along a single 9p mount:

```
<9p mount root>                         OK    OK    OK
<mount>/<dir>                           OK    OK    OK
<mount>/<dir>/<dir>                     OK    OK    OK
<mount>/<dir>/<dir>/<dir>               OK    OK    OK
<mount>/.../project                     OK    OK    OK
<mount>/.../project/<subdir>            DENY  DENY  DENY
```

Six directories, one filesystem, two answers, each stable across repeats. A
probe of one path therefore says nothing about another, which is why the
backend refuses a workspace on such a filesystem *by type*
(`landlock_ruleset.UNRELIABLE_FILESYSTEMS`) and only probes types it does not
recognise. Unreliable enforcement is not enforcement.

To reproduce it, run `probe_landlock_reach.py` with several directories at
increasing depth along one mount — on WSL, anything under `/mnt/c`.

### A read-only remount of `/` leaves bind submounts writable

With the workspace as a bind submount:

```
remount flags: MS_REMOUNT|MS_BIND|MS_RDONLY
  workspace source dir         EROFS
  bind submount of source      WRITABLE
  /etc (root mount)            EROFS
  /usr (root mount)            EROFS
```

`MS_REMOUNT|MS_BIND|MS_RDONLY` applies to that one mount rather than the
underlying superblock, so the workspace can be a bind submount and stay
writable while the rest of the root becomes read-only. The plain
`MS_REMOUNT|MS_RDONLY` form returns `EPERM` inside a rootless user namespace,
so the bind form is the only option available as well as the one that works.

## Running them

They import from the repository root, so run them from there:

```bash
python diagnostics/check_code_hygiene.py
python diagnostics/check_text_hygiene.py
python diagnostics/secret_scan.py
python diagnostics/show_benchmark.py benchmark-v3-results.json

python diagnostics/probe_landlock_mask.py
python diagnostics/probe_landlock_reach.py
bash   diagnostics/probe_namespace_mapping.sh
unshare --user --map-root-user --mount -- \
    python3 diagnostics/probe_read_only_remount.py bind
```

The Landlock probes apply a ruleset in a child process and must not be run
against a shell you intend to keep using.
