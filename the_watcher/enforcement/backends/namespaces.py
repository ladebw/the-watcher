"""Linux namespace enforcement backend.

Builds the sandbox from primitives this host actually provides:

* **user, PID, mount, network, IPC and UTS namespaces** via ``unshare``;
* a **private mount tree** with a read-only root and explicit writable mounts;
* **Landlock** as the filesystem allow-list;
* **seccomp-bpf** as the syscall denylist;
* **capability drop** plus ``no_new_privs``;
* **rlimits** for process, memory, descriptor and file-size ceilings.

No container daemon is involved, so there is no Docker socket to leak and no
root-owned helper on the critical path. The trade-off, stated plainly: a
rootless user namespace is the boundary, not a VM.

Ordering guarantee: to make ``RLIMIT_NPROC`` and ``setrlimit`` safe and
meaningful, and to keep Landlock able to install its ruleset, all privileged
setup happens before the drop. Everything after the drop only removes
authority.
"""

from __future__ import annotations

import base64
import json
import os
import select
import shutil
import signal
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, replace
from typing import Any

from ...exceptions import (
    ContainmentRefused,
    ContainmentStartError,
    EnforcementUnavailable,
)
from ...runtime import LocalProcess
from ..base import (
    ContainmentIdentity,
    ContainmentState,
    ContainmentUnit,
    EnforcementEvidence,
    Enforcer,
    SandboxSpec,
    SurvivorScan,
    TerminationOutcome,
)
from ..declared import require_honourable
from ..procfs import (
    catches_signal,
    child_pids,
    descendants_of,
    filesystem_type,
    namespace_inode,
    pid_exists,
    process_start_time,
    read_cgroup,
    read_namespaces,
    read_network_interfaces,
    read_network_routes,
    read_status,
    snapshot,
)

__all__ = ["NamespaceEnforcer"]

GUARD_MODULES = (
    "exec_guard.py",
    "seccomp_filter.py",
    "landlock_ruleset.py",
    "resource_limits.py",
)

#: Private scratch tree. It is mounted on its own directory rather than on
#: ``/tmp`` itself, because mounting a tmpfs over ``/tmp`` would shadow any
#: workspace or file the operator had placed there.
SCRATCH_BASE = "/tmp/.watcher"
SCRATCH_INNER = "/tmp/.watcher/scratch"
CONTROL_DIR_INNER = "/tmp/.watcher/control"
WORKSPACE_INNER = "/tmp/.watcher/workspace"
#: The profile names /tmp logically; inside, that becomes a private tmpfs.
TEMP_PLACEHOLDER = "/tmp"
REPORT_TIMEOUT = 30.0

#: How long to wait for a SIGTERM that the kernel is going to discard anyway.
#: Only used when the workload has no SIGTERM handler; see ``terminate``.
GRACE_FOR_UNDELIVERABLE_SIGTERM = 0.15


@dataclass(frozen=True)
class _Layout:
    """Resolved inner-sandbox paths for one unit."""

    workspace_host: str
    workspace_inner: str
    control_inner: "str | None"
    read_paths: tuple[str, ...]
    write_paths: tuple[str, ...]
    cwd_inner: "str | None"

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspace_host": self.workspace_host,
            "workspace_inner": self.workspace_inner,
            "control_inner": self.control_inner,
            "read_paths": list(self.read_paths),
            "write_paths": list(self.write_paths),
            "cwd_inner": self.cwd_inner,
        }


class NamespaceEnforcer(Enforcer):
    """Rootless namespace + Landlock + seccomp containment."""

    backend_name = "namespaces"

    def __init__(self, capabilities=None, runtime_root: "str | None" = None) -> None:
        super().__init__(capabilities)
        self._runtime_root = runtime_root
        # The guard modules live in the sibling ``linux`` package directory.
        self._guard_source = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "linux"
        )
        self._logs: dict[str, Any] = {}
        #: ``st_dev -> bool``: whether Landlock path rules work there.
        self._landlock_reach: dict[int, bool] = {}

    # -- preparation -----------------------------------------------------

    def plan(self, spec: SandboxSpec) -> dict[str, Any]:
        """Resolve the inner path layout without launching anything."""
        return self._resolve_layout(spec, spec.control_dir_host).to_dict()

    def prepare(self, profile, spec: "SandboxSpec | None" = None) -> None:
        self.require_available()
        profile.validate()
        # A declared setting this backend cannot honour must stop the session
        # here, before anything is launched, rather than being discovered from a
        # digest that claims it was enforced.
        require_honourable(
            profile,
            self.backend_name,
            allow_reduced_protection=profile.allow_reduced_protection,
        )

        caps = self.capabilities
        problems: list[str] = []

        if not caps.unshare_binary:
            problems.append("unshare is not installed")
        if not caps.unprivileged_userns_ok:
            problems.append(
                "unprivileged user namespaces are unusable: "
                f"{caps.unprivileged_userns_detail}"
            )
        if not caps.seccomp_available:
            problems.append("seccomp filters cannot be installed")
        if profile.filesystem.landlock_required and caps.landlock_abi is None:
            problems.append(
                "the profile requires Landlock but this kernel does not "
                "provide it (set filesystem.landlock_required=false to accept "
                "mount isolation alone)"
            )
        if profile.filesystem.read_only_root and not caps.mount_namespaces:
            problems.append("a read-only root requires mount namespaces")

        if profile.network.value == "none" and not caps.network_namespaces:
            problems.append("network isolation requires network namespaces")

        if problems:
            raise EnforcementUnavailable(
                "namespace containment cannot be enforced on this host: "
                + "; ".join(problems)
            )

        # Partial egress cannot be enforced without host network privileges.
        # Refusing is better than claiming a restriction that is not there.
        if profile.network.value == "restricted":
            raise ContainmentRefused(
                "network=restricted needs host network privileges to program "
                "an egress allow-list, which the rootless namespace backend "
                "does not have. Use network=none, network=open, or a container "
                "backend that can enforce egress policy."
            )

        if profile.allow_privileged or profile.allow_docker_socket:
            raise ContainmentRefused(
                "the namespace backend never provides privileged mode or the "
                "container runtime socket"
            )

        if spec is not None:
            self._validate_spec(profile, spec)
            self._verify_landlock_reach(profile, spec)

    def _verify_landlock_reach(self, profile, spec: SandboxSpec) -> None:
        """Prove Landlock can actually reach the workspace before launching.

        Two gates, because one is not enough:

        1. **Filesystem type.** Landlock identifies rules by inode and walks
           the file's ancestors to match them. On 9p/drvfs/CIFS-style
           filesystems that identity is not stable enough, and the kernel will
           accept a rule and then deny access anyway. Measured on WSL2: six
           directories on one 9p mount gave two different answers, each stable
           across repeats — so a probe of one path cannot vouch for another,
           and the filesystem must be refused outright.
        2. **Functional probe** of the exact workspace path, for filesystems
           not on the known-bad list.

        Launching anyway would produce a sandbox in which the workspace is
        simply unreadable: protection that is really breakage.
        """
        if not profile.filesystem.landlock_required:
            return

        from ..linux import landlock_ruleset  # POSIX-only, imported lazily

        real = os.path.realpath(spec.workspace_host)
        fstype = filesystem_type(real)

        if fstype in landlock_ruleset.UNRELIABLE_FILESYSTEMS:
            raise ContainmentRefused(
                f"the workspace {real!r} is on a {fstype!r} filesystem, where "
                "Landlock path rules are accepted but not reliably honoured. "
                "Refusing rather than running with filesystem enforcement that "
                "may silently not apply. Use a Linux-native workspace (ext4, "
                "xfs, btrfs, tmpfs or overlayfs); on WSL that means a path "
                "under /, not /mnt/c. Set filesystem.landlock_required=false "
                "only if you knowingly accept mount isolation alone."
            )

        if fstype in landlock_ruleset.RELIABLE_FILESYSTEMS:
            # Known-good, so no probe is needed. Probing costs a subprocess and
            # proves nothing extra here.
            return

        # Anything else has to demonstrate that it works before it is trusted.
        try:
            device = os.stat(real).st_dev
        except OSError as exc:
            raise ContainmentRefused(f"cannot inspect the workspace {real!r}: {exc}") from exc

        if device in self._landlock_reach:
            return

        ok, detail = landlock_ruleset.probe_path_access(real)
        self._landlock_reach[device] = ok
        if not ok:
            raise ContainmentRefused(
                f"Landlock cannot enforce an allow-list on {real!r} "
                f"(filesystem type {fstype!r}): {detail}. The workspace must "
                "live on a filesystem where path-based rules are honoured. Set "
                "filesystem.landlock_required=false only if you accept mount "
                "isolation alone."
            )

    def _validate_spec(self, profile, spec: SandboxSpec) -> None:
        workspace = os.path.realpath(spec.workspace_host)
        if not os.path.isdir(workspace):
            raise ContainmentRefused(
                f"workspace does not exist or is not a directory: {workspace}"
            )

        # Nothing belonging to the supervisor may be visible inside a
        # directory the workload can write. Both directions matter:
        # a control directory *inside* the workspace could be replaced by the
        # workload, and a workspace *inside* the control directory would let it
        # reach the IPC socket and the session storage.
        if spec.control_dir_host:
            control = os.path.realpath(spec.control_dir_host)
            if control == workspace or control.startswith(workspace + os.sep):
                raise ContainmentRefused(
                    f"the supervisor control directory {control!r} must not be "
                    "inside the workspace: the workload could replace it"
                )
            if workspace.startswith(control + os.sep):
                raise ContainmentRefused(
                    f"the workspace {workspace!r} must not contain the "
                    f"supervisor control directory {control!r}"
                )

        if not profile.filesystem.read_only_root and not profile.filesystem.allow_write:
            raise ContainmentRefused(
                "a writable root with no explicit writable paths is not a "
                "containment configuration"
            )

    # -- launch ----------------------------------------------------------

    def launch(self, spec: SandboxSpec) -> ContainmentUnit:
        # The runtime root must live OUTSIDE the workspace, so the sandbox
        # cannot read the guard sources, the report log or the IPC control
        # directory through its own writable mount.
        if not self._runtime_root:
            self._runtime_root = tempfile.mkdtemp(prefix="watcher-v3-")

        unit_key = spec.unit_key or uuid.uuid4().hex
        # The runtime directory is unique per launch even when the caller reuses
        # a unit key. Two units must never share a guard directory, and once the
        # guard directory has been made read-only for the sandbox a second
        # install into it would fail.
        runtime_dir = os.path.join(self._runtime_root, f"{unit_key}-{uuid.uuid4().hex[:8]}")
        guard_dir = os.path.join(runtime_dir, "guard")
        os.makedirs(guard_dir, mode=0o700, exist_ok=True)
        self._install_guard(guard_dir)

        control_dir = spec.control_dir_host
        layout = self._resolve_layout(spec, control_dir)
        mounts = self._mount_plan(spec, layout)
        self._prepare_mount_points(spec, layout)

        # The report pipe is created before the command is built so the guard
        # can be told the real descriptor number. ``pass_fds`` preserves fd
        # numbers, but the number is whatever ``os.pipe`` handed back.
        read_fd, write_fd = os.pipe()
        os.set_inheritable(write_fd, True)

        payload = self._spec_payload(spec, mounts, layout)
        command = self._unshare_command(spec, guard_dir, payload, write_fd)

        # Output goes to a file rather than a pipe: a pipe would either block
        # the workload when it fills or deadlock if nobody drained it.
        log_handle = open(  # noqa: SIM115 - closed by _release_log()
            os.path.join(runtime_dir, "guard.log"), "wb"
        )

        process = LocalProcess(
            command,
            env=self._host_environment(spec, layout),
            stdout=log_handle,
            stderr=log_handle,
            pass_fds=(write_fd,),
        )

        try:
            pid = process.start()
        except Exception:
            os.close(read_fd)
            os.close(write_fd)
            log_handle.close()
            raise
        finally:
            # The supervisor's copy must go, or the read end would never see
            # EOF when the sandbox died without reporting.
            os.close(write_fd)

        unit = ContainmentUnit(
            unit_key=unit_key,
            backend=self.backend_name,
            profile_digest=spec.profile.digest(),
            process=process,
            host_pid=pid,
            state=ContainmentState.STARTING,
            control_dir_inner=layout.control_inner,
            workspace_inner=layout.workspace_inner,
            started_at=int(time.time()),
            metadata={
                "runtime_dir": runtime_dir,
                "guard_dir": guard_dir,
                "log_path": os.path.join(runtime_dir, "guard.log"),
                "network_mode": spec.profile.network.value,
                "landlock_required": spec.profile.filesystem.landlock_required,
                "read_only_root": spec.profile.filesystem.read_only_root,
                "layout": layout.to_dict(),
                "launcher_pid": pid,
            },
        )
        self._logs[unit_key] = log_handle

        # ``unshare --pid --fork`` creates the namespaces in the launcher and
        # then forks. The launcher keeps the old PID namespace and is *not*
        # the sandboxed process; its child is. Point the unit at the child so
        # every later /proc observation describes the workload.
        sandbox_pid = self._await_sandbox_pid(pid)
        if sandbox_pid:
            unit.host_pid = sandbox_pid
            unit.metadata["sandbox_pid"] = sandbox_pid

        report = self._read_report(read_fd, pid)
        unit.metadata["guard_report"] = report

        if not report or not report.get("ok"):
            # Fail closed: a sandbox we cannot confirm is not a sandbox.
            detail = "; ".join((report or {}).get("problems") or ["no guard report"])
            self._force_kill(process)
            self._release_log(unit_key)
            unit.state = ContainmentState.FAILED
            raise ContainmentStartError(
                f"the sandbox guard did not complete successfully: {detail}"
            )

        if not sandbox_pid:
            self._force_kill(process)
            self._release_log(unit_key)
            unit.state = ContainmentState.FAILED
            raise ContainmentStartError(
                "the sandbox process could not be located from the host, so "
                "its containment cannot be verified"
            )

        unit.refresh_namespaces()

        # Record the launch-time identity ONCE, from the live sandbox process.
        # Everything later that asks "is the unit gone?" answers against this,
        # not against a fresh read of a pid that may already be dead: an
        # identity the workload can erase by exiting is not an identity.
        unit.identity = ContainmentIdentity(
            launcher_pid=pid,
            launcher_start_time=process_start_time(pid),
            sandbox_pid=sandbox_pid,
            sandbox_start_time=process_start_time(sandbox_pid),
            namespaces=unit.namespaces,
            # Cgroup membership is deliberately NOT recorded here. This backend
            # does not create a per-unit cgroup, so whatever /proc reports is the
            # *ambient* cgroup the supervisor is in too - a systemd user slice,
            # or `/` when a cgroup namespace is in play. Matching on that would
            # report every process in the slice as a unit survivor. A cgroup is
            # only an identity when the backend created it, so until the cgroup
            # phase lands this stays None and the scan skips the layer.
            cgroup=None,
            recorded_at=int(time.time()),
        )
        unit.metadata["identity"] = unit.identity.to_dict()

        unit.state = ContainmentState.RUNNING
        return unit

    def _await_sandbox_pid(self, launcher_pid: int, timeout: float = 10.0) -> "int | None":
        """Wait for the forked sandbox process to appear, and return its pid."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            kids = child_pids(launcher_pid)
            if kids:
                return kids[0]
            if not pid_exists(launcher_pid):
                return None
            time.sleep(0.01)
        return None

    def _release_log(self, unit_key: str) -> None:
        handle = self._logs.pop(unit_key, None)
        if handle is not None and not handle.closed:
            try:
                handle.close()
            except OSError:
                pass

    def _install_guard(self, guard_dir: str) -> None:
        """Copy the standalone guard modules into a read-only session dir.

        Copying means the sandbox needs no access to the Watcher package, so
        the agent cannot read the supervisor's source, configuration or
        storage through the guard's own imports.
        """
        # A reused runtime root may hold a directory left read-only by an
        # earlier run; restore write permission rather than failing obscurely.
        if os.path.isdir(guard_dir):
            try:
                os.chmod(guard_dir, 0o700)
            except OSError:
                pass

        for name in GUARD_MODULES:
            source = os.path.join(self._guard_source, name)
            if not os.path.isfile(source):
                raise ContainmentStartError(f"guard module missing: {source}")
            target = os.path.join(guard_dir, name)
            if os.path.exists(target):
                try:
                    os.chmod(target, 0o600)
                except OSError:
                    pass
            shutil.copyfile(source, target)
            os.chmod(target, 0o500)
        os.chmod(guard_dir, 0o500)

    # -- path layout -----------------------------------------------------

    def _interpreter_paths(self, spec: SandboxSpec) -> tuple[str, ...]:
        """Read paths the command's own runtime needs.

        Rule: if the program *as invoked* sits at ``<prefix>/bin/<name>``,
        grant read access to ``<prefix>``. That covers a virtual environment or
        a conda environment uniformly, and it is the minimum needed for the
        program to start.

        The invoked path is used rather than ``realpath`` deliberately. A venv
        interpreter is a **symlink** to the system binary, so resolving it
        first would grant ``/usr`` and lose ``<prefix>/pyvenv.cfg``, which the
        interpreter reads at start-up; the result is a healthy-looking sandbox
        whose workload dies with ``PermissionError`` before running a line.
        """
        if not spec.command:
            return ()

        # Resolved against the environment the workload will actually get, so
        # PATH is interpreted the same way it will be at exec time.
        environment = self._host_environment(spec, None)
        program = shutil.which(spec.command[0], path=environment.get("PATH"))
        if not program:
            return ()

        invoked = os.path.abspath(program)
        directory = os.path.dirname(invoked)
        paths: list[str] = []

        prefix = os.path.dirname(directory)
        if os.path.basename(directory) == "bin" and os.path.isdir(prefix):
            paths.append(prefix)
        else:
            paths.append(directory)

        # The symlink target's directory as well, so a symlinked interpreter
        # whose real binary lives elsewhere is still executable.
        real_directory = os.path.dirname(os.path.realpath(invoked))
        if real_directory not in paths:
            paths.append(real_directory)

        return tuple(paths)

    def _resolve_layout(self, spec: SandboxSpec, control_dir: "str | None") -> _Layout:
        """Decide where the workspace and the control socket appear inside.

        The workspace keeps its **host path** and is additionally bind-mounted
        onto itself. That is not cosmetic. Remounting ``/`` read-only with
        ``MS_REMOUNT|MS_BIND|MS_RDONLY`` applies to that one mount, so a bind
        submount keeps its own writable flags while the rest of the root
        becomes read-only (measured, not assumed). A self-bind achieves that
        without changing any path the workload sees, so the operator's command
        still resolves and no argument rewriting is needed.

        Mount points are created by the supervisor before the namespaces
        exist, because a rootless user namespace cannot create directories on
        filesystems owned by uids that are not mapped into it.
        """
        profile = spec.profile
        placeholder = profile.filesystem.workspace
        host_workspace = os.path.realpath(spec.workspace_host)

        requested = (spec.workspace_inner or "").strip()
        if not requested or requested in (placeholder, host_workspace):
            # Keep the host path. The workspace is still made its own mount by
            # bind-mounting it onto itself, which gives it independent mount
            # flags without changing a single path the workload sees — so the
            # command the operator typed still resolves.
            requested = host_workspace
        workspace_inner = requested

        def substitute(path: str) -> str:
            if path == placeholder:
                return workspace_inner
            if path == TEMP_PLACEHOLDER:
                return SCRATCH_INNER
            return path

        read_paths = tuple(dict.fromkeys([substitute(p) for p in spec.read_paths]))
        write_paths = tuple(dict.fromkeys([substitute(p) for p in spec.write_paths]))
        if workspace_inner not in read_paths:
            read_paths = read_paths + (workspace_inner,)

        # The program the operator asked to run lives somewhere, and the
        # sandbox has to be able to read it. A system interpreter is already
        # covered by the profile's read roots; a virtual environment or conda
        # prefix is not, and the failure mode without this is an exec that
        # dies with EACCES inside an otherwise healthy sandbox.
        for extra in self._interpreter_paths(spec):
            if extra not in read_paths:
                read_paths = read_paths + (extra,)

        cwd = spec.cwd_inner or placeholder
        cwd_inner = workspace_inner if cwd in (placeholder, host_workspace) else cwd

        control_inner: "str | None" = None
        if control_dir:
            requested_control = (spec.control_dir_inner or "").strip()
            if not requested_control or requested_control.startswith("/run/"):
                # /run is not creatable inside the namespace either, so the
                # socket is exposed under the scratch base instead.
                control_inner = CONTROL_DIR_INNER
            else:
                control_inner = requested_control

        return _Layout(
            workspace_host=host_workspace,
            workspace_inner=workspace_inner,
            control_inner=control_inner,
            read_paths=read_paths,
            write_paths=write_paths,
            cwd_inner=cwd_inner,
        )

    def _mount_plan(self, spec: SandboxSpec, layout: _Layout) -> list[dict]:
        filesystem = spec.profile.filesystem
        plan: list[dict] = [{"kind": "private", "target": "/"}]

        # When source and target are the same path this is a self-bind: it
        # stacks an independent mount on the same directory, which is what
        # keeps the workspace writable once / is remounted read-only.
        plan.append(
            {
                "kind": "bind",
                "source": layout.workspace_host,
                "target": layout.workspace_inner,
                "read_only": False,
            }
        )
        plan.append(
            {
                "kind": "tmpfs",
                "target": SCRATCH_INNER,
                "options": f"size={filesystem.tmpfs_size_mb}m,mode=1777",
            }
        )
        if layout.control_inner:
            plan.append(
                {
                    "kind": "bind",
                    "source": os.path.realpath(spec.control_dir_host or ""),
                    "target": layout.control_inner,
                    "read_only": False,
                }
            )
        if filesystem.read_only_root:
            plan.append({"kind": "read_only_root", "target": "/"})
        return plan

    def _prepare_mount_points(self, spec: SandboxSpec, layout: _Layout) -> None:
        """Create mount points on the host, before the namespaces exist.

        A rootless user namespace cannot create directories on filesystems
        owned by uids that are not mapped into it, so the points have to be
        made by the supervisor while it still has ordinary host permissions.
        Creating them here also means the sandbox never has to mutate the host
        filesystem for its own setup.
        """
        points = [SCRATCH_BASE, SCRATCH_INNER]
        if layout.control_inner:
            points.append(layout.control_inner)
        # A self-bind needs no mount point: the directory already exists.
        if layout.workspace_inner != layout.workspace_host:
            points.append(layout.workspace_inner)

        for point in points:
            try:
                os.makedirs(point, mode=0o700, exist_ok=True)
            except OSError as exc:
                raise ContainmentStartError(
                    f"cannot create sandbox mount point {point!r}: {exc}. The "
                    "workspace and the scratch tree must live on a filesystem "
                    "the supervisor can write to."
                ) from exc

    def _spec_payload(
        self,
        spec: SandboxSpec,
        mounts: list[dict],
        layout: _Layout,
    ) -> str:
        profile = spec.profile
        payload = {
            "mounts": mounts,
            "read_paths": list(layout.read_paths),
            "write_paths": list(layout.write_paths),
            "landlock_required": profile.filesystem.landlock_required,
            "landlock_abi": self.capabilities.landlock_abi,
            "processes": profile.processes.to_dict(),
            "resources": profile.resources.to_dict(),
            "syscalls": profile.syscalls.to_dict(),
            "cwd_inner": layout.cwd_inner,
            "environment": dict(spec.environment),
            "scratch_inner": SCRATCH_INNER,
            "control_dir_inner": layout.control_inner,
            "unit_key": spec.unit_key,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    def _unshare_command(
        self, spec: SandboxSpec, guard_dir: str, payload_b64: str, report_fd: int
    ) -> list[str]:
        caps = self.capabilities
        command: list[str] = [
            caps.unshare_binary or "unshare",
            "--user",
            # Namespace-local root is what makes the mount setup possible at
            # all; it is not host root, and every capability is dropped again
            # before the workload starts.
            "--map-root-user",
            "--pid",
            "--fork",
            "--mount",
            "--ipc",
            "--uts",
            "--mount-proc",
        ]
        if spec.profile.network.value == "none":
            command.append("--net")

        command.extend(
            [
                sys.executable,
                # The guard is invoked by its HOST path: it is the component
                # that creates the in-sandbox mount tree, so it must exist
                # before that tree does. Once it has applied Landlock, the
                # workload cannot read this path anyway, because the guard
                # directory is not on the allow-list.
                os.path.join(guard_dir, "exec_guard.py"),
                "--spec-b64",
                payload_b64,
                "--report-fd",
                str(report_fd),
                "--",
                *spec.command,
            ]
        )
        return command

    def _host_environment(self, spec: SandboxSpec, layout: "_Layout | None") -> dict[str, str]:
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("WATCHER_")
        }
        env["PATH"] = env.get("PATH", "/usr/local/bin:/usr/bin:/bin")
        env["HOME"] = layout.workspace_inner if layout is not None else spec.workspace_inner
        env.setdefault("LANG", "C.UTF-8")
        env["TMPDIR"] = SCRATCH_INNER
        env["TEMP"] = SCRATCH_INNER
        env["TMP"] = SCRATCH_INNER
        env.update({str(k): str(v) for k, v in spec.environment.items()})
        return env

    def _read_report(self, read_fd: int, pid: int) -> dict:
        """Read the guard's JSON report, bounded by a timeout."""
        chunks: list[bytes] = []
        deadline = time.monotonic() + REPORT_TIMEOUT
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                ready, _, _ = select.select([read_fd], [], [], min(1.0, remaining))
                if not ready:
                    if not pid_exists(pid):
                        break
                    continue
                chunk = os.read(read_fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"}" in chunk:
                    # The report is a single JSON object and is written in one
                    # call, so a closing brace means it is complete.
                    break
        except OSError:
            pass
        finally:
            os.close(read_fd)

        raw = b"".join(chunks).decode("utf-8", "replace").strip()
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"ok": False, "problems": [f"unparsable guard report: {raw[:200]}"]}

    # -- inspection ------------------------------------------------------

    def inspect(self, unit: ContainmentUnit) -> EnforcementEvidence:
        """Observe the running unit from the trusted side.

        Everything read here comes from ``/proc`` in the *supervisor's*
        namespaces. The guard's own report is used only to describe state the
        host cannot see from outside (Landlock, mounts, rlimits), and the
        host-visible facts always win.
        """
        problems: list[str] = []
        pid = unit.host_pid
        report = unit.metadata.get("guard_report") or {}
        profile_mode = unit.metadata.get("network_mode", "none")

        if not pid:
            return EnforcementEvidence(
                backend=self.backend_name,
                verified=False,
                problems=("no pid recorded",),
            )

        status = read_status(pid)
        observed = read_namespaces(pid)
        # Never let a read of a dead or recycled pid blank the unit's identity.
        # That was the fail-open bug: after the workload exited, ``inspect``
        # replaced the recorded namespaces with an empty set, and the emptiness
        # check then found "no namespace to look for" and reported the sandbox
        # as empty even when descendants were still running.
        if observed.values:
            unit.namespaces = observed
            if unit.identity is not None and not unit.identity.namespaces.values:
                unit.identity = replace(unit.identity, namespaces=observed)
        namespaces = unit.namespaces
        if not observed.values:
            problems.append(
                "the workload's namespaces could not be read from the host, so "
                "its containment could not be confirmed"
            )

        uid_on_host = None
        if status.get("Uid"):
            try:
                uid_on_host = int(status["Uid"].split()[0])
            except (ValueError, IndexError):
                uid_on_host = None

        capabilities_host = status.get("CapEff", "")
        no_new_privs = status.get("NoNewPrivs") == "1"
        seccomp_mode = None
        if status.get("Seccomp"):
            try:
                seccomp_mode = int(status["Seccomp"])
            except ValueError:
                seccomp_mode = None

        # -- host-visible assertions ------------------------------------
        if seccomp_mode != 2:
            problems.append(
                f"seccomp filter is not active on the workload (mode={seccomp_mode})"
            )
        if not no_new_privs:
            problems.append("no_new_privs is not set on the workload")
        if capabilities_host and capabilities_host.strip("0") != "":
            problems.append(
                f"the workload still holds host-visible capabilities: {capabilities_host}"
            )

        own_user_ns = namespace_inode(os.getpid(), "user")
        if namespaces.user and own_user_ns and namespaces.user == own_user_ns:
            problems.append("the workload shares the supervisor's user namespace")
        own_pid_ns = namespace_inode(os.getpid(), "pid")
        if namespaces.pid and own_pid_ns and namespaces.pid == own_pid_ns:
            problems.append("the workload shares the supervisor's PID namespace")
        # -- network ----------------------------------------------------
        network_isolated = False
        interfaces: tuple[str, ...] = read_network_interfaces(pid)
        routes: tuple[str, ...] = read_network_routes(pid)
        default_route = any(r.startswith("0.0.0.0/") for r in routes)
        if profile_mode == "none":
            # Two independent observations: the namespace inode differs from
            # ours, and the namespace itself contains no route off the host.
            own_net_ns = namespace_inode(os.getpid(), "net")
            unit_net_ns = namespaces.get("net")
            network_isolated = bool(unit_net_ns and unit_net_ns != own_net_ns)
            if not network_isolated:
                problems.append("network isolation was requested but not applied")
            if default_route:
                problems.append(
                    f"a default route exists inside the sandbox: {routes}"
                )
            if any(name != "lo" for name in interfaces):
                problems.append(
                    f"unexpected network interfaces inside the sandbox: {interfaces}"
                )
        else:
            # ``open`` is a *declared posture*, not a containment failure. It
            # provides no egress restriction, and that is recorded as reduced
            # protection - but treating it as a broken sandbox made every
            # non-``none`` profile impossible to complete, which was a bug
            # rather than a safety property.
            unit.metadata.setdefault("network_notes", []).append(
                "network=open: the sandbox shares the host network namespace, "
                "so egress is not restricted"
            )

        # -- guard-reported, inner-side state ---------------------------
        landlock = report.get("landlock") or {}
        if landlock and not landlock.get("enabled"):
            problems.append("Landlock was not enabled inside the sandbox")
        if report.get("landlock") is None and unit.metadata.get("landlock_required"):
            problems.append("no Landlock result was reported by the guard")

        capabilities_inner = report.get("capabilities") or {}
        if capabilities_inner and not capabilities_inner.get("effective_cleared"):
            problems.append("capabilities were not cleared inside the sandbox")

        limits = report.get("limits") or {}

        survivors = list(self.scan_survivors(unit).survivors)
        process_count = max(0, len(survivors))
        evidence = EnforcementEvidence(
            backend=self.backend_name,
            verified=not problems,
            uid_on_host=uid_on_host,
            uid_inside_namespace=report.get("uid_inside"),
            capabilities_effective=capabilities_host,
            capabilities_on_host=capabilities_host,
            no_new_privs=no_new_privs,
            seccomp_mode=seccomp_mode,
            landlock_abi=landlock.get("abi") or self.capabilities.landlock_abi,
            namespaces=namespaces.to_dict(),
            cgroup=read_cgroup(pid),
            read_only_root=bool(
                any(str(m).startswith("read_only_root") for m in report.get("mounts") or [])
            ),
            network_isolated=network_isolated,
            network_interfaces=interfaces,
            process_count=process_count,
            problems=tuple(problems),
        )

        # Extra detail that belongs in the audit trail but not in the summary.
        evidence_dict = evidence.to_dict()
        evidence_dict.update(
            {
                "limits": limits,
                "mounts": report.get("mounts") or [],
                "seccomp_blocked_count": (report.get("seccomp") or {}).get("blocked_count"),
                "seccomp_blocked_syscalls": (report.get("seccomp") or {}).get(
                    "blocked_syscalls"
                ),
                "landlock_granted_paths": landlock.get("granted_paths"),
                "landlock_skipped_paths": landlock.get("skipped_paths"),
                "landlock_masked_paths": landlock.get("masked_paths"),
                "network_routes": list(routes),
                "network_interfaces": list(interfaces),
                "status_inside": report.get("status_inside"),
                "landlock_write_paths": landlock.get("write_paths"),
                "landlock_read_paths": landlock.get("read_paths"),
                "guard_pid": report.get("pid"),
            }
        )
        unit.metadata["evidence_detail"] = evidence_dict
        unit.metadata["network_isolated"] = network_isolated
        return evidence

    # -- isolation and termination ---------------------------------------

    def isolate_network(self, unit: ContainmentUnit) -> tuple[bool, str]:
        """Cut network egress before the unit is destroyed.

        For ``network=none`` the workload is already inside an empty network
        namespace, so isolation holds by construction and is re-verified here.
        For any other mode the namespace cannot be changed retroactively, so
        the whole unit is **frozen** with ``SIGSTOP`` first: a stopped process
        cannot transmit, which is the strongest isolation available without
        host network privileges.
        """
        mode = unit.metadata.get("network_mode", "none")
        pid = unit.host_pid

        if mode == "none":
            # A verified fact does not expire with the pid, so a unit whose
            # workload has already exited still reports how it was isolated.
            if unit.metadata.get("network_isolated"):
                return True, "workload was verified to be in an isolated network namespace"
            if not pid or not pid_exists(pid):
                return False, "no live sandbox process to verify"
            own_net_ns = namespace_inode(os.getpid(), "net")
            unit_net_ns = namespace_inode(pid, "net")
            if unit_net_ns and unit_net_ns != own_net_ns:
                return True, "workload is in an isolated network namespace"
            return False, "expected an isolated network namespace but found none"

        if not pid or not pid_exists(pid):
            return False, "no live sandbox process to freeze"
        try:
            os.killpg(os.getpgid(pid), signal.SIGSTOP)
        except (ProcessLookupError, PermissionError, OSError) as exc:
            return False, f"could not freeze the unit: {type(exc).__name__}"
        unit.metadata["frozen"] = True
        return True, "unit frozen with SIGSTOP before termination"

    def terminate(self, unit: ContainmentUnit, grace: float = 2.0) -> TerminationOutcome:
        """Destroy the unit. The SIGTERM phase is bounded by whether it can work.

        A process that is PID 1 of a PID namespace has ``SIGNAL_UNKILLABLE``
        set, so the kernel **discards** any signal with default disposition —
        including SIGTERM — and only SIGKILL gets through. Measured here:
        ``killpg(SIGTERM)`` left the sandbox alive for the whole grace period,
        after which SIGKILL removed it immediately.

        SIGTERM is still sent first, because a workload that installs a handler
        does receive it and that is the correct way to ask it to stop. But the
        supervisor reads the target's signal mask first, so it does not sit out
        a grace period waiting for a signal the kernel is going to throw away.
        Both the check and its outcome are recorded, so the trace explains the
        escalation instead of making the workload look uncooperative.
        """
        started = time.perf_counter()
        process = unit.process
        if process is None or not process.started:
            unit.state = ContainmentState.TERMINATED
            return TerminationOutcome(
                state=ContainmentState.TERMINATED,
                method="never_started",
                duration_seconds=time.perf_counter() - started,
            )

        unit.state = ContainmentState.TERMINATING
        frozen = bool(unit.metadata.get("frozen"))

        sandbox_pid = unit.metadata.get("sandbox_pid") or unit.host_pid
        deliverable = bool(sandbox_pid) and catches_signal(
            int(sandbox_pid), signal.SIGTERM
        )
        unit.metadata["sigterm_deliverable"] = deliverable

        if frozen:
            effective_grace = 0.0
        elif deliverable:
            effective_grace = grace
        else:
            effective_grace = min(grace, GRACE_FOR_UNDELIVERABLE_SIGTERM)

        try:
            report = process.terminate_tree(grace=effective_grace)
        except Exception as exc:  # noqa: BLE001 - reported as a failed kill
            unit.state = ContainmentState.KILL_FAILED
            return TerminationOutcome(
                state=ContainmentState.KILL_FAILED,
                method="error",
                duration_seconds=time.perf_counter() - started,
                error=f"{type(exc).__name__}: {exc}",
            )

        # Belt and braces: a PID-namespace init can leave descendants that the
        # process-group kill missed. Hunt them by namespace and kill directly.
        survivors: list[int] = []
        deadline = time.monotonic() + max(0.5, min(grace, 2.0))
        while time.monotonic() < deadline:
            survivors = self._unit_processes(unit)
            if not survivors:
                break
            for pid in survivors:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            time.sleep(0.05)

        survivors = self._unit_processes(unit)
        if survivors:
            unit.state = ContainmentState.KILL_FAILED
        else:
            unit.state = ContainmentState.TERMINATED

        self._release_log(unit.unit_key)

        detail = dict(report.to_dict())
        detail.update(
            {
                "sigterm_deliverable": deliverable,
                "effective_grace": effective_grace,
                "requested_grace": grace,
                "sigterm_note": (
                    "the workload installs a SIGTERM handler"
                    if deliverable
                    else (
                        "the workload is a namespace init with no SIGTERM "
                        "handler, so the kernel discards SIGTERM; SIGKILL is "
                        "the only signal that terminates it"
                    )
                ),
            }
        )

        outcome = TerminationOutcome(
            state=unit.state,
            method=report.method,
            terminated=report.terminated,
            remaining=tuple(survivors),
            forced=report.forced_termination,
            network_isolated=bool(unit.metadata.get("network_isolated")),
            duration_seconds=time.perf_counter() - started,
            report=detail,
        )
        unit.termination = outcome
        return outcome

    def scan_survivors(self, unit: ContainmentUnit) -> SurvivorScan:
        """Ask whether any process of the unit survives, using every view available.

        No single namespace inode is a complete identity. A process inside the
        sandbox can create *child* namespaces - a nested user or PID namespace -
        and would then carry different inode values while still belonging to the
        unit. So the scan combines independent layers and reports which one saw
        what, and it fails closed when it has no identity to work from.

        Layers
        ------
        ``pid_namespace``
            Processes carrying the unit's PID-namespace inode. A process cannot
            move out of the PID namespace it was created in, and an orphan
            re-parents to that namespace's init, so this is the strongest single
            key.
        ``user_namespace``
            Processes carrying the unit's user-namespace inode. Catches a
            descendant that created a nested PID namespace but kept the unit's
            user namespace.
        ``ancestry``
            Live roots (the launcher the supervisor itself spawned, and the
            sandbox init) plus everything descended from them. Catches a
            descendant that created *both* a nested user and a nested PID
            namespace, which neither layer above can see. Roots are re-checked
            against their recorded ``starttime``, so a recycled pid is not
            mistaken for the unit.
        ``cgroup``
            Cgroup membership, when a cgroup was recorded at launch.
        """
        identity = unit.identity
        namespaces = (
            identity.namespaces
            if identity is not None and identity.namespaces.values
            else unit.namespaces
        )

        layers: dict[str, Any] = {}
        if not namespaces.values and (identity is None or not identity.known):
            layers["identity"] = "unknown"
            return SurvivorScan(
                empty=False,
                identity_known=False,
                layers=layers,
                note=(
                    "the unit has no recorded identity, so it cannot be verified "
                    "empty; treating it as not empty"
                ),
            )

        records = snapshot(exclude={os.getpid()})
        survivors: set[int] = set()

        if namespaces.pid:
            hits = [r.pid for r in records if r.pid_ns == namespaces.pid and r.live]
            layers["pid_namespace"] = {"inode": namespaces.pid, "pids": sorted(hits)}
            survivors.update(hits)

        if namespaces.user:
            hits = [r.pid for r in records if r.user_ns == namespaces.user and r.live]
            layers["user_namespace"] = {"inode": namespaces.user, "pids": sorted(hits)}
            survivors.update(hits)

        if identity is not None and identity.ancestry_roots:
            roots = identity.ancestry_roots
            by_pid = {record.pid: record for record in records}
            live_roots = [
                pid
                for pid, start in roots.items()
                if pid in by_pid
                and by_pid[pid].live
                and (start is None or by_pid[pid].start_time == start)
            ]
            hits = descendants_of(roots, records)
            layers["ancestry"] = {
                "roots": sorted(roots),
                "live_roots": sorted(live_roots),
                "pids": hits,
            }
            # The roots count too: the launcher is the supervisor's own child
            # and belongs to the unit even though it lives in the host PID
            # namespace.
            survivors.update(hits)
            survivors.update(live_roots)

        if identity is not None and identity.cgroup:
            # A cgroup is only an identity when it is *unit-specific*. The
            # ambient cgroup the supervisor itself sits in (a systemd user
            # slice, or `/` under a cgroup namespace) is shared with unrelated
            # host processes, and matching on it reported pid 1 and other
            # system processes as unit survivors. Guard against that even if a
            # backend one day records a cgroup by mistake.
            own_cgroup = read_cgroup(os.getpid())
            if own_cgroup and identity.cgroup == own_cgroup:
                layers["cgroup"] = {
                    "path": identity.cgroup,
                    "pids": [],
                    "skipped": (
                        "the recorded cgroup is shared with the supervisor, so "
                        "it does not identify this unit"
                    ),
                }
            else:
                hits = [
                    r.pid for r in records if r.cgroup == identity.cgroup and r.live
                ]
                layers["cgroup"] = {"path": identity.cgroup, "pids": sorted(hits)}
                survivors.update(hits)

        return SurvivorScan(
            empty=not survivors,
            survivors=tuple(sorted(survivors)),
            identity_known=True,
            layers=layers,
        )

    def _unit_processes(self, unit: ContainmentUnit) -> list[int]:
        """Live processes belonging to the unit, across every scan layer."""
        return list(self.scan_survivors(unit).survivors)

    def verify_empty(self, unit: ContainmentUnit) -> tuple[bool, list[int]]:
        scan = self.scan_survivors(unit)
        unit.metadata["survivor_scan"] = scan.to_dict()
        if not scan.identity_known and not unit.metadata.get("identity_note"):
            unit.metadata["identity_note"] = scan.note
        return scan.empty, list(scan.survivors)

    def _force_kill(self, process: LocalProcess) -> None:
        try:
            process.terminate_tree(grace=0.5)
        except Exception:  # noqa: BLE001 - best effort during failure handling
            pass
