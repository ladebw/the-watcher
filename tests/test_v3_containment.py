"""V3 containment tests: the operating system refuses, not the Watcher.

These are Linux-only. Where enforcement is unavailable the tests skip with the
reason, because a test that silently passes on a host where nothing is enforced
would be worse than no test at all.

The centrepiece is :func:`test_bypass_agent_never_escapes`: the agent used here
never imports ``WatcherClient`` and never opens the IPC socket. If it is still
stopped, the only component that could have stopped it is the kernel.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from conftest import (
    BYPASS_AGENT,
    requires_enforcement,
    run_contained,
    wait_for,
)

# Marked ``v3`` as well as conditionally skipped: the marker is what lets the
# cross-platform matrix exclude this module structurally, instead of relying on
# a host probe to notice that containment is impossible here. On a runner that
# reports Docker as reachable but cannot start a container, the probe says
# enforcement is available and every test below then fails for a reason that
# has nothing to do with the Watcher.
pytestmark = [requires_enforcement(), pytest.mark.v3]


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------


@dataclass
class ContainedRun:
    """Everything a test needs to reason about one contained execution."""

    unit: object
    evidence: object
    guard: dict
    agent: dict
    enforcer: object
    profile: object
    exit_code: int
    duration_seconds: float

    @property
    def escaped(self) -> list[str]:
        return list(self.agent.get("escaped") or [])

    def attempt(self, name: str) -> dict:
        entry = self.agent.get(name)
        assert isinstance(entry, dict), (
            f"{name} was not attempted (exit {self.exit_code}); "
            f"attempted: {sorted(self.agent)}; "
            f"guard log: {self.guard.get('guard_log_tail', '')!r}"
        )
        return entry

    def detail(self, name: str) -> str:
        return str(self.attempt(name).get("detail", ""))


@pytest.fixture()
def contained(enforcer_factory, containment_workspace: Path):
    """Run the bypass agent inside a fresh containment unit."""

    def _run(
        attempt: str = "workspace",
        profile=None,
        backend: "str | None" = None,
        command: "list[str] | None" = None,
        extra_agent_args: "list[str] | None" = None,
        timeout: float = 60.0,
    ) -> ContainedRun:
        enforcer, resolved = enforcer_factory(profile=profile, backend=backend)
        report_path = containment_workspace / f"agent-{attempt}.json"

        argv = command or [sys.executable, str(containment_workspace / "bypass_agent.py")]
        if command is None:
            argv += ["--attempt", attempt, "--json-out", str(report_path)]
        argv += list(extra_agent_args or [])

        started = time.monotonic()
        unit, evidence, guard = run_contained(
            enforcer,
            resolved,
            containment_workspace,
            argv,
            timeout=timeout,
            unit_key=f"test-{attempt}",
            registry=enforcer_factory.units,
        )
        duration = time.monotonic() - started
        exit_code = unit.returncode if unit.returncode is not None else -1

        agent: dict = {}
        if report_path.is_file():
            agent = json.loads(report_path.read_text())

        return ContainedRun(
            unit=unit,
            evidence=evidence,
            guard=guard,
            agent=agent,
            enforcer=enforcer,
            profile=resolved,
            exit_code=exit_code,
            duration_seconds=duration,
        )

    return _run


# ---------------------------------------------------------------------------
# 1-6: the sandbox is a real, separate execution environment
# ---------------------------------------------------------------------------


def test_guard_reports_success(contained):
    run = contained("workspace")
    assert run.guard.get("ok") is True, run.guard.get("problems")


def test_workload_runs_in_a_separate_user_namespace(contained):
    run = contained("escape")
    own = os.readlink("/proc/self/ns/user")
    theirs = run.evidence.namespaces.get("user")
    assert theirs is not None
    assert theirs != own, "the workload must not share the supervisor's user namespace"


def test_workload_runs_in_a_separate_pid_namespace(contained):
    run = contained("escape")
    own = os.readlink("/proc/self/ns/pid")
    theirs = run.evidence.namespaces.get("pid")
    assert theirs and theirs != own


def test_workload_runs_in_a_separate_mount_namespace(contained):
    run = contained("file")
    own = os.readlink("/proc/self/ns/mnt")
    theirs = run.evidence.namespaces.get("mnt")
    assert theirs and theirs != own


def test_workload_runs_in_a_separate_network_namespace(contained):
    run = contained("network")
    own = os.readlink("/proc/self/ns/net")
    theirs = run.evidence.namespaces.get("net")
    assert theirs and theirs != own
    assert run.evidence.network_isolated is True


def test_workload_runs_in_a_separate_ipc_and_uts_namespace(contained):
    run = contained("workspace")
    for kind in ("ipc", "uts"):
        own = os.readlink(f"/proc/self/ns/{kind}")
        theirs = run.evidence.namespaces.get(kind)
        assert theirs and theirs != own, kind


def test_pid_namespace_contains_only_the_workload(contained):
    """A fresh PID namespace holds exactly one process, so /proc cannot leak."""
    run = contained("escape")
    assert run.attempt("pid_namespace_contents")["value"] == [1]
    assert run.attempt("proc_pid_count")["value"] == 1


# ---------------------------------------------------------------------------
# 7-14: the kernel-level protections reported by the guard
# ---------------------------------------------------------------------------


def test_seccomp_filter_is_active(contained):
    run = contained("syscall")
    report = run.guard.get("seccomp") or {}
    assert report.get("blocked_count", 0) > 20
    # Verified from outside as well: /proc/<pid>/status says mode 2 (filter).
    assert run.evidence.seccomp_mode == 2


def test_seccomp_blocks_the_named_dangerous_syscalls(contained):
    run = contained("syscall")
    blocked = set((run.guard.get("seccomp") or {}).get("blocked_syscalls") or [])
    for name in ("mount", "ptrace", "unshare", "reboot", "bpf", "init_module"):
        assert name in blocked, f"{name} must be blocked by seccomp"


def test_landlock_allowlist_is_installed(contained):
    run = contained("file")
    landlock = run.guard.get("landlock") or {}
    assert landlock.get("enabled") is True
    assert landlock.get("abi")
    assert landlock.get("granted_paths"), "an empty allow-list would deny everything"


def test_landlock_masks_bits_per_object_type(contained):
    """The kernel rejects access bits that do not apply to a regular file.

    Requesting ``READ_DIR`` for a file is an ``EINVAL`` for the whole ruleset,
    so the mask has to be narrowed per object type. That the sandbox launched
    at all proves it was, and the report records exactly what was dropped.
    """
    run = contained("file")
    landlock = run.guard.get("landlock") or {}
    masked = landlock.get("masked_paths") or []
    assert masked, "regular files in the allow-list must be masked"
    for entry in masked:
        assert entry["type"] == "file"
        assert entry["dropped"], "something must have been dropped for a file"


def test_capabilities_are_cleared(contained):
    run = contained("syscall")
    assert run.evidence.capabilities_effective in ("", "0000000000000000")
    inner = run.guard.get("capabilities") or {}
    assert inner.get("effective_cleared") is True
    assert inner.get("cap_eff_inside") == "0000000000000000"


def test_capability_bounding_set_is_dropped(contained):
    run = contained("syscall")
    inner = run.guard.get("capabilities") or {}
    assert inner.get("bounding_set_dropped", 0) > 0
    assert inner.get("cap_bnd_inside") == "0000000000000000"
    assert not inner.get("bounding_set_failures")


def test_no_new_privileges_is_set(contained):
    run = contained("workspace")
    assert run.evidence.no_new_privs is True
    assert (run.guard.get("status_inside") or {}).get("NoNewPrivs") == "1"


def test_root_filesystem_is_read_only(contained):
    run = contained("root")
    assert run.evidence.read_only_root is True
    assert "read_only_root:/" in (run.guard.get("mounts") or [])


def test_resource_limits_are_applied(contained):
    run = contained("process")
    limits = run.guard.get("limits") or {}
    for name in ("RLIMIT_NPROC", "RLIMIT_AS", "RLIMIT_NOFILE", "RLIMIT_FSIZE"):
        assert name in limits, f"{name} was not applied"
    assert limits["RLIMIT_AS"] == (run.profile.resources.memory_mb or 0) * 1024 * 1024
    # The process ceiling is expressed against a measured baseline, and both
    # numbers are recorded so the audit trail is not misleading.
    assert limits["nproc_budget"] == run.profile.processes.max_processes
    assert "nproc_baseline" in limits


def test_evidence_is_verified_and_names_the_backend(contained):
    run = contained("workspace")
    assert run.evidence.backend == run.enforcer.backend_name
    assert run.evidence.verified is True, run.evidence.problems
    assert run.evidence.problems == ()
    assert run.evidence.uid_on_host == os.getuid()


def test_evidence_records_both_uids_honestly(contained):
    """Rootless containment cannot avoid namespace-root; it must say so.

    ``--map-root-user`` maps namespace uid 0 to the unprivileged host uid. A
    report that claimed "non-root" would be misleading, so both numbers are
    recorded and no non-root claim is made.
    """
    run = contained("workspace")
    assert run.evidence.uid_on_host == os.getuid()
    assert run.evidence.uid_inside_namespace == 0
    assert run.guard.get("uid_inside") == 0


# ---------------------------------------------------------------------------
# 15-18: profile integrity inside the Proof of Execution
# ---------------------------------------------------------------------------


def test_profile_digest_is_attached_to_the_unit(contained):
    run = contained("workspace")
    assert run.unit.profile_digest == run.profile.digest()
    assert len(run.unit.profile_digest) == 64


def test_unit_records_where_things_appear(contained, containment_workspace):
    run = contained("workspace")
    assert run.unit.workspace_inner == str(containment_workspace)
    layout = (run.unit.metadata or {}).get("layout") or {}
    assert layout.get("workspace_inner") == str(containment_workspace)
    assert layout.get("write_paths")


def test_guard_log_is_kept_outside_the_workspace(contained, containment_workspace):
    """The sandbox must not be able to read the supervisor's own log."""
    run = contained("workspace")
    log_path = (run.unit.metadata or {}).get("log_path")
    assert log_path
    assert not str(log_path).startswith(str(containment_workspace))
    runtime_dir = (run.unit.metadata or {}).get("runtime_dir")
    assert runtime_dir and not str(runtime_dir).startswith(str(containment_workspace))


def test_guard_modules_live_outside_the_workspace(contained, containment_workspace):
    """The sandbox must not be handed the Watcher's own source directory.

    The guard is copied to a supervisor-owned directory that is not on the
    Landlock allow-list, so even knowing its path does not make it readable
    from inside.
    """
    unit = contained("file").unit
    runtime_dir = (unit.metadata or {}).get("runtime_dir")
    guard_dir = (unit.metadata or {}).get("guard_dir")
    assert runtime_dir and guard_dir
    assert not str(runtime_dir).startswith(str(containment_workspace) + os.sep)
    assert os.path.isfile(os.path.join(guard_dir, "exec_guard.py"))
    granted = (contained("file").guard.get("landlock") or {}).get("granted_paths") or []
    assert not any(str(path).startswith(runtime_dir) for path in granted)


# ---------------------------------------------------------------------------
# 19-30: the bypass agent — the three critical experiments and their relatives
# ---------------------------------------------------------------------------


def test_bypass_agent_is_independent_of_the_watcher():
    """The agent must not import the client, or the experiment proves nothing.

    Checked through the *imports* rather than the text: the module docstring
    deliberately mentions ``WatcherClient`` in order to explain that it is
    never used, and a substring search would flag that explanation.
    """
    import ast

    tree = ast.parse(Path(BYPASS_AGENT).read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                imported.append("." * node.level + (node.module or ""))
            else:
                imported.append(node.module or "")

    assert imported, "the agent must import something"
    for name in imported:
        assert not name.startswith("the_watcher"), f"agent imports {name}"
        assert not name.startswith("."), f"agent imports relative module {name}"
    # And no IPC configuration is read from the environment either.
    source = Path(BYPASS_AGENT).read_text(encoding="utf-8")
    assert "WATCHER_IPC" not in source


def test_bypass_agent_never_escapes(contained):
    """The critical experiment: an agent that ignores the Watcher is stopped.

    This is what makes ``DENY`` an operating-system fact rather than a
    message. The agent attempts file access, network access, forbidden
    syscalls, resource abuse and namespace escapes, and nothing succeeds.
    """
    run = contained("all", timeout=180.0)
    assert run.agent, "the agent produced no report; the sandbox probably broke"
    assert run.escaped == [], f"the agent escaped via: {run.escaped}"
    assert run.agent["contained"] is True
    assert run.exit_code == 0


def test_direct_file_access_outside_the_workspace_fails(contained):
    """Critical experiment 1: filesystem containment."""
    run = contained("file")
    assert run.escaped == []
    assert run.detail("read_etc_shadow") == "EACCES"
    assert run.detail("read_root_ssh_key") == "EACCES"
    assert run.detail("list_root") == "EACCES"


def test_filesystem_containment_survives_path_tricks(contained):
    """The same file reached by a different path must still be denied.

    Landlock decides on the resolved path, so /proc/self/root, an open
    directory descriptor and a ``..`` traversal must all reach the same
    verdict as the direct path.
    """
    run = contained("file")
    assert run.detail("read_via_proc_self_root") == "EACCES"
    assert run.detail("list_root_via_fd") == "EACCES"
    assert run.detail("traverse_dotdot") == "EACCES"


def test_filesystem_containment_covers_the_host_mount(contained):
    run = contained("file")
    assert run.detail("read_mnt_c") in ("EACCES", "ENOENT")


def test_direct_network_access_fails(contained):
    """Critical experiment 2: network containment."""
    run = contained("network")
    assert run.escaped == []
    for name in ("connect_ipv4", "connect_dns", "connect_gateway", "udp_sendto"):
        assert "ENETUNREACH" in run.detail(name) or "EPERM" in run.detail(name), name
    assert "resolve_dns" in run.agent
    assert run.attempt("resolve_dns")["escaped"] is False


def test_loopback_is_available_inside_the_sandbox(contained):
    """Isolation must still leave a working loopback, or the sandbox is broken."""
    run = contained("network")
    assert run.detail("resolve_localhost").startswith("127.")


def test_direct_forbidden_syscalls_fail(contained):
    """Critical experiment 3: syscall containment."""
    run = contained("syscall")
    assert run.escaped == []
    for name in (
        "unshare_user_namespace",
        "unshare_mount_namespace",
        "unshare_network_namespace",
        "mount_tmpfs",
        "mount_proc",
        "ptrace",
        "reboot",
        "kexec_load",
    ):
        assert run.detail(name) == "EPERM", f"{name} -> {run.detail(name)}"


def test_privilege_escalation_is_blocked(contained):
    """Capabilities cannot be regained, and no other uid can be adopted."""
    run = contained("syscall")
    assert run.detail("capset_regain") == "EPERM"
    assert run.detail("setuid_to_unmapped_uid") in ("EINVAL", "EPERM")
    # no_new_privs is one-way, so clearing it must fail too.
    assert run.detail("clear_no_new_privs") in ("EINVAL", "EPERM")


def test_writing_outside_the_workspace_fails(contained):
    run = contained("root")
    assert run.escaped == []
    for name in ("write_etc", "write_usr_bin", "write_root_dir", "mkdir_root"):
        assert run.detail(name) == "EROFS", f"{name} -> {run.detail(name)}"
    assert run.detail("chmod_etc_passwd") == "EROFS"


def test_symlink_and_hardlink_do_not_escape(contained):
    run = contained("root")
    assert run.detail("symlink_then_follow") == "EACCES"
    assert run.detail("hardlink_from_etc") in ("EXDEV", "EPERM", "EACCES")


def test_namespace_escape_attempts_fail(contained):
    run = contained("escape")
    assert run.escaped == []
    for name in ("setns_host_mount", "setns_host_pid", "bind_host_root"):
        assert run.detail(name) == "EPERM", f"{name} -> {run.detail(name)}"
    assert run.detail("open_by_handle") == "EPERM"


def test_process_ceiling_stops_a_fork_bomb(contained):
    run = contained("process")
    assert run.escaped == []
    value = run.attempt("fork_bomb")["value"]
    assert value["errno_name"] == "EAGAIN"
    assert value["spawned"] < 400


def test_intended_operations_still_work(contained, containment_workspace):
    """Containment must not be indistinguishable from a broken sandbox."""
    run = contained("workspace")
    assert run.escaped == []
    assert (containment_workspace / "workspace_probe.txt").is_file()
    assert "wrote" in run.detail("write_workspace")
    assert "wrote" in run.detail("write_scratch")
    assert run.attempt("read_etc_passwd")["value"] > 0
    assert run.attempt("read_usr_lib")["value"] is True


def test_scratch_is_a_private_mount(contained):
    """The private scratch tmpfs must be its own mount, not the host's /tmp."""
    run = contained("workspace")
    mounts = run.guard.get("mounts") or []
    assert any(str(m).startswith("tmpfs:/tmp/.watcher/scratch") for m in mounts), mounts


def test_host_tmp_is_not_shadowed(contained, containment_workspace, tmp_path):
    """Mounting over /tmp would hide operator data; the sandbox must not."""
    run = contained("workspace")
    mounts = run.guard.get("mounts") or []
    assert "tmpfs:/tmp" not in mounts


# ---------------------------------------------------------------------------
# 31-36: fail-closed behaviour and honest reporting
# ---------------------------------------------------------------------------


def test_fail_closed_when_the_host_cannot_enforce(monkeypatch, enforcer_factory):
    """Enforced mode must refuse rather than run the workload unprotected."""
    from the_watcher.enforcement import SandboxSpec
    from the_watcher.exceptions import EnforcementUnavailable

    enforcer, profile = enforcer_factory()
    spec = SandboxSpec(command=("true",), profile=profile, workspace_host="/tmp")

    def _refuse(self):
        raise EnforcementUnavailable("simulated: no backend on this host")

    monkeypatch.setattr(type(enforcer), "require_available", _refuse)
    with pytest.raises(EnforcementUnavailable):
        enforcer.prepare(profile, spec)


def test_workspace_on_an_unreliable_filesystem_is_refused(
    monkeypatch, enforcer_factory, tmp_path
):
    """Landlock is not reliably honoured on 9p/CIFS-style filesystems.

    Launching there produces a sandbox whose own workspace is unreadable, so
    the session is refused instead of pretending the protection applies.
    """
    from the_watcher.enforcement import SandboxSpec
    from the_watcher.exceptions import ContainmentRefused

    enforcer, profile = enforcer_factory()
    monkeypatch.setattr(
        "the_watcher.enforcement.backends.namespaces.filesystem_type",
        lambda path: "9p",
    )
    spec = SandboxSpec(command=("true",), profile=profile, workspace_host=str(tmp_path))
    with pytest.raises(ContainmentRefused, match="not reliably honoured"):
        enforcer.prepare(profile, spec)


def test_landlock_optional_when_explicitly_disabled(monkeypatch, enforcer_factory, tmp_path):
    """Disabling Landlock is the only way to accept an unreliable filesystem."""
    import dataclasses

    from the_watcher.enforcement import SandboxSpec

    enforcer, profile = enforcer_factory()
    relaxed = profile.replace(
        filesystem=dataclasses.replace(profile.filesystem, landlock_required=False)
    )
    monkeypatch.setattr(
        "the_watcher.enforcement.backends.namespaces.filesystem_type",
        lambda path: "9p",
    )
    spec = SandboxSpec(command=("true",), profile=relaxed, workspace_host=str(tmp_path))
    enforcer.prepare(relaxed, spec)  # must not raise


def test_control_directory_may_not_live_in_the_workspace(enforcer_factory, tmp_path):
    """The IPC socket must never live inside the writable workspace."""
    from the_watcher.enforcement import SandboxSpec
    from the_watcher.exceptions import ContainmentRefused

    enforcer, profile = enforcer_factory()
    workspace = tmp_path / "ws"
    control = workspace / "control"
    control.mkdir(parents=True)

    spec = SandboxSpec(
        command=("true",),
        profile=profile,
        workspace_host=str(workspace),
        control_dir_host=str(control),
    )
    with pytest.raises(ContainmentRefused, match="must not be inside the workspace"):
        enforcer.prepare(profile, spec)


def test_workspace_may_not_live_in_the_control_directory(enforcer_factory, tmp_path):
    """...and the workspace must not be inside the control directory either.

    Otherwise the workload could reach the supervisor's socket and storage by
    walking upwards from its own working directory.
    """
    from the_watcher.enforcement import SandboxSpec
    from the_watcher.exceptions import ContainmentRefused

    enforcer, profile = enforcer_factory()
    control = tmp_path / "control"
    workspace = control / "ws"
    workspace.mkdir(parents=True)

    spec = SandboxSpec(
        command=("true",),
        profile=profile,
        workspace_host=str(workspace),
        control_dir_host=str(control),
    )
    with pytest.raises(ContainmentRefused, match="must not contain the supervisor"):
        enforcer.prepare(profile, spec)


def test_explicit_unavailable_backend_is_not_downgraded(enforcer_factory, tmp_path):
    from the_watcher.exceptions import EnforcementUnavailable

    with pytest.raises(EnforcementUnavailable):
        enforcer_factory(backend="quantum")


def test_terminate_is_idempotent(contained):
    run = contained("workspace")
    first = run.enforcer.terminate(run.unit, grace=0.5)
    second = run.enforcer.terminate(run.unit, grace=0.5)
    assert first.state is second.state
    empty, survivors = run.enforcer.verify_empty(run.unit)
    assert empty is True and survivors == []


def test_verify_empty_finds_nothing_after_termination(contained):
    run = contained("workspace")
    run.enforcer.terminate(run.unit, grace=0.5)
    empty, survivors = run.enforcer.verify_empty(run.unit)
    assert empty, f"processes survived containment: {survivors}"
    assert survivors == []


def test_isolate_network_reports_the_verified_state(contained):
    run = contained("network")
    ok, detail = run.enforcer.isolate_network(run.unit)
    assert ok is True
    assert "isolated network namespace" in detail


# ---------------------------------------------------------------------------
# 34b. Adversarial descendant: a child that changes its namespaces
# ---------------------------------------------------------------------------

#: Forks, and in the child attempts to create child namespaces so that the
#: descendant no longer carries the unit's namespace inode values. Records what
#: the kernel said, then both processes stay alive long enough to be observed.
_ADVERSARY = r'''
import ctypes, json, os, pathlib, sys, time

CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
CLONE_NEWPID = 0x20000000

libc = ctypes.CDLL(None, use_errno=True)
out = pathlib.Path(sys.argv[1])

pid = os.fork()
if pid == 0:
    results = {}
    for name, flag in (
        ("user", CLONE_NEWUSER),
        ("pid", CLONE_NEWPID),
        ("mnt", CLONE_NEWNS),
        ("net", CLONE_NEWNET),
    ):
        ctypes.set_errno(0)
        rc = libc.unshare(ctypes.c_int(flag))
        results[name] = {"rc": rc, "errno": ctypes.get_errno()}
    out.write_text(json.dumps({"child_pid": os.getpid(), "unshare": results}))
    time.sleep(30)
    os._exit(0)

time.sleep(30)
'''


def test_a_descendant_that_changes_namespaces_is_still_found(
    enforcer_factory, containment_workspace
):
    """A child cannot become invisible by creating its own namespaces.

    The escape this guards against: a descendant calls ``unshare`` to get a
    child user/PID namespace, after which its ``ns/user`` and ``ns/pid`` inode
    values differ from the unit's. A scan keyed on a single inode would then
    report the sandbox as empty while the process was still running.

    Two outcomes are acceptable, and both are asserted rather than assumed:

    * the kernel refuses the ``unshare`` (seccomp blocks namespace
      manipulation), which is the primary defence; or
    * it succeeds, and the layered scan still finds the child - by PID
      namespace, by user namespace, or by ancestry.
    """
    from the_watcher.enforcement import SandboxSpec

    enforcer, profile = enforcer_factory()
    script = containment_workspace / "adversary.py"
    script.write_text(_ADVERSARY, encoding="utf-8")
    marker = containment_workspace / "adversary.json"

    spec = SandboxSpec(
        command=(sys.executable, str(script), str(marker)),
        profile=profile,
        workspace_host=str(containment_workspace),
        cwd_inner=str(containment_workspace),
        unit_key="adversary",
    )
    enforcer.prepare(profile, spec)
    unit = enforcer.launch(spec)
    enforcer_factory.units.append((enforcer, unit))

    assert wait_for(lambda: marker.exists(), timeout=30), (
        "the adversarial workload never reported; guard log: "
        + str((unit.metadata.get("guard_report") or {}).get("problems"))
    )
    payload = json.loads(marker.read_text(encoding="utf-8"))
    attempted = payload["unshare"]
    succeeded = [name for name, result in attempted.items() if result["rc"] == 0]

    scan = enforcer.scan_survivors(unit)
    assert scan.empty is False, (
        "the unit was reported empty while the workload and its child ran: "
        f"{scan.to_dict()}"
    )
    assert len(scan.survivors) >= 2, (
        "the forked descendant was invisible to the survivor scan: "
        f"{scan.to_dict()}"
    )
    if succeeded:
        # Namespaces really did change, so at least one independent layer must
        # have caught the child.
        assert scan.layers["ancestry"]["pids"], (
            f"a descendant changed namespaces ({succeeded}) and only the "
            f"ancestry layer could see it, but it saw nothing: {scan.to_dict()}"
        )

    enforcer.terminate(unit, grace=1.0)
    empty, survivors = enforcer.verify_empty(unit)
    assert empty, f"processes survived termination: {survivors}"


def test_verify_empty_fails_closed_without_a_recorded_identity(contained):
    """An unverifiable unit must never be reported as empty."""
    run = contained("workspace")
    # Erase the identity the way a stale read used to, and prove the check
    # refuses to reassure.
    run.unit.identity = None
    from the_watcher.enforcement.procfs import NamespaceIds

    run.unit.namespaces = NamespaceIds(values={})
    empty, survivors = run.enforcer.verify_empty(run.unit)
    assert empty is False
    assert survivors == []
    scan = run.unit.metadata.get("survivor_scan") or {}
    assert scan.get("identity_known") is False


# ---------------------------------------------------------------------------
# 34c. Which enforcement stops which namespace primitive
# ---------------------------------------------------------------------------

PROBE = str(Path(__file__).resolve().parents[1] / "diagnostics" / "probe_namespace_primitives.py")


def _read_json_when_complete(path, timeout: float = 60.0):
    """Read a JSON file the contained workload is still writing.

    The file is created by ``open(..., "w")`` and only then written, so a
    poller that checks existence alone can read an empty file. Retrying until
    it parses is the correct handshake for a file-based channel.
    """
    deadline = time.monotonic() + timeout
    last_error = "not attempted"
    while time.monotonic() < deadline:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            time.sleep(0.1)
    raise AssertionError(f"{path} never contained complete JSON ({last_error})")


def _run_probe_in_sandbox(enforcer, profile, workspace, extra_args, marker_name):
    """Run the namespace probe as the contained workload and return its output."""
    from the_watcher.enforcement import SandboxSpec

    probe = Path(workspace) / "probe_namespace_primitives.py"
    probe.write_text(Path(PROBE).read_text(encoding="utf-8"), encoding="utf-8")
    marker = Path(workspace) / marker_name
    if marker.exists():
        marker.unlink()

    spec = SandboxSpec(
        command=(sys.executable, str(probe), *extra_args),
        profile=profile,
        workspace_host=str(workspace),
        cwd_inner=str(workspace),
        unit_key=f"probe-{marker_name}",
    )
    enforcer.prepare(profile, spec)
    unit = enforcer.launch(spec)
    return unit, marker


def test_every_namespace_primitive_is_denied_inside_the_sandbox(
    enforcer_factory, containment_workspace
):
    """Name the exact enforcement behind each namespace primitive.

    ``unshare``, ``setns`` and ``clone3`` are denied outright by the seccomp
    denylist. The legacy ``clone`` syscall cannot be denied outright - Python
    threads and every ordinary subprocess go through it - so it is denied
    *conditionally*, on its flags argument. All four must now return ``EPERM``
    from inside the sandbox.
    """
    enforcer, profile = enforcer_factory()
    report = Path(containment_workspace) / "primitives.json"
    unit, _ = _run_probe_in_sandbox(
        enforcer, profile, containment_workspace, ("--json", str(report), "--hold", "3"), "primitives"
    )
    enforcer_factory.units.append((enforcer, unit))
    assert wait_for(report.exists, timeout=60), (
        "the probe produced no output; guard log tail: "
        + str((unit.metadata.get("guard_report") or {}).get("problems"))
    )
    findings = _read_json_when_complete(report)

    # The filter really is active, so a denied primitive is denied by seccomp
    # and not merely by the kernel's privilege rules. The control is the
    # user-namespace case: `unshare(CLONE_NEWUSER)` succeeds on this host
    # outside a sandbox (see the probe's standalone output), so an EPERM here
    # can only come from the filter.
    assert findings["seccomp_mode"] == 2, findings

    for name in ("unshare_newuser", "unshare_newpid", "unshare_newns"):
        entry = findings["primitives"][name]
        assert entry["attempted"] is True, name
        assert entry["ok"] is False, f"{name} unexpectedly succeeded: {entry}"
        assert entry["errno_name"] == "EPERM", (
            f"{name} failed with {entry['errno_name']}, so it is not the seccomp "
            f"filter that stopped it: {entry}"
        )

    # clone3 is refused too, but deliberately with ENOSYS rather than EPERM.
    # glibc's __clone_internal falls back to the legacy clone syscall *only*
    # when clone3 reports ENOSYS; returning EPERM made pthread_create fail
    # inside the sandbox with "can't start new thread". This host's kernel
    # supports clone3 (the probe's standalone run succeeds), so an ENOSYS here
    # can only come from the filter.
    clone3 = findings["primitives"]["clone3"]
    assert clone3["attempted"] is True
    assert clone3["ok"] is False, f"clone3 unexpectedly succeeded: {clone3}"
    assert clone3["errno_name"] == "ENOSYS", (
        "clone3 must report ENOSYS so that runtimes fall back to the legacy "
        f"clone path, which is guarded separately: {clone3}"
    )

    # The gap this closes: legacy clone with namespace flags.
    nested = findings["primitives"]["legacy_clone_nested"]
    if nested.get("errno_name") == "ENOSYS":
        pytest.skip(
            "this architecture has no machine-code child stub, so the legacy "
            "clone attempt cannot be made here (reported as a limitation)"
        )
    assert nested["ok"] is False, (
        "legacy clone with namespace flags still succeeded inside the sandbox: "
        f"{nested}"
    )
    assert nested["errno_name"] == "EPERM", (
        "legacy clone was refused by something other than the seccomp filter: "
        f"{nested}"
    )
    assert nested["child_pid"] is None, "a nested child was created anyway"

    # And the filter is reported, so the trace shows the rule in force.
    report_data = unit.metadata.get("guard_report") or {}
    seccomp = report_data.get("seccomp") or {}
    assert "clone" not in (seccomp.get("blocked_syscalls") or []), (
        "clone must stay callable; it is denied conditionally, not outright"
    )
    guards = seccomp.get("argument_guards") or {}
    assert "clone" in guards, f"the clone argument guard is missing: {seccomp}"
    assert guards["clone"]["low_mask"] == "0x7e020080", guards


def test_ordinary_threads_and_subprocesses_still_work(
    enforcer_factory, containment_workspace
):
    """The clone rule must not break the runtimes agents actually use.

    A security rule that stops namespace creation by breaking threads or
    ``subprocess`` would be worse than the gap it closes. This runs a workload
    that exercises both inside the real sandbox and demands that it finishes
    cleanly.
    """
    enforcer, profile = enforcer_factory()
    result = Path(containment_workspace) / "ordinary.json"
    if result.exists():
        result.unlink()

    workload = Path(containment_workspace) / "ordinary_workload.py"
    workload.write_text(
        "import json, pathlib, subprocess, sys, threading\n"
        "out = pathlib.Path(sys.argv[1])\n"
        "seen = []\n"
        "def worker(n):\n"
        "    seen.append(n)\n"
        "threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]\n"
        "for t in threads: t.start()\n"
        "for t in threads: t.join()\n"
        "proc = subprocess.run([sys.executable, '-c', 'print(6*7)'],\n"
        "                      capture_output=True, text=True, check=True)\n"
        "forked = subprocess.Popen([sys.executable, '-c', 'print(1)'],\n"
        "                          stdout=subprocess.PIPE)\n"
        "forked.communicate()\n"
        "out.write_text(json.dumps({\n"
        "    'threads_started': len(threads),\n"
        "    'threads_ran': sorted(seen),\n"
        "    'subprocess_stdout': proc.stdout.strip(),\n"
        "    'subprocess_rc': proc.returncode,\n"
        "    'popen_rc': forked.returncode,\n"
        "}))\n",
        encoding="utf-8",
    )

    from the_watcher.enforcement import SandboxSpec

    spec = SandboxSpec(
        command=(sys.executable, str(workload), str(result)),
        profile=profile,
        workspace_host=str(containment_workspace),
        cwd_inner=str(containment_workspace),
        unit_key="ordinary-workload",
    )
    enforcer.prepare(profile, spec)
    unit = enforcer.launch(spec)
    enforcer_factory.units.append((enforcer, unit))

    assert wait_for(result.exists, timeout=60), (
        "the workload did not finish; guard problems "
        f"{(unit.metadata.get('guard_report') or {}).get('problems')}, log tail: "
        + str((unit.metadata.get("guard_report") or {}).get("guard_log_tail"))
    )
    payload = _read_json_when_complete(result)

    assert payload["threads_started"] == 8
    assert payload["threads_ran"] == list(range(8)), payload
    assert payload["subprocess_stdout"] == "42"
    assert payload["subprocess_rc"] == 0
    assert payload["popen_rc"] == 0


# ---------------------------------------------------------------------------
# 34d. The hard case: nested namespaces + ancestor exit + reparent
# ---------------------------------------------------------------------------


def test_a_nested_namespace_survivor_cannot_evade_verify_empty(
    enforcer_factory, containment_workspace
):
    """The adversarial lifecycle, end to end.

    ``sandbox init -> descendant -> descendant creates nested user/PID
    namespaces with legacy clone -> the ancestor exits -> the nested child is
    reparented and stays alive -> verify_empty() runs``.

    The nested child carries **different** ``user``, ``pid`` and ``mnt``
    inode values from the unit, so a check based on namespace inode equality
    cannot see it. The point of this test is that the layered scan still does.
    """
    enforcer, profile = enforcer_factory()
    marker = Path(containment_workspace) / "hard-case.json"
    unit, marker = _run_probe_in_sandbox(
        enforcer,
        profile,
        containment_workspace,
        ("--hard-case", str(marker), "--hold", "25"),
        "hard-case.json",
    )
    enforcer_factory.units.append((enforcer, unit))

    assert wait_for(marker.exists, timeout=60), (
        "the adversarial workload reported nothing; guard problems: "
        + str((unit.metadata.get("guard_report") or {}).get("problems"))
    )
    payload = _read_json_when_complete(marker)
    nested = payload["nested"]

    if not nested.get("ok"):
        # This is now the expected outcome, and it is a PASS rather than a
        # skip: the seccomp argument guard denied the primitive before any
        # escape existed. Reported explicitly so the log says which enforcement
        # held, and so a future regression to "succeeded" is visible here.
        assert nested.get("clone_errno_name") == "EPERM", (
            "the escape was refused, but not by the seccomp filter: "
            f"{nested}"
        )
        assert payload.get("nested_alive_after_ancestor_exit") is not True, (
            "the primitive was refused yet a nested child was left behind: "
            f"{payload}"
        )
        # The detection logic itself is still covered, synthetically and on
        # every platform, by tests/test_containment_identity.py. Say so here so
        # nobody reads this early return as "the scan was never tested".
        return

    # Defence in depth: if a future kernel or profile ever lets the primitive
    # through again, the survivor scan must still find the result. Everything
    # below is what makes that claim testable rather than assumed.
    assert payload["ancestor_exited"] is True
    sandbox_ns = payload["sandbox_namespaces"]
    child_ns = nested["child_namespaces"]
    assert child_ns["user"] != sandbox_ns["user"], "the child kept the unit's user namespace"
    assert child_ns["pid"] != sandbox_ns["pid"], "the child kept the unit's PID namespace"
    assert child_ns["mnt"] != sandbox_ns["mnt"], "the child kept the unit's mount namespace"
    # ...and the nested child outlived the ancestor that created it.
    assert payload["nested_state_after_ancestor_exit"] != "Z", (
        "the nested child was not alive after its ancestor exited, so the hard "
        f"case was not exercised: {payload}"
    )
    assert payload["nested_reparented_to"] == 1, (
        "the nested child was not reparented to the sandbox init"
    )

    from the_watcher.enforcement.procfs import snapshot

    child_pid_ns = child_ns["pid"]
    host_pids = [
        record.pid
        for record in snapshot()
        if record.pid_ns == child_pid_ns and record.live
    ]
    assert host_pids, "the nested child is not visible to the host at all"

    # The survivor is found - and only the layered scan can do it, because
    # neither inode comparison matches.
    scan = enforcer.scan_survivors(unit)
    assert scan.empty is False, (
        "verify_empty reported the unit as empty while a nested-namespace "
        f"descendant was alive: {scan.to_dict()}"
    )
    assert any(pid in scan.survivors for pid in host_pids), (
        "the nested descendant was alive but invisible to the survivor scan: "
        f"child={host_pids} survivors={scan.survivors} layers={scan.layers}"
    )
    assert scan.layers["ancestry"]["pids"], (
        "nothing was found by ancestry, so the detection rested on an "
        f"assumption that the escape defeats: {scan.layers}"
    )

    # And after termination the unit really is empty.
    enforcer.terminate(unit, grace=1.0)
    empty, survivors = enforcer.verify_empty(unit)
    assert empty, f"processes survived termination: {survivors}"


# ---------------------------------------------------------------------------
# 37+: kill switch and daemon integration
# ---------------------------------------------------------------------------


@pytest.fixture()
def enforced_daemon(tmp_path, containment_workspace, enforcement_caps):
    """A real daemon in enforced mode, torn down after the test."""
    from the_watcher import Policy
    from the_watcher.enforcement import EnforcementMode, get_preset
    from the_watcher.supervisor import DaemonConfig, WatcherDaemon

    created: list = []

    def _make(command=None, profile=None, **kwargs):
        settings = {
            "command": command
            or [
                sys.executable,
                str(containment_workspace / "bypass_agent.py"),
                "--attempt",
                "workspace",
            ],
            "policy": Policy(workspace_root=str(containment_workspace)),
            "workspace_root": str(containment_workspace),
            "cwd": str(containment_workspace),
            "storage_root": str(tmp_path / "storage"),
            "enforcement": EnforcementMode.ENFORCED,
            "containment": profile or get_preset("research-strict"),
            "enforcement_runtime_root": str(tmp_path / "enforcement"),
            "heartbeat_interval": 0.0,
        }
        settings.update(kwargs)
        daemon = WatcherDaemon(DaemonConfig(**settings))
        created.append(daemon)
        return daemon

    yield _make

    for daemon in created:
        try:
            daemon.stop("TEST_TEARDOWN")
        except Exception:  # noqa: BLE001
            pass


def test_daemon_launches_inside_a_containment_unit(enforced_daemon, containment_workspace):
    daemon = enforced_daemon()
    exit_code = daemon.run()
    assert exit_code == 0, daemon.internal_error
    assert daemon.contained is True
    assert daemon.unit is not None
    assert daemon.evidence is not None
    assert daemon.evidence.verified is True, daemon.evidence.problems


def test_an_unenforceable_requested_ceiling_stops_the_session_before_launch(
    enforced_daemon, containment_workspace, tmp_path
):
    """An explicitly requested control the backend cannot apply fails closed.

    ``--cpus`` is the concrete case: the rootless namespace backend has no
    cgroup quota, so a requested CPU ceiling cannot be honoured. The session
    must be refused with exit 78 (enforcement refused) and the workload must
    **never have run** - no marker file, and no ``process_started`` event.
    """
    import dataclasses

    from the_watcher.enforcement import get_preset

    marker = tmp_path / "workload-ran.txt"
    profile = dataclasses.replace(
        get_preset("research-strict"),
        resources=dataclasses.replace(
            get_preset("research-strict").resources, cpus=2.0
        ),
    )
    daemon = enforced_daemon(
        command=[
            sys.executable,
            "-c",
            f"import pathlib; pathlib.Path({str(marker)!r}).write_text('ran')",
        ],
        profile=profile,
    )

    exit_code = daemon.run()

    assert exit_code == 78, (
        f"expected the enforcement-refused code, got {exit_code}: {daemon.internal_error}"
    )
    assert daemon.enforcement_refused, "the refusal was not reported"
    assert "resources.cpus" in daemon.enforcement_refused
    assert not marker.exists(), "the workload ran despite the refused ceiling"
    assert daemon.unit is None, "a containment unit was launched anyway"
    # The refusal happens during preparation, before a trace exists at all -
    # so there is nothing to inspect, which is itself the strongest form of
    # "the workload never started".
    if daemon.prepared:
        types = [event.event_type for event in daemon.trace]
        assert "process_started" not in types
        assert "containment_started" not in types
        assert daemon.trace.verify().valid


def test_an_unspecified_ceiling_does_not_stop_the_session(
    enforced_daemon, containment_workspace
):
    """Not asking for a control is not the same as asking for one we lack."""
    daemon = enforced_daemon()
    exit_code = daemon.run()
    assert exit_code == 0, daemon.internal_error


def test_reduced_protection_opt_in_is_recorded_and_allows_the_session(
    enforced_daemon, containment_workspace
):
    """The explicit waiver is the only way to run without a requested ceiling."""
    import dataclasses

    from the_watcher.enforcement import get_preset

    base = get_preset("research-strict")
    profile = dataclasses.replace(
        base,
        resources=dataclasses.replace(base.resources, cpus=2.0),
        allow_reduced_protection=True,
    )
    daemon = enforced_daemon(profile=profile)
    exit_code = daemon.run()
    assert exit_code == 0, daemon.internal_error

    prepared = [
        event for event in daemon.trace if event.event_type == "containment_prepared"
    ]
    assert prepared, "no containment_prepared event"
    metadata = prepared[0].metadata
    assert metadata["allow_reduced_protection"] is True
    assert metadata["reduced_protection"] is True
    assert any(
        entry["field"] == "resources.cpus"
        for entry in metadata["declared_but_unhonoured"]
    )
    assert daemon.trace.verify().valid


def test_daemon_records_the_containment_lifecycle(enforced_daemon):
    daemon = enforced_daemon()
    daemon.run()
    types = [event.event_type for event in daemon.trace]

    for expected in (
        "containment_prepared",
        "containment_started",
        "containment_verified",
        "namespaces_created",
        "seccomp_enabled",
        "landlock_enabled",
        "capabilities_dropped",
        "resource_limit_applied",
        "read_only_root_enforced",
        "network_namespace_created",
        "network_isolated",
        "container_termination_started",
        "container_terminated",
        "containment_verified_empty",
    ):
        assert expected in types, f"{expected} missing from the trace"


def test_declared_events_are_not_invented(enforced_daemon):
    """No success event may be recorded without evidence behind it."""
    daemon = enforced_daemon()
    daemon.run()
    started = [e for e in daemon.trace if e.event_type == "containment_started"]
    assert len(started) == 1
    metadata = started[0].metadata or {}
    assert metadata.get("backend")
    assert metadata.get("profile_digest")
    assert metadata.get("host_pid")
    assert metadata.get("mounts")


def test_daemon_metadata_carries_the_enforcement_section(enforced_daemon):
    daemon = enforced_daemon()
    daemon.run()
    metadata = daemon.stats()["metadata"]
    section = metadata.get("enforcement")
    assert section is not None
    assert section["mode"] == "enforced"
    assert section["backend"] == "namespaces"
    assert section["profile_digest"]
    assert section["evidence"]["verified"] is True
    assert section["termination"]["empty"] is True
    assert section["termination"]["terminated"] is True


def test_trace_stays_verifiable_in_enforced_mode(enforced_daemon):
    daemon = enforced_daemon()
    daemon.run()
    verification = daemon.verify()
    assert verification.valid is True, verification.signals
    assert daemon.trace.sealed is True


def test_kill_switch_destroys_the_unit(enforced_daemon, containment_workspace):
    """A kill must isolate, terminate, and prove the sandbox is empty."""
    sleeper = containment_workspace / "sleeper.py"
    sleeper.write_text("import time\nprint('up', flush=True)\ntime.sleep(120)\n")

    daemon = enforced_daemon(
        command=[sys.executable, str(sleeper)],
        session_timeout=1.5,
        termination_grace=1.0,
    )
    exit_code = daemon.run()

    assert daemon.killed is True
    assert exit_code == 137
    termination = daemon.containment_termination
    assert termination is not None
    assert termination["isolated"] is True
    assert termination["empty"] is True
    assert termination["survivors"] == []

    types = [event.event_type for event in daemon.trace]
    assert "container_termination_started" in types
    assert "container_terminated" in types
    assert "containment_verified_empty" in types
    assert "kill_failed" not in types


def test_kill_reports_a_failure_when_processes_survive(
    enforced_daemon, monkeypatch
):
    """A surviving process must be recorded as KILL_FAILED, not glossed over."""
    from the_watcher.enforcement import ContainmentState, TerminationOutcome
    from the_watcher.enforcement.backends.namespaces import NamespaceEnforcer

    def _fake_verify_empty(self, unit):
        return False, [4242]

    def _fake_terminate(self, unit, grace=2.0):
        unit.state = ContainmentState.KILL_FAILED
        outcome = TerminationOutcome(
            state=ContainmentState.KILL_FAILED,
            method="simulated",
            remaining=(4242,),
        )
        unit.termination = outcome
        return outcome

    # Patched on the class, so the instance the daemon creates in _prepare is
    # affected without any hook into its internals.
    monkeypatch.setattr(NamespaceEnforcer, "verify_empty", _fake_verify_empty)
    monkeypatch.setattr(NamespaceEnforcer, "terminate", _fake_terminate)

    daemon = enforced_daemon()
    daemon.run()

    types = [event.event_type for event in daemon.trace]
    assert "kill_failed" in types
    termination = daemon.containment_termination
    assert termination["empty"] is False
    assert termination["survivors"] == [4242]
    assert termination["state"] == ContainmentState.KILL_FAILED.value

    kill_events = [e for e in daemon.trace if e.event_type == "kill_failed"]
    assert str(kill_events[0].risk).lower() == "critical", kill_events[0].risk


def test_unverified_containment_refuses_the_session(enforced_daemon, monkeypatch):
    """If the kernel's view does not match the profile, do not continue.

    A sandbox that cannot be verified is treated as unusable rather than
    assumed to be working: running the workload anyway would mean relying on
    protection nobody checked.
    """
    from the_watcher.enforcement import EnforcementEvidence
    from the_watcher.enforcement.backends.namespaces import NamespaceEnforcer

    def _unverifiable(self, unit):
        return EnforcementEvidence(
            backend="namespaces",
            verified=False,
            problems=("simulated: seccomp is not active on the workload",),
        )

    monkeypatch.setattr(NamespaceEnforcer, "inspect", _unverifiable)

    daemon = enforced_daemon(command=[sys.executable, "-c", "print('ran')"])
    exit_code = daemon.run()

    assert exit_code == 78, daemon.internal_error
    assert daemon.enforcement_refused
    types = [event.event_type for event in daemon.trace]
    assert "containment_health_failed" in types
    assert "containment_verified" not in types


def test_enforced_mode_refuses_a_workspace_it_cannot_contain(
    enforced_daemon, tmp_path
):
    """A workspace Landlock cannot reach must abort before the workload runs."""
    absent = tmp_path / "absent"
    daemon = enforced_daemon(
        command=[sys.executable, "-c", "print('should never run')"],
        workspace_root=str(absent),
        cwd=str(absent),
    )
    exit_code = daemon.run()

    assert exit_code == 78, f"expected the enforcement-refused code, got {exit_code}"
    assert daemon.enforcement_refused
    assert daemon.unit is None
    types = [event.event_type for event in daemon.trace] if daemon.prepared else []
    assert "process_started" not in types


def test_unenforced_mode_is_unchanged(enforced_daemon):
    """V2 behaviour must be untouched when enforcement is off."""
    from the_watcher.enforcement import EnforcementMode

    daemon = enforced_daemon(command=[sys.executable, "-c", "print('plain')"])
    daemon._config.enforcement = EnforcementMode.OFF
    daemon._config.containment = None
    exit_code = daemon.run()

    assert exit_code == 0, daemon.internal_error
    assert daemon.contained is False
    assert daemon.unit is None
    metadata = daemon.stats()["metadata"]
    assert metadata.get("enforcement") is None
    types = [event.event_type for event in daemon.trace]
    assert "containment_started" not in types
