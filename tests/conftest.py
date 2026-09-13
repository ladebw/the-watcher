"""Shared test fixtures.

Adds the project root to ``sys.path`` and to ``PYTHONPATH`` (so protected
child processes can import ``the_watcher`` even in an uninstalled checkout),
defines a deterministic clock, and provides a harness for running a real
:class:`~the_watcher.supervisor.daemon.WatcherDaemon` in a background thread.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Inherited by protected child processes via the daemon's environment.
os.environ.setdefault("PYTHONPATH", str(PROJECT_ROOT))

AGENTS_DIR = Path(__file__).resolve().parent / "agents"
IPC_AGENT = str(AGENTS_DIR / "ipc_agent.py")

#: The project's own adversarial agent: it deliberately never imports
#: ``WatcherClient`` and never touches the IPC socket, so anything that stops
#: it can only be the operating system.
BYPASS_AGENT = str(PROJECT_ROOT / "examples" / "v3_bypass_agents" / "bypass_agent.py")


class FakeClock:
    """Monotonic, deterministic clock: each call advances by ``step``."""

    def __init__(self, start: int = 1_760_000_000, step: int = 1) -> None:
        self._now = int(start)
        self._step = int(step)

    def __call__(self) -> float:
        value = self._now
        self._now += self._step
        return float(value)

    def advance(self, seconds: int) -> None:
        self._now += int(seconds)


@pytest.fixture()
def clock() -> FakeClock:
    """A deterministic clock for reproducible timestamps and hashes."""
    return FakeClock()


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    """An empty workspace directory that mirrors a sandbox root."""
    root = tmp_path / "workspace"
    root.mkdir()
    return root


def pid_is_alive(pid: int) -> bool:
    """Best-effort cross-platform liveness check for a pid."""
    if pid <= 0:
        return False
    if os.name == "posix":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True

    import subprocess

    try:
        completed = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return str(pid) in (completed.stdout or "")


def wait_for(predicate, timeout: float = 10.0, interval: float = 0.05) -> bool:
    """Poll ``predicate`` until it returns truthy or the timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


@pytest.fixture()
def spawner_script(tmp_path: Path) -> tuple[list[str], Path]:
    """A python command that spawns a grandchild and reports its pid to a file."""
    pid_file = tmp_path / "child.pid"
    script = (
        "import subprocess, sys, time, pathlib\n"
        "child = subprocess.Popen("
        "[sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))\n"
        "time.sleep(30)\n"
    )
    return [sys.executable, "-c", script], pid_file


# ---------------------------------------------------------------------------
# V2 supervisor harness
# ---------------------------------------------------------------------------


class DaemonHarness:
    """Runs a real WatcherDaemon in a background thread for a test."""

    def __init__(self, daemon) -> None:
        self.daemon = daemon
        self.exit_code: "int | None" = None
        self.error: "BaseException | None" = None
        self._thread: "threading.Thread | None" = None

    def start(self) -> "DaemonHarness":
        self._thread = threading.Thread(
            target=self._target, name="test-daemon", daemon=True
        )
        self._thread.start()
        return self

    def _target(self) -> None:
        try:
            self.exit_code = self.daemon.run()
        except BaseException as exc:  # noqa: BLE001 - surfaced to the test
            self.error = exc

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def wait(self, timeout: float = 60.0) -> int:
        if self._thread is not None:
            self._thread.join(timeout)
            if self._thread.is_alive():
                self.daemon.stop("TEST_TIMEOUT")
                self._thread.join(10)
        if self.error is not None:
            raise self.error
        return int(self.exit_code if self.exit_code is not None else -1)

    def stop(self, reason: str = "TEST_STOP") -> None:
        self.daemon.stop(reason)

    def wait_until_running(self, timeout: float = 20.0) -> bool:
        """Wait until the protected process is up and IPC is listening."""
        return wait_for(
            lambda: self.daemon.endpoint is not None
            and self.daemon.process is not None
            and self.daemon.process.started,
            timeout=timeout,
        )

    def wait_for_client_authentication(self, timeout: float = 20.0) -> bool:
        """Wait until a client has actually authenticated over IPC.

        Readiness is not authentication. The heartbeat clock starts at
        authentication and the session timeout is measured from process spawn,
        so a heartbeat test that did not wait for this would be racing the
        session timeout against the child's startup cost and would pass or fail
        according to machine speed. Waiting on the recorded event makes the
        precondition observable instead of assumed.
        """
        return wait_for(
            lambda: self.daemon.prepared
            and bool(self.events_of("client_authenticated")),
            timeout=timeout,
        )

    def event_types(self) -> list[str]:
        return [event.event_type for event in self.daemon.trace]

    def events_of(self, event_type: str):
        return [event for event in self.daemon.trace if event.event_type == event_type]


@pytest.fixture()
def harness_factory(tmp_path: Path):
    """Build :class:`DaemonHarness` objects with safe test defaults.

    Storage defaults to ``tmp_path/watcher-home`` (never the protected
    process's working directory), which is what the daemon enforces.
    """
    from the_watcher import Policy
    from the_watcher.supervisor import DaemonConfig, WatcherDaemon

    created: list[DaemonHarness] = []

    def _make(
        mode: str = "normal",
        policy: "Policy | None" = None,
        command: "list[str] | None" = None,
        storage_root: "str | None" = None,
        cwd: "str | None" = None,
        child_env: "dict | None" = None,
        start: bool = True,
        **config_kwargs,
    ) -> DaemonHarness:
        env = {
            "WATCHER_AGENT_MODE": mode,
            "WATCHER_AGENT_WORKSPACE": str(PROJECT_ROOT),
        }
        env.update(child_env or {})
        config = DaemonConfig(
            command=command or [sys.executable, IPC_AGENT],
            policy=policy or Policy(),
            workspace_root=str(PROJECT_ROOT),
            cwd=cwd or str(PROJECT_ROOT),
            storage_root=storage_root or str(tmp_path / "watcher-home"),
            child_env=env,
            **config_kwargs,
        )
        harness = DaemonHarness(WatcherDaemon(config))
        created.append(harness)
        if start:
            harness.start()
        return harness

    yield _make

    for harness in created:
        try:
            harness.daemon.stop("TEST_TEARDOWN")
        except Exception:  # noqa: BLE001
            pass
        if harness.running:
            harness.wait(timeout=15)


# ---------------------------------------------------------------------------
# V3 containment harness
# ---------------------------------------------------------------------------


def enforcement_unavailable_reason() -> "str | None":
    """Why V3 enforced mode cannot run here, or ``None`` when it can.

    Returned as a string rather than a bool so a skipped test says *why*
    instead of just disappearing. On native Windows this is always non-empty:
    the enforcement backend is Linux-only, and pretending otherwise would be
    the kind of overclaim V3 exists to avoid.
    """
    if sys.platform != "linux":
        return (
            f"V3 OS-enforced containment requires Linux with user namespaces "
            f"and seccomp; this is {sys.platform}. V2 external supervision "
            f"remains available here."
        )
    try:
        from the_watcher.enforcement import detect_capabilities

        caps = detect_capabilities()
    except Exception as exc:  # noqa: BLE001
        return f"cannot probe containment capabilities: {type(exc).__name__}: {exc}"

    if not caps.enforced_mode_available:
        detail = "; ".join(caps.problems) or "no backend available"
        return f"no containment backend can enforce anything here: {detail}"
    return None


def requires_enforcement():
    """Skip the calling test when the host cannot enforce containment."""
    reason = enforcement_unavailable_reason()
    return pytest.mark.skipif(reason is not None, reason=reason or "")


@pytest.fixture(scope="session")
def enforcement_caps():
    """Probed host capabilities, computed once."""
    from the_watcher.enforcement import detect_capabilities

    return detect_capabilities()


@pytest.fixture()
def containment_workspace(tmp_path: Path) -> Path:
    """A workspace on a Linux-native filesystem, with the bypass agent in it.

    Landlock's path rules are not honoured on WSL's ``/mnt/c`` (9p), and the
    backend refuses such a workspace rather than launching a sandbox whose own
    workspace is unreadable. ``tmp_path`` is under ``/tmp`` on Linux, which is
    native, so this fixture is the correct place to run from.
    """
    root = tmp_path / "containment-workspace"
    root.mkdir()
    if os.path.exists(BYPASS_AGENT):
        import shutil

        shutil.copyfile(BYPASS_AGENT, root / "bypass_agent.py")
    return root


@pytest.fixture()
def enforcer_factory(enforcement_caps, tmp_path: Path):
    """Build an enforcer and tear down anything it started."""
    from the_watcher.enforcement import get_preset, select_backend

    started: list = []

    def _make(profile=None, backend: "str | None" = None):
        resolved = profile or get_preset("research-strict")
        if backend:
            resolved = resolved.replace(backend=backend)
        enforcer = select_backend(
            profile=resolved,
            capabilities=enforcement_caps,
            runtime_root=str(tmp_path / "enforcement"),
        )
        return enforcer, resolved

    _make.units = started  # type: ignore[attr-defined]
    yield _make

    for enforcer, unit in started:
        try:
            enforcer.terminate(unit, grace=0.5)
        except Exception:  # noqa: BLE001 - teardown is best effort
            pass


def run_contained(
    enforcer,
    profile,
    workspace: Path,
    command: "list[str]",
    *,
    timeout: float = 60.0,
    unit_key: str = "test-unit",
    registry: "list | None" = None,
):
    """Launch a containment unit, wait for the workload, return everything.

    Returns ``(unit, evidence, report)``, where ``report`` is the guard's own
    JSON report describing what it applied inside the sandbox.
    """
    from the_watcher.enforcement import SandboxSpec

    spec = SandboxSpec(
        command=tuple(command),
        profile=profile,
        workspace_host=str(workspace),
        cwd_inner=str(workspace),
        unit_key=unit_key,
    )
    enforcer.prepare(profile, spec)
    unit = enforcer.launch(spec)
    if registry is not None:
        registry.append((enforcer, unit))

    # Observe *before* waiting. Once the child is reaped its /proc entry is
    # gone, and with it the namespace ids, capability masks and seccomp state
    # that make up the evidence. The daemon inspects at exactly this point.
    evidence = enforcer.inspect(unit)

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and unit.alive:
        time.sleep(0.02)

    report = dict(unit.metadata.get("guard_report") or {})

    # If the workload produced no report of its own, the guard log is the only
    # place the reason can be: a failed exec leaves the sandbox healthy but
    # tells the caller nothing. Surfacing it turns a mysterious empty result
    # into a readable one.
    log_path = unit.metadata.get("log_path")
    if log_path and os.path.isfile(log_path):
        with open(log_path, errors="replace") as handle:
            tail = handle.read().strip()[-800:]
        if tail:
            report["guard_log_tail"] = tail

    return unit, evidence, report
