"""Local process protection.

V1 protects a single local process tree. The architecture is deliberately
Linux-first for tree introspection (``/proc``), with a best-effort Windows
path via ``taskkill /T``, and an explicit "I cannot enumerate children here"
result elsewhere rather than a silent lie.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Sequence

from ..exceptions import SessionError

__all__ = ["TerminationReport", "LocalProcess", "descendant_pids"]

_IS_WINDOWS = os.name == "nt"
_POSIX = os.name == "posix"


@dataclass(frozen=True)
class TerminationReport:
    """Outcome of terminating a process tree.

    The extra fields added in V2 exist so the external supervisor can record a
    complete, auditable account of how a kill was carried out.
    """

    pid: int
    method: str
    terminated: tuple[int, ...] = field(default_factory=tuple)
    failed: tuple[int, ...] = field(default_factory=tuple)
    tree_enumerated: bool = False
    error: str = ""
    descendant_count: int = 0
    grace_period: float = 0.0
    forced_termination: bool = False
    started_at: "int | None" = None
    finished_at: "int | None" = None

    @property
    def ok(self) -> bool:
        return not self.failed

    @property
    def duration_seconds(self) -> float:
        if self.started_at is None or self.finished_at is None:
            return 0.0
        return float(self.finished_at - self.started_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "method": self.method,
            "terminated": list(self.terminated),
            "failed": list(self.failed),
            "tree_enumerated": self.tree_enumerated,
            "ok": self.ok,
            "error": self.error,
            "descendant_count": self.descendant_count,
            "grace_period": self.grace_period,
            "forced_termination": self.forced_termination,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
        }

    def summary(self) -> str:
        return (
            f"{self.method}: terminated {len(self.terminated)} process(es)"
            + (f", {len(self.failed)} failed" if self.failed else "")
            + (" (forced)" if self.forced_termination else "")
        )


def _proc_ppid_map() -> dict[int, int]:
    """Return ``{pid: ppid}`` from ``/proc``. Empty when unavailable."""
    root = "/proc"
    if not os.path.isdir(root):
        return {}

    mapping: dict[int, int] = {}
    try:
        entries = os.listdir(root)
    except OSError:
        return {}

    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(os.path.join(root, entry, "stat"), "r", encoding="utf-8") as handle:
                data = handle.read()
        except OSError:
            continue
        # Format: "<pid> (<comm>) <state> <ppid> ..."; comm may contain spaces,
        # so split after the final ')'.
        close = data.rfind(")")
        if close == -1:
            continue
        fields = data[close + 2 :].split()
        if len(fields) < 2:
            continue
        try:
            mapping[int(entry)] = int(fields[1])
        except ValueError:
            continue
    return mapping


def descendant_pids(pid: int) -> tuple[list[int], bool]:
    """Return ``(descendants, enumerated)`` for ``pid``, deepest last."""
    if pid <= 0 or not _POSIX:
        return [], False

    ppid_map = _proc_ppid_map()
    if not ppid_map:
        return [], False

    children: dict[int, list[int]] = {}
    for child, parent in ppid_map.items():
        children.setdefault(parent, []).append(child)

    ordered: list[int] = []
    queue = list(children.get(pid, []))
    seen: set[int] = set()
    while queue:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        ordered.append(current)
        queue.extend(children.get(current, []))

    # Reverse so the deepest descendants are terminated first.
    ordered.reverse()
    return ordered, True


class LocalProcess:
    """A protected subprocess plus its known descendants."""

    def __init__(
        self,
        argv: "Sequence[str] | str",
        cwd: "str | None" = None,
        env: "Mapping[str, str] | None" = None,
        stdin: Any = None,
        stdout: Any = None,
        stderr: Any = None,
        shell: bool = False,
        pass_fds: "Sequence[int]" = (),
    ) -> None:
        if isinstance(argv, str):
            argv = [argv]
        argv = list(argv)
        if not argv:
            raise SessionError("LocalProcess requires a command")

        self._argv = argv
        self._cwd = cwd
        self._env = dict(env) if env is not None else None
        self._stdin = stdin
        self._stdout = stdout
        self._stderr = stderr
        self._shell = shell
        self._pass_fds = tuple(pass_fds)
        self._proc: "subprocess.Popen[bytes] | None" = None

    # -- lifecycle -------------------------------------------------------

    def start(self) -> int:
        """Start the process and return its pid."""
        if self._proc is not None:
            raise SessionError("process already started")

        kwargs: dict[str, Any] = {
            "cwd": self._cwd,
            "env": self._env,
            "stdin": self._stdin if self._stdin is not None else subprocess.DEVNULL,
            "stdout": self._stdout if self._stdout is not None else subprocess.DEVNULL,
            "stderr": self._stderr if self._stderr is not None else subprocess.DEVNULL,
            "shell": self._shell,
        }

        if _POSIX:
            # Own process group: lets the kill switch signal the whole tree.
            kwargs["start_new_session"] = True
            if self._pass_fds:
                # Only meaningful on POSIX; the V3 sandbox guard reports its
                # results over an inherited pipe. In Python 3.13+ this keeps
                # the descriptor inheritable explicitly.
                kwargs["pass_fds"] = self._pass_fds
        elif _IS_WINDOWS:
            kwargs["creationflags"] = getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )

        try:
            self._proc = subprocess.Popen(self._argv, **kwargs)  # type: ignore[arg-type]
        except (OSError, ValueError) as exc:
            raise SessionError(f"failed to start protected process: {exc}") from exc

        return self._proc.pid

    def wait(self, timeout: "float | None" = None) -> int:
        """Wait for the process and return its exit code."""
        if self._proc is None:
            raise SessionError("process has not been started")
        return self._proc.wait(timeout=timeout)

    def poll(self) -> "int | None":
        return self._proc.poll() if self._proc is not None else None

    # -- state -----------------------------------------------------------

    @property
    def pid(self) -> "int | None":
        return self._proc.pid if self._proc is not None else None

    @property
    def argv(self) -> list[str]:
        return list(self._argv)

    @property
    def returncode(self) -> "int | None":
        return self._proc.returncode if self._proc is not None else None

    @property
    def alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def started(self) -> bool:
        return self._proc is not None

    def children(self) -> list[int]:
        """Direct and transitive child pids, when the platform allows it."""
        if self.pid is None:
            return []
        descendants, _ = descendant_pids(self.pid)
        return descendants

    def process_count(self) -> int:
        """Number of live processes in this tree, including the root."""
        if not self.alive:
            return 0
        return 1 + len(self.children())

    # -- termination -----------------------------------------------------

    def terminate_tree(self, grace: float = 2.0) -> TerminationReport:
        """Terminate the process and its descendants. Idempotent."""
        started_at = int(time.time())

        if self._proc is None:
            return TerminationReport(
                pid=0,
                method="never_started",
                grace_period=grace,
                started_at=started_at,
                finished_at=started_at,
            )

        pid = self._proc.pid
        if self._proc.poll() is not None:
            return TerminationReport(
                pid=pid,
                method="already_exited",
                terminated=(),
                failed=(),
                tree_enumerated=False,
                grace_period=grace,
                started_at=started_at,
                finished_at=int(time.time()),
            )

        if _POSIX:
            report = self._terminate_posix(pid, grace)
        elif _IS_WINDOWS:
            report = self._terminate_windows(pid, grace)
        else:
            # Unknown platform: kill the root only, and say so.
            try:
                self._proc.kill()
                self._proc.wait(timeout=grace)
                report = TerminationReport(
                    pid=pid,
                    method="root_only",
                    terminated=(pid,),
                    forced_termination=True,
                )
            except Exception:  # noqa: BLE001 - reported through the record
                report = TerminationReport(
                    pid=pid,
                    method="root_only",
                    terminated=(),
                    failed=(pid,),
                    forced_termination=True,
                    error="platform does not support tree termination",
                )

        return replace(
            report,
            grace_period=report.grace_period or grace,
            started_at=report.started_at or started_at,
            finished_at=int(time.time()),
        )

    def _terminate_posix(self, pid: int, grace: float) -> TerminationReport:
        import signal

        descendants, enumerated = descendant_pids(pid)
        terminated: list[int] = []
        failed: list[int] = []

        targets = [pid, *descendants]

        def _signal(sig: int) -> None:
            for target in targets:
                try:
                    os.kill(target, sig)
                    if target not in terminated:
                        terminated.append(target)
                except ProcessLookupError:
                    if target not in terminated:
                        terminated.append(target)
                except (PermissionError, OSError):
                    if target not in failed:
                        failed.append(target)

        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            _signal(signal.SIGTERM)

        deadline = time.monotonic() + max(0.0, grace)
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                break
            time.sleep(0.02)

        forced = False
        if self._proc.poll() is None:
            # Graceful termination was refused: escalate.
            forced = True
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                _signal(signal.SIGKILL)
            try:
                self._proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                failed.append(pid)

        # Reap anything still listening for a signal.
        for target in targets:
            if target in terminated or target in failed:
                continue
            try:
                os.kill(target, 0)
            except (ProcessLookupError, OSError):
                terminated.append(target)
            except PermissionError:
                failed.append(target)

        reason = "process_group"
        return TerminationReport(
            pid=pid,
            method=reason,
            terminated=tuple(sorted(set(terminated))),
            failed=tuple(sorted(set(failed))),
            tree_enumerated=enumerated,
            descendant_count=len(descendants),
            grace_period=grace,
            forced_termination=forced,
        )

    def _terminate_windows(self, pid: int, grace: float) -> TerminationReport:
        """Use ``taskkill /T /F`` which walks the child tree itself."""
        taskkill_error = ""
        completed: "subprocess.CompletedProcess[str] | None" = None
        try:
            completed = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=max(5.0, grace * 2),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            taskkill_error = f"{type(exc).__name__}: {exc}"

        # Always make sure the root is gone even if taskkill was unavailable.
        try:
            self._proc.kill()  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001 - already dead is fine
            pass

        try:
            self._proc.wait(timeout=grace)  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001
            pass

        if completed is not None and completed.returncode == 0:
            return TerminationReport(
                pid=pid,
                method="taskkill_tree",
                terminated=(pid,),
                # taskkill /T walks the child tree, but we did not enumerate it
                # ourselves, so descendant_count stays 0 and this stays False
                # rather than claiming knowledge we do not have.
                tree_enumerated=False,
                grace_period=grace,
                # taskkill /F is a forced termination by definition.
                forced_termination=True,
            )

        return TerminationReport(
            pid=pid,
            method="root_kill",
            terminated=(pid,),
            failed=(),
            tree_enumerated=False,
            grace_period=grace,
            forced_termination=True,
            error=taskkill_error,
        )

    def __repr__(self) -> str:
        state = "not-started" if self._proc is None else (
            "running" if self.alive else f"exited({self.returncode})"
        )
        return f"<LocalProcess pid={self.pid} {state} argv={self._argv!r}>"
