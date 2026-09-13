"""Supervisor-owned process control.

The protected process is a **child of the supervisor**, so the supervisor
always holds the authoritative handle, the pid and the exit status. Nothing in
the protected process can change that relationship.

Termination keeps the V1 policy and adds the accounting V2 must record:
graceful first, escalate if refused, and report what actually happened.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Mapping, Sequence

from ..exceptions import SessionError
from ..runtime import LocalProcess, TerminationReport

__all__ = ["ProcessSupervisor"]


class ProcessSupervisor:
    """Owns the protected process for the lifetime of a session."""

    def __init__(
        self,
        command: "Sequence[str] | str",
        cwd: "str | None" = None,
        env: "Mapping[str, str] | None" = None,
        stdout: Any = None,
        stderr: Any = None,
        clock: "Callable[[], float] | None" = None,
    ) -> None:
        self._clock = clock or time.time
        self._process = LocalProcess(
            command, cwd=cwd, env=env, stdout=stdout, stderr=stderr
        )
        self._started_at: "int | None" = None
        self._terminated_at: "int | None" = None
        self._termination: "dict[str, Any] | None" = None

    # -- lifecycle -------------------------------------------------------

    @classmethod
    def adopt(
        cls,
        process: LocalProcess,
        clock: "Callable[[], float] | None" = None,
    ) -> "ProcessSupervisor":
        """Wrap a process that was started elsewhere.

        Used by V3 enforced mode: the containment backend owns the launch
        (it has to, in order to build the namespaces), but the daemon must
        still hold the authoritative handle, pid and exit status. Adopting
        keeps every later supervision and kill path identical to V2.
        """
        instance = cls.__new__(cls)
        instance._clock = clock or time.time
        instance._process = process
        instance._started_at = int(instance._clock())
        instance._terminated_at = None
        instance._termination = None
        return instance

    def start(self) -> int:
        pid = self._process.start()
        self._started_at = int(self._clock())
        return pid

    def wait(self, timeout: "float | None" = None) -> int:
        return self._process.wait(timeout=timeout)

    def poll(self) -> "int | None":
        return self._process.poll()

    # -- state -----------------------------------------------------------

    @property
    def pid(self) -> "int | None":
        return self._process.pid

    @property
    def alive(self) -> bool:
        return self._process.alive

    @property
    def started(self) -> bool:
        return self._process.started

    @property
    def returncode(self) -> "int | None":
        return self._process.returncode

    @property
    def command(self) -> list[str]:
        return self._process.argv

    @property
    def local_process(self) -> LocalProcess:
        """The underlying V1 process object (used as the kill-switch target)."""
        return self._process

    @property
    def started_at(self) -> "int | None":
        return self._started_at

    @property
    def duration_seconds(self) -> float:
        if self._started_at is None:
            return 0.0
        end = self._terminated_at or int(self._clock())
        return float(end - self._started_at)

    def children(self) -> list[int]:
        return self._process.children()

    def process_count(self) -> int:
        return self._process.process_count()

    def safe_state(self) -> dict[str, Any]:
        """A description that deliberately contains no environment."""
        return {
            "pid": self.pid,
            "command": self.command,
            "started": self.started,
            "alive": self.alive,
            "returncode": self.returncode,
            "started_at": self._started_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "child_count": len(self.children()) if self.started else 0,
            "termination": dict(self._termination) if self._termination else None,
        }

    # -- termination -----------------------------------------------------

    def terminate(
        self, grace: float = 2.0, reason: str = ""
    ) -> TerminationReport:
        """Terminate the process tree, recording the report for later use.

        ``reason`` is accepted for symmetry with the audit trail; the caller
        (the daemon) is responsible for recording it in the trace.
        """
        if not self._process.started:
            raise SessionError("cannot terminate a process that never started")

        report = self._process.terminate_tree(grace=grace)
        self._terminated_at = int(self._clock())
        self._termination = report.to_dict()
        return report

    def note_external_termination(self, report: Mapping[str, Any]) -> None:
        """Record a termination carried out elsewhere.

        The kill-switch path terminates the process through the V1
        ``LocalProcess`` handle rather than through this class, so the report
        is handed back here to keep the supervisor's own summary accurate.
        """
        self._terminated_at = int(self._clock())
        self._termination = dict(report)

    @property
    def termination(self) -> "dict[str, Any] | None":
        return self._termination

    def __repr__(self) -> str:
        state = "not-started" if not self.started else (
            "running" if self.alive else f"exited({self.returncode})"
        )
        return f"<ProcessSupervisor pid={self.pid} {state}>"
