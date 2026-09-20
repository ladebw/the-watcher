"""The Watcher — runtime observation, PoE recording and emergency control.

Design rules that are not negotiable:

* **Deterministic decisions.** Policy is evaluated by pure functions in
  :mod:`the_watcher.watcher.policy`. No model, no network, no agent input.
* **Tripwires outrank policy.** Touching a canary ends the session.
* **Deny by default once compromised.** A quarantined session that attempts a
  second blocked action is killed. A killed session can never be re-allowed.
* **Everything is recorded.** Every decision, denial, quarantine, tripwire
  activation and kill becomes part of the hash-chained trace.

In V1 the Watcher runs in the same process as the code it observes, which is
convenient for development but *not* a containment boundary. The interfaces
are shaped so the Watcher can move out-of-process later (see the README): the
watched agent only ever calls :meth:`PoEWatcher.evaluate` and
:meth:`PoEWatcher.observe`, and never owns policy, tripwires, the kill switch
or the trace.
"""

from __future__ import annotations

import enum
import subprocess
import time
from typing import Any, Callable, Mapping, Sequence

from ..exceptions import SessionError
from ..poe import (
    EventType,
    ExecutionTrace,
    PoEEvent,
    Recorder,
    VerificationResult,
    coerce_event_type,
)
from ..runtime import LocalProcess, TerminationReport
from .decision import Decision, Evaluation, Risk
from .kill_switch import KillRecord, KillSwitch
from .policy import Policy
from .signals import HostSignal, response_for
from .tripwire import TripwireRegistry

__all__ = ["PoEWatcher", "Session", "SessionStatus"]


class SessionStatus(str, enum.Enum):
    """Lifecycle of a protected session."""

    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TERMINATED = "TERMINATED"
    TIMEOUT = "TIMEOUT"
    KILLED = "KILLED"


class Session:
    """A single protected process plus the trace of its session.

    Created by :meth:`PoEWatcher.protect`; never instantiate directly.
    """

    def __init__(
        self,
        watcher: "PoEWatcher",
        command: "Sequence[str] | str",
        cwd: "str | None" = None,
        env: "Mapping[str, str] | None" = None,
        stdout: Any = None,
        stderr: Any = None,
    ) -> None:
        self._watcher = watcher
        self._command = [command] if isinstance(command, str) else list(command)
        if not self._command:
            raise SessionError("protect() requires a command")

        self._process = LocalProcess(
            self._command, cwd=cwd, env=env, stdout=stdout, stderr=stderr
        )
        self._status = SessionStatus.CREATED
        self._started_at: "int | None" = None
        self._finished_at: "int | None" = None
        self._finalised = False

    # -- accessors -------------------------------------------------------

    @property
    def status(self) -> SessionStatus:
        return self._status

    @property
    def trace(self) -> ExecutionTrace:
        return self._watcher.trace

    @property
    def process(self) -> LocalProcess:
        return self._process

    @property
    def pid(self) -> "int | None":
        return self._process.pid

    @property
    def returncode(self) -> "int | None":
        return self._process.returncode

    @property
    def command(self) -> list[str]:
        return list(self._command)

    @property
    def duration_seconds(self) -> float:
        if self._started_at is None:
            return 0.0
        end = self._finished_at or int(time.time())
        return float(end - self._started_at)

    # -- lifecycle -------------------------------------------------------

    def start(self) -> "Session":
        """Start the protected process and open the session."""
        if self._status is not SessionStatus.CREATED:
            raise SessionError(f"session already started ({self._status.value})")

        self._watcher._assert_armed()
        self._started_at = int(time.time())
        pid = self._process.start()
        self._status = SessionStatus.RUNNING
        self._watcher._attach_process(self._process)
        self._watcher._record_session_start(self, pid)
        return self

    def wait(self, timeout: "float | None" = None) -> int:
        """Wait for the protected process, then close the session."""
        if self._status is SessionStatus.CREATED:
            raise SessionError("session has not been started")

        try:
            code = self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._status = SessionStatus.TIMEOUT
            raise

        self._finalise(exit_code=code)
        return code

    def kill(self, reason: str = "SESSION_KILLED_BY_CALLER") -> KillRecord:
        """Engage the kill switch for this session's process."""
        self._status = SessionStatus.KILLED
        return self._watcher.kill(reason=reason, process=self._process)

    def close(self, seal: bool = False) -> None:
        """Finalise the session; optionally seal the trace."""
        self._finalise(exit_code=self._process.returncode)
        if seal:
            self._watcher.seal()

    def _finalise(self, exit_code: "int | None" = None) -> None:
        if self._finalised:
            return
        self._finalised = True
        self._finished_at = int(time.time())

        terminated_by_cleanup = False
        if (
            self._process.started
            and self._process.alive
            and not self._watcher.killed
        ):
            # The caller is done with the session but the process is not:
            # terminate it so nothing is leaked beyond the protected window.
            report = self._process.terminate_tree()
            self._watcher._record_termination(
                self._process, report, reason="SESSION_CLEANUP"
            )
            exit_code = self._process.returncode
            terminated_by_cleanup = True

        if self._watcher.killed:
            self._status = SessionStatus.KILLED
        elif terminated_by_cleanup:
            self._status = SessionStatus.TERMINATED
        elif self._status is SessionStatus.TIMEOUT:
            pass
        elif exit_code == 0:
            self._status = SessionStatus.COMPLETED
        else:
            self._status = SessionStatus.FAILED

        self._watcher._record_session_end(self, exit_code=exit_code)
        self._watcher._detach_process(self._process)

    # -- reporting -------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        return {
            "command": self._command,
            "pid": self._process.pid,
            "status": self._status.value,
            "returncode": self._process.returncode,
            "duration_seconds": round(self.duration_seconds, 3),
            "events": len(self._watcher.trace),
            "killed": self._watcher.killed,
            "final_hash": self._watcher.trace.final_hash,
        }

    # -- context manager -------------------------------------------------

    def __enter__(self) -> "Session":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> bool:
        self._finalise(exit_code=self._process.returncode)
        return False

    def __repr__(self) -> str:
        return f"<Session {self._status.value} pid={self._process.pid}>"


class PoEWatcher:
    """Universal runtime observer and emergency control layer.

    Parameters
    ----------
    policy:
        Deterministic rule set. Defaults to a permissive-but-sane policy with
        the standard protected environment variables.
    tripwires:
        Canary registry. Defaults to :meth:`TripwireRegistry.default`.
    trace / recorder / session_id:
        Supply an existing trace or recorder to continue an audit record.
    clock:
        Injectable time source, used by tests for deterministic timestamps.
    """

    def __init__(
        self,
        policy: "Policy | None" = None,
        tripwires: "TripwireRegistry | None" = None,
        trace: "ExecutionTrace | None" = None,
        recorder: "Recorder | None" = None,
        session_id: "str | None" = None,
        clock: "Callable[[], float] | None" = None,
        workspace_root: "str | None" = None,
    ) -> None:
        self._clock = clock or time.time
        self._policy = policy or Policy(
            workspace_root=workspace_root or "."
        )

        if tripwires is None:
            tripwires = TripwireRegistry.default(
                workspace_root=workspace_root or self._policy.workspace_root,
                extra_env_vars=self._policy.protected_env_vars,
            )
        self._tripwires = tripwires

        if recorder is not None:
            if trace is not None or session_id is not None:
                raise SessionError(
                    "pass either recorder, or trace/session_id - not both"
                )
            self._recorder = recorder
        else:
            self._recorder = Recorder(
                session_id=session_id, trace=trace, clock=self._clock
            )

        self._kill_switch = KillSwitch(clock=self._clock)
        self._quarantined = False
        self._quarantine_reason: "str | None" = None
        self._active_process: "LocalProcess | None" = None
        self._kill_event_written = False

    # -- accessors -------------------------------------------------------

    @property
    def policy(self) -> Policy:
        """The policy in force. Read-only by design."""
        return self._policy

    @property
    def tripwires(self) -> TripwireRegistry:
        """The tripwire registry in force. Read-only by design."""
        return self._tripwires

    @property
    def trace(self) -> ExecutionTrace:
        return self._recorder.trace

    @property
    def recorder(self) -> Recorder:
        return self._recorder

    @property
    def killed(self) -> bool:
        return self._kill_switch.engaged

    @property
    def quarantined(self) -> bool:
        return self._quarantined

    @property
    def kill_record(self) -> "KillRecord | None":
        return self._kill_switch.record

    def state(self) -> dict[str, Any]:
        """Machine-readable snapshot, suitable for a control-plane API."""
        return {
            "session_id": self.trace.session_id,
            "killed": self.killed,
            "quarantined": self._quarantined,
            "quarantine_reason": self._quarantine_reason,
            "kill": self._kill_switch.describe(),
            "policy": self._policy.name,
            "tripwires": len(self._tripwires),
            "event_count": len(self.trace),
            "final_hash": self.trace.final_hash,
        }

    # -- core API --------------------------------------------------------

    def evaluate(
        self,
        event_type: "EventType | str",
        action: str,
        resource: str = "",
        metadata: "Mapping[str, Any] | None" = None,
        record: bool = True,
    ) -> Evaluation:
        """Decide whether an attempted action may proceed.

        Call this **before** the action is performed. The returned
        :class:`Evaluation` is also written to the trace when ``record`` is
        true (the default).
        """
        kind = coerce_event_type(event_type)
        meta = dict(metadata or {})

        # 1. A killed session authorises nothing, ever.
        if self.killed:
            evaluation = Evaluation(
                Decision.KILL,
                Risk.CRITICAL,
                f"session is killed ({self._kill_switch.reason}); all actions blocked",
                "session_killed",
            )
            if record:
                self._recorder.record(
                    kind,
                    action,
                    resource,
                    decision=Decision.KILL,
                    risk=Risk.CRITICAL,
                    reason=evaluation.reason,
                    metadata={**meta, "rule": evaluation.rule},
                )
            return evaluation

        # 2. Tripwires outrank policy.
        tripwire = self._tripwires.check(kind, action, resource, meta)
        if tripwire is not None:
            reason = (
                f"tripwire touched: {tripwire.id} ({tripwire.description})"
            )
            activation = self._recorder.record(
                EventType.TRIPWIRE_ACTIVATION,
                action=f"tripwire:{tripwire.id}",
                resource=resource,
                decision=tripwire.decision,
                risk=tripwire.risk,
                reason=reason,
                metadata={
                    **meta,
                    "tripwire_id": tripwire.id,
                    "attempted_event_type": kind,
                    "attempted_action": action,
                },
            )
            evaluation = Evaluation(
                tripwire.decision,
                tripwire.risk,
                reason,
                f"tripwire:{tripwire.id}",
                tripwire.id,
            )
            self._apply(evaluation, kind, action, resource, meta, activation)
            return evaluation

        # 3. Deterministic policy.
        evaluation = self._policy.evaluate(kind, action, resource, meta)

        # 4. A quarantined session gets exactly one more chance - to comply.
        if self._quarantined and evaluation.blocked:
            evaluation = Evaluation(
                Decision.KILL,
                Risk.CRITICAL,
                "quarantined session attempted another blocked action: "
                + evaluation.reason,
                "quarantine_escalation",
            )

        decision_event: "PoEEvent | None" = None
        if record:
            decision_event = self._record_decision(
                kind, action, resource, meta, evaluation
            )

        self._apply(evaluation, kind, action, resource, meta, decision_event)
        return evaluation

    def observe(
        self,
        event_type: "EventType | str",
        action: str,
        resource: str = "",
        decision: "Decision | str" = Decision.ALLOW,
        risk: "Risk | str" = Risk.NORMAL,
        reason: str = "",
        metadata: "Mapping[str, Any] | None" = None,
    ) -> PoEEvent:
        """Record an event that already happened (post-hoc telemetry)."""
        return self._recorder.record(
            event_type,
            action,
            resource,
            decision=decision,
            risk=risk,
            reason=reason,
            metadata=metadata,
        )

    def report_signal(
        self,
        signal: "HostSignal | str",
        detail: str = "",
        resource: str = "",
        metadata: "Mapping[str, Any] | None" = None,
    ) -> Evaluation:
        """Ingest a sandbox-escape signal from an external monitor.

        This is the single stable entry point for container runtimes, seccomp,
        eBPF, host process monitors, VM supervisors and cloud runtimes.
        """
        decision, risk = response_for(signal)
        name = signal.value if isinstance(signal, HostSignal) else str(signal)
        if self.killed:
            decision, risk = Decision.KILL, Risk.CRITICAL

        reason = f"host signal {name}" + (f": {detail}" if detail else "")
        evaluation = Evaluation(decision, risk, reason, f"host_signal:{name}")
        event = self._recorder.record(
            EventType.HOST_SIGNAL,
            action=name,
            resource=resource,
            decision=decision,
            risk=risk,
            reason=reason,
            metadata={**(dict(metadata or {})), "signal": name, "detail": detail},
        )
        if decision is Decision.KILL:
            self.kill(reason=f"HOST_SIGNAL:{name}", triggering_event=event)
        elif decision is Decision.QUARANTINE:
            self._quarantine(reason=f"HOST_SIGNAL:{name}", triggering_event=event)
        return evaluation

    def report_process(
        self,
        pid: "int | None" = None,
        ppid: "int | None" = None,
        process_count: "int | None" = None,
        metadata: "Mapping[str, Any] | None" = None,
    ) -> Evaluation:
        """Report a newly observed child process and enforce the process limit."""
        if process_count is None:
            if self._active_process is not None and self._active_process.started:
                process_count = self._active_process.process_count()
            else:
                process_count = 0

        payload = {
            **(dict(metadata or {})),
            "pid": pid,
            "ppid": ppid,
            "process_count": process_count,
        }
        resource = str(pid) if pid is not None else ""

        # Record the observation (evidence) before judging it.
        self._recorder.record(
            EventType.PROCESS_CREATION,
            action="spawn",
            resource=resource,
            decision=Decision.ALLOW,
            risk=Risk.NORMAL,
            reason="child process observed",
            metadata=payload,
        )
        return self.evaluate(
            EventType.PROCESS_CREATION,
            action="spawn",
            resource=resource,
            metadata=payload,
        )

    def kill(
        self,
        reason: str,
        triggering_event: "PoEEvent | None" = None,
        process: "LocalProcess | None" = None,
    ) -> KillRecord:
        """Engage the kill switch and record it in the trace.

        Terminates the protected process and its known descendants, blocks
        every future action and appends the kill event to the hash chain.
        """
        target = process or self._active_process
        record = self._kill_switch.engage(
            reason=reason, target=target, triggering_event=triggering_event
        )

        if not self._kill_event_written:
            self._kill_event_written = True
            self._active_process = None
            resource = ""
            if target is not None and getattr(target, "argv", None):
                resource = " ".join(str(part) for part in target.argv)
            self._recorder.record(
                EventType.KILL_SWITCH,
                action="engage",
                resource=resource,
                decision=Decision.KILL,
                risk=Risk.CRITICAL,
                reason=reason,
                metadata={
                    "triggering_event_hash": record.triggering_event_hash,
                    "triggering_event": record.triggering_event_summary,
                    "termination": dict(record.termination),
                },
            )
        return record

    def quarantine(self, reason: str = "OPERATOR_QUARANTINE") -> None:
        """Manually quarantine the session without terminating it."""
        self._quarantine(reason=reason)

    # -- sessions --------------------------------------------------------

    def protect(
        self,
        command: "Sequence[str] | str",
        cwd: "str | None" = None,
        env: "Mapping[str, str] | None" = None,
        stdout: Any = None,
        stderr: Any = None,
    ) -> Session:
        """Return a :class:`Session` protecting ``command``.

        Usable as a context manager::

            with watcher.protect("python agent.py") as session:
                session.wait()
        """
        return Session(
            self, command, cwd=cwd, env=env, stdout=stdout, stderr=stderr
        )

    # -- trace utilities -------------------------------------------------

    def seal(self) -> str:
        """Seal the trace so later truncation is detectable."""
        return self._recorder.seal()

    def verify(self) -> VerificationResult:
        """Verify the hash chain of this session's trace."""
        return self.trace.verify()

    def export_trace(self, path: "str | None" = None) -> "dict[str, Any] | str":
        """Export the trace. Seals it first so truncation is detectable."""
        self.seal()
        if path:
            return self.trace.export(path)
        return self.trace.to_dict()

    # -- internals -------------------------------------------------------

    def _record_decision(
        self,
        kind: str,
        action: str,
        resource: str,
        meta: Mapping[str, Any],
        evaluation: Evaluation,
    ) -> PoEEvent:
        # Policy evidence is assembled from two things the supervisor owns: the
        # policy in force, and the verdict it has just produced. Nothing here is
        # taken from ``meta``, which is the workload's account of itself. The
        # merge happens last so a client-supplied key of the same name cannot
        # displace it.
        policy_evidence = {**self._policy.evidence(), **dict(evaluation.evidence)}
        metadata = {
            **meta,
            "rule": evaluation.rule,
            "attempted_event_type": kind,
            "attempted_action": action,
            # Which facts the verdict rested on, and how much each was
            # worth. Recorded so a reader can tell a decision built on host
            # observation from one built on the workload's own account of
            # itself.
            "fact_authority": dict(evaluation.facts),
        }
        if policy_evidence:
            metadata["policy_evidence"] = policy_evidence

        decision_event = self._recorder.record(
            EventType.POLICY_DECISION,
            action=action,
            resource=resource,
            decision=evaluation.decision,
            risk=evaluation.risk,
            reason=evaluation.reason,
            metadata=metadata,
        )

        if evaluation.decision is Decision.DENY:
            denied_metadata: dict[str, Any] = {**meta, "rule": evaluation.rule}
            if policy_evidence:
                denied_metadata["policy_evidence"] = policy_evidence
            self._recorder.record(
                EventType.DENIED_ACTION,
                action=action,
                resource=resource,
                decision=Decision.DENY,
                risk=evaluation.risk,
                reason=evaluation.reason,
                metadata=denied_metadata,
            )
        return decision_event

    def _apply(
        self,
        evaluation: Evaluation,
        kind: str,
        action: str,
        resource: str,
        meta: Mapping[str, Any],
        triggering_event: "PoEEvent | None",
    ) -> None:
        source = (
            f"TRIPWIRE:{evaluation.tripwire_id}"
            if evaluation.tripwire_id
            else f"POLICY:{evaluation.rule}"
        )
        if evaluation.decision is Decision.KILL:
            self.kill(reason=source, triggering_event=triggering_event)
        elif evaluation.decision is Decision.QUARANTINE:
            self._quarantine(reason=source, triggering_event=triggering_event)

    def _quarantine(
        self, reason: str, triggering_event: "PoEEvent | None" = None
    ) -> None:
        if self._quarantined:
            return
        self._quarantined = True
        self._quarantine_reason = reason
        self._recorder.record(
            EventType.QUARANTINE,
            action="quarantine",
            decision=Decision.QUARANTINE,
            risk=Risk.HIGH,
            reason=reason,
            metadata={
                "triggering_event_hash": getattr(triggering_event, "event_hash", None)
            },
        )

    def _record_session_start(self, session: Session, pid: int) -> PoEEvent:
        return self._recorder.record(
            EventType.SESSION_START,
            action="start",
            resource=" ".join(session.command),
            decision=Decision.ALLOW,
            risk=Risk.NORMAL,
            reason="protected session started",
            metadata={
                "pid": pid,
                "policy": self._policy.name,
                "tripwires": len(self._tripwires),
            },
        )

    def _record_session_end(
        self, session: Session, exit_code: "int | None" = None
    ) -> PoEEvent:
        return self._recorder.record(
            EventType.SESSION_END,
            action="end",
            resource=" ".join(session.command),
            decision=Decision.KILL if self.killed else Decision.ALLOW,
            risk=Risk.CRITICAL if self.killed else Risk.NORMAL,
            reason=(
                f"session killed: {self._kill_switch.reason}"
                if self.killed
                else "session finished"
            ),
            metadata={
                "status": session.status.value,
                "exit_code": exit_code,
                "duration_seconds": round(session.duration_seconds, 3),
            },
        )

    def _record_termination(
        self,
        process: LocalProcess,
        report: TerminationReport,
        reason: str,
    ) -> PoEEvent:
        return self._recorder.record(
            EventType.PROCESS_TERMINATION,
            action="terminate_tree",
            resource=str(process.pid),
            decision=Decision.ALLOW,
            risk=Risk.NORMAL,
            reason=reason,
            metadata=report.to_dict(),
        )

    def _attach_process(self, process: LocalProcess) -> None:
        self._active_process = process

    def _detach_process(self, process: LocalProcess) -> None:
        if self._active_process is process:
            self._active_process = None

    def _assert_armed(self) -> None:
        self._kill_switch.assert_armed()

    def __repr__(self) -> str:
        return (
            f"<PoEWatcher session={self.trace.session_id[:8]} "
            f"events={len(self.trace)} killed={self.killed}>"
        )
