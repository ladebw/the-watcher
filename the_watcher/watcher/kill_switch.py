"""The kill switch.

Engaging the kill switch is irreversible for the lifetime of a session. It:

1. flips the session to a terminal KILLED state *first*, so no further action
   can be authorised while termination is in flight;
2. terminates the protected process and its known descendants;
3. returns a :class:`KillRecord` describing what happened.

Recording the kill event in the Proof of Execution trace is the Watcher's job,
not the kill switch's — that keeps the switch usable (and testable) on its own
while guaranteeing the record exists.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ..exceptions import KillSwitchError

__all__ = ["KillState", "KillRecord", "KillSwitch"]


class KillState(str, enum.Enum):
    """Lifecycle of a kill switch."""

    ARMED = "ARMED"
    ENGAGED = "ENGAGED"


@dataclass(frozen=True)
class KillRecord:
    """What happened when the kill switch was engaged."""

    reason: str
    triggered_at: int
    triggering_event_hash: "str | None" = None
    triggering_event_summary: "str | None" = None
    termination: Mapping[str, Any] = field(default_factory=dict)

    @property
    def state(self) -> KillState:
        return KillState.ENGAGED

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "reason": self.reason,
            "triggered_at": self.triggered_at,
            "triggering_event_hash": self.triggering_event_hash,
            "triggering_event_summary": self.triggering_event_summary,
            "termination": dict(self.termination),
        }

    def summary(self) -> str:
        suffix = ""
        if self.termination:
            terminated = self.termination.get("terminated") or []
            failed = self.termination.get("failed") or []
            suffix = f" terminated={len(terminated)} failed={len(failed)}"
        return f"KILL ({self.reason}){suffix}"


class KillSwitch:
    """Irreversible, idempotent session terminator."""

    def __init__(self, clock: "Callable[[], float] | None" = None) -> None:
        self._clock = clock or time.time
        self._state = KillState.ARMED
        self._record: "KillRecord | None" = None

    # -- state -----------------------------------------------------------

    @property
    def state(self) -> KillState:
        return self._state

    @property
    def engaged(self) -> bool:
        return self._state is KillState.ENGAGED

    @property
    def armed(self) -> bool:
        return self._state is KillState.ARMED

    @property
    def record(self) -> "KillRecord | None":
        return self._record

    @property
    def reason(self) -> "str | None":
        return self._record.reason if self._record else None

    def describe(self) -> dict[str, Any]:
        """Machine-readable current state, e.g. for a control-plane API."""
        if self._record is None:
            return {"state": self._state.value, "reason": None, "triggered_at": None}
        return self._record.to_dict()

    # -- engagement ------------------------------------------------------

    def engage(
        self,
        reason: str,
        target: "Any | None" = None,
        triggering_event: "Any | None" = None,
    ) -> KillRecord:
        """Engage the switch. Idempotent: the first reason wins."""
        if self._record is not None:
            return self._record

        if not reason or not str(reason).strip():
            raise KillSwitchError("kill switch requires a non-empty reason")

        # Flip state before touching the process so any concurrent evaluate()
        # call already sees a killed session.
        self._state = KillState.ENGAGED

        termination: Mapping[str, Any] = {}
        if target is not None:
            termination = self._terminate(target)

        self._record = KillRecord(
            reason=str(reason),
            triggered_at=int(self._clock()),
            triggering_event_hash=getattr(triggering_event, "event_hash", None),
            triggering_event_summary=(
                triggering_event.summary() if hasattr(triggering_event, "summary") else None
            ),
            termination=termination,
        )
        return self._record

    def _terminate(self, target: Any) -> Mapping[str, Any]:
        terminator = getattr(target, "terminate_tree", None)
        if callable(terminator):
            try:
                report = terminator()
            except Exception as exc:  # noqa: BLE001 - surfaced in the record
                return {
                    "error": f"{type(exc).__name__}: {exc}",
                    "terminated": [],
                    "failed": [],
                }
            if hasattr(report, "to_dict"):
                return dict(report.to_dict())
            if isinstance(report, Mapping):
                return dict(report)
            return {"result": str(report)}

        pid = getattr(target, "pid", None)
        if pid is not None:
            return {
                "error": "target does not expose terminate_tree; only recorded pid",
                "pid": pid,
                "terminated": [],
                "failed": [],
            }

        return {
            "error": f"target {type(target).__name__} is not terminable",
            "terminated": [],
            "failed": [],
        }

    def assert_armed(self) -> None:
        """Raise when the switch has already been engaged."""
        if self.engaged:
            raise KillSwitchError(
                f"session already killed: {self.reason}"
            )

    def __repr__(self) -> str:
        return f"<KillSwitch {self._state.value} reason={self.reason!r}>"
