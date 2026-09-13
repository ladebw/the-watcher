"""Explicit session state machine.

Modelling the session lifecycle as a state machine (rather than a handful of
booleans) is what makes the "terminal state is terminal" guarantee testable.

::

    CREATED ──▶ STARTING ──▶ RUNNING ──┬──▶ COMPLETED   (terminal)
                                       ├──▶ FAILED      (terminal)
                                       └──▶ KILLED      (terminal)
                              │
                              └──▶ QUARANTINED ──┬──▶ COMPLETED
                                                 ├──▶ FAILED
                                                 └──▶ KILLED

A terminal session can never return to ``RUNNING``, and ``KILLED`` is
irreversible: no IPC message, however formed, can move a session out of it.
"""

from __future__ import annotations

import enum
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ..exceptions import SessionStateError

__all__ = [
    "SessionState",
    "TERMINAL_STATES",
    "ALLOWED_TRANSITIONS",
    "SessionStateMachine",
]


class SessionState(str, enum.Enum):
    """Lifecycle states of a protected session."""

    CREATED = "CREATED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    QUARANTINED = "QUARANTINED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    KILLED = "KILLED"


#: States from which no further transition is possible.
TERMINAL_STATES: frozenset[SessionState] = frozenset(
    {SessionState.COMPLETED, SessionState.FAILED, SessionState.KILLED}
)

#: Every legal transition. Anything not listed here raises.
ALLOWED_TRANSITIONS: dict[SessionState, frozenset[SessionState]] = {
    SessionState.CREATED: frozenset({SessionState.STARTING, SessionState.FAILED}),
    SessionState.STARTING: frozenset(
        {SessionState.RUNNING, SessionState.FAILED, SessionState.KILLED}
    ),
    SessionState.RUNNING: frozenset(
        {
            SessionState.QUARANTINED,
            SessionState.COMPLETED,
            SessionState.FAILED,
            SessionState.KILLED,
        }
    ),
    # Quarantine is recoverable in principle: a quarantined session may still
    # finish normally, or be killed. It may not silently return to RUNNING.
    SessionState.QUARANTINED: frozenset(
        {SessionState.COMPLETED, SessionState.FAILED, SessionState.KILLED}
    ),
    SessionState.COMPLETED: frozenset(),
    SessionState.FAILED: frozenset(),
    SessionState.KILLED: frozenset(),
}


@dataclass(frozen=True)
class StateTransition:
    """One recorded transition."""

    state: SessionState
    at: int
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state.value, "at": self.at, "reason": self.reason}


@dataclass
class SessionStateMachine:
    """Thread-safe state machine with an audit trail."""

    clock: Callable[[], float] = field(default=time.time)
    _state: SessionState = field(default=SessionState.CREATED, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)
    _history: list[StateTransition] = field(default_factory=list, init=False)
    _started_at: "int | None" = field(default=None, init=False)
    _ended_at: "int | None" = field(default=None, init=False)
    _quarantine_reason: "str | None" = field(default=None, init=False)

    def __post_init__(self) -> None:
        self._history.append(
            StateTransition(SessionState.CREATED, int(self.clock()), "session created")
        )

    # -- accessors -------------------------------------------------------

    @property
    def state(self) -> SessionState:
        with self._lock:
            return self._state

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def killed(self) -> bool:
        return self.state is SessionState.KILLED

    @property
    def quarantined(self) -> bool:
        return self.state is SessionState.QUARANTINED

    @property
    def quarantine_reason(self) -> "str | None":
        return self._quarantine_reason

    @property
    def started_at(self) -> "int | None":
        return self._started_at

    @property
    def ended_at(self) -> "int | None":
        return self._ended_at

    @property
    def history(self) -> list[StateTransition]:
        with self._lock:
            return list(self._history)

    # -- mutation --------------------------------------------------------

    def can_transition(self, new_state: SessionState) -> bool:
        with self._lock:
            if self._state in TERMINAL_STATES:
                return False
            if new_state is self._state:
                return True
            return new_state in ALLOWED_TRANSITIONS.get(self._state, frozenset())

    def transition(
        self, new_state: "SessionState | str", reason: str = ""
    ) -> SessionState:
        """Move to ``new_state`` or raise :class:`SessionStateError`."""
        target = (
            new_state
            if isinstance(new_state, SessionState)
            else SessionState(str(new_state).upper())
        )
        at = int(self.clock())

        with self._lock:
            current = self._state
            if current is target:
                return current

            if current in TERMINAL_STATES:
                raise SessionStateError(
                    f"session is terminal ({current.value}); cannot move to {target.value}"
                )
            if target not in ALLOWED_TRANSITIONS.get(current, frozenset()):
                raise SessionStateError(
                    f"illegal transition {current.value} -> {target.value}"
                )

            self._state = target
            self._history.append(StateTransition(target, at, reason))

            if target is SessionState.RUNNING and self._started_at is None:
                self._started_at = at
            if target is SessionState.QUARANTINED:
                self._quarantine_reason = reason or self._quarantine_reason
            if target in TERMINAL_STATES:
                self._ended_at = at

            return target

    def transition_quiet(
        self, new_state: "SessionState | str", reason: str = ""
    ) -> bool:
        """Best-effort transition used on shutdown paths. Never raises."""
        try:
            self.transition(new_state, reason)
        except (SessionStateError, ValueError):
            return False
        return True

    # -- serialisation ---------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "is_terminal": self.is_terminal,
            "quarantine_reason": self._quarantine_reason,
            "started_at": self._started_at,
            "ended_at": self._ended_at,
            "history": [entry.to_dict() for entry in self._history],
        }
