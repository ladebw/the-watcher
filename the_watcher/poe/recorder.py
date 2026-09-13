"""Trace recorder.

The single write path into a trace. Borrowing AAIP's ``ProofOfExecution``
context-manager and ``track_tool`` decorator ergonomics, the recorder is the
component that:

* stamps each event with a monotonic sequence and a timestamp,
* redacts secrets *before* they can reach the trace,
* serialises writes behind a lock so concurrent threads cannot interleave the
  hash chain.
"""

from __future__ import annotations

import functools
import inspect
import threading
import time
import uuid
from typing import Any, Callable, Mapping, TypeVar

from ..exceptions import TraceError
from .event import EventType, PoEEvent, as_text, coerce_event_type
from .redact import DEFAULT_REDACTOR, Redactor
from .trace import ExecutionTrace

__all__ = ["Recorder"]

F = TypeVar("F", bound=Callable[..., Any])


class Recorder:
    """Append-only writer that owns (or is attached to) an execution trace."""

    def __init__(
        self,
        session_id: "str | None" = None,
        trace: "ExecutionTrace | None" = None,
        redactor: "Redactor | None" = None,
        clock: "Callable[[], float] | None" = None,
    ) -> None:
        self._clock = clock or time.time
        self._redactor = redactor or DEFAULT_REDACTOR
        self._lock = threading.RLock()

        if trace is not None and session_id and trace.session_id != session_id:
            raise TraceError(
                "session_id does not match the supplied trace "
                f"({session_id!r} != {trace.session_id!r})"
            )

        if trace is not None:
            self._trace = trace
        else:
            self._trace = ExecutionTrace(
                session_id=session_id or uuid.uuid4().hex,
                created_at=int(self._clock()),
            )

    # -- accessors -------------------------------------------------------

    @property
    def trace(self) -> ExecutionTrace:
        return self._trace

    @property
    def session_id(self) -> str:
        return self._trace.session_id

    @property
    def redactor(self) -> Redactor:
        return self._redactor

    # -- writing ---------------------------------------------------------

    def record(
        self,
        event_type: "EventType | str",
        action: str,
        resource: str = "",
        decision: Any = "ALLOW",
        risk: Any = "NORMAL",
        reason: str = "",
        metadata: "Mapping[str, Any] | None" = None,
    ) -> PoEEvent:
        """Redact, stamp and append one event. Returns the stored event."""
        event = PoEEvent(
            sequence=0,  # assigned by ExecutionTrace.append
            timestamp=int(self._clock()),
            event_type=coerce_event_type(event_type),
            action=as_text(action),
            resource=self._redactor.redact_text(as_text(resource)),
            decision=as_text(decision).upper(),
            risk=as_text(risk).upper(),
            reason=as_text(reason),
            metadata=self._redactor.redact(dict(metadata or {})),
        )
        with self._lock:
            return self._trace.append(event)

    def record_tool(
        self,
        tool_name: str,
        decision: Any = "ALLOW",
        risk: Any = "NORMAL",
        reason: str = "",
    ) -> PoEEvent:
        """Record a tool invocation without wrapping a callable."""
        return self.record(
            EventType.TOOL_REQUEST,
            action=f"invoke:{tool_name}",
            resource=tool_name,
            decision=decision,
            risk=risk,
            reason=reason,
        )

    def track_tool(
        self,
        tool_name: "str | None" = None,
        decision: Any = "ALLOW",
        risk: Any = "NORMAL",
    ) -> Callable[[F], F]:
        """Decorator that records a ``tool_request`` event per invocation.

        Supports both sync and async callables::

            @recorder.track_tool("web_search")
            def web_search(query): ...
        """

        def decorator(func: F) -> F:
            name = tool_name or func.__name__

            if inspect.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    self.record_tool(name, decision=decision, risk=risk)
                    try:
                        return await func(*args, **kwargs)
                    except Exception as exc:  # noqa: BLE001 - recorded then re-raised
                        self.record(
                            EventType.TOOL_REQUEST,
                            action=f"error:{name}",
                            resource=name,
                            decision="ALLOW",
                            risk="ELEVATED",
                            reason=f"{type(exc).__name__}: {exc}",
                        )
                        raise

                return async_wrapper  # type: ignore[return-value]

            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                self.record_tool(name, decision=decision, risk=risk)
                try:
                    return func(*args, **kwargs)
                except Exception as exc:  # noqa: BLE001 - recorded then re-raised
                    self.record(
                        EventType.TOOL_REQUEST,
                        action=f"error:{name}",
                        resource=name,
                        decision="ALLOW",
                        risk="ELEVATED",
                        reason=f"{type(exc).__name__}: {exc}",
                    )
                    raise

            return wrapper  # type: ignore[return-value]

        return decorator

    # -- sealing ---------------------------------------------------------

    def seal(self) -> str:
        """Seal the trace, fixing its final hash."""
        with self._lock:
            return self._trace.seal()

    def __repr__(self) -> str:
        return (
            f"<Recorder session={self.session_id[:8]} events={len(self._trace)}>"
        )
