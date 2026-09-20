"""Exception hierarchy for The Watcher.

All public errors derive from :class:`WatcherError` so that embedders can
catch a single base class without depending on internals.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

__all__ = [
    "WatcherError",
    "CanonicalizationError",
    "TraceError",
    "TraceVerificationError",
    "TraceSealedError",
    "PolicyError",
    "PolicyIssue",
    "PolicyParseError",
    "PolicyValidationError",
    "TripwireViolation",
    "SessionError",
    "SessionKilledError",
    "KillSwitchError",
    "SupervisorError",
    "SessionStateError",
    "StorageError",
    "IpcError",
    "IpcTransportError",
    "IpcDrainTimeout",
    "AuthenticationError",
    "ProtocolError",
    "EnforcementError",
    "EnforcementUnavailable",
    "ContainmentRefused",
    "ContainmentStartError",
    "ContainmentVerifyError",
    "KillFailed",
]


class WatcherError(Exception):
    """Base class for every error raised by The Watcher."""


class CanonicalizationError(WatcherError):
    """A value could not be serialised deterministically."""


class TraceError(WatcherError):
    """A Proof of Execution trace is malformed or cannot be constructed."""


class TraceVerificationError(TraceError):
    """A trace failed verification and the caller asked for an exception."""

    def __init__(self, message: str, signals: "list[str] | None" = None) -> None:
        super().__init__(message)
        self.signals = list(signals or [])


class TraceSealedError(TraceError):
    """An event was appended to a trace that has already been sealed.

    Sealing fixes the declared final hash, which is what makes later
    truncation detectable. Letting an append through after that point would
    silently change the event count and head hash, so verification would
    report ``INVALID_FINAL_TRACE_HASH`` on a trace nobody tampered with. The
    append is therefore refused outright rather than recorded and regretted.
    """


class PolicyError(WatcherError):
    """A policy is invalid or cannot be applied."""


@dataclass(frozen=True)
class PolicyIssue:
    """One reason a policy document was rejected.

    ``path`` locates the problem inside the document in the same dotted form a
    reader sees in the JSON - ``filesystem.alow``, ``on_violation.tripwire``,
    ``resources.pids`` - so an error message points at the exact line a person
    has to edit rather than at the document as a whole.

    ``code`` is a stable machine-readable identifier so tooling can branch on
    the *kind* of problem without matching on prose.
    """

    path: str
    message: str
    code: str = "invalid"

    def __str__(self) -> str:
        return f"{self.path}: {self.message}" if self.path else self.message


class PolicyParseError(PolicyError):
    """A policy document could not be read as JSON at all.

    Separated from :class:`PolicyValidationError` because the two need different
    responses: a parse failure means "this is not a JSON document" (or not the
    encoding and size limits the loader accepts), while a validation failure
    means "this is JSON, and here are the exact fields that are wrong".
    """


class PolicyValidationError(PolicyError):
    """A policy document parsed but is not a valid document.

    Carries every issue found rather than only the first, so one review pass
    surfaces the whole list instead of a fix-and-retry loop.
    """

    def __init__(
        self, summary: str = "policy document is not valid", issues: "Sequence[PolicyIssue] | None" = None
    ) -> None:
        self.summary = summary
        self.issues: tuple[PolicyIssue, ...] = tuple(issues or ())
        detail = "; ".join(str(issue) for issue in self.issues)
        super().__init__(f"{summary}: {detail}" if detail else summary)


class TripwireViolation(WatcherError):
    """A tripwire was touched. Carries the identifier of the tripwire."""

    def __init__(self, message: str, tripwire_id: str = "") -> None:
        super().__init__(message)
        self.tripwire_id = tripwire_id


class SessionError(WatcherError):
    """A protected session could not be created or driven."""


class SessionKilledError(SessionError):
    """The kill switch was engaged; the session refuses to continue."""


class KillSwitchError(WatcherError):
    """The kill switch could not reach or terminate its target."""


# ---------------------------------------------------------------------------
# V2 - external supervisor, IPC and storage
# ---------------------------------------------------------------------------


class SupervisorError(WatcherError):
    """Base class for external-supervisor failures."""


class SessionStateError(SupervisorError):
    """An illegal session state transition was attempted."""


class StorageError(SupervisorError):
    """Authoritative trace storage could not be created or written."""


class IpcError(WatcherError):
    """Base class for IPC failures."""


class IpcTransportError(IpcError):
    """The local IPC transport failed, closed or timed out."""


class IpcDrainTimeout(IpcError):
    """IPC workers did not stop within the shutdown deadline.

    Raised instead of returning quietly, because the supervisor must not seal
    the trace while an authoritative writer could still append to it. A caller
    that sees this must treat the session as having failed to shut down
    cleanly, not as having stopped normally.
    """

    def __init__(
        self, message: str, remaining: "list[str] | None" = None
    ) -> None:
        super().__init__(message)
        self.remaining = list(remaining or [])


class AuthenticationError(IpcError):
    """A client failed to authenticate against the Watcher daemon."""


class ProtocolError(IpcError):
    """A message violated the IPC protocol.

    ``code`` is one of :class:`the_watcher.ipc.protocol.ErrorCode`; it is safe
    to return to the client (it never contains internal detail).

    ``fatal`` marks a violation that left the byte stream out of sync — an
    oversized frame is rejected *before* being drained, so the remaining bytes
    of that frame would otherwise be reinterpreted as the next message. A
    fatal violation must close the connection rather than attempt recovery.
    """

    def __init__(self, code: "object", message: str = "", fatal: bool = False) -> None:
        self.code = getattr(code, "value", str(code))
        self.fatal = bool(fatal)
        super().__init__(f"{self.code}: {message}" if message else str(self.code))


# ---------------------------------------------------------------------------
# V3 - OS-enforced containment
# ---------------------------------------------------------------------------


class EnforcementError(WatcherError):
    """Base class for containment failures."""


class EnforcementUnavailable(EnforcementError):
    """The host cannot provide the requested enforcement.

    Raised before anything is launched. In enforced mode this is fatal: the
    Watcher must never quietly run the workload with less protection.
    """


class ContainmentRefused(EnforcementError):
    """A dangerous or incoherent containment configuration was requested."""


class ContainmentStartError(EnforcementError):
    """The containment unit could not be started."""


class ContainmentVerifyError(EnforcementError):
    """The running containment unit did not match the profile it claimed."""


class KillFailed(EnforcementError):
    """Protected processes survived termination. Always critical."""
