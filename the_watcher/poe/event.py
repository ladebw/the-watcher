"""Ordered Proof-of-Execution events.

An event is the atomic unit of the trace. It is immutable once created and
carries the hash of the event before it, which is what turns a list of
records into a tamper-evident chain.

This module intentionally knows nothing about policies, tripwires or the
kill switch — it is pure data plus hashing.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace
from typing import Any, Mapping

from ..exceptions import TraceError
from .canonical import GENESIS_HASH, canonical_bytes, sha256_hex

__all__ = [
    "EventType",
    "PoEEvent",
    "coerce_event_type",
    "as_text",
    "EVENT_TYPES",
]


class EventType(str, enum.Enum):
    """Runtime event categories recorded in the trace."""

    MODEL_CALL = "model_call"
    TOOL_REQUEST = "tool_request"
    SHELL_COMMAND = "shell_command"
    FILE_ACCESS = "file_access"
    FILE_MODIFICATION = "file_modification"
    PROCESS_CREATION = "process_creation"
    NETWORK_REQUEST = "network_request"
    API_REQUEST = "api_request"
    POLICY_DECISION = "policy_decision"
    DENIED_ACTION = "denied_action"
    TRIPWIRE_ACTIVATION = "tripwire_activation"
    QUARANTINE = "quarantine"
    KILL_SWITCH = "kill_switch"
    PROCESS_TERMINATION = "process_termination"
    HOST_SIGNAL = "host_signal"
    SESSION_START = "session_start"
    SESSION_END = "session_end"

    # -- V2 supervisor-side lifecycle events -----------------------------
    SESSION_CREATED = "session_created"
    IPC_READY = "ipc_ready"
    CLIENT_CONNECTED = "client_connected"
    CLIENT_AUTHENTICATED = "client_authenticated"
    CLIENT_DISCONNECTED = "client_disconnected"
    PROCESS_STARTED = "process_started"
    PROCESS_EXITED = "process_exited"
    HEARTBEAT = "heartbeat"
    HEARTBEAT_LOST = "heartbeat_lost"
    IPC_LOST = "ipc_lost"
    IPC_VIOLATION = "ipc_violation"
    #: IPC writers did not stop before the seal deadline. Recorded as a
    #: critical condition, because a writer that outlives shutdown is exactly
    #: what used to corrupt an otherwise valid trace.
    IPC_DRAIN_TIMEOUT = "ipc_drain_timeout"
    CLIENT_FIELD_REJECTED = "client_field_rejected"
    SESSION_TIMEOUT = "session_timeout"
    TRACE_SEALED = "trace_sealed"

    # -- V3 OS-enforced containment --------------------------------------
    #: Emitted only by enforcement backends, never by a client.
    CONTAINMENT_PREPARED = "containment_prepared"
    CONTAINMENT_STARTED = "containment_started"
    CONTAINMENT_VERIFIED = "containment_verified"
    CONTAINMENT_HEALTH_FAILED = "containment_health_failed"
    SECCOMP_ENABLED = "seccomp_enabled"
    LANDLOCK_ENABLED = "landlock_enabled"
    CAPABILITIES_DROPPED = "capabilities_dropped"
    NO_NEW_PRIVILEGES_ENABLED = "no_new_privileges_enabled"
    NAMESPACES_CREATED = "namespaces_created"
    NETWORK_NAMESPACE_CREATED = "network_namespace_created"
    NETWORK_POLICY_APPLIED = "network_policy_applied"
    RESOURCE_LIMIT_APPLIED = "resource_limit_applied"
    READ_ONLY_ROOT_ENFORCED = "read_only_root_enforced"

    #: The OS refused an operation. Distinct from a policy denial.
    OS_ACTION_DENIED = "os_action_denied"
    BOUNDARY_VIOLATION = "boundary_violation"

    NETWORK_ISOLATED = "network_isolated"
    CONTAINER_TERMINATION_STARTED = "container_termination_started"
    CONTAINER_TERMINATED = "container_terminated"
    CONTAINMENT_VERIFIED_EMPTY = "containment_verified_empty"
    KILL_FAILED = "kill_failed"

    # -- V4 Phase 0: truthful shutdown/termination vocabulary -------------
    #: The supervisor is stopping (or was signalled) while the workload was
    #: still running. Recorded *before* anything is terminated, so a trace
    #: always shows that the stop was requested rather than inferred.
    SHUTDOWN_REQUESTED = "shutdown_requested"
    #: Termination of a still-running workload has begun.
    TERMINATION_INITIATED = "termination_initiated"
    #: The workload was observed to be gone after termination. Only ever
    #: recorded when the supervisor actually observed the absence.
    TERMINATION_VERIFIED = "termination_verified"
    #: Termination could not be confirmed. Critical: the trace must not then
    #: assert an exit that was never observed.
    TERMINATION_UNVERIFIED = "termination_unverified"


EVENT_TYPES: tuple[str, ...] = tuple(member.value for member in EventType)


def coerce_event_type(value: "EventType | str") -> str:
    """Return the canonical string for an event type.

    Unknown strings are allowed so that custom event categories can be
    recorded, but they are normalised to lowercase snake case.
    """
    if isinstance(value, enum.Enum):
        return str(value.value)
    if not isinstance(value, str) or not value.strip():
        raise TraceError(f"invalid event_type: {value!r}")
    return value.strip().lower()


def as_text(value: Any) -> str:
    """Coerce an enum-or-string value to its plain string form.

    ``str(SomeStrEnum.MEMBER)`` yields ``"SomeStrEnum.MEMBER"``, so ``.value``
    must be used explicitly for enums.
    """
    if isinstance(value, enum.Enum):
        return str(value.value)
    return str(value)


@dataclass(frozen=True)
class PoEEvent:
    """A single immutable, hash-chained execution record.

    Attributes
    ----------
    sequence:
        Zero-based position in the trace. The trace assigns this, never the
        caller, and verification rejects gaps or duplicates.
    timestamp:
        Unix time in whole seconds at the moment the event was recorded.
    event_type:
        One of :class:`EventType` (or a custom lowercase identifier).
    action:
        The attempted or observed verb, e.g. ``"connect"`` or ``"read"``.
    resource:
        The target of the action — path, domain, tool name, model name.
    decision:
        ``ALLOW``, ``DENY``, ``QUARANTINE`` or ``KILL``.
    risk:
        ``NORMAL``, ``ELEVATED``, ``HIGH`` or ``CRITICAL``.
    reason:
        Human-readable justification for the decision.
    metadata:
        Free-form, already-redacted extra context.
    previous_hash:
        ``event_hash`` of the preceding event, or :data:`GENESIS_HASH`.
    event_hash:
        SHA-256 over this event's hashed payload (which includes
        ``previous_hash``).
    """

    sequence: int
    timestamp: int
    event_type: str
    action: str
    resource: str = ""
    decision: str = "ALLOW"
    risk: str = "NORMAL"
    reason: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)
    previous_hash: str = GENESIS_HASH
    event_hash: str = ""

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise TraceError(f"event sequence must be >= 0, got {self.sequence}")
        if not isinstance(self.timestamp, int):
            raise TraceError("event timestamp must be an int (unix seconds)")

    # -- hashing ---------------------------------------------------------

    def hashed_payload(self) -> dict[str, Any]:
        """Return exactly the data that feeds the event hash.

        ``event_hash`` is excluded (an event cannot hash itself) while
        ``previous_hash`` is included, which is what chains the events.
        """
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "action": self.action,
            "resource": self.resource,
            "decision": self.decision,
            "risk": self.risk,
            "reason": self.reason,
            "metadata": dict(self.metadata),
            "previous_hash": self.previous_hash,
        }

    def compute_hash(self) -> str:
        """Recompute the event hash from its current contents."""
        return sha256_hex(canonical_bytes(self.hashed_payload()))

    def verify_hash(self) -> bool:
        """Return ``True`` when ``event_hash`` matches the recomputed value."""
        return bool(self.event_hash) and self.event_hash == self.compute_hash()

    def with_hash(self) -> "PoEEvent":
        """Return a copy of this event with a freshly computed ``event_hash``."""
        return replace(self, event_hash=self.compute_hash())

    # -- serialisation ---------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        payload = self.hashed_payload()
        payload["event_hash"] = self.event_hash
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PoEEvent":
        if not isinstance(data, Mapping):
            raise TraceError(f"event must be a mapping, got {type(data).__name__}")

        missing = [
            key
            for key in ("sequence", "timestamp", "event_type", "action")
            if key not in data
        ]
        if missing:
            raise TraceError(f"event is missing required fields: {', '.join(missing)}")

        try:
            sequence = int(data["sequence"])
            timestamp = int(data["timestamp"])
        except (TypeError, ValueError) as exc:
            raise TraceError(f"event sequence/timestamp must be integers: {exc}") from exc

        metadata = data.get("metadata") or {}
        if not isinstance(metadata, Mapping):
            raise TraceError("event metadata must be a mapping")

        return cls(
            sequence=sequence,
            timestamp=timestamp,
            event_type=coerce_event_type(data["event_type"]),
            action=as_text(data["action"]),
            resource=as_text(data.get("resource", "")),
            decision=as_text(data.get("decision", "ALLOW")),
            risk=as_text(data.get("risk", "NORMAL")),
            reason=as_text(data.get("reason", "")),
            metadata=dict(metadata),
            previous_hash=as_text(data.get("previous_hash", GENESIS_HASH)),
            event_hash=as_text(data.get("event_hash", "")),
        )

    def summary(self) -> str:
        """Compact one-line description, useful for logs and the CLI."""
        target = f" -> {self.resource}" if self.resource else ""
        return (
            f"#{self.sequence:04d} {self.event_type} {self.action}{target} "
            f"[{self.decision}/{self.risk}] {self.event_hash[:12]}"
        )
