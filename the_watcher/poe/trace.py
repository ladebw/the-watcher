"""The hash-chained Proof-of-Execution trace.

AAIP proved the value of a deterministic digest over a finished execution
record. The Watcher keeps the determinism but upgrades the record from a
*summary* into an *ordered chain*: every event commits to its predecessor,
so a single edited, dropped, inserted or reordered event invalidates the
whole trace from that point onward.

    event[0] --hash--> event[1] --hash--> event[2] --hash--> final_hash

No blockchain, no signatures and no identity are involved.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, replace
from typing import Any, Iterator, Mapping

from ..exceptions import TraceError, TraceSealedError
from .canonical import GENESIS_HASH, canonical_bytes, sha256_hex
from .event import EventType, PoEEvent, as_text, coerce_event_type

__all__ = ["CLOCK_REGRESSION_KEY", "ExecutionTrace", "SCHEMA_VERSION"]

SCHEMA_VERSION = "watcher-poe/1"

#: Reserved metadata key under which a trace records a backwards wall-clock
#: step.
#:
#: The trace owns this key: whatever a caller supplies under it is removed
#: before the event is appended, so the evidence can only ever appear because
#: the trace itself observed the clock move.
#:
#: Scope of that guarantee, stated precisely: an untrusted agent or client
#: cannot supply this metadata, because the only route from a client into a
#: trace is the daemon's recorder. ``AUTHORITATIVE_FIELDS`` strips ``timestamp``
#: (and ``sequence``, ``previous_hash``, ``event_hash``, ``final_hash``,
#: ``decision``, ``risk``) from client payloads recursively, and
#: ``Recorder.record()`` accepts no timestamp argument, so the value it stamps
#: comes only from the daemon's own clock.
#:
#: ``append()`` and ``add()`` are internal/embedder APIs, not the client path.
#: A caller with in-process access can pass an arbitrary ``timestamp`` and so
#: induce a record. That is not a provenance hole to be papered over: the
#: evidence still reports the value it was given, and the key is stripped and
#: re-set by the trace either way.
CLOCK_REGRESSION_KEY = "clock_regression"


@dataclass
class ExecutionTrace:
    """An ordered, hash-chained sequence of :class:`PoEEvent` objects."""

    session_id: str
    events: list[PoEEvent] = field(default_factory=list)
    created_at: int = 0
    schema_version: str = SCHEMA_VERSION

    #: Hash the trace claimed when it was sealed or loaded. Compared against a
    #: freshly computed hash during verification, which catches tampering with
    #: the tail of the chain and with the event list length.
    declared_final_hash: "str | None" = None

    def __post_init__(self) -> None:
        if not self.session_id:
            raise TraceError("trace requires a session_id")
        if not self.created_at:
            self.created_at = int(time.time())

    # -- chain construction ---------------------------------------------

    @property
    def head_hash(self) -> str:
        """Hash of the newest event, or the genesis anchor when empty."""
        return self.events[-1].event_hash if self.events else GENESIS_HASH

    @property
    def last_event(self) -> "PoEEvent | None":
        return self.events[-1] if self.events else None

    def append(self, event: PoEEvent) -> PoEEvent:
        """Append ``event``, assigning its sequence and chain links.

        The caller's ``sequence``, ``previous_hash`` and ``event_hash`` are
        overwritten: chain integrity is the trace's responsibility.

        Sealing is a one-way door. A sealed trace has a declared final hash
        that covers the event count and the head hash, so an append afterwards
        would leave verification reporting ``INVALID_FINAL_TRACE_HASH`` for a
        trace nobody tampered with. Refusing the append keeps the invariant
        "sealed means no further event may be appended" true by construction
        rather than by every caller remembering it.
        """
        if self.declared_final_hash is not None:
            raise TraceSealedError(
                f"trace for session {self.session_id} is sealed; "
                f"refusing to append {len(self.events)} -> {len(self.events) + 1}"
            )

        # Wall-clock timestamps can step backwards when the host resynchronises
        # its time - NTP, a VM resuming, or WSL2 catching up with the Windows
        # clock. Verification reads a decreasing timestamp as evidence of
        # reordering, so an unclamped step is reported as tampering on a trace
        # nobody touched. Measured on this machine: one step of -1.23s in 9,698
        # samples over 200s, which was enough to fail a concurrency run.
        #
        # The authoritative timestamp therefore stays non-decreasing, but the
        # anomaly is not discarded. The raw reading, the timestamp it would
        # have clashed with, and the size of the step are attached under a
        # trace-owned key. That lands in ``metadata``, which is part of the
        # event hash, so the evidence is itself tamper-evident.
        #
        # This does not blunt the reorder signal: reordering happens to events
        # *after* they were appended, so a swap still produces a decrease and
        # is still reported as ``TIMESTAMP_REGRESSION``.
        #
        # ``append`` trusts the timestamp it is given. That is sound on the
        # authoritative path, where the value can only come from
        # ``Recorder``'s clock; see the note on CLOCK_REGRESSION_KEY for the
        # scope of that claim and for what an in-process caller can do.
        metadata = dict(event.metadata or {})
        metadata.pop(CLOCK_REGRESSION_KEY, None)

        timestamp = int(event.timestamp)
        if self.events and timestamp < self.events[-1].timestamp:
            previous = self.events[-1].timestamp
            metadata[CLOCK_REGRESSION_KEY] = {
                "raw_timestamp": timestamp,
                "previous_timestamp": previous,
                "delta_seconds": previous - timestamp,
            }
            timestamp = previous

        chained = replace(
            event,
            sequence=len(self.events),
            previous_hash=self.head_hash,
            event_hash="",
            timestamp=timestamp,
            metadata=metadata,
        ).with_hash()
        self.events.append(chained)
        return chained

    def add(
        self,
        event_type: "EventType | str",
        action: str,
        resource: str = "",
        decision: Any = "ALLOW",
        risk: Any = "NORMAL",
        reason: str = "",
        metadata: "Mapping[str, Any] | None" = None,
        timestamp: "int | None" = None,
    ) -> PoEEvent:
        """Build and append an event in one step."""
        event = PoEEvent(
            sequence=0,
            timestamp=int(time.time()) if timestamp is None else int(timestamp),
            event_type=coerce_event_type(event_type),
            action=as_text(action),
            resource=as_text(resource),
            decision=as_text(decision),
            risk=as_text(risk),
            reason=as_text(reason),
            metadata=dict(metadata or {}),
        )
        return self.append(event)

    # -- final hash ------------------------------------------------------

    def compute_final_hash(self) -> str:
        """Compute the trace's fingerprint from its current contents."""
        return sha256_hex(
            canonical_bytes(
                {
                    "schema_version": self.schema_version,
                    "session_id": self.session_id,
                    "event_count": len(self.events),
                    "genesis_hash": GENESIS_HASH,
                    "final_event_hash": self.head_hash,
                }
            )
        )

    @property
    def final_hash(self) -> str:
        """The live hash of the trace as it currently stands."""
        return self.compute_final_hash()

    def seal(self) -> str:
        """Fix the current final hash so later mutation is detectable."""
        self.declared_final_hash = self.compute_final_hash()
        return self.declared_final_hash

    def relink(self, start: int = 0) -> None:
        """Recompute sequence numbers and chain links from ``start`` onward.

        Intended for *sanctioned* edits, such as redacting a trace before it is
        exported: after changing content the chain must be rebuilt, then
        re-sealed. Applied to an already-sealed trace this models a full
        attacker rewrite — the rebuilt chain is internally consistent but no
        longer matches the published hash, which verification reports as
        ``INVALID_FINAL_TRACE_HASH``.
        """
        if not 0 <= start <= len(self.events):
            raise TraceError(f"relink start out of range: {start}")

        for index in range(start, len(self.events)):
            previous = (
                self.events[index - 1].event_hash if index > 0 else GENESIS_HASH
            )
            self.events[index] = replace(
                self.events[index],
                sequence=index,
                previous_hash=previous,
                event_hash="",
            ).with_hash()

    @property
    def sealed(self) -> bool:
        return self.declared_final_hash is not None

    @property
    def clock_regressions(self) -> list[dict[str, Any]]:
        """Every backwards wall-clock step this trace observed, in append order.

        Empty for an ordinary session. A non-empty list means the host clock
        moved backwards while the trace was being written - the events
        themselves stay consistent and verify, which is exactly why the raw
        anomaly is recorded here rather than allowed to break the sequence.

        Each entry carries ``sequence``, ``raw_timestamp`` (what the clock
        actually said), ``previous_timestamp`` (the authoritative timestamp it
        clashed with) and ``delta_seconds``.
        """
        found: list[dict[str, Any]] = []
        for event in self.events:
            evidence = (event.metadata or {}).get(CLOCK_REGRESSION_KEY)
            if isinstance(evidence, Mapping):
                found.append({"sequence": event.sequence, **evidence})
        return found

    # -- verification ----------------------------------------------------

    def verify(self):
        """Verify the chain. Returns a :class:`VerificationResult`."""
        from .verifier import TraceVerifier

        return TraceVerifier().verify(self)

    def verify_or_raise(self) -> None:
        """Verify the chain and raise on any tamper signal."""
        self.verify().raise_if_invalid()

    # -- serialisation ---------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "event_count": len(self.events),
            "genesis_hash": GENESIS_HASH,
            # Prefer the sealed value so tampering *after* sealing is visible.
            "final_hash": self.declared_final_hash or self.compute_final_hash(),
            "events": [event.to_dict() for event in self.events],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def export(self, path: str) -> str:
        """Write the trace to ``path`` as pretty JSON and return the path."""
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.to_json())
        return path

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ExecutionTrace":
        if not isinstance(data, Mapping):
            raise TraceError(f"trace must be a mapping, got {type(data).__name__}")

        if "session_id" not in data:
            raise TraceError("trace is missing required field: session_id")
        if "events" not in data:
            raise TraceError("trace is missing required field: events")

        raw_events = data["events"]
        if not isinstance(raw_events, list):
            raise TraceError("trace 'events' must be a list")

        return cls(
            session_id=as_text(data["session_id"]),
            events=[PoEEvent.from_dict(item) for item in raw_events],
            created_at=int(data.get("created_at") or 0),
            schema_version=as_text(data.get("schema_version", SCHEMA_VERSION)),
            declared_final_hash=(
                as_text(data["final_hash"]) if data.get("final_hash") else None
            ),
        )

    @classmethod
    def from_json(cls, raw: str) -> "ExecutionTrace":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise TraceError(f"trace is not valid JSON: {exc}") from exc
        return cls.from_dict(data)

    @classmethod
    def load(cls, path: str) -> "ExecutionTrace":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_json(handle.read())

    # -- sequence protocol ----------------------------------------------

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self) -> Iterator[PoEEvent]:
        return iter(self.events)

    def __getitem__(self, index: int) -> PoEEvent:
        return self.events[index]

    def __bool__(self) -> bool:
        return bool(self.events)
