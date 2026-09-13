"""The trace verifier — tamper detection over the hash chain.

Modelled on AAIP's ``PoEVerifier`` verdict/signal idea, but retargeted from
"is this summary self-consistent and signed?" to "has this ordered chain been
edited since it was written?".

Detected conditions
-------------------
* **modified** event        -> ``EVENT_HASH_MISMATCH``
* **deleted** event         -> ``NON_CONTIGUOUS_SEQUENCE`` + ``BROKEN_PREVIOUS_HASH``
* **inserted** event        -> ``NON_CONTIGUOUS_SEQUENCE`` + ``BROKEN_PREVIOUS_HASH``
* **reordered** events      -> ``NON_CONTIGUOUS_SEQUENCE`` + ``TIMESTAMP_REGRESSION``
* **broken link**           -> ``BROKEN_PREVIOUS_HASH`` / ``INVALID_GENESIS_LINK``
* **invalid final hash**    -> ``INVALID_FINAL_TRACE_HASH``
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..exceptions import TraceError, TraceVerificationError
from .canonical import GENESIS_HASH, is_hex_digest
from .trace import ExecutionTrace

__all__ = ["TamperSignal", "VerificationResult", "TraceVerifier"]


class TamperSignal(str, enum.Enum):
    """Machine-readable reasons a trace failed verification."""

    MALFORMED_TRACE = "MALFORMED_TRACE"
    MISSING_FIELDS = "MISSING_FIELDS"
    NON_CONTIGUOUS_SEQUENCE = "NON_CONTIGUOUS_SEQUENCE"
    BROKEN_PREVIOUS_HASH = "BROKEN_PREVIOUS_HASH"
    INVALID_GENESIS_LINK = "INVALID_GENESIS_LINK"
    EVENT_HASH_MISMATCH = "EVENT_HASH_MISMATCH"
    INVALID_EVENT_HASH = "INVALID_EVENT_HASH"
    TIMESTAMP_REGRESSION = "TIMESTAMP_REGRESSION"
    INVALID_FINAL_TRACE_HASH = "INVALID_FINAL_TRACE_HASH"


#: Convenience sets for callers that want to classify a failure.
TAMPER_SIGNALS: frozenset[str] = frozenset(
    {
        TamperSignal.NON_CONTIGUOUS_SEQUENCE.value,
        TamperSignal.BROKEN_PREVIOUS_HASH.value,
        TamperSignal.INVALID_GENESIS_LINK.value,
        TamperSignal.EVENT_HASH_MISMATCH.value,
        TamperSignal.INVALID_EVENT_HASH.value,
        TamperSignal.TIMESTAMP_REGRESSION.value,
        TamperSignal.INVALID_FINAL_TRACE_HASH.value,
    }
)


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying a trace."""

    verdict: str
    signals: tuple[str, ...]
    event_count: int
    final_hash: str
    declared_hash: "str | None" = None
    checked_at: int = field(default_factory=lambda: int(time.time()))

    @property
    def valid(self) -> bool:
        return self.verdict == "valid"

    @property
    def tampered(self) -> bool:
        """``True`` when the failure looks like deliberate modification."""
        return any(signal.split(":", 1)[0] in TAMPER_SIGNALS for signal in self.signals)

    def __bool__(self) -> bool:
        return self.valid

    def summary(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "valid": self.valid,
            "tampered": self.tampered,
            "event_count": self.event_count,
            "final_hash": self.final_hash,
            "declared_hash": self.declared_hash,
            "signals": list(self.signals),
            "checked_at": self.checked_at,
        }

    def raise_if_invalid(self) -> None:
        if not self.valid:
            raise TraceVerificationError(
                "trace failed verification: " + ", ".join(self.signals),
                signals=list(self.signals),
            )

    def __str__(self) -> str:
        if self.valid:
            return f"valid ({self.event_count} events, final={self.final_hash[:12]})"
        return f"invalid ({len(self.signals)} signals): " + ", ".join(self.signals)


class TraceVerifier:
    """Recomputes a trace's hash chain and reports every divergence."""

    def verify(self, trace: ExecutionTrace) -> VerificationResult:
        if not isinstance(trace, ExecutionTrace):
            raise TraceError(
                f"TraceVerifier.verify expects an ExecutionTrace, got "
                f"{type(trace).__name__}"
            )

        signals: list[str] = []
        expected_previous = GENESIS_HASH
        previous_timestamp: "int | None" = None

        for index, event in enumerate(trace.events):
            # Sequence numbers must be a dense 0..n-1 range. Gaps mean an event
            # was deleted or an unattached event was inserted.
            if event.sequence != index:
                signals.append(
                    f"{TamperSignal.NON_CONTIGUOUS_SEQUENCE.value}:"
                    f"index={index}:sequence={event.sequence}"
                )

            # Each event must point at its predecessor's hash.
            if event.previous_hash != expected_previous:
                if index == 0 and event.previous_hash != GENESIS_HASH:
                    signals.append(
                        f"{TamperSignal.INVALID_GENESIS_LINK.value}:index=0"
                    )
                else:
                    signals.append(
                        f"{TamperSignal.BROKEN_PREVIOUS_HASH.value}:index={index}"
                    )

            # The stored hash must match a recomputation from the payload.
            if not is_hex_digest(event.event_hash):
                signals.append(
                    f"{TamperSignal.INVALID_EVENT_HASH.value}:index={index}"
                )
            elif event.event_hash != event.compute_hash():
                signals.append(
                    f"{TamperSignal.EVENT_HASH_MISMATCH.value}:index={index}"
                )

            # Ordering must be monotonic; a swap shows up here.
            if previous_timestamp is not None and event.timestamp < previous_timestamp:
                signals.append(
                    f"{TamperSignal.TIMESTAMP_REGRESSION.value}:index={index}"
                )

            expected_previous = event.event_hash
            previous_timestamp = event.timestamp

        computed = trace.compute_final_hash()
        if trace.declared_final_hash is not None and (
            trace.declared_final_hash != computed
        ):
            signals.append(TamperSignal.INVALID_FINAL_TRACE_HASH.value)

        return VerificationResult(
            verdict="valid" if not signals else "invalid",
            signals=tuple(signals),
            event_count=len(trace.events),
            final_hash=computed,
            declared_hash=trace.declared_final_hash,
        )

    def verify_dict(self, data: Mapping[str, Any]) -> VerificationResult:
        """Verify a serialised trace, reporting malformed input as invalid."""
        try:
            trace = ExecutionTrace.from_dict(data)
        except (TraceError, KeyError, TypeError, ValueError) as exc:
            return VerificationResult(
                verdict="invalid",
                signals=(f"{TamperSignal.MALFORMED_TRACE.value}:{exc}",),
                event_count=0,
                final_hash="",
                declared_hash=None,
            )

        if not trace.events:
            return VerificationResult(
                verdict="invalid",
                signals=(f"{TamperSignal.MISSING_FIELDS.value}:no_events",),
                event_count=0,
                final_hash=trace.compute_final_hash(),
                declared_hash=trace.declared_final_hash,
            )

        return self.verify(trace)

    def verify_file(self, path: str) -> VerificationResult:
        """Load and verify a trace JSON file."""
        try:
            trace = ExecutionTrace.load(path)
        except (OSError, TraceError) as exc:
            return VerificationResult(
                verdict="invalid",
                signals=(f"{TamperSignal.MALFORMED_TRACE.value}:{exc}",),
                event_count=0,
                final_hash="",
                declared_hash=None,
            )
        return self.verify(trace)
