"""Proof of Execution — a tamper-evident black-box flight recorder.

Public surface::

    from the_watcher.poe import Recorder, ExecutionTrace, PoEEvent, TraceVerifier

The layer has no dependency on policies, the kill switch or any identity
system. It can be used standalone as an audit log.
"""

from __future__ import annotations

from .canonical import (
    GENESIS_HASH,
    canonical_bytes,
    canonical_json,
    hash_value,
    is_hex_digest,
    normalise,
    sha256_hex,
)
from .event import EVENT_TYPES, EventType, PoEEvent, as_text, coerce_event_type
from .recorder import Recorder
from .redact import DEFAULT_REDACTOR, REDACTED, Redactor, redact
from .trace import SCHEMA_VERSION, ExecutionTrace
from .verifier import TAMPER_SIGNALS, TamperSignal, TraceVerifier, VerificationResult

__all__ = [
    # canonicalisation
    "GENESIS_HASH",
    "normalise",
    "canonical_json",
    "canonical_bytes",
    "sha256_hex",
    "hash_value",
    "is_hex_digest",
    # events
    "EventType",
    "EVENT_TYPES",
    "PoEEvent",
    "coerce_event_type",
    "as_text",
    # trace
    "ExecutionTrace",
    "SCHEMA_VERSION",
    # recording
    "Recorder",
    # redaction
    "Redactor",
    "DEFAULT_REDACTOR",
    "redact",
    "REDACTED",
    # verification
    "TraceVerifier",
    "VerificationResult",
    "TamperSignal",
    "TAMPER_SIGNALS",
]
