"""Tamper detection: modification, deletion, insertion, reordering, truncation."""

from __future__ import annotations

import dataclasses

import pytest

from the_watcher import ExecutionTrace, Recorder, TraceVerifier
from the_watcher.exceptions import TraceSealedError, TraceVerificationError
from the_watcher.poe import TamperSignal

SIGNAL_PREFIXES = {signal.value for signal in TamperSignal}


def build_trace(clock, count: int = 4, seal: bool = False) -> ExecutionTrace:
    recorder = Recorder(session_id="session-tamper", clock=clock)
    for index in range(count):
        recorder.record("file_access", "read", f"/workspace/file{index}.txt")
    if seal:
        recorder.trace.seal()
    return recorder.trace


def has_signal(result, name: str) -> bool:
    return any(signal.split(":", 1)[0] == name for signal in result.signals)


# ---------------------------------------------------------------------------
# Control
# ---------------------------------------------------------------------------


def test_untampered_trace_verifies(clock):
    result = TraceVerifier().verify(build_trace(clock, seal=True))
    assert result.valid
    assert result.tampered is False


# ---------------------------------------------------------------------------
# Modified events
# ---------------------------------------------------------------------------


def test_modified_event_is_detected(clock):
    trace = build_trace(clock, seal=True)
    assert trace.verify().valid

    trace.events[1] = dataclasses.replace(
        trace.events[1], resource="/workspace/exfiltrated.txt"
    )
    result = trace.verify()

    assert not result.valid
    assert result.tampered
    assert has_signal(result, "EVENT_HASH_MISMATCH")


def test_modified_decision_and_risk_are_detected(clock):
    trace = build_trace(clock, seal=True)
    trace.events[2] = dataclasses.replace(
        trace.events[2], decision="DENY", risk="HIGH"
    )

    result = trace.verify()
    assert not result.valid
    assert has_signal(result, "EVENT_HASH_MISMATCH")


def test_in_place_modification_is_detected_at_the_edited_event(clock):
    trace = build_trace(clock, count=5, seal=True)
    trace.events[1] = dataclasses.replace(trace.events[1], action="tampered")

    result = trace.verify()
    assert not result.valid
    assert has_signal(result, "EVENT_HASH_MISMATCH")

    # Only the edited event's recomputed hash diverges: the *stored* hashes of
    # later events still point at the stored hash of their predecessor, so the
    # chain itself is not reported as broken. Recomputing a hash (below) does
    # break the links, which is why an attacker cannot hide either way.
    assert not has_signal(result, "BROKEN_PREVIOUS_HASH")


def test_rehashing_a_modified_event_still_breaks_the_chain(clock):
    """An attacker who recomputes the hash cannot repair the chain."""
    trace = build_trace(clock, count=4, seal=True)
    forged = dataclasses.replace(
        trace.events[1], resource="/workspace/exfiltrated.txt"
    ).with_hash()
    trace.events[1] = forged

    # The forged event's own hash is self-consistent...
    assert forged.verify_hash()
    # ...but its successors still point at the old hash.
    result = trace.verify()
    assert not result.valid
    assert has_signal(result, "BROKEN_PREVIOUS_HASH")


# ---------------------------------------------------------------------------
# Deleted events
# ---------------------------------------------------------------------------


def test_deleted_event_is_detected(clock):
    trace = build_trace(clock, seal=True)
    del trace.events[1]

    result = trace.verify()
    assert not result.valid
    assert has_signal(result, "NON_CONTIGUOUS_SEQUENCE")
    assert has_signal(result, "BROKEN_PREVIOUS_HASH")
    assert has_signal(result, "INVALID_FINAL_TRACE_HASH")


def test_deleting_the_last_event_is_detected_when_sealed(clock):
    trace = build_trace(clock, seal=True)
    trace.events.pop()

    result = trace.verify()
    assert not result.valid
    assert has_signal(result, "INVALID_FINAL_TRACE_HASH")


def test_deleting_a_middle_event_is_detected_unsealed(clock):
    trace = build_trace(clock, seal=False)
    del trace.events[2]

    result = trace.verify()
    assert not result.valid
    assert has_signal(result, "NON_CONTIGUOUS_SEQUENCE")


# ---------------------------------------------------------------------------
# Inserted events
# ---------------------------------------------------------------------------


def test_splicing_in_a_copied_event_is_detected(clock):
    trace = build_trace(clock, count=4, seal=True)
    trace.events.insert(1, trace.events[2])

    result = trace.verify()
    assert not result.valid
    assert has_signal(result, "NON_CONTIGUOUS_SEQUENCE")
    assert has_signal(result, "BROKEN_PREVIOUS_HASH")


def test_inserting_a_fully_rehashed_event_is_detected(clock):
    """Even a perfectly-formed forged event cannot be spliced in."""
    trace = build_trace(clock, count=4, seal=True)
    forged = dataclasses.replace(
        trace.events[2],
        sequence=1,
        previous_hash=trace.events[0].event_hash,
        event_hash="",
    ).with_hash()
    trace.events.insert(1, forged)

    # Local to its predecessor, the forged event looks valid...
    assert forged.previous_hash == trace.events[0].event_hash
    assert forged.verify_hash()

    result = trace.verify()
    assert not result.valid
    assert has_signal(result, "NON_CONTIGUOUS_SEQUENCE")
    assert has_signal(result, "BROKEN_PREVIOUS_HASH")


# ---------------------------------------------------------------------------
# Reordered events
# ---------------------------------------------------------------------------


def test_reordered_events_are_detected(clock):
    trace = build_trace(clock, count=4, seal=True)
    trace.events[1], trace.events[2] = trace.events[2], trace.events[1]

    result = trace.verify()
    assert not result.valid
    assert has_signal(result, "NON_CONTIGUOUS_SEQUENCE")
    assert has_signal(result, "BROKEN_PREVIOUS_HASH")
    assert has_signal(result, "TIMESTAMP_REGRESSION")


def test_swapping_the_first_two_events_is_detected(clock):
    trace = build_trace(clock, count=3, seal=True)
    trace.events[0], trace.events[1] = trace.events[1], trace.events[0]

    result = trace.verify()
    assert not result.valid
    assert has_signal(result, "NON_CONTIGUOUS_SEQUENCE")


# ---------------------------------------------------------------------------
# Broken links and final hash
# ---------------------------------------------------------------------------


def test_broken_previous_hash_is_detected(clock):
    trace = build_trace(clock, count=4, seal=True)
    trace.events[2] = dataclasses.replace(
        trace.events[2], previous_hash="f" * 64
    ).with_hash()

    result = trace.verify()
    assert not result.valid
    assert has_signal(result, "BROKEN_PREVIOUS_HASH")


def test_invalid_genesis_link_is_detected(clock):
    trace = build_trace(clock, count=2, seal=True)
    trace.events[0] = dataclasses.replace(
        trace.events[0], previous_hash="f" * 64
    ).with_hash()

    result = trace.verify()
    assert not result.valid
    assert has_signal(result, "INVALID_GENESIS_LINK")


def test_appending_after_sealing_invalidates_the_final_hash(clock):
    """A sealed trace refuses the append outright.

    Letting the append through used to leave ``compute_final_hash()``
    different from ``declared_final_hash``, so verification reported
    INVALID_FINAL_TRACE_HASH on a trace nobody had tampered with. Refusing it
    removes the whole class of false verdict, and the trace stays valid.
    """
    trace = build_trace(clock, count=3, seal=True)
    declared = trace.declared_final_hash
    count = len(trace.events)

    with pytest.raises(TraceSealedError):
        trace.add("file_access", "read", "/workspace/sneaky.txt")

    # The refusal changed nothing...
    assert len(trace.events) == count
    assert trace.declared_final_hash == declared
    # ...so the trace still verifies, and truncation is still detectable.
    assert trace.verify().valid


def test_invalid_event_hash_format_is_detected(clock):
    trace = build_trace(clock, count=2)
    trace.events[1] = dataclasses.replace(trace.events[1], event_hash="not-a-digest")

    result = trace.verify()
    assert not result.valid
    assert has_signal(result, "INVALID_EVENT_HASH")


# ---------------------------------------------------------------------------
# Malformed input and exceptions
# ---------------------------------------------------------------------------


def test_malformed_trace_is_reported_as_invalid():
    result = TraceVerifier().verify_dict({"session_id": "session-x"})
    assert not result.valid
    assert has_signal(result, "MALFORMED_TRACE")


def test_empty_trace_is_reported_as_invalid():
    result = TraceVerifier().verify_dict({"session_id": "session-x", "events": []})
    assert not result.valid
    assert has_signal(result, "MISSING_FIELDS")


def test_missing_file_is_reported_as_invalid(tmp_path):
    result = TraceVerifier().verify_file(str(tmp_path / "does-not-exist.json"))
    assert not result.valid
    assert has_signal(result, "MALFORMED_TRACE")


def test_raise_if_invalid_raises_with_signals(clock):
    trace = build_trace(clock, count=3, seal=True)
    del trace.events[0]

    result = trace.verify()
    assert not result.valid
    with pytest.raises(TraceVerificationError) as excinfo:
        result.raise_if_invalid()
    assert excinfo.value.signals
    assert "NON_CONTIGUOUS_SEQUENCE" in " ".join(excinfo.value.signals)


def test_raise_if_invalid_is_silent_for_valid_traces(clock):
    build_trace(clock, count=2, seal=True).verify_or_raise()


def test_verify_or_raise_on_execution_trace(clock):
    trace = build_trace(clock, count=3)
    trace.verify_or_raise()

    trace.events[0] = dataclasses.replace(trace.events[0], action="tampered")
    with pytest.raises(TraceVerificationError):
        trace.verify_or_raise()


def test_verification_result_summary_is_serialisable(clock):
    import json

    trace = build_trace(clock, count=3, seal=True)
    del trace.events[1]
    summary = trace.verify().summary()

    assert summary["valid"] is False
    assert summary["tampered"] is True
    assert isinstance(summary["signals"], list)
    json.dumps(summary)  # must not raise
