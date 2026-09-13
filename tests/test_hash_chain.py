"""The tamper-evident hash chain: ordering, linking and final hash."""

from __future__ import annotations

import dataclasses

import pytest

from the_watcher import GENESIS_HASH, ExecutionTrace, Recorder, TraceVerifier
from the_watcher.exceptions import TraceError

from conftest import FakeClock


def build_trace(clock, count: int = 4) -> ExecutionTrace:
    recorder = Recorder(session_id="session-hash-chain", clock=clock)
    for index in range(count):
        recorder.record(
            "file_access",
            "read",
            f"/workspace/file{index}.txt",
            metadata={"index": index},
        )
    return recorder.trace


# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------


def test_first_event_links_to_the_genesis_anchor(clock):
    trace = build_trace(clock, count=1)
    assert trace[0].previous_hash == GENESIS_HASH
    assert GENESIS_HASH == "0" * 64


def test_every_event_links_to_its_predecessor(clock):
    trace = build_trace(clock, count=5)
    for index in range(1, len(trace)):
        assert trace[index].previous_hash == trace[index - 1].event_hash


def test_sequence_numbers_are_dense_and_ordered(clock):
    trace = build_trace(clock, count=6)
    assert [event.sequence for event in trace] == list(range(6))


def test_head_hash_follows_the_last_event(clock):
    trace = build_trace(clock, count=3)
    assert trace.head_hash == trace[-1].event_hash

    trace.add("file_access", "read", "/workspace/extra.txt")
    assert trace.head_hash == trace[-1].event_hash


def test_append_overwrites_caller_supplied_chain_fields(clock):
    from the_watcher import PoEEvent

    trace = build_trace(clock, count=1)
    forged = PoEEvent(
        sequence=99,
        timestamp=1_760_000_000,
        event_type="file_access",
        action="read",
        resource="/workspace/forged.txt",
        previous_hash="f" * 64,
        event_hash="f" * 64,
    )
    stored = trace.append(forged)

    assert stored.sequence == 1
    assert stored.previous_hash == trace[0].event_hash
    assert stored.event_hash == stored.compute_hash()
    assert stored.event_hash != "f" * 64


# ---------------------------------------------------------------------------
# Determinism and final hash
# ---------------------------------------------------------------------------


def test_final_hash_is_deterministic_for_identical_traces():
    first = build_trace(FakeClock(), count=3)
    second = build_trace(FakeClock(), count=3)
    assert first.final_hash == second.final_hash


def test_final_hash_changes_when_an_event_is_appended(clock):
    trace = build_trace(clock, count=3)
    before = trace.final_hash
    trace.add("file_access", "read", "/workspace/file99.txt")
    assert trace.final_hash != before


def test_final_hash_changes_when_content_changes(clock):
    trace = build_trace(clock, count=3)
    before = trace.final_hash

    trace.events[1] = dataclasses.replace(
        trace.events[1], resource="/workspace/other.txt"
    )
    trace.relink(1)

    assert trace.final_hash != before


def test_a_fully_rehashed_rewrite_is_caught_by_the_sealed_hash(clock):
    """A consistent rewrite still cannot match a published (sealed) hash."""
    trace = build_trace(clock, count=3)
    trace.seal()
    sealed = trace.declared_final_hash

    trace.events[1] = dataclasses.replace(
        trace.events[1], resource="/workspace/other.txt"
    )
    trace.relink(1)

    # The rebuilt chain is internally consistent...
    assert all(event.verify_hash() for event in trace)
    # ...but it no longer matches the sealed hash.
    assert trace.compute_final_hash() != sealed
    result = TraceVerifier().verify(trace)
    assert not result.valid
    assert any(
        signal.split(":", 1)[0] == "INVALID_FINAL_TRACE_HASH"
        for signal in result.signals
    )


def test_relink_rejects_an_out_of_range_start(clock):
    trace = build_trace(clock, count=2)
    with pytest.raises(TraceError):
        trace.relink(5)


def test_seal_freezes_the_declared_hash(clock):
    trace = build_trace(clock, count=3)
    assert trace.declared_final_hash is None
    sealed = trace.seal()
    assert trace.declared_final_hash == sealed
    assert sealed == trace.final_hash


def test_exported_final_hash_uses_the_sealed_value(clock):
    """The export reports the sealed hash, so post-seal edits stay visible."""
    trace = build_trace(clock, count=3)
    trace.seal()
    declared = trace.declared_final_hash

    # A sealed trace now refuses appends, so the cheap post-seal tamper is a
    # deletion. Either way the exported hash must remain the sealed one, which
    # is what makes the edit detectable at all.
    trace.events.pop()

    assert trace.to_dict()["final_hash"] == declared


# ---------------------------------------------------------------------------
# Verification of a healthy chain
# ---------------------------------------------------------------------------


def test_valid_chain_verifies(clock):
    trace = build_trace(clock, count=4)
    result = TraceVerifier().verify(trace)

    assert result.valid
    assert result.verdict == "valid"
    assert result.signals == ()
    assert result.event_count == 4
    assert bool(result) is True


def test_sealed_chain_verifies(clock):
    trace = build_trace(clock, count=4)
    trace.seal()
    assert TraceVerifier().verify(trace).valid


def test_verification_reports_the_final_hash(clock):
    trace = build_trace(clock, count=2)
    result = TraceVerifier().verify(trace)
    assert result.final_hash == trace.final_hash


def test_every_event_hash_recomputes(clock):
    trace = build_trace(clock, count=5)
    assert all(event.verify_hash() for event in trace)


def test_round_trip_preserves_verification(clock):
    trace = build_trace(clock, count=4)
    trace.seal()
    restored = ExecutionTrace.from_dict(trace.to_dict())
    assert TraceVerifier().verify(restored).valid


def test_verifier_rejects_non_trace_input():
    with pytest.raises(TraceError):
        TraceVerifier().verify({"session_id": "x", "events": []})  # type: ignore[arg-type]
