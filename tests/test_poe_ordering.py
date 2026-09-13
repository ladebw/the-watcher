"""Deterministic regression tests for PoE append ordering.

These cover the race that made a legitimate concurrent trace verify as
tampered. ``Recorder.record()`` used to read the clock *before* taking the
lock that decides append order, so two threads straddling a whole-second
boundary could be appended in the opposite order to the one they were stamped
in. The chain stayed intact and the verifier correctly reported
``TIMESTAMP_REGRESSION`` — a false tamper verdict on an untampered trace.

Neither test depends on wall-clock timing or on winning a scheduling race.

* The deterministic test uses the fake clock itself as the synchronisation
  point. The clock is only reachable *outside* the lock in the buggy
  implementation, so starting the second writer once the first has reached the
  clock forces the losing interleaving rather than hoping for it. On correct
  code the second writer is blocked on the recorder lock and the bounded probe
  simply expires; the probe is a deadlock detector, not a race.
* The stress test hammers the append path and asserts the invariant directly.
"""

from __future__ import annotations

import threading

import pytest

from the_watcher import Recorder

#: Bounded wait for the other thread to reach the clock. On correct code that
#: can never happen, so this always expires. Kept small so the probe does not
#: slow the suite down.
_PROBE_TIMEOUT = 0.2


class CountingClock:
    """A clock that advances by one whole second per reading."""

    def __init__(self, start: float = 1000.0) -> None:
        self._lock = threading.Lock()
        self._value = start
        #: Every value handed out, in the order it was handed out. Lets a test
        #: compare append order against clock order directly.
        self.readings: list[float] = []

    def __call__(self) -> float:
        with self._lock:
            self._value += 1.0
            self.readings.append(self._value)
            return self._value


class SteppedClock(CountingClock):
    """A clock that can pause the first caller while the second arrives.

    The timer is deliberately coarse (whole seconds) because that is what the
    real one does, and it is what makes the window observable at all.
    """

    def __init__(self, start: float = 1000.0) -> None:
        super().__init__(start=start)
        self.first_caller_entered = threading.Event()
        self._release_first = threading.Event()
        self._first = True

    def arm(self) -> None:
        """Treat the next reading as the first one.

        Needed because ``Recorder.__init__`` takes a reading for
        ``created_at``, which would otherwise consume the pause.
        """
        with self._lock:
            self._first = True
        self.first_caller_entered.clear()
        self._release_first.clear()

    def __call__(self) -> float:
        value = super().__call__()
        with self._lock:
            first = self._first
            self._first = False

        if first:
            self.first_caller_entered.set()
            self._release_first.wait(_PROBE_TIMEOUT)
        return value


def test_timestamp_is_taken_inside_the_append_critical_section():
    """The stamp must be acquired under the same lock as the append.

    With the timestamp taken outside the lock, the writer that reads the
    clock first can be appended second, producing
    ``sequence 0 -> 1001, sequence 1 -> 1000``. Forcing that interleaving here
    is what makes this a regression test rather than a coincidence.
    """
    clock = SteppedClock()
    recorder = Recorder(session_id="ordering-race", clock=clock)
    clock.arm()

    first = threading.Thread(
        target=recorder.record, args=("tool_request",), kwargs={"action": "first"}
    )
    second = threading.Thread(
        target=recorder.record, args=("tool_request",), kwargs={"action": "second"}
    )

    first.start()
    assert clock.first_caller_entered.wait(5.0), "the clock was never reached"

    # Start the second writer only once the first is inside the clock call.
    # On buggy code it then overtakes; on correct code it blocks on the lock.
    second.start()

    first.join(10)
    second.join(10)
    assert not first.is_alive(), "the first writer never finished"
    assert not second.is_alive(), "the second writer never finished"

    events = list(recorder.trace)
    sequences = [event.sequence for event in events]
    timestamps = [event.timestamp for event in events]

    assert sequences == [0, 1]
    assert timestamps == sorted(timestamps), (
        "timestamps regressed in append order: "
        f"{timestamps} (expected the stamp order to follow the append order)"
    )
    assert len(set(timestamps)) == len(timestamps), (
        f"two events share a timestamp: {timestamps}"
    )

    # The strongest statement of the invariant: the timestamps must be the
    # clock readings in the order the clock handed them out. With the stamp
    # taken outside the lock this comes out reversed instead. Reading 0 is the
    # trace's created_at, taken during construction.
    readings = [int(value) for value in clock.readings[1:]]
    assert timestamps == readings, (
        f"append order does not follow clock order: {timestamps} != {readings}"
    )

    result = recorder.trace.verify()
    assert result.valid, result.signals


def test_a_slow_stamp_cannot_reorder_the_append():
    """A clock that is slow on its first call must not reorder the trace."""
    delay = threading.Event()

    class SlowFirstClock(CountingClock):
        def __call__(self) -> float:
            value = super().__call__()
            if value == 1001.0:
                # Hold the stamp long enough for another writer to arrive.
                delay.wait(_PROBE_TIMEOUT)
            return value

    clock = SlowFirstClock()
    recorder = Recorder(session_id="slow-stamp", clock=clock)

    writers = [
        threading.Thread(
            target=recorder.record, args=("tool_request", "invoke:search")
        )
        for _ in range(4)
    ]
    for writer in writers:
        writer.start()
    for writer in writers:
        writer.join(10)

    assert all(not writer.is_alive() for writer in writers)

    timestamps = [event.timestamp for event in recorder.trace]
    assert timestamps == sorted(timestamps), f"timestamps regressed: {timestamps}"
    assert recorder.trace.verify().valid


@pytest.mark.parametrize("rounds", [100])
def test_concurrent_records_never_produce_non_monotonic_timestamps(rounds):
    """Hammer the append path: append order and timestamp order must agree.

    100 rounds of 8 concurrent writers. Each round asserts dense sequence
    numbers, strictly increasing timestamps, and a valid trace, so a single
    regression anywhere in the run fails the test.
    """
    writers_per_round = 8
    events_per_writer = 25

    for round_index in range(rounds):
        recorder = Recorder(
            session_id=f"ordering-stress-{round_index}", clock=CountingClock()
        )
        gate = threading.Barrier(writers_per_round)

        def worker(rec: Recorder, barrier: threading.Barrier) -> None:
            barrier.wait()
            for _ in range(events_per_writer):
                rec.record("tool_request", "invoke:search")

        threads = [
            threading.Thread(target=worker, args=(recorder, gate))
            for _ in range(writers_per_round)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        assert all(not thread.is_alive() for thread in threads), (
            f"round {round_index}: a writer hung"
        )

        trace = recorder.trace
        assert len(trace) == writers_per_round * events_per_writer

        sequences = [event.sequence for event in trace]
        assert sequences == list(range(len(sequences))), (
            f"round {round_index}: sequence numbers are not dense"
        )

        timestamps = [event.timestamp for event in trace]
        for index in range(1, len(timestamps)):
            assert timestamps[index] > timestamps[index - 1], (
                f"round {round_index}: timestamp regressed at index {index} "
                f"({timestamps[index - 1]} -> {timestamps[index]}); "
                "append order and stamp order disagree"
            )

        result = trace.verify()
        assert result.valid, f"round {round_index}: {result.signals}"
