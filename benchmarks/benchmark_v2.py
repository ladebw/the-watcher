"""V2 benchmark: IPC, policy, PoE append, throughput and kill latency.

    python benchmarks/benchmark_v2.py
    python benchmarks/benchmark_v2.py --quick

Writes ``benchmark-results.json`` next to the working directory and prints a
readable table. No expected numbers are hardcoded: the point is to measure the
machine this is running on, not to assert a target.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Sequence

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from the_watcher import Policy, Recorder  # noqa: E402
from the_watcher.ipc.protocol import IpcLimits, MessageType, build_request  # noqa: E402
from the_watcher.ipc.transport import (  # noqa: E402
    CLIENT_RECEIVE_TYPES,
    connect,
)
from the_watcher.supervisor import DaemonConfig, WatcherDaemon  # noqa: E402

AGENT = os.path.join(PROJECT_ROOT, "examples", "v2_agent.py")


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def percentile(values: Sequence[float], fraction: float) -> float:
    """Nearest-rank percentile. ``values`` must be non-empty."""
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    index = max(0, min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1)))))
    return float(ordered[index])


def summarise(samples: Sequence[float]) -> dict[str, Any]:
    """Summarise a list of millisecond samples."""
    if not samples:
        return {"count": 0}
    values = [float(sample) for sample in samples]
    return {
        "count": len(values),
        "median_ms": round(statistics.median(values), 4),
        "mean_ms": round(statistics.fmean(values), 4),
        "p95_ms": round(percentile(values, 0.95), 4),
        "p99_ms": round(percentile(values, 0.99), 4),
        "min_ms": round(min(values), 4),
        "max_ms": round(max(values), 4),
    }


def timed(operation: Callable[[], Any]) -> float:
    """Run ``operation`` once and return elapsed milliseconds."""
    started = time.perf_counter()
    operation()
    return (time.perf_counter() - started) * 1000.0


# ---------------------------------------------------------------------------
# Component benchmarks
# ---------------------------------------------------------------------------


def bench_policy(iterations: int) -> dict[str, Any]:
    policy = Policy(
        workspace_root=PROJECT_ROOT,
        allowed_paths=["./workspace"],
        forbidden_paths=["/etc/shadow", "~/.ssh"],
        allowed_domains=["github.com"],
        forbidden_tools=["shell"],
        max_processes=10,
    )
    cases = [
        ("file_access", "read", "./workspace/notes.txt"),
        ("file_access", "read", "/etc/shadow"),
        ("network_request", "connect", "https://github.com/x"),
        ("network_request", "connect", "https://evil.example/x"),
        ("tool_request", "invoke", "search"),
        ("shell_command", "exec", "sudo rm -rf /"),
    ]
    samples = []
    for index in range(iterations):
        event_type, action, resource = cases[index % len(cases)]
        samples.append(
            timed(
                lambda et=event_type, act=action, res=resource: policy.evaluate(
                    et, act, res
                )
            )
        )
    return summarise(samples)


def bench_poe_append(iterations: int) -> dict[str, Any]:
    recorder = Recorder(session_id="benchmark-poe")
    samples = []
    for index in range(iterations):
        samples.append(
            timed(
                lambda i=index: recorder.record(
                    "file_access", "read", f"/workspace/file{i}.txt"
                )
            )
        )
    verification = recorder.trace.verify()
    return {
        **summarise(samples),
        "final_hash": recorder.trace.declared_final_hash or recorder.trace.final_hash,
        "chain_valid": verification.valid,
    }


def bench_canonical_hash(iterations: int) -> dict[str, Any]:
    from the_watcher.poe.canonical import canonical_bytes, sha256_hex

    payload = {
        "sequence": 42,
        "timestamp": 1_760_000_000,
        "event_type": "network_request",
        "action": "connect",
        "resource": "https://example.com/path?q=1",
        "decision": "ALLOW",
        "risk": "NORMAL",
        "reason": "no policy rule matched for network_request",
        "metadata": {"rule": "default", "ipc": {"kind": "evaluate"}},
        "previous_hash": "a" * 64,
    }
    samples = [
        timed(lambda: sha256_hex(canonical_bytes(payload))) for _ in range(iterations)
    ]
    return summarise(samples)


# ---------------------------------------------------------------------------
# Daemon-backed benchmarks
# ---------------------------------------------------------------------------


class RunningDaemon:
    """Context manager that runs a real daemon in a background thread."""

    def __init__(self, storage_root: str, limits: "IpcLimits | None" = None) -> None:
        self._storage_root = storage_root
        self._daemon = WatcherDaemon(
            DaemonConfig(
                command=[sys.executable, AGENT],
                policy=Policy(),
                workspace_root=PROJECT_ROOT,
                cwd=PROJECT_ROOT,
                storage_root=storage_root,
                child_env={
                    "WATCHER_AGENT_MODE": "heartbeat",
                    "WATCHER_AGENT_SLEEP": "120",
                },
                heartbeat_interval=1.0,
                heartbeat_timeout=120.0,
                limits=limits,
                stdout=None,
            )
        )
        self._thread: "threading.Thread | None" = None
        self.exit_code: "int | None" = None

    @property
    def daemon(self) -> WatcherDaemon:
        return self._daemon

    def __enter__(self) -> "RunningDaemon":
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if (
                self._daemon.endpoint is not None
                and self._daemon.process is not None
                and self._daemon.process.started
            ):
                return self
            time.sleep(0.02)
        raise RuntimeError("daemon did not become ready")

    def _run(self) -> None:
        try:
            self.exit_code = self._daemon.run()
        except BaseException as exc:  # noqa: BLE001
            self.exit_code = -1
            print(f"daemon error: {exc!r}", file=sys.stderr)

    def auth_connection(self):
        # This benchmark is impersonating the protected client, and a client
        # authenticates with the session token. Reaching into the daemon for it
        # is deliberate: the daemon has no public accessor precisely so that
        # the token is not casually available to application code.
        limits = self._daemon._server.limits
        connection = connect(self._daemon.endpoint, timeout=10.0)
        connection.send(
            build_request(
                MessageType.HELLO,
                {
                    "token": self._daemon._token,
                    "pid": os.getpid(),
                    "protocol_version": 1,
                },
                session_id=self._daemon.session_id,
            ),
            limits,
        )
        response = connection.receive(limits, allowed_types=CLIENT_RECEIVE_TYPES)
        if not response.get("ok"):
            raise RuntimeError(f"benchmark client could not authenticate: {response}")
        return connection

    def evaluate(self, connection, resource: str = "/workspace/bench.txt") -> Any:
        limits = self._daemon._server.limits
        connection.send(
            build_request(
                MessageType.EVALUATE,
                {"event_type": "file_access", "action": "read", "resource": resource},
                session_id=self._daemon.session_id,
            ),
            limits,
        )
        return connection.receive(limits, allowed_types=CLIENT_RECEIVE_TYPES)

    def __exit__(self, exc_type, exc, tb) -> bool:
        self._daemon.stop("BENCHMARK_DONE")
        if self._thread is not None:
            self._thread.join(60)
        return False


def bench_ipc_roundtrip(iterations: int, storage_root: str) -> dict[str, Any]:
    with RunningDaemon(storage_root) as running:
        connection = running.auth_connection()
        # Warm up so the first-call costs are not in the sample.
        for _ in range(20):
            running.evaluate(connection)
        samples = [
            timed(lambda: running.evaluate(connection)) for _ in range(iterations)
        ]
        connection.close()
    return summarise(samples)


def bench_throughput(iterations: int, storage_root: str) -> dict[str, Any]:
    with RunningDaemon(storage_root) as running:
        connection = running.auth_connection()
        started = time.perf_counter()
        for _ in range(iterations):
            running.evaluate(connection)
        elapsed = time.perf_counter() - started
        connection.close()
        result = {
            "events": iterations,
            "seconds": round(elapsed, 4),
            "events_per_second": round(iterations / elapsed, 1),
            "mean_ms_per_event": round(elapsed / iterations * 1000.0, 4),
        }
    return result


def bench_concurrent(
    threads: int, per_thread: int, storage_root: str
) -> dict[str, Any]:
    limits = IpcLimits(
        max_connections_per_session=threads + 4, request_timeout=60.0
    )
    with RunningDaemon(storage_root, limits=limits) as running:
        connections = [running.auth_connection() for _ in range(threads)]
        latencies: list[float] = []
        lock = threading.Lock()
        errors: list[BaseException] = []

        def worker(connection) -> None:
            local: list[float] = []
            for _ in range(per_thread):
                try:
                    local.append(timed(lambda: running.evaluate(connection)))
                except BaseException as exc:  # noqa: BLE001
                    with lock:
                        errors.append(exc)
                    return
            with lock:
                latencies.extend(local)

        started = time.perf_counter()
        workers = [
            threading.Thread(target=worker, args=(connection,), daemon=True)
            for connection in connections
        ]
        for thread in workers:
            thread.start()
        for thread in workers:
            thread.join(180)
        elapsed = time.perf_counter() - started

        for connection in connections:
            connection.close()

        total = threads * per_thread
        sequences = [event.sequence for event in running.daemon.trace]
        result = {
            **summarise(latencies),
            "threads": threads,
            "requests": total,
            "errors": len(errors),
            "seconds": round(elapsed, 4),
            "events_per_second": round(total / elapsed, 1) if elapsed else 0.0,
            "sequence_is_dense": sequences == list(range(len(sequences))),
            "unique_event_hashes": len(
                {event.event_hash for event in running.daemon.trace}
            )
            == len(running.daemon.trace),
            "chain_valid": running.daemon.verify().valid,
        }
    return result


def bench_kill_latency(sessions: int, storage_root: str) -> dict[str, Any]:
    """Time from 'kill decided' to 'process tree gone'."""
    samples: list[float] = []
    for index in range(sessions):
        session_storage = os.path.join(storage_root, f"kill-{index}")
        daemon = WatcherDaemon(
            DaemonConfig(
                command=[sys.executable, "-c", "import time; time.sleep(120)"],
                storage_root=session_storage,
                cwd=PROJECT_ROOT,
                termination_grace=2.0,
            )
        )
        thread = threading.Thread(target=daemon.run, daemon=True)
        thread.start()

        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if daemon.process is not None and daemon.process.started:
                break
            time.sleep(0.01)
        else:
            thread.join(10)
            continue

        started = time.perf_counter()
        daemon.stop("BENCHMARK_KILL")
        thread.join(60)
        samples.append((time.perf_counter() - started) * 1000.0)

    return summarise(samples)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def print_section(title: str, payload: dict[str, Any]) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    for key, value in payload.items():
        if key.endswith("_ms"):
            print(f"  {key:<26} {value:>12.4f} ms")
        else:
            print(f"  {key:<26} {value}")


def main(argv: "Sequence[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description="The Watcher V2 benchmark")
    parser.add_argument(
        "--quick", action="store_true", help="run a short version of the benchmark"
    )
    parser.add_argument(
        "--output",
        default="benchmark-results.json",
        help="where to write machine-readable results",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    scale = 0.25 if args.quick else 1.0
    policy_iterations = int(20_000 * scale)
    poe_iterations = int(10_000 * scale)
    hash_iterations = int(50_000 * scale)
    ipc_iterations = int(1_000 * scale)
    throughput_iterations = int(2_000 * scale)
    concurrent_threads = 4
    concurrent_per_thread = int(250 * scale)
    kill_sessions = 3

    storage_root = tempfile.mkdtemp(prefix="watcher-benchmark-")
    results: dict[str, Any] = {
        "generated_at": int(time.time()),
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "quick": args.quick,
        "scales": {
            "policy_iterations": policy_iterations,
            "poe_iterations": poe_iterations,
            "hash_iterations": hash_iterations,
            "ipc_iterations": ipc_iterations,
            "throughput_iterations": throughput_iterations,
            "concurrent_threads": concurrent_threads,
            "concurrent_per_thread": concurrent_per_thread,
            "kill_sessions": kill_sessions,
        },
    }

    print("The Watcher - V2 benchmark")
    print("=" * 64)

    try:
        results["canonical_hash"] = bench_canonical_hash(hash_iterations)
        print_section("canonical JSON + SHA-256", results["canonical_hash"])

        results["policy_evaluation"] = bench_policy(policy_iterations)
        print_section("policy evaluation", results["policy_evaluation"])

        results["poe_append"] = bench_poe_append(poe_iterations)
        print_section("PoE event append (hash chained)", results["poe_append"])

        results["ipc_roundtrip"] = bench_ipc_roundtrip(ipc_iterations, storage_root)
        print_section(
            "IPC round trip (EVALUATE, end to end)", results["ipc_roundtrip"]
        )

        results["throughput_sequential"] = bench_throughput(
            throughput_iterations, storage_root
        )
        print_section("sequential throughput", results["throughput_sequential"])

        results["throughput_concurrent"] = bench_concurrent(
            concurrent_threads, concurrent_per_thread, storage_root
        )
        print_section(
            "concurrent throughput", results["throughput_concurrent"]
        )

        results["kill_latency"] = bench_kill_latency(kill_sessions, storage_root)
        print_section(
            "kill decision -> process tree terminated", results["kill_latency"]
        )
    finally:
        shutil.rmtree(storage_root, ignore_errors=True)

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, sort_keys=True)

    print()
    print("=" * 64)
    print(f"results written to {os.path.abspath(args.output)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
