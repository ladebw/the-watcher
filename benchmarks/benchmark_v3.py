"""V3 benchmark: enforcement cost, and what V2 versus V3 actually stops.

    python benchmarks/benchmark_v3.py
    python benchmarks/benchmark_v3.py --quick
    python benchmarks/benchmark_v3.py --output benchmark-v3-results.json

Two things are measured.

**Cost.** Preparing, launching, inspecting and tearing down a containment unit,
plus the total wall time of a real contained session.

**Effect.** The same adversarial agent is run twice: once under V2 supervision
(the Watcher decides and the agent is trusted to ask) and once under V3
containment (the kernel decides). The comparison reports how many of its
attempts *succeeded* in each case, which is the number that matters.

A deliberate limitation, stated here rather than discovered later: only the
non-destructive attempt groups can be run unenforced. Under V2 an agent that
ignores the Watcher can write to ``/etc``, delete files and fork without limit;
running those groups in a benchmark against the host is not acceptable. Their
V3 results are measured anyway, because there they are contained.

On a host where enforcement is unavailable the benchmark reports that plainly
and measures what it can, instead of printing numbers that mean nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import sys
import tempfile
import time
from typing import Any, Callable, Sequence

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from the_watcher.enforcement import (  # noqa: E402
    EnforcementMode,
    SandboxSpec,
    detect_capabilities,
    get_preset,
    select_backend,
)

BYPASS_AGENT = os.path.join(
    PROJECT_ROOT, "examples", "v3_bypass_agents", "bypass_agent.py"
)

#: Attempt groups that are safe to run *without* containment.
SAFE_GROUPS = ("file", "network", "workspace")
#: Attempt groups that only make sense (or are only acceptable) contained.
CONTAINED_ONLY_GROUPS = ("syscall", "process", "root", "escape")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    index = max(0, min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1)))))
    return float(ordered[index])


def summarise(samples: Sequence[float]) -> dict[str, Any]:
    if not samples:
        return {"count": 0}
    values = [float(sample) for sample in samples]
    return {
        "count": len(values),
        "median_ms": round(statistics.median(values), 4),
        "mean_ms": round(statistics.fmean(values), 4),
        "p95_ms": round(percentile(values, 0.95), 4),
        "min_ms": round(min(values), 4),
        "max_ms": round(max(values), 4),
    }


def timed(operation: Callable[[], Any]) -> tuple[Any, float]:
    started = time.perf_counter()
    value = operation()
    return value, (time.perf_counter() - started) * 1000.0


def print_section(title: str, payload: dict[str, Any]) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    for key, value in payload.items():
        if key.endswith("_ms"):
            print(f"  {key:<26} {value:>12.4f} ms")
        else:
            print(f"  {key:<26} {value}")


def stage_workspace(root: str) -> str:
    """A workspace on a Linux-native filesystem, holding the bypass agent."""
    workspace = os.path.join(root, "workspace")
    os.makedirs(workspace, exist_ok=True)
    shutil.copyfile(BYPASS_AGENT, os.path.join(workspace, "bypass_agent.py"))
    return workspace


def read_agent_report(workspace: str, group: str) -> dict:
    path = os.path.join(workspace, f"agent-{group}.json")
    if not os.path.isfile(path):
        return {}
    with open(path) as handle:
        return json.load(handle)


def agent_command(workspace: str, group: str) -> list[str]:
    return [
        sys.executable,
        os.path.join(workspace, "bypass_agent.py"),
        "--attempt",
        group,
        "--json-out",
        os.path.join(workspace, f"agent-{group}.json"),
    ]


# ---------------------------------------------------------------------------
# lifecycle cost
# ---------------------------------------------------------------------------


def bench_lifecycle(iterations: int, root: str, capabilities) -> dict[str, Any]:
    """Prepare, launch, inspect and terminate a unit, repeatedly."""
    profile = get_preset("research-strict")
    workspace = stage_workspace(root)
    runtime_root = os.path.join(root, "runtime")

    prepare_samples: list[float] = []
    launch_samples: list[float] = []
    inspect_samples: list[float] = []
    terminate_samples: list[float] = []

    for index in range(iterations):
        enforcer = select_backend(profile, capabilities, runtime_root=runtime_root)
        spec = SandboxSpec(
            command=(sys.executable, "-c", "import time; time.sleep(1)"),
            profile=profile,
            workspace_host=workspace,
            cwd_inner=workspace,
            unit_key=f"bench-{index}",
        )

        _, prepare_ms = timed(lambda: enforcer.prepare(profile, spec))
        prepare_samples.append(prepare_ms)

        unit, launch_ms = timed(lambda: enforcer.launch(spec))
        launch_samples.append(launch_ms)

        _, inspect_ms = timed(lambda: enforcer.inspect(unit))
        inspect_samples.append(inspect_ms)

        unit.metadata["network_mode"] = profile.network.value
        _, terminate_ms = timed(lambda: enforcer.terminate(unit, grace=1.0))
        terminate_samples.append(terminate_ms)

    return {
        "iterations": iterations,
        "prepare": summarise(prepare_samples),
        "launch": summarise(launch_samples),
        "inspect": summarise(inspect_samples),
        "terminate": summarise(terminate_samples),
        "total_median_ms": round(
            summarise(prepare_samples)["median_ms"]
            + summarise(launch_samples)["median_ms"]
            + summarise(terminate_samples)["median_ms"],
            4,
        ),
    }


def bench_kill_latency(iterations: int, root: str, capabilities) -> dict[str, Any]:
    """How long it takes to isolate, terminate and prove a unit empty."""
    profile = get_preset("research-strict")
    workspace = stage_workspace(root)
    runtime_root = os.path.join(root, "runtime")

    durations: list[float] = []
    verified_empty = 0
    survivors_total: list[int] = []

    for index in range(iterations):
        enforcer = select_backend(profile, capabilities, runtime_root=runtime_root)
        spec = SandboxSpec(
            command=(sys.executable, "-c", "import time; time.sleep(60)"),
            profile=profile,
            workspace_host=workspace,
            cwd_inner=workspace,
            unit_key=f"kill-{index}",
        )
        enforcer.prepare(profile, spec)
        unit = enforcer.launch(spec)
        time.sleep(0.15)  # let the interpreter start

        started = time.perf_counter()
        enforcer.isolate_network(unit)
        outcome = enforcer.terminate(unit, grace=1.0)
        empty, survivors = enforcer.verify_empty(unit)
        durations.append((time.perf_counter() - started) * 1000.0)

        if empty and outcome.remaining == ():
            verified_empty += 1
        survivors_total.extend(survivors)

    return {
        "iterations": iterations,
        "isolate_and_terminate": summarise(durations),
        "verified_empty": verified_empty,
        "verification_failures": iterations - verified_empty,
        "survivors": sorted(set(survivors_total)),
    }


# ---------------------------------------------------------------------------
# V2 versus V3 on the same agent
# ---------------------------------------------------------------------------


def _run_daemon(command: list[str], workspace: str, storage_root: str, enforced: bool):
    """Run one session and return ``(exit_code, wall_ms, metadata)``."""
    from the_watcher import Policy
    from the_watcher.supervisor import DaemonConfig, WatcherDaemon

    config = DaemonConfig(
        command=command,
        policy=Policy(workspace_root=workspace),
        workspace_root=workspace,
        cwd=workspace,
        storage_root=storage_root,
        heartbeat_interval=0.0,
        enforcement=EnforcementMode.ENFORCED if enforced else EnforcementMode.OFF,
        containment=get_preset("research-strict") if enforced else None,
    )
    daemon = WatcherDaemon(config)

    started = time.perf_counter()
    exit_code = daemon.run()
    wall_ms = (time.perf_counter() - started) * 1000.0

    metadata: dict[str, Any] = {}
    try:
        metadata = daemon.stats()["metadata"]
    except Exception:  # noqa: BLE001 - a failed session may have no metadata
        pass

    return exit_code, wall_ms, metadata


def bench_mode_comparison(root: str, groups: Sequence[str]) -> dict[str, Any]:
    """Run the same agent under V2 and V3 and count what got through."""
    results: dict[str, Any] = {}

    for group in groups:
        workspace = stage_workspace(os.path.join(root, group))
        storage = os.path.join(root, group, "storage")
        os.makedirs(storage, exist_ok=True)

        entry: dict[str, Any] = {}

        # V2: the Watcher decides, and the agent never asks.
        exit_code, wall_ms, metadata = _run_daemon(
            agent_command(workspace, group), workspace, storage, enforced=False
        )
        v2_report = read_agent_report(workspace, group)
        entry["v2"] = {
            "exit_code": exit_code,
            "wall_ms": round(wall_ms, 3),
            "escaped": list(v2_report.get("escaped") or []),
            "escape_count": len(v2_report.get("escaped") or []),
            "enforced": None,
        }

        # V3: the kernel decides, whether or not the agent asks.
        os.remove(os.path.join(workspace, f"agent-{group}.json"))
        exit_code, wall_ms, metadata = _run_daemon(
            agent_command(workspace, group), workspace, storage, enforced=True
        )
        v3_report = read_agent_report(workspace, group)
        enforcement = (metadata or {}).get("enforcement") or {}
        entry["v3"] = {
            "exit_code": exit_code,
            "wall_ms": round(wall_ms, 3),
            "escaped": list(v3_report.get("escaped") or []),
            "escape_count": len(v3_report.get("escaped") or []),
            "enforced": bool(enforcement.get("backend")),
            "backend": enforcement.get("backend"),
            "profile_digest": enforcement.get("profile_digest"),
            "containment_verified": (enforcement.get("evidence") or {}).get("verified"),
            "containment_empty_after": (enforcement.get("termination") or {}).get("empty"),
        }

        entry["overhead_ms"] = round(
            entry["v3"]["wall_ms"] - entry["v2"]["wall_ms"], 3
        )
        entry["overhead_ratio"] = (
            round(entry["v3"]["wall_ms"] / entry["v2"]["wall_ms"], 3)
            if entry["v2"]["wall_ms"]
            else None
        )
        results[group] = entry

    return results


def bench_contained_only(root: str, groups: Sequence[str]) -> dict[str, Any]:
    """Groups that are only acceptable to run *inside* containment."""
    results: dict[str, Any] = {}
    for group in groups:
        workspace = stage_workspace(os.path.join(root, f"contained-{group}"))
        storage = os.path.join(root, f"contained-{group}", "storage")
        os.makedirs(storage, exist_ok=True)

        exit_code, wall_ms, metadata = _run_daemon(
            agent_command(workspace, group), workspace, storage, enforced=True
        )
        report = read_agent_report(workspace, group)
        enforcement = (metadata or {}).get("enforcement") or {}
        results[group] = {
            "exit_code": exit_code,
            "wall_ms": round(wall_ms, 3),
            "escaped": list(report.get("escaped") or []),
            "escape_count": len(report.get("escaped") or []),
            "attempts": sum(
                1 for value in report.values() if isinstance(value, dict)
            ),
            "containment_verified": (enforcement.get("evidence") or {}).get("verified"),
            "containment_empty_after": (enforcement.get("termination") or {}).get("empty"),
            "note": "not run unenforced: destructive on an unprotected host",
        }
    return results


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv: "Sequence[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description="The Watcher V3 benchmark")
    parser.add_argument("--quick", action="store_true", help="a short version")
    parser.add_argument(
        "--output",
        default="benchmark-v3-results.json",
        help="where to write machine-readable results",
    )
    parser.add_argument(
        "--workspace-root",
        default=None,
        help=(
            "where to stage the benchmark workspace; must be on a "
            "Linux-native filesystem (default: a temporary directory)"
        ),
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    scale = 0.25 if args.quick else 1.0
    lifecycle_iterations = max(3, int(12 * scale))
    kill_iterations = max(3, int(6 * scale))

    capabilities = detect_capabilities(refresh=True)

    print("The Watcher - V3 benchmark")
    print("=" * 66)
    print(f"platform:          {sys.platform} ({capabilities.arch})")
    print(f"kernel:            {capabilities.kernel_release}")
    print(f"enforced mode:     {'AVAILABLE' if capabilities.enforced_mode_available else 'UNAVAILABLE'}")
    if capabilities.enforced_mode_available:
        print(f"backend:           {', '.join(capabilities.available_backends)}")
        print(f"landlock ABI:      {capabilities.landlock_abi}")
        print(f"seccomp:           {capabilities.seccomp_available}")
    else:
        for problem in capabilities.problems:
            print(f"  reason:          {problem}")

    root = args.workspace_root or tempfile.mkdtemp(prefix="watcher-v3-benchmark-")
    owns_root = args.workspace_root is None
    os.makedirs(root, exist_ok=True)

    results: dict[str, Any] = {
        "generated_at": int(time.time()),
        "platform": sys.platform,
        "kernel": capabilities.kernel_release,
        "python": sys.version.split()[0],
        "quick": args.quick,
        "enforcement_available": capabilities.enforced_mode_available,
        "available_backends": list(capabilities.available_backends),
        "landlock_abi": capabilities.landlock_abi,
        "seccomp_available": capabilities.seccomp_available,
        "workspace_root": root,
    }

    try:
        if not capabilities.enforced_mode_available:
            results["skipped"] = (
                "V3 enforcement is unavailable on this host, so no containment "
                "numbers were produced. This is reported rather than estimated."
            )
            print()
            print("No containment backend is available here, so the V3")
            print("measurements are skipped. Nothing is estimated.")
        else:
            print()
            print("Measuring containment lifecycle cost...")
            results["lifecycle"] = bench_lifecycle(
                lifecycle_iterations, root, capabilities
            )
            print_section("containment lifecycle", results["lifecycle"])

            print()
            print("Measuring kill latency...")
            results["kill_latency"] = bench_kill_latency(
                kill_iterations, root, capabilities
            )
            print_section("kill: isolate -> terminate -> verify", results["kill_latency"])

            print()
            print("Running the same agent under V2 and V3...")
            results["mode_comparison"] = bench_mode_comparison(root, SAFE_GROUPS)
            for group, entry in results["mode_comparison"].items():
                print()
                print(f"  {group}")
                print(
                    f"    V2 (supervisor): {entry['v2']['escape_count']} escaped"
                    f"  {entry['v2']['wall_ms']:.0f} ms"
                )
                print(
                    f"    V3 (contained):  {entry['v3']['escape_count']} escaped"
                    f"  {entry['v3']['wall_ms']:.0f} ms"
                    f"  (backend={entry['v3']['backend']},"
                    f" verified={entry['v3']['containment_verified']})"
                )
                if entry["v2"]["escaped"]:
                    print(f"      V2 let through: {', '.join(entry['v2']['escaped'])}")

            print()
            print("Running the destructive groups contained only...")
            results["contained_only"] = bench_contained_only(
                root, CONTAINED_ONLY_GROUPS
            )
            for group, entry in results["contained_only"].items():
                print(
                    f"  {group:<10} attempts={entry['attempts']:<3}"
                    f" escaped={entry['escape_count']}"
                    f"  verified={entry['containment_verified']}"
                    f"  empty_after={entry['containment_empty_after']}"
                )
    finally:
        if owns_root:
            shutil.rmtree(root, ignore_errors=True)

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, sort_keys=True)

    print()
    print("=" * 66)
    print(f"results written to {os.path.abspath(args.output)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
