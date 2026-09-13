"""Print the headline numbers from a V3 benchmark result file."""

import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "benchmark-v3-results.json"
data = json.load(open(path))

print(f"platform: {data['platform']}  kernel: {data['kernel']}  python: {data['python']}")
print(f"backends: {data['available_backends']}  landlock ABI: {data['landlock_abi']}  seccomp: {data['seccomp_available']}")
print(f"enforcement available: {data['enforcement_available']}")
print()

if "lifecycle" in data:
    life = data["lifecycle"]
    print(f"lifecycle ({life['iterations']} sessions)")
    for stage in ("prepare", "launch", "inspect", "terminate"):
        block = life[stage]
        print(f"  {stage:<10} median {block['median_ms']:>9.2f} ms   p95 {block['p95_ms']:>9.2f} ms")
    print(f"  {'total':<10} median {life['total_median_ms']:>9.2f} ms")
    print()

if "kill_latency" in data:
    kill = data["kill_latency"]
    print("kill latency (isolate -> terminate -> verify empty)")
    print(f"  iterations           {kill['iterations']}")
    print(f"  median               {kill['isolate_and_terminate']['median_ms']:.2f} ms")
    print(f"  verified empty       {kill['verified_empty']}/{kill['iterations']}")
    print(f"  survivors            {kill['survivors']}")
    print()

if "mode_comparison" in data:
    print("same agent, V2 (supervisor) vs V3 (contained)")
    print(f"  {'group':<12} {'V2 escapes':>10} {'V2 ms':>8} {'V3 escapes':>10} {'V3 ms':>8}  verified")
    for group, entry in data["mode_comparison"].items():
        print(
            f"  {group:<12} {entry['v2']['escape_count']:>10} {entry['v2']['wall_ms']:>8.0f}"
            f" {entry['v3']['escape_count']:>10} {entry['v3']['wall_ms']:>8.0f}"
            f"  {entry['v3']['containment_verified']}"
        )
        if entry["v2"]["escaped"]:
            print(f"      V2 let through: {', '.join(entry['v2']['escaped'])}")
    print()

if "contained_only" in data:
    attempts = sum(entry["attempts"] for entry in data["contained_only"].values())
    escaped = sum(entry["escape_count"] for entry in data["contained_only"].values())
    print(f"destructive groups, contained only: {attempts} attempts, {escaped} escaped")
    for group, entry in data["contained_only"].items():
        print(
            f"  {group:<10} attempts={entry['attempts']:<3} escaped={entry['escape_count']}"
            f"  verified={entry['containment_verified']}"
            f"  empty_after={entry['containment_empty_after']}"
        )
