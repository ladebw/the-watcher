"""Policy V1 benchmark: document parse, normalisation and digest cost.

    python benchmarks/benchmark_policy_v1.py
    python benchmarks/benchmark_policy_v1.py --quick
    python benchmarks/benchmark_policy_v1.py --output benchmark-policy-v1-results.json

The question this answers is narrow, and worth answering before anyone optimises
anything: **is loading a policy document negligible at startup?** A policy is
read once per session, so anything in the hundreds of microseconds is free. A
second question is measured alongside it because it is the one that will matter
later: how much does *matching* one path against one pattern cost, since Phase 2
will do that once per rule per action.

Reported figures are medians, with the maximum alongside. The maximum on a
shared machine is dominated by the scheduler, not the code, so it is printed to
be seen rather than to be trusted - a 30 ms "worst case" for an 8 us call is
the host, not the matcher.

Nothing here is a promise about another machine. The environment is printed with
the results for exactly that reason.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
from typing import Any, Callable

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from the_watcher import policy_v1  # noqa: E402
from the_watcher.poe.canonical import canonical_bytes  # noqa: E402
from the_watcher.policy_v1 import (  # noqa: E402
    MAX_PATTERN_LENGTH,
    compile_pattern,
    load_policy,
    loads_policy,
    parse_policy,
)

#: A realistic document: the shape the design document proposes, with a handful
#: of rules in each section.
TYPICAL: dict[str, Any] = {
    "version": 1,
    "name": "benchmark",
    "filesystem": {
        "allow": ["/workspace/**"],
        "deny": ["/etc/**", "/root/.ssh/**", "/var/**", "/proc/**"],
    },
    "network": {
        "mode": "restricted",
        "allow": ["api.openai.com", "api.deepseek.com"],
    },
    "process": {"max_children": 8, "max_runtime_seconds": 600},
    "resources": {"memory_mb": 1024, "cpu_seconds": 600},
    "tripwires": ["/var/run/docker.sock", "/root/.ssh/id_rsa"],
    "on_violation": {"filesystem": "DENY", "tripwire": "KILL"},
}

#: A deliberately large document, to show how cost scales with rule count.
LARGE_RULES = 1000

#: Adversarial matcher shapes, all sized to the enforced caps. Each pairs a
#: pattern an operator could plausibly write with a subject the *supervised* agent
#: chooses, so the cost of one match attempt is a security property and not a
#: curiosity: the party being watched must not be able to spend the watcher's CPU
#: by picking awkward paths.
#:
#: The third element is the cost of the same shape and subject measured on the
#: pre-review revision (milliseconds, median, same host). ``None`` means the shape
#: was not measured before the review. Comparisons are only ever made
#: shape-for-shape; comparing one shape's "before" with another shape's "after"
#: would flatter the change and prove nothing.
ADVERSARIAL_SHAPES: list[tuple[str, str, "float | None"]] = [
    ("star_then_question_run", "/" + "*" + "?" * 2040, 1678.0),
    ("alternating_star_question", "/" + "*?" * 1020, 2.827),
    ("many_literal_runs", "/" + "*a" * 1020 + "*", None),
    ("trailing_literal_mismatch", "/" + "*a" * 1020 + "z", 2.759),
    ("block_star_question_run", "/**/" + "*" + "?" * 2040, 1313.0),
    ("question_star_runs", "/" + "?*" * 1020, None),
    ("star_then_question_pairs", "/" + "*" + "a?" * 1020, None),
]

#: The subject every adversarial shape is matched against: one 4095-character
#: segment, i.e. the longest single segment a capped subject can hold.
ADVERSARIAL_SUBJECT = "/" + "a" * (MAX_PATTERN_LENGTH - 1)

#: Segment-level adversarial shapes: many ``**`` at the segment cap, matched
#: against the longest near-miss subject a capped document allows. The reported
#: comparison count is the complexity evidence - it must stay at or below the
#: proven ``(pattern_segments + 1) x (subject_segments + 1)`` state bound, not
#: the naive ``pattern_segments x subject_segments`` - and it is exact rather
#: than timed, so it means the same thing on every machine.
SEGMENT_SHAPES: list[tuple[str, list[str]]] = [
    ("many_double_star", ["**", "a" * 28] * 128),
    ("star_before_every_segment", ["**", "?" * 14] * 128),
    ("dense_double_star_pairs", ["**", "**", "a" * 14] * 85),
    ("star_then_question_segments", ["**"] * 128 + ["?" * 15] * 128),
]

#: 256 segments and 4096 characters: the largest subject the caps permit.
SEGMENT_SUBJECT = ["a" * 15] * 255 + ["b" * 15]


def measure(call: Callable[[], Any], repeats: int) -> dict[str, float]:
    """Return median/max seconds per call, with one warm-up discarded."""
    call()
    samples: list[float] = []
    for _ in range(repeats):
        started = time.perf_counter()
        call()
        samples.append(time.perf_counter() - started)
    return {
        "median_us": statistics.median(samples) * 1e6,
        "max_us": max(samples) * 1e6,
        "repeats": float(repeats),
    }


def run(quick: bool) -> dict[str, Any]:
    repeats = 60 if quick else 300
    results: dict[str, Any] = {
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "measurements": {},
    }

    text = json.dumps(TYPICAL)
    large_document = dict(TYPICAL)
    large_document["filesystem"] = {
        "allow": ["/workspace/**"],
        "deny": ["/deny/%d/**" % index for index in range(LARGE_RULES)],
    }
    large_text = json.dumps(large_document)

    results["document_bytes"] = len(text)
    results["large_document_bytes"] = len(large_text)
    results["large_rule_count"] = LARGE_RULES

    policy = loads_policy(text)
    pattern = compile_pattern("/workspace/**", "bench")

    measurements = results["measurements"]
    measurements["loads_policy"] = measure(lambda: loads_policy(text), repeats)
    measurements["parse_policy"] = measure(lambda: parse_policy(TYPICAL), repeats)
    measurements["document_digest_cached"] = measure(
        lambda: policy.document_digest, max(repeats, 2000)
    )
    measurements["canonical_encode"] = measure(
        lambda: canonical_bytes(policy.normalized()), repeats * 3
    )
    measurements["path_pattern_match"] = measure(
        lambda: pattern.matches("/workspace/a/b/c.txt"), repeats * 20
    )
    measurements["loads_policy_large"] = measure(
        lambda: loads_policy(large_text), max(10, repeats // 10)
    )

    # File loading adds the read/decode boundary; worth separating so the
    # in-memory figures above are not mistaken for I/O numbers.
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "watcher.json")
        with open(path, "wb") as handle:
            handle.write(text.encode("utf-8"))
        measurements["load_policy_from_file"] = measure(
            lambda: load_policy(path), repeats
        )

    # A per-action cost estimate for Phase 2, so the number is on record before
    # anyone builds an evaluator on top of it.
    rules = len(policy.filesystem.deny) + len(policy.filesystem.allow)
    per_match = measurements["path_pattern_match"]["median_us"]
    results["evaluation_note"] = {
        "rules_in_typical_document": rules,
        "median_us_per_pattern_match": round(per_match, 3),
        "estimated_us_to_match_every_rule": round(per_match * rules, 1),
        "note": (
            "Phase 2 should canonicalise the subject path once per action rather "
            "than once per rule; matches() validates its subject on every call, "
            "which is deliberate (a matcher must not answer 'no match' to a "
            "question it cannot parse) but is not free."
        ),
    }

    # Adversarial shapes: the worst case a supervised agent can reach by choosing
    # its own paths. Measured at the caps, against the same 4095-character subject.
    adversarial: dict[str, Any] = {}
    for label, shape, before_ms in ADVERSARIAL_SHAPES:
        compiled = compile_pattern(shape, "bench")
        stats = measure(
            lambda p=compiled: p.matches(ADVERSARIAL_SUBJECT),
            max(5, repeats // 20),
        )
        stats["pattern_length"] = float(len(shape))
        stats["previous_revision_ms"] = before_ms
        adversarial[label] = stats
    results["adversarial"] = adversarial
    results["adversarial_subject_length"] = len(ADVERSARIAL_SUBJECT)
    results["adversarial_note"] = {
        "worst_median_us": round(
            max(stats["median_us"] for stats in adversarial.values()), 3
        ),
        "note": (
            "The previous matcher kept a single backtrack point and re-scanned the "
            "whole pattern tail once per subject character, so its cost grew with "
            "pattern x subject. star_then_question_run measured ~1.7 s per match "
            "attempt on the previous revision. Shapes whose previous cost was "
            "already low move less; what matters is that no shape is now unbounded, "
            "so a path chosen by the supervised agent cannot consume the "
            "supervisor's CPU."
        ),
    }

    # Segment level (``**``): the comparison count is the complexity evidence and
    # is exact, not timed. Each comparison is one (pattern_position,
    # subject_position) state, the matcher never re-enters a state, and there is
    # no comparison cache, so the count is a direct measure of the state bound.
    subject = "/" + "/".join(SEGMENT_SUBJECT)
    segment_rows: list[dict[str, Any]] = []
    for label, segments in SEGMENT_SHAPES:
        pattern = "/" + "/".join(segments)
        compiled = compile_pattern(pattern, "bench")

        original = policy_v1._segment_matches
        comparisons: list[int] = []

        def counting(p: str, t: str, _original=original) -> bool:
            comparisons.append(1)
            return _original(p, t)

        policy_v1._segment_matches = counting  # type: ignore[assignment]
        try:
            decision = compiled.matches(subject)
        finally:
            policy_v1._segment_matches = original  # type: ignore[assignment]

        stats = measure(
            lambda c=compiled, s=subject: c.matches(s), max(5, repeats // 20)
        )
        segment_rows.append(
            {
                "shape": label,
                "pattern_segments": len(segments),
                "subject_segments": len(SEGMENT_SUBJECT),
                "comparisons": len(comparisons),
                "bound": (len(segments) + 1) * (len(SEGMENT_SUBJECT) + 1),
                "decision": decision,
                "median_us": round(stats["median_us"], 3),
                "max_us": round(stats["max_us"], 3),
            }
        )
    results["segment_adversarial"] = segment_rows
    results["segment_adversarial_note"] = {
        "worst_comparisons": max(row["comparisons"] for row in segment_rows),
        "bound": segment_rows[0]["bound"],
        "note": (
            "Comparisons count (pattern_position, subject_position) states visited. "
            "The bound column is (pattern_segments + 1) x (subject_segments + 1): "
            "257 x 257 = 66,049 at the caps. It is NOT pattern_segments x "
            "subject_segments - a lone ** against 77 segments visits 78 states, so "
            "P*T is false as an absolute bound, though the cost is still O(P*T). The "
            "bound comes from a potential-function argument recorded on "
            "_segments_match; the matcher never re-enters a state, and a dict memo "
            "of comparisons that could never hit was removed."
        ),
    }
    return results


def report(results: dict[str, Any]) -> None:
    environment = results["environment"]
    print(
        "Policy V1 benchmark  "
        f"(Python {environment['python']}, {environment['machine']})"
    )
    print(f"platform: {environment['platform']}")
    print(
        f"typical document: {results['document_bytes']} bytes; "
        f"large document: {results['large_document_bytes']} bytes "
        f"({results['large_rule_count']} rules)"
    )
    print()
    print(f"{'measurement':<28}{'median':>12}{'max':>14}")
    print("-" * 54)
    for name, stats in results["measurements"].items():
        median, maximum = stats["median_us"], stats["max_us"]
        if median >= 1000:
            shown = f"{median / 1000:.2f} ms"
        else:
            shown = f"{median:.2f} us"
        if maximum >= 1000:
            worst = f"{maximum / 1000:.2f} ms"
        else:
            worst = f"{maximum:.2f} us"
        print(f"{name:<28}{shown:>12}{worst:>14}")
    print()
    note = results["evaluation_note"]
    print(
        "phase 2 note: {} rules x {:.3f} us = ~{:.1f} us per full match pass"
        .format(
            note["rules_in_typical_document"],
            note["median_us_per_pattern_match"],
            note["estimated_us_to_match_every_rule"],
        )
    )
    print("(the max column is scheduler noise on a shared machine, not the code)")

    print()
    print(
        "adversarial match cost  "
        f"(subject {results['adversarial_subject_length']} chars, at the caps)"
    )
    print(
        f"{'shape':<28}{'pattern':>9}{'median':>12}{'max':>13}{'before':>13}"
    )
    print("-" * 75)
    for name, stats in results["adversarial"].items():
        before = stats["previous_revision_ms"]
        if before is None:
            shown_before = "-"
        elif before >= 1000:
            shown_before = f"{before / 1000:.2f} s"
        else:
            shown_before = f"{before:.2f} ms"
        print(
            f"{name:<28}{int(stats['pattern_length']):>9}"
            f"{stats['median_us']:>10.1f} us{stats['max_us']:>10.1f} us"
            f"{shown_before:>13}"
        )
    worst = results["adversarial_note"]["worst_median_us"]
    print()
    print(
        f"worst adversarial shape now: {worst:.1f} us "
        f"(previous revision, worst shape was 1.7 s)"
    )
    print("(a pattern is operator-chosen; the subject is chosen by the supervised agent)")

    print()
    print(
        "segment-level ( ** ) adversarial cost  "
        f"(subject {len(SEGMENT_SUBJECT)} segments)"
    )
    print(
        f"{'shape':<28}{'P':>5}{'T':>5}{'comparisons':>13}{'bound (P+1)(T+1)':>19}"
        f"{'median':>11}{'decision':>10}"
    )
    print("-" * 91)
    for row in results["segment_adversarial"]:
        print(
            f"{row['shape']:<28}{row['pattern_segments']:>5}"
            f"{row['subject_segments']:>5}{row['comparisons']:>13}"
            f"{row['bound']:>19}{row['median_us']:>9.1f} us"
            f"{str(row['decision']):>10}"
        )
    segment_note = results["segment_adversarial_note"]
    print()
    print(
        f"worst comparisons: {segment_note['worst_comparisons']} of a "
        f"{segment_note['bound']} bound (exact count, not a timing)"
    )
    print("(states visited <= (P+1)(T+1): NOT P*T, which 78 > 77 at P=1 T=77 disproves)")


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--quick", action="store_true", help="fewer repeats, faster run"
    )
    parser.add_argument(
        "--output", metavar="FILE", help="also write the raw results as JSON"
    )
    args = parser.parse_args(argv)

    results = run(args.quick)
    report(results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(results, handle, indent=2, sort_keys=True)
        print(f"\nraw results written to {args.output}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
