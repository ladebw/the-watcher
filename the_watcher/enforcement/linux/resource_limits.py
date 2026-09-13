"""Resource ceilings applied with ``setrlimit``.

Standard library only, and free of intra-package imports, because this file is
copied into the sandbox and imported by the exec guard.

An honest note on ``RLIMIT_NPROC``
----------------------------------
``RLIMIT_NPROC`` is a **per-uid, host-wide** ceiling, not a per-process-tree
one: the kernel checks it against the number of processes owned by the same
uid in the initial user namespace. Setting it to a small absolute number would
therefore block the workload *and* the operator's other processes.

So the guard sets it to ``baseline + budget``, where ``baseline`` is the uid's
current process count measured at launch. That caps how many processes the
sandbox can *add*, which is the property that matters for a fork-bomb test,
while leaving existing processes alone. The raw applied value and the measured
baseline are both recorded so the audit trail states exactly what was done.

``RLIMIT_AS`` (virtual address space) is used for the memory ceiling because
it needs no cgroup delegation. It is a real kernel refusal, but it bounds
*address space*, not resident memory, so it is stricter than an RSS limit in
some cases and weaker in others.
"""

from __future__ import annotations

import math
import os
import resource
from typing import Any, Mapping

MEBIBYTE = 1024 * 1024


def count_user_processes() -> int:
    """Best-effort count of processes owned by the current real uid."""
    uid = os.getuid()
    count = 0
    try:
        entries = os.listdir("/proc")
    except OSError:
        return 0
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/status", "r", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("Uid:"):
                        if int(line.split()[1]) == uid:
                            count += 1
                        break
        except (OSError, ValueError, IndexError):
            continue
    return count


def _set(limit: int, value: "int | None", applied: dict[str, Any], problems: list[str], name: str) -> None:
    if value is None:
        return
    try:
        soft, hard = resource.getrlimit(limit)
        # Never raise a hard limit; only tighten.
        new_hard = value if hard == resource.RLIM_INFINITY else min(hard, value)
        resource.setrlimit(limit, (new_hard, new_hard))
        applied[name] = new_hard
    except (ValueError, OSError) as exc:
        problems.append(f"{name}: {type(exc).__name__}: {exc}")


def apply_limits(
    processes: Mapping[str, Any],
    resources: Mapping[str, Any],
    nproc_baseline: "int | None" = None,
) -> dict[str, Any]:
    """Apply the profile's ceilings to the calling process."""
    applied: dict[str, Any] = {}
    problems: list[str] = []

    max_processes = int(processes.get("max_processes") or 0)
    if max_processes > 0:
        baseline = count_user_processes() if nproc_baseline is None else int(nproc_baseline)
        raw = baseline + max_processes
        _set(resource.RLIMIT_NPROC, raw, applied, problems, "RLIMIT_NPROC")
        applied["nproc_baseline"] = baseline
        applied["nproc_budget"] = max_processes

    max_files = int(processes.get("max_open_files") or 0)
    if max_files > 0:
        _set(resource.RLIMIT_NOFILE, max_files, applied, problems, "RLIMIT_NOFILE")

    max_stack = int(processes.get("max_stack_mb") or 0)
    if max_stack > 0:
        _set(resource.RLIMIT_STACK, max_stack * MEBIBYTE, applied, problems, "RLIMIT_STACK")

    memory_mb = resources.get("memory_mb")
    if memory_mb:
        _set(resource.RLIMIT_AS, int(memory_mb) * MEBIBYTE, applied, problems, "RLIMIT_AS")

    file_size_mb = resources.get("max_file_size_mb")
    if file_size_mb is not None:
        _set(
            resource.RLIMIT_FSIZE,
            int(file_size_mb) * MEBIBYTE,
            applied,
            problems,
            "RLIMIT_FSIZE",
        )

    core_mb = resources.get("max_core_dump_mb")
    if core_mb is not None:
        _set(resource.RLIMIT_CORE, int(core_mb) * MEBIBYTE, applied, problems, "RLIMIT_CORE")

    runtime = resources.get("max_runtime_seconds")
    if runtime:
        # CPU-time backstop. Wall-clock is enforced by the supervisor.
        _set(resource.RLIMIT_CPU, int(math.ceil(float(runtime))), applied, problems, "RLIMIT_CPU")

    return {"applied": applied, "problems": problems}
