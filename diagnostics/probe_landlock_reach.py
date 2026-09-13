#!/usr/bin/env python3
"""Measure whether Landlock path rules are honoured, across paths and repeats.

Why this exists
---------------
``landlock_ruleset.UNRELIABLE_FILESYSTEMS`` refuses 9p/drvfs/CIFS-style
filesystems, and that list exists because a *functional probe was not enough*.

Measured on WSL2 (kernel 6.6.87.2), probing directories along one 9p mount at
increasing depth::

    <9p mount root>                         OK    OK    OK
    <mount>/<dir>                           OK    OK    OK
    <mount>/<dir>/<dir>                     OK    OK    OK
    <mount>/<dir>/<dir>/<dir>               OK    OK    OK
    <mount>/.../project                     OK    OK    OK
    <mount>/.../project/<subdir>            DENY  DENY  DENY

Six directories, one filesystem, two answers, each stable across repeats. A
probe of one path therefore says nothing about another, and unreliable
enforcement has to be refused rather than tested for.

Usage::

    python3 diagnostics/probe_landlock_reach.py                 # a few defaults
    python3 diagnostics/probe_landlock_reach.py /mnt/c /tmp    # explicit paths

To reproduce the original finding, pass several directories of increasing
depth along a single 9p mount (on WSL, anything under ``/mnt/c``).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from the_watcher.enforcement.linux import landlock_ruleset as ll  # noqa: E402
from the_watcher.enforcement.procfs import filesystem_type  # noqa: E402

REPEATS = 3


def default_paths() -> "list[str]":
    """Whatever is worth looking at on this host, without assuming a layout."""
    candidates = ["/tmp", "/usr", "/dev/shm", "/mnt/c", "/mnt/wsl"]
    return [path for path in candidates if os.path.isdir(path)]


def measure(paths: "list[str]", repeats: int = REPEATS) -> None:
    header = f"{'path':<46} {'fs':<9} " + " ".join(f"run{i + 1}" for i in range(repeats))
    print(header)
    print("-" * len(header))

    for path in paths:
        if not os.path.isdir(path):
            print(f"{path:<46} (missing)")
            continue
        verdicts = []
        for _ in range(repeats):
            ok, _detail = ll.probe_path_access(path)
            verdicts.append("OK  " if ok else "DENY")
        stable = "stable" if len(set(verdicts)) == 1 else "INCONSISTENT"
        print(
            f"{path:<46} {filesystem_type(path):<9} "
            + " ".join(verdicts)
            + f"  {stable}"
        )

    print()
    print("A DENY here means the kernel accepted a rule for that path and then")
    print("denied access anyway, so path-based enforcement cannot be relied on")
    print("for it. An INCONSISTENT result is worse: it means the answer is not")
    print("even a property of the path.")


def main(argv: "list[str]") -> int:
    paths = argv[1:] or default_paths()
    if not paths:
        print("no candidate paths exist on this host")
        return 1
    print(f"checking {len(paths)} path(s), {REPEATS} repeats each")
    print()
    measure(paths)

    print()
    print("Verification over the same filesystem as the repeated evidence is what")
    print("matters: run this with every path under one mount to reproduce it.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
