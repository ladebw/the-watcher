"""Report code-quality signals before a release.

Run from the repository root:

    python diagnostics/check_code_hygiene.py

Flags the things a reviewer would flag: leftover debug output, stale TODOs,
commented-out code, bare `except:` clauses, and `print()` calls outside the
CLI and examples where they are the intended interface.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from typing import Iterator

SKIP_DIRS = {"__pycache__", ".pytest_cache", ".ruff_cache", ".git", ".venv", "venv"}

#: `print` *is* the interface for these, so it is not a smell there. The check
#: exists to catch debug output left behind in library code.
PRINT_ALLOWED_PREFIXES = ("benchmarks/", "diagnostics/", "examples/", "tests/")
PRINT_ALLOWED_FILES = {
    "the_watcher/cli.py",
    # The sandbox guard is a standalone script. Before it execs the workload
    # its only output channel is stderr, which the supervisor captures into
    # guard.log — that is the interface, not debug output.
    "the_watcher/enforcement/linux/exec_guard.py",
}

#: This checker itself, which mentions the patterns it searches for.
SELF = "diagnostics/check_code_hygiene.py"

TODO = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")
COMMENTED_CODE = re.compile(r"^\s*#\s*(import |from |def |class |return |if |for |while |with )")


def iter_python(root: str = ".") -> Iterator[str]:
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = [
            d for d in subdirs if d not in SKIP_DIRS and not d.endswith(".egg-info")
        ]
        for name in files:
            if name.endswith(".py"):
                yield os.path.join(directory, name)


def rel(path: str) -> str:
    return os.path.relpath(path, ".").replace(os.sep, "/")


def use_utf8_output() -> None:
    """A Windows console defaults to a legacy code page.

    This report quotes source lines, so without this the tool can crash on a
    line containing a character the console cannot encode.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


def main() -> int:
    use_utf8_output()
    findings: list[str] = []

    for path in sorted(iter_python()):
        name = rel(path)
        if name == SELF:
            continue
        text = open(path, encoding="utf-8").read()
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            findings.append(f"{name}: does not parse: {exc}")
            continue

        # Bare or over-broad `except:` clauses.
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                findings.append(f"{name}:{node.lineno}: bare `except:`")

        # print() in library code, where it would be leftover debug output.
        if name not in PRINT_ALLOWED_FILES and not name.startswith(PRINT_ALLOWED_PREFIXES):
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "print"
                ):
                    findings.append(f"{name}:{node.lineno}: print() in library code")

        for number, line in enumerate(text.splitlines(), 1):
            if TODO.search(line):
                findings.append(f"{name}:{number}: {line.strip()[:90]}")
            if COMMENTED_CODE.match(line):
                findings.append(f"{name}:{number}: commented-out code? {line.strip()[:80]}")

    for finding in findings:
        print(finding)
    print()
    print(f"{len(findings)} finding(s)")
    # Exit non-zero on findings, matching check_text_hygiene.py. A hygiene gate
    # that always exits 0 is decorative: it would make a CI step that can never
    # fail, which is a worse outcome than not running it at all.
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
