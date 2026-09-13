"""Text hygiene checks for a public release.

Run from the repository root:

    python diagnostics/check_text_hygiene.py

Reports:

* **mojibake** — characters that indicate a file was written with the wrong
  encoding somewhere along the way (a real readability problem in a README);
* **non-UTF-8 files** — a published repository should be UTF-8 throughout;
* **tabs** in Python source, which conflict with the 4-space style;
* **trailing whitespace**, excluding Markdown where two trailing spaces are a
  meaningful line break.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Iterator

SKIP_DIRS = {"__pycache__", ".pytest_cache", ".ruff_cache", ".git", ".venv", "venv"}
TEXT_SUFFIXES = {".py", ".md", ".sh", ".toml", ".json", ".txt", ".yml", ".yaml", ".cfg", ".ini"}

#: Sequences that mean the bytes were decoded or encoded with the wrong codec.
MOJIBAKE = re.compile(
    r"[\u00c2\u00c3\u00c5\u00e2][\u0080-\u00bf\u2013\u2014\u2018\u2019\u201c\u201d\u20ac\u2122]"
    r"|\ufffd"
)


def iter_text_files(root: str = ".") -> Iterator[str]:
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = [
            d for d in subdirs if d not in SKIP_DIRS and not d.endswith(".egg-info")
        ]
        for name in files:
            if os.path.splitext(name)[1].lower() in TEXT_SUFFIXES:
                yield os.path.join(directory, name)


def rel(path: str) -> str:
    return os.path.relpath(path, ".").replace(os.sep, "/")


def use_utf8_output() -> None:
    """A Windows console defaults to a legacy code page.

    This report quotes the characters it is checking for, so without this the
    tool crashes on exactly the machine that needs it.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


def main() -> int:
    use_utf8_output()
    problems = 0
    file_count = 0

    for path in sorted(iter_text_files()):
        file_count += 1
        raw = open(path, "rb").read()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            print(f"{rel(path)}: not valid UTF-8 ({exc})")
            problems += 1
            continue

        if path.endswith(".py"):
            lines = text.splitlines()
            tab_lines = [i for i, line in enumerate(lines, 1) if "\t" in line]
            if tab_lines:
                print(f"{rel(path)}: tabs on line(s) {tab_lines[:5]}")
                problems += 1

        if not path.endswith(".md"):
            trailing = [
                i
                for i, line in enumerate(text.splitlines(), 1)
                if line != line.rstrip()
            ]
            if trailing:
                print(f"{rel(path)}: trailing whitespace on line(s) {trailing[:5]}")
                problems += 1

        for match in MOJIBAKE.finditer(text):
            line_number = text[: match.start()].count("\n") + 1
            line = text.splitlines()[line_number - 1].strip()[:100]
            print(f"{rel(path)}:{line_number}: possible mojibake: {line}")
            problems += 1
            break

    print()
    print(f"checked {file_count} text files; {problems} issue(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
