"""Scan the repository for credential-like strings before publishing.

Run from the repository root:

    python diagnostics/secret_scan.py

It reports *candidates*, not verdicts. Test fixtures that deliberately mention
`token` or `OPENAI` are expected; a live key is not.
"""

from __future__ import annotations

import os
import re
import sys

SKIP_DIRS = {"__pycache__", ".pytest_cache", ".ruff_cache", ".git", ".venv", "venv"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz"}
TEXT_SUFFIXES = {
    ".py", ".md", ".sh", ".toml", ".json", ".txt", ".yml", ".yaml",
    ".cfg", ".ini", ".gitignore", ".editorconfig",
}

PATTERNS: dict[str, re.Pattern[str]] = {
    "password": re.compile(r"password", re.I),
    "secret": re.compile(r"secret", re.I),
    "api_key": re.compile(r"api[_-]?key", re.I),
    "openai": re.compile(r"OPENAI", re.I),
    "anthropic": re.compile(r"ANTHROPIC", re.I),
    "deepseek": re.compile(r"DEEPSEEK", re.I),
    "bearer": re.compile(r"Bearer\s+\S", re.I),
    "private_key": re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
    "token": re.compile(r"\btoken\b", re.I),
    "env_path": re.compile(r"(?<![\w/])(?:[A-Za-z]:\\\\(?:Users|Documents)|/home/[a-z0-9_.-]+/|/Users/[A-Za-z0-9_.-]+/)"),
}

#: Strings that are obviously placeholders rather than live credentials.
PLACEHOLDER = re.compile(
    r"(placeholder|example|dummy|fake|fixture|redacted|test|xxx|your[_-])",
    re.I,
)


def iter_files(root: str = ".") -> "list[str]":
    found: list[str] = []
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for name in files:
            path = os.path.join(directory, name)
            _, suffix = os.path.splitext(name)
            if suffix.lower() in SKIP_SUFFIXES:
                continue
            if suffix.lower() not in TEXT_SUFFIXES and name not in (".gitignore",):
                continue
            found.append(path)
    return sorted(found)


def use_utf8_output() -> None:
    """A Windows console defaults to a legacy code page.

    These reports quote the very characters being checked for, so without this
    the tool crashes on exactly the machine that needs it.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


def main() -> int:
    use_utf8_output()
    hits: dict[str, list[str]] = {}
    total = 0
    for path in iter_files():
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for label, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                line_number = text[: match.start()].count("\n") + 1
                line = text.splitlines()[line_number - 1].strip()[:120]
                total += 1
                hits.setdefault(label, []).append(
                    f"{os.path.relpath(path, '.')}:{line_number}: {line}"
                )

    print(f"scanned {len(iter_files())} text files; {total} candidate matches\n")
    for label in PATTERNS:
        found = hits.get(label, [])
        print(f"--- {label}: {len(found)} ---")
        for entry in found[:12]:
            flag = " [placeholder?]" if PLACEHOLDER.search(entry) else ""
            print(f"    {entry}{flag}")
        if len(found) > 12:
            print(f"    ... {len(found) - 12} more")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
