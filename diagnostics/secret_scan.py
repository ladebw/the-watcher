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

#: Shapes that identify a *live* credential rather than a mention of one.
#:
#: These mirror the value patterns the trace recorder redacts with
#: (``the_watcher/poe/redact.py``), minus the URL-userinfo rule — that masks a
#: password rather than recognising a key. The advisory report above lists
#: everything it can find; this list is the part that fails a build, so it is
#: deliberately narrow. A detector that fires on documentation is a detector
#: people learn to ignore.
HIGH_CONFIDENCE: dict[str, re.Pattern[str]] = {
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"),
    "github_token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    "github_pat": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    "aws_key_id": re.compile(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    "jwt": re.compile(
        r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b"
    ),
    "bearer_header": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{8,}"),
    # A real PEM body is long; the short placeholder in the tests does not
    # match even before the exemption below is applied.
    "pem_private_key": re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{64,}?-----END [A-Z ]*PRIVATE KEY-----"
    ),
}

#: Paths whose *purpose* is to describe these shapes, plus test fixtures.
#: Scanning them would flag the detector rather than a leak.
HIGH_CONFIDENCE_EXEMPT: tuple[str, ...] = (
    "tests/",
    "the_watcher/poe/redact.py",
    "diagnostics/secret_scan.py",
)


def relative(path: str) -> str:
    return os.path.relpath(path, ".").replace(os.sep, "/")


def scan_high_confidence() -> "list[str]":
    """Return matches that look like a real credential, or an empty list."""
    found: list[str] = []
    for path in iter_files():
        name = relative(path)
        if name.startswith(HIGH_CONFIDENCE_EXEMPT):
            continue
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for label, pattern in HIGH_CONFIDENCE.items():
            for match in pattern.finditer(text):
                line_number = text[: match.start()].count("\n") + 1
                line = text.splitlines()[line_number - 1].strip()[:120]
                found.append(f"{name}:{line_number}: {label}: {line}")
    return found


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

    critical = scan_high_confidence()
    print("--- high-confidence credential shapes ---")
    if critical:
        for entry in critical:
            print(f"    {entry}")
        print()
        print(
            f"{len(critical)} match(es) look like a live credential. The advisory "
            "list above is expected to be noisy; this one is not."
        )
        return 1
    print("    none")
    print()
    print("no live credential shapes found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
