"""Packaging and repository-hygiene tests.

These guard the properties a *published* release depends on, and that are easy
to break silently: the declared version matching the code, the dependency-free
promise holding, and the sandbox guard not acquiring an import from the
package it is supposed to be independent of.
"""

from __future__ import annotations

import ast
import os
import pathlib
import re

import pytest

from the_watcher import __version__

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
PYPROJECT = PROJECT_ROOT / "pyproject.toml"


def _pyproject_text() -> str:
    return PYPROJECT.read_text(encoding="utf-8")


def test_version_matches_pyproject():
    """``the_watcher.__version__`` and the packaging metadata must agree.

    They drifted once, which is exactly the kind of thing that ships because
    nothing fails loudly when it happens.
    """
    declared = re.search(r'^version\s*=\s*"([^"]+)"', _pyproject_text(), re.M)
    assert declared is not None, "pyproject.toml has no version"
    assert declared.group(1) == __version__


def test_version_is_semver_shaped():
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__), __version__


def test_project_declares_no_runtime_dependencies():
    """The zero-dependency promise is a feature, so it is asserted.

    The Linux enforcement layer talks to the kernel through ``ctypes`` and
    ``os`` rather than pulling in a binding, which is what makes the sandbox
    guard copyable into an environment that has nothing installed.
    """
    text = _pyproject_text()
    dependencies = re.search(r"^dependencies\s*=\s*(.+)$", text, re.M)
    assert dependencies is not None
    assert dependencies.group(1).strip() == "[]"


def test_console_script_is_declared():
    assert 'watcher = "the_watcher.cli:main"' in _pyproject_text()


def test_python_floor_is_declared():
    requires = re.search(r'^requires-python\s*=\s*"([^"]+)"', _pyproject_text(), re.M)
    assert requires is not None
    assert requires.group(1).startswith(">=")


def test_readme_and_license_exist():
    for name in ("README.md", "LICENSE"):
        assert (PROJECT_ROOT / name).is_file(), f"{name} is declared but missing"


def test_license_is_mit():
    assert "MIT License" in (PROJECT_ROOT / "LICENSE").read_text(encoding="utf-8")
    assert 'license = { text = "MIT" }' in _pyproject_text()


@pytest.mark.parametrize(
    "relative",
    [
        ".gitignore",
        "public/the-watcher-logo.png",
        "diagnostics/README.md",
        "benchmarks/benchmark_v2.py",
        "benchmarks/benchmark_v3.py",
        "examples/v3_bypass_agents/bypass_agent.py",
    ],
)
def test_release_assets_are_present(relative):
    """Files the README links to must actually exist.

    A published README that points at a missing asset is worse than one that
    says less.
    """
    assert (PROJECT_ROOT / relative).exists(), f"missing release asset: {relative}"


def test_readme_logo_reference_resolves():
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    references = re.findall(r'src="([^"]+)"', readme)
    assert references, "the README should reference the project logo"
    for reference in references:
        if reference.startswith(("http://", "https://")):
            continue
        assert (PROJECT_ROOT / reference).is_file(), f"broken README asset: {reference}"


def test_readme_has_no_windows_local_paths():
    """Machine-specific paths must not leak into public documentation."""
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    offenders = [
        line
        for line in readme.splitlines()
        if re.search(r"[A-Za-z]:\\\\Users\\\\|C:\\\\Users", line)
    ]
    assert not offenders, f"local paths in README: {offenders[:3]}"


def _github_slug(heading: str) -> str:
    """Reproduce GitHub's heading anchor algorithm.

    Lowercase, drop anything that is not alphanumeric, space, hyphen or
    underscore, then replace spaces with hyphens. Emphasis markers go first,
    because they are rendered away before the anchor is computed.
    """
    text = heading.strip()
    text = re.sub(r"^#+\s*", "", text)
    text = text.replace("*", "").replace("`", "")
    text = text.lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"\s", "-", text)


def _readme_anchors() -> "set[str]":
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    anchors = set()
    in_fence = False
    for line in readme.splitlines():
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or not line.startswith("#"):
            continue
        anchors.add(_github_slug(line))
    return anchors


def test_readme_internal_links_resolve():
    """A table of contents that goes nowhere is worse than none."""
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    anchors = _readme_anchors()
    targets = set(re.findall(r"\]\(#([^)]+)\)", readme))
    assert targets, "the README should cross-reference its own sections"
    missing = sorted(target for target in targets if target not in anchors)
    assert not missing, f"README links to missing anchors: {missing}"


def test_readme_file_links_exist():
    """Relative links out of the README must point at real files."""
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    missing = []
    for target in re.findall(r"\]\((?!https?://|#)([^)#]+)", readme):
        if not (PROJECT_ROOT / target).exists():
            missing.append(target)
    assert not missing, f"README links to missing files: {missing}"


def test_readme_documented_directories_exist():
    """The structure section must not describe directories that are absent."""
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    for name in ("the_watcher/", "tests/", "examples/", "benchmarks/", "diagnostics/", "public/"):
        assert name in readme, f"the README should describe {name}"
        assert (PROJECT_ROOT / name.rstrip("/")).is_dir(), f"missing directory: {name}"


def test_readme_documents_only_existing_cli_commands():
    """Every `watcher <sub>` in the README must be a real subcommand."""
    from the_watcher.cli import build_parser

    parser = build_parser()
    subcommands = set()
    for action in parser._actions:  # noqa: SLF001 - argparse offers no public API
        if hasattr(action, "choices") and action.choices:
            subcommands.update(action.choices)

    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    referenced = set(re.findall(r"\bwatcher\s+(run|status|verify|demo|doctor)\b", readme))
    assert referenced, "the README should show CLI usage"
    assert referenced <= subcommands, f"documented but not implemented: {referenced - subcommands}"


def test_no_generated_junk_is_committable():
    """Caches and build output must be ignored, not merely absent."""
    ignored = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (
        "__pycache__/",
        "*.py[cod]",
        ".pytest_cache/",
        ".ruff_cache/",
        "*.egg-info/",
        ".venv/",
        ".env",
        "traces/",
        "*.log",
        ".DS_Store",
        "Thumbs.db",
    ):
        assert pattern in ignored, f".gitignore is missing {pattern}"


def test_diagnostic_scripts_parse():
    """Diagnostics are run by hand, so nothing else would catch a syntax error."""
    for path in sorted((PROJECT_ROOT / "diagnostics").glob("*.py")):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_shell_scripts_are_executable_or_documented():
    """Shell entry points should either be runnable or say how to run them."""
    for path in sorted((PROJECT_ROOT / "diagnostics").glob("*.sh")):
        text = path.read_text(encoding="utf-8")
        assert text.startswith("#!"), f"{path.name} has no shebang"
        assert "Run" in text or "run" in text, f"{path.name} does not say how to run it"


def test_no_user_specific_paths_in_public_files():
    """Published files must not reveal a developer's home or machine paths.

    Generic WSL mount points such as ``/mnt/c`` are fine and explain the
    platform; ``/mnt/c/Users/<someone>`` is not.
    """
    user_path = re.compile(
        r"/home/[A-Za-z0-9._-]+/"
        r"|/mnt/c/Users/"
        r"|[A-Za-z]:\\\\Users\\\\"
        r"|[A-Za-z]:/Users/"
    )
    subjects = [PROJECT_ROOT / "README.md"]
    subjects += [p for p in sorted((PROJECT_ROOT / "diagnostics").glob("*")) if p.is_file()]
    subjects += sorted((PROJECT_ROOT / "examples").rglob("*.py"))

    offenders: list[str] = []
    for path in subjects:
        if path.suffix not in (".md", ".py", ".sh"):
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if user_path.search(line):
                offenders.append(f"{path.relative_to(PROJECT_ROOT)}:{number}")
    assert not offenders, f"user-specific paths in public files: {offenders}"


def test_package_imports_cleanly_without_optional_extras():
    """Importing the package must not require anything outside the stdlib."""
    import importlib

    module = importlib.import_module("the_watcher")
    assert module.Watcher is module.PoEWatcher


def test_enforcement_package_never_imports_on_windows_unsafely():
    """The enforcement package must import on any platform.

    Importing it must not touch POSIX-only APIs at import time, or ``watcher``
    would be unusable on Windows for reasons unrelated to containment.
    """
    import the_watcher.enforcement as enforcement

    for name in enforcement.__all__:
        getattr(enforcement, name)
    assert os.name in ("nt", "posix")
