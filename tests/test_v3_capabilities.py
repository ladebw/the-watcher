"""Host capability probing and backend selection. Runs on every platform.

The point of these tests is that V3 never claims more than the host can do. On
a platform with no enforcement the answer must be "unavailable", stated
plainly, and enforced mode must refuse rather than silently fall back to
V2-style supervision.
"""

from __future__ import annotations

import sys

import pytest

from the_watcher.enforcement import (
    BackendAvailability,
    NetworkMode,
    clear_capability_cache,
    detect_capabilities,
    get_preset,
    select_backend,
)
from the_watcher.exceptions import EnforcementUnavailable


def test_detection_reports_the_platform_truthfully():
    caps = detect_capabilities()
    assert caps.is_linux == sys.platform.startswith("linux")
    assert caps.os_name
    assert caps.checked_at > 0


def test_detection_is_cached_and_refreshable():
    clear_capability_cache()
    first = detect_capabilities()
    second = detect_capabilities()
    assert first is second, "a repeated probe must reuse the cached result"

    refreshed = detect_capabilities(refresh=True)
    assert refreshed is not first
    assert refreshed.is_linux == first.is_linux


def test_every_backend_is_described():
    caps = detect_capabilities()
    names = {backend.name for backend in caps.backends}
    assert {"namespaces", "docker"} <= names
    for backend in caps.backends:
        assert isinstance(backend, BackendAvailability)
        assert backend.detail, f"{backend.name} must explain itself"


def test_non_linux_hosts_report_enforcement_unavailable():
    caps = detect_capabilities()
    if caps.is_linux:
        pytest.skip("this assertion is about non-Linux hosts")
    assert not caps.enforced_mode_available
    assert caps.available_backends == ()
    assert not caps.namespaces_available


def test_doctor_report_states_the_platform():
    caps = detect_capabilities()
    report = caps.doctor_report()
    assert "The Watcher" in report
    assert caps.os_name in report
    assert "V3 enforced mode:" in report
    if not caps.enforced_mode_available:
        assert "UNAVAILABLE" in report
        assert "Reason:" in report


def test_doctor_report_does_not_overclaim():
    """The report must never promise containment the host cannot deliver."""
    caps = detect_capabilities()
    report = caps.doctor_report()
    if caps.enforced_mode_available:
        assert "AVAILABLE" in report
    else:
        assert "UNAVAILABLE" in report
        # It must say what to do about it, not just that it failed.
        assert "WSL" in report or "Linux" in report


def test_capability_dict_round_trips():
    caps = detect_capabilities()
    payload = caps.to_dict()
    assert payload["is_linux"] == caps.is_linux
    assert payload["backends"] == [b.to_dict() for b in caps.backends]


# -- backend selection ------------------------------------------------------


def test_select_backend_raises_when_nothing_is_available():
    import dataclasses

    caps = detect_capabilities()
    stripped = dataclasses.replace(
        caps,
        backends=(
            BackendAvailability("namespaces", False, "forced unavailable"),
            BackendAvailability("docker", False, "forced unavailable"),
        ),
    )
    with pytest.raises(EnforcementUnavailable) as excinfo:
        select_backend(get_preset("research-strict"), stripped)
    assert "no containment backend" in str(excinfo.value)
    # The message must point somewhere useful.
    assert "WSL" in str(excinfo.value) or "Linux" in str(excinfo.value)


def test_explicit_unavailable_backend_is_refused_not_downgraded():
    """An explicit backend that is unavailable must raise, never fall back."""
    caps = detect_capabilities()
    docker = caps.backend("docker")
    if docker is not None and docker.available:
        pytest.skip("docker is available here; the negative case cannot be tested")

    profile = get_preset("research-strict").replace(backend="docker")
    with pytest.raises(EnforcementUnavailable) as excinfo:
        select_backend(profile, caps)
    assert "docker" in str(excinfo.value)


def test_unknown_backend_name_is_rejected():
    profile = get_preset("research-strict").replace(backend="quantum")
    with pytest.raises(EnforcementUnavailable, match="unknown containment backend"):
        select_backend(profile)


def test_auto_prefers_namespaces_over_containers(enforcement_caps):
    """The rootless namespace backend needs no daemon, so it wins."""
    if not enforcement_caps.enforced_mode_available:
        pytest.skip("no backend available here")
    enforcer = select_backend(
        get_preset("research-strict").replace(backend="auto"), enforcement_caps
    )
    assert enforcer.backend_name in enforcement_caps.available_backends
    if "namespaces" in enforcement_caps.available_backends:
        assert enforcer.backend_name == "namespaces"


def test_backend_aliases_are_accepted():
    for alias in ("namespaces", "namespace", "linux"):
        profile = get_preset("research-strict").replace(backend=alias)
        assert profile.backend == alias


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="namespace backend is Linux-only"
)
def test_namespace_backend_requires_a_usable_host():
    """Preparation must refuse when the host cannot support the sandbox."""
    from the_watcher.enforcement.backends.namespaces import NamespaceEnforcer

    caps = detect_capabilities()
    enforcer = NamespaceEnforcer(caps)
    if caps.unprivileged_userns_ok and caps.seccomp_available:
        enforcer.prepare(get_preset("research-strict"))
    else:
        with pytest.raises(EnforcementUnavailable):
            enforcer.prepare(get_preset("research-strict"))


def test_docker_backend_refuses_dangerous_configuration():
    """The container backend must refuse configuration it cannot guarantee.

    A fabricated capability object is used so the refusal under test is the
    *configuration* check, not the "is docker installed" check.
    """
    import dataclasses

    from the_watcher.enforcement.backends.docker import DockerEnforcer
    from the_watcher.exceptions import ContainmentRefused

    caps = detect_capabilities()
    pretend = dataclasses.replace(
        caps, backends=(BackendAvailability("docker", True, "fabricated"),)
    )
    enforcer = DockerEnforcer(pretend)

    privileged = dataclasses.replace(get_preset("research-strict"), allow_privileged=True)
    with pytest.raises(ContainmentRefused, match="privileged"):
        enforcer.prepare(privileged)

    socket = dataclasses.replace(
        get_preset("research-strict"), allow_docker_socket=True
    )
    with pytest.raises(ContainmentRefused, match="socket"):
        enforcer.prepare(socket)

    restricted = dataclasses.replace(
        get_preset("research-strict"),
        network=NetworkMode.RESTRICTED,
        allowed_networks=("10.0.0.0/8",),
    )
    with pytest.raises(ContainmentRefused, match="restricted"):
        enforcer.prepare(restricted)


def test_enforcement_mode_values():
    from the_watcher.enforcement import EnforcementMode

    assert EnforcementMode.OFF.value == "off"
    assert EnforcementMode.ENFORCED.value == "enforced"


def test_containment_states_include_kill_failed():
    from the_watcher.enforcement import (
        TERMINAL_CONTAINMENT_STATES,
        ContainmentState,
    )

    assert ContainmentState.KILL_FAILED in TERMINAL_CONTAINMENT_STATES
    assert ContainmentState.TERMINATED in TERMINAL_CONTAINMENT_STATES
    # KILL_FAILED must never be treated as a clean finish.
    assert ContainmentState.KILL_FAILED is not ContainmentState.TERMINATED


def test_guard_modules_are_stdarlib_only():
    """The in-sandbox guard must not be able to import the Watcher package.

    It is copied into the sandbox, so any dependency on ``the_watcher`` would
    mean exporting the supervisor's own code into the environment it is
    supposed to be protecting.
    """
    import ast
    import pathlib

    guard_dir = (
        pathlib.Path(__file__).resolve().parents[1]
        / "the_watcher"
        / "enforcement"
        / "linux"
    )
    offenders: list[str] = []
    for name in ("exec_guard.py", "seccomp_filter.py", "landlock_ruleset.py", "resource_limits.py"):
        source = (guard_dir / name).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "the_watcher":
                        offenders.append(f"{name} imports {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module.split(".")[0] == "the_watcher" or (node.level and node.level > 0):
                    offenders.append(f"{name} imports from {'.' * node.level}{module}")
    assert not offenders, "guard modules must be standalone: " + "; ".join(offenders)


def test_guard_modules_import_only_the_standard_library():
    import ast
    import pathlib
    import sys as _sys

    guard_dir = (
        pathlib.Path(__file__).resolve().parents[1]
        / "the_watcher"
        / "enforcement"
        / "linux"
    )
    allowed_siblings = {"seccomp_filter", "landlock_ruleset", "resource_limits", "exec_guard"}
    stdlib = _sys.stdlib_module_names
    unexpected: list[str] = []

    for name in ("exec_guard.py", "seccomp_filter.py", "landlock_ruleset.py", "resource_limits.py"):
        tree = ast.parse((guard_dir / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and not node.level:
                modules = [(node.module or "").split(".")[0]]
            for module in modules:
                if module and module not in stdlib and module not in allowed_siblings:
                    unexpected.append(f"{name}: {module}")
    assert not unexpected, "guard modules must be stdlib-only: " + "; ".join(unexpected)


def test_os_getuid_is_not_needed_for_importing_the_package():
    """Importing the enforcement layer must not require POSIX."""
    # Deliberately importing every public name; this would fail on Windows if
    # any module touched POSIX-only APIs at import time.
    import the_watcher.enforcement as enforcement

    for name in enforcement.__all__:
        getattr(enforcement, name)


def test_enforcement_lazy_backends():
    """Backend classes must be reachable without importing them eagerly."""
    import the_watcher.enforcement as enforcement

    assert enforcement.NamespaceEnforcer.backend_name == "namespaces"
    assert enforcement.DockerEnforcer.backend_name == "docker"
    with pytest.raises(AttributeError):
        _ = enforcement.NoSuchBackend


def test_enforcer_require_available_message(monkeypatch):
    from the_watcher.enforcement.backends.namespaces import NamespaceEnforcer

    caps = detect_capabilities()
    enforcer = NamespaceEnforcer(caps)
    if caps.backend("namespaces") and caps.backend("namespaces").available:
        pytest.skip("the namespace backend is available here")
    with pytest.raises(EnforcementUnavailable):
        enforcer.require_available()


def test_spec_paths_derive_from_the_profile(tmp_path):
    """Read/write paths come from the profile plus explicit extras."""
    from the_watcher.enforcement import SandboxSpec

    profile = get_preset("research-strict")
    spec = SandboxSpec(
        command=("true",),
        profile=profile,
        workspace_host=str(tmp_path),
        extra_read_paths=("/opt/extra",),
    )
    assert "/opt/extra" in spec.read_paths
    assert "/workspace" in spec.write_paths
    assert spec.write_paths == tuple(dict.fromkeys(spec.write_paths)), "no duplicates"


def test_workspace_placeholder_is_substituted_by_the_backend():
    """``/workspace`` in a profile is a logical name, not a literal path.

    The backend replaces it with wherever the workspace really appears inside,
    which is what keeps the Landlock allow-list pointing at the right inode.
    """
    if not sys.platform.startswith("linux"):
        pytest.skip("the namespace backend is Linux-only")
    from the_watcher.enforcement import SandboxSpec
    from the_watcher.enforcement.backends.namespaces import NamespaceEnforcer

    profile = get_preset("research-strict")
    spec = SandboxSpec(
        command=("true",),
        profile=profile,
        workspace_host="/tmp/some-workspace",
    )
    enforcer = NamespaceEnforcer()
    layout = enforcer.plan(spec)
    assert layout["workspace_inner"] == "/tmp/some-workspace"
    assert "/workspace" not in layout["write_paths"]
    assert layout["workspace_inner"] in layout["write_paths"]
