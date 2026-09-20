"""Phase 0 Blocker D: declared configuration versus enforced configuration.

The defect these tests exist for: the containment profile digest hashed the
*declaration*, and several declared settings were read by nothing at all.

* ``resources.cpus`` defaulted to ``1.0``, was printed by ``profile.summary()``
  and entered the digest, and the namespace backend never consumed it. A CPU
  limit silently did not exist.
* ``no_new_privileges=False``, ``drop_all_capabilities=False`` and
  ``add_capabilities=(...)`` were never consulted by any backend or guard. The
  guard always set ``no_new_privs`` and always cleared every capability, so a
  profile could declare a posture the operating system did not implement - and
  a granted capability was dropped silently, so the workload failed with EACCES.

The invariant asserted here:

    No configuration value may be presented as enforced configuration while the
    selected backend silently ignores it.

Every unhonoured setting is either refused before launch or explicitly labelled
``UNSUPPORTED`` / ``PARTIALLY_ENFORCED``, and that report is recorded beside the
profile digest in the Proof of Execution.
"""

from __future__ import annotations

import dataclasses

import pytest

from the_watcher.enforcement import (
    NEVER_OVERRIDABLE,
    BackendAvailability,
    ContainmentProfile,
    Enforcement,
    NetworkMode,
    ResourcePolicy,
    detect_capabilities,
    enforcement_report,
    get_preset,
    refusals,
    require_honourable,
    unhonoured,
)
from the_watcher.exceptions import ContainmentRefused

DEFAULT = ContainmentProfile()


def _status(profile: ContainmentProfile, backend: str, field: str) -> Enforcement:
    for entry in enforcement_report(profile, backend):
        if entry.field == field:
            return entry.status
    raise AssertionError(f"{field} is not classified for {backend}")


def _docker_enforcer():
    from the_watcher.enforcement.backends.docker import DockerEnforcer

    pretend = dataclasses.replace(
        detect_capabilities(),
        backends=(BackendAvailability("docker", True, "fabricated"),),
    )
    return DockerEnforcer(pretend)


def _namespaces_enforcer():
    from the_watcher.enforcement.backends.namespaces import NamespaceEnforcer

    pretend = dataclasses.replace(
        detect_capabilities(),
        backends=(BackendAvailability("namespaces", True, "fabricated"),),
        unshare_binary="/usr/bin/unshare",
        unprivileged_userns_ok=True,
        seccomp_available=True,
        landlock_abi=3,
        user_namespaces=True,
        pid_namespaces=True,
        mount_namespaces=True,
        network_namespaces=True,
    )
    return NamespaceEnforcer(pretend, runtime_root=None)


# ---------------------------------------------------------------------------
# The default profile must be honest
# ---------------------------------------------------------------------------


def test_the_default_profile_claims_nothing_it_does_not_enforce():
    """A profile nobody edited must have no unhonoured setting at all."""
    assert unhonoured(DEFAULT, "namespaces") == ()
    assert refusals(DEFAULT, "namespaces") == ()


def test_cpus_no_longer_defaults_to_a_value_nothing_enforces():
    """The old default of 1.0 was hashed into the digest and never applied."""
    assert ResourcePolicy().cpus is None
    assert _status(DEFAULT, "namespaces", "resources.cpus") is Enforcement.ENFORCED


def test_every_profile_field_is_classified_on_every_backend():
    """No field may be absent from the report; absence would be silence."""
    fields = {entry.field for entry in enforcement_report(DEFAULT, "namespaces")}
    for required in (
        "resources.cpus",
        "resources.memory_mb",
        "no_new_privileges",
        "drop_all_capabilities",
        "add_capabilities",
        "network",
        "processes.max_processes",
    ):
        assert required in fields, f"{required} is not classified"
    # And the container backend classifies the same set of fields.
    assert {entry.field for entry in enforcement_report(DEFAULT, "docker")} == fields


# ---------------------------------------------------------------------------
# Unsupported settings are reported, never silently ignored
# ---------------------------------------------------------------------------


def test_a_declared_cpu_limit_is_refused_not_silently_ignored():
    """An explicitly requested ceiling the backend cannot apply fails closed.

    This is the difference between *not specified* (fine to proceed) and
    *explicitly specified but unsupported* (refuse before launch). Recording
    UNSUPPORTED and continuing would mean running a session that claims a CPU
    ceiling nothing implements.
    """
    profile = dataclasses.replace(
        DEFAULT, resources=dataclasses.replace(DEFAULT.resources, cpus=4.0)
    )
    assert _status(profile, "namespaces", "resources.cpus") is Enforcement.REFUSED

    with pytest.raises(ContainmentRefused, match="resources.cpus"):
        require_honourable(profile, "namespaces")

    # ...and the same request one level down, through the real backend.
    enforcer = _namespaces_enforcer()
    with pytest.raises(ContainmentRefused, match="resources.cpus"):
        enforcer.prepare(profile)

    # Not specifying it is not an error anywhere.
    require_honourable(DEFAULT, "namespaces")
    _namespaces_enforcer().prepare(DEFAULT)


def test_reduced_protection_can_be_explicitly_accepted_and_is_returned():
    profile = dataclasses.replace(
        DEFAULT,
        resources=dataclasses.replace(DEFAULT.resources, cpus=4.0),
        allow_reduced_protection=True,
    )
    waived = require_honourable(profile, "namespaces")
    assert [entry.field for entry in waived] == ["resources.cpus"]
    assert waived[0].declared == 4.0
    assert waived[0].enforced is None
    assert profile.allow_reduced_protection is True


@pytest.mark.parametrize(
    "field, override",
    [
        ("network", {"network": NetworkMode.RESTRICTED}),
        ("no_new_privileges", {"no_new_privileges": False}),
        ("drop_all_capabilities", {"drop_all_capabilities": False}),
        ("add_capabilities", {"add_capabilities": ("CAP_NET_BIND_SERVICE",)}),
        ("allowed_networks", {"allowed_networks": ("10.0.0.0/8",)}),
    ],
)
def test_the_reduced_protection_opt_in_never_waives_the_trust_boundary(
    field, override
):
    """Some settings describe the posture itself and are never waivable.

    Accepting ``no_new_privileges=false`` or ``network=restricted`` would not
    mean "running without a control"; it would mean recording a posture the
    kernel does not implement, which is the defect this whole phase removes.
    """
    profile = dataclasses.replace(DEFAULT, allow_reduced_protection=True, **override)
    with pytest.raises(ContainmentRefused, match=field):
        require_honourable(profile, "namespaces")
    assert field in NEVER_OVERRIDABLE


def test_every_default_profile_field_is_reported_as_enforced_or_explained():
    """A field is never simply absent: silence is the thing being removed."""
    for backend in ("namespaces", "docker"):
        report = enforcement_report(DEFAULT, backend)
        assert report
        for entry in report:
            assert entry.mechanism or entry.status is Enforcement.ENFORCED, entry
            if entry.status is not Enforcement.ENFORCED:
                assert entry.detail, f"{entry.field} is unhonoured with no reason"


def test_legacy_seccomp_flags_are_reported_as_partial_not_as_independent():
    """``block_kexec`` and ``block_swap`` have no independent effect."""
    for field in ("syscalls.block_kexec", "syscalls.block_swap"):
        assert _status(DEFAULT, "namespaces", field) is Enforcement.PARTIALLY_ENFORCED
    entry = next(
        item
        for item in enforcement_report(DEFAULT, "namespaces")
        if item.field == "syscalls.block_kexec"
    )
    assert "block_reboot" in entry.detail


def test_memory_and_process_ceilings_are_labelled_partially_enforced():
    assert _status(DEFAULT, "namespaces", "resources.memory_mb") is (
        Enforcement.PARTIALLY_ENFORCED
    )
    assert _status(DEFAULT, "namespaces", "processes.max_processes") is (
        Enforcement.PARTIALLY_ENFORCED
    )
    # ...and the reason is stated, not merely implied.
    entry = next(
        item
        for item in enforcement_report(DEFAULT, "namespaces")
        if item.field == "resources.memory_mb"
    )
    assert "RLIMIT_AS" in entry.mechanism
    assert "address space" in entry.detail


def test_network_open_is_a_declared_posture_not_a_containment_failure():
    """``open`` used to be reported as a problem, which failed every such run."""
    profile = dataclasses.replace(DEFAULT, network=NetworkMode.OPEN)
    assert _status(profile, "namespaces", "network") is Enforcement.ENFORCED
    assert refusals(profile, "namespaces") == ()
    # It is still honestly described as reduced protection.
    assert profile.is_reduced_protection
    entry = next(
        item
        for item in enforcement_report(profile, "namespaces")
        if item.field == "network"
    )
    assert "no egress restriction" in entry.detail


# ---------------------------------------------------------------------------
# Settings that must be refused before launch
# ---------------------------------------------------------------------------


def test_network_restricted_is_refused_and_the_message_names_the_value():
    profile = dataclasses.replace(
        get_preset("research-net"), backend="docker"
    )
    with pytest.raises(ContainmentRefused, match="restricted"):
        require_honourable(profile, "docker")


def test_no_new_privileges_false_is_refused():
    """The guard always sets it, so declaring it false is not honourable."""
    profile = dataclasses.replace(DEFAULT, no_new_privileges=False)
    assert _status(profile, "namespaces", "no_new_privileges") is Enforcement.REFUSED
    with pytest.raises(ContainmentRefused, match="no_new_privileges"):
        require_honourable(profile, "namespaces")


def test_drop_all_capabilities_false_is_refused():
    profile = dataclasses.replace(DEFAULT, drop_all_capabilities=False)
    assert _status(profile, "namespaces", "drop_all_capabilities") is (
        Enforcement.REFUSED
    )
    with pytest.raises(ContainmentRefused, match="drop_all_capabilities"):
        require_honourable(profile, "namespaces")


def test_granting_a_capability_is_refused_rather_than_silently_dropped():
    """The guard always clears capabilities, so a grant would just break."""
    profile = dataclasses.replace(
        DEFAULT, add_capabilities=("CAP_NET_BIND_SERVICE",)
    )
    assert _status(profile, "namespaces", "add_capabilities") is Enforcement.REFUSED
    with pytest.raises(ContainmentRefused, match="add_capabilities"):
        require_honourable(profile, "namespaces")


def test_allowed_networks_without_restricted_is_refused():
    profile = dataclasses.replace(DEFAULT, allowed_networks=("10.0.0.0/8",))
    assert _status(profile, "namespaces", "allowed_networks") is Enforcement.REFUSED
    with pytest.raises(ContainmentRefused):
        require_honourable(profile, "namespaces")


def test_refusal_message_explains_why_rather_than_only_refusing():
    profile = dataclasses.replace(DEFAULT, no_new_privileges=False)
    with pytest.raises(ContainmentRefused) as excinfo:
        require_honourable(profile, "namespaces")
    message = str(excinfo.value)
    assert "nothing implements" in message
    assert "no_new_privileges" in message


# ---------------------------------------------------------------------------
# The backends enforce the classification at prepare()
# ---------------------------------------------------------------------------


def test_docker_prepare_refuses_an_unhonourable_setting():
    """The container backend refuses what it cannot honour, before launch."""
    enforcer = _docker_enforcer()
    profile = dataclasses.replace(DEFAULT, network=NetworkMode.RESTRICTED)
    with pytest.raises(ContainmentRefused, match="restricted"):
        enforcer.prepare(profile)


def test_docker_reports_what_it_does_not_apply():
    """The container backend applies very little of a profile; it must say so."""
    report = enforcement_report(DEFAULT, "docker")
    by_field = {entry.field: entry for entry in report}

    # It genuinely maps these onto runtime flags.
    assert by_field["resources.memory_mb"].status is Enforcement.ENFORCED
    assert "memory.max" in by_field["resources.memory_mb"].mechanism
    assert by_field["processes.max_processes"].status is Enforcement.ENFORCED

    # It does not apply these, and says so rather than staying quiet.
    for field in (
        "filesystem.allow_read",
        "filesystem.landlock_required",
        "syscalls.block_ptrace",
    ):
        assert by_field[field].status is Enforcement.UNSUPPORTED, field
        assert by_field[field].enforced is None


def test_a_declared_cpu_limit_is_enforced_by_the_container_backend():
    profile = dataclasses.replace(
        DEFAULT, resources=dataclasses.replace(DEFAULT.resources, cpus=2.0)
    )
    assert _status(profile, "docker", "resources.cpus") is Enforcement.ENFORCED


def test_unknown_backend_names_are_treated_as_the_strict_backend():
    """An unrecognised backend must not be described as enforcing anything extra."""
    assert enforcement_report(DEFAULT, "something-else") == enforcement_report(
        DEFAULT, "namespaces"
    )


# ---------------------------------------------------------------------------
# The report is recorded in the Proof of Execution
# ---------------------------------------------------------------------------


def test_the_report_is_recorded_beside_the_profile_digest(tmp_path):
    """A digest alone must never stand as a claim of enforcement."""
    import sys as _sys

    from the_watcher.supervisor import DaemonConfig, WatcherDaemon

    profile = dataclasses.replace(
        DEFAULT, resources=dataclasses.replace(DEFAULT.resources, cpus=4.0)
    )
    daemon = WatcherDaemon(
        DaemonConfig(
            command=[_sys.executable, "-c", "pass"],
            containment=profile,
            workspace_root=str(tmp_path),
            cwd=str(tmp_path),
            storage_root=str(tmp_path / "watcher-home"),
            allow_storage_in_cwd=True,
        )
    )
    # Record the containment-prepared event without needing an enforcement host:
    # this is the event the trace stores the digest and the report in.
    daemon._prepare()
    daemon._enforcer = _FlagEnforcer()
    daemon._record_containment_prepared()

    prepared = [
        event
        for event in daemon.trace.events
        if event.event_type == "containment_prepared"
    ]
    assert prepared, "no containment_prepared event was recorded"
    metadata = prepared[0].metadata
    assert "profile_digest" in metadata
    assert "enforcement_report" in metadata
    assert metadata["enforcement_report"]["counts"]["REFUSED"] == 1
    assert any(
        entry["field"] == "resources.cpus"
        for entry in metadata["declared_but_unhonoured"]
    )
    assert metadata["reduced_protection"] is True
    assert prepared[0].risk == "HIGH"


class _FlagEnforcer:
    """A stand-in enforcer that reports the namespace backend's name."""

    backend_name = "namespaces"

    def prepare(self, profile, spec=None) -> None:
        return None
