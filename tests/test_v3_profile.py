"""Containment profile tests. These run on every platform.

A profile is the declarative form of the containment policy: what the sandbox
will allow, what it will deny, and what it must never be asked for. It is
validated before anything is launched, and its digest is recorded in the Proof
of Execution, so these tests are about the integrity of that contract.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from the_watcher.enforcement import (
    PROFILE_PRESETS,
    ContainmentProfile,
    FilesystemPolicy,
    NetworkMode,
    get_preset,
)
from the_watcher.exceptions import ContainmentRefused


def test_presets_all_validate():
    assert PROFILE_PRESETS, "there must be at least one built-in profile"
    for name in PROFILE_PRESETS:
        profile = get_preset(name)
        profile.validate()
        assert profile.name == name


def test_unknown_preset_is_an_error():
    with pytest.raises(ContainmentRefused, match="unknown containment profile"):
        get_preset("no-such-profile")


def test_research_strict_is_the_strict_one():
    profile = get_preset("research-strict")
    assert profile.network is NetworkMode.NONE
    assert profile.filesystem.read_only_root is True
    assert profile.filesystem.landlock_required is True
    assert profile.drop_all_capabilities is True
    assert profile.processes.max_processes > 0
    assert not profile.is_reduced_protection


def test_research_net_differs_only_in_network():
    strict = get_preset("research-strict")
    networked = get_preset("research-net")
    assert strict.network is not networked.network
    assert strict.filesystem == networked.filesystem
    assert strict.processes == networked.processes


def test_dev_preset_is_flagged_as_reduced_protection():
    dev = get_preset("dev")
    assert dev.is_reduced_protection or dev.network is NetworkMode.OPEN
    assert "network=open" in dev.reduced_protection_reasons()


def test_digest_is_stable():
    profile = get_preset("research-strict")
    assert profile.digest() == get_preset("research-strict").digest()
    assert len(profile.digest()) == 64


@pytest.mark.parametrize(
    "change",
    [
        {"network": NetworkMode.OPEN},
        {"backend": "docker"},
        {"drop_all_capabilities": False},
        {"filesystem": FilesystemPolicy(read_only_root=False)},
    ],
)
def test_digest_changes_when_anything_changes(change):
    base = get_preset("research-strict")
    changed = dataclasses.replace(base, **change)
    assert changed.digest() != base.digest()


def test_digest_is_independent_of_key_order():
    profile = get_preset("research-strict")
    payload = profile.to_dict()
    shuffled = dict(reversed(list(payload.items())))
    from the_watcher.poe.canonical import canonical_bytes, sha256_hex

    assert sha256_hex(canonical_bytes(shuffled)) == profile.digest()


def test_profile_round_trips_through_dict():
    """A serialised profile must reload to an *equal* profile.

    Equality matters beyond tidiness: the digest is computed from
    ``to_dict()``, so a profile that reloads into a different shape could
    validate under one digest and behave under another.
    """
    profile = get_preset("research-strict")
    restored = ContainmentProfile.from_dict(profile.to_dict())
    assert restored.digest() == profile.digest()
    assert restored == profile


def test_loaded_profiles_hold_tuples_not_lists():
    """A frozen dataclass holding a mutable list is not really frozen."""
    profile = get_preset("research-strict")
    restored = ContainmentProfile.from_dict(profile.to_dict())
    assert isinstance(restored.filesystem.allow_read, tuple)
    assert isinstance(restored.filesystem.allow_write, tuple)
    assert isinstance(restored.add_capabilities, tuple)
    try:
        restored.filesystem.allow_write.append("/etc")
    except AttributeError:
        pass
    else:  # pragma: no cover - only reached if the field is mutable
        raise AssertionError("a loaded profile must not be mutable through a field")


def test_unknown_profile_keys_are_refused():
    """A typo must fail loudly, not leave the default silently in force."""
    payload = get_preset("research-strict").to_dict()
    payload["netwrok"] = "open"
    with pytest.raises(ContainmentRefused, match="unknown containment profile key"):
        ContainmentProfile.from_dict(payload)


def test_unknown_section_keys_are_refused():
    payload = get_preset("research-strict").to_dict()
    payload["filesystem"]["allow_reed"] = ["/etc"]
    with pytest.raises(ContainmentRefused, match="invalid filesystem section"):
        ContainmentProfile.from_dict(payload)


def test_profile_round_trips_through_json_file(tmp_path):
    profile = dataclasses.replace(
        get_preset("research-strict"), name="custom", backend="namespaces"
    )
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile.to_dict()), encoding="utf-8")

    restored = ContainmentProfile.from_file(str(path))
    assert restored.digest() == profile.digest()


def test_profile_file_with_invalid_json_is_rejected(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        ContainmentProfile.from_file(str(path))


def test_missing_profile_file_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        ContainmentProfile.from_file(str(tmp_path / "absent.json"))


def test_replace_revalidates():
    profile = get_preset("research-strict")
    with pytest.raises(ContainmentRefused):
        profile.replace(allow_privileged=True)


# -- the refusal rules ------------------------------------------------------


def test_privileged_mode_is_refused():
    profile = dataclasses.replace(get_preset("research-strict"), allow_privileged=True)
    with pytest.raises(ContainmentRefused, match="privileged"):
        profile.validate()


def test_docker_socket_is_refused():
    profile = dataclasses.replace(
        get_preset("research-strict"), allow_docker_socket=True
    )
    with pytest.raises(ContainmentRefused, match="socket"):
        profile.validate()


def test_dangerous_capabilities_are_refused_without_the_override():
    profile = dataclasses.replace(
        get_preset("research-strict"), add_capabilities=("CAP_SYS_ADMIN",)
    )
    with pytest.raises(ContainmentRefused, match="CAP_SYS_ADMIN"):
        profile.validate()


def test_dangerous_capabilities_allowed_only_with_the_explicit_override():
    profile = dataclasses.replace(
        get_preset("research-strict"),
        add_capabilities=("CAP_SYS_ADMIN",),
        allow_dangerous_capabilities=True,
    )
    profile.validate()
    # ... and the session must be recorded as reduced protection.
    assert profile.is_reduced_protection


def test_harmless_capability_is_allowed():
    profile = dataclasses.replace(
        get_preset("research-strict"), add_capabilities=("CAP_NET_BIND_SERVICE",)
    )
    profile.validate()


def test_network_restricted_without_networks_is_refused():
    profile = dataclasses.replace(
        get_preset("research-strict"),
        network=NetworkMode.RESTRICTED,
        allowed_networks=(),
    )
    with pytest.raises(ContainmentRefused, match="restricted"):
        profile.validate()


def test_profile_refuses_incoherent_limits():
    with pytest.raises(ContainmentRefused, match="max_processes"):
        dataclasses.replace(
            get_preset("research-strict"),
            processes=dataclasses.replace(
                get_preset("research-strict").processes, max_processes=0
            ),
        ).validate()

    with pytest.raises(ContainmentRefused, match="memory_mb"):
        dataclasses.replace(
            get_preset("research-strict"),
            resources=dataclasses.replace(
                get_preset("research-strict").resources, memory_mb=1
            ),
        ).validate()


def test_backend_refuses_a_writable_root_with_no_writable_paths(tmp_path):
    """A writable root and no write allow-list is not a containment config."""
    from the_watcher.enforcement import SandboxSpec
    from the_watcher.enforcement.backends.namespaces import NamespaceEnforcer

    profile = dataclasses.replace(
        get_preset("research-strict"),
        filesystem=FilesystemPolicy(allow_write=(), read_only_root=False),
    )
    spec = SandboxSpec(
        command=("true",), profile=profile, workspace_host=str(tmp_path)
    )
    with pytest.raises(ContainmentRefused, match="writable root"):
        NamespaceEnforcer()._validate_spec(profile, spec)


def test_backend_refuses_a_missing_workspace(tmp_path):
    from the_watcher.enforcement import SandboxSpec
    from the_watcher.enforcement.backends.namespaces import NamespaceEnforcer

    profile = get_preset("research-strict")
    spec = SandboxSpec(
        command=("true",),
        profile=profile,
        workspace_host=str(tmp_path / "does-not-exist"),
    )
    with pytest.raises(ContainmentRefused, match="does not exist"):
        NamespaceEnforcer()._validate_spec(profile, spec)


def test_reduced_protection_detects_escape_hatches():
    strict = get_preset("research-strict")
    assert not strict.is_reduced_protection
    assert strict.reduced_protection_reasons() == ()

    for change, reason in (
        ({"no_new_privileges": False}, "no_new_privileges=false"),
        ({"drop_all_capabilities": False}, "drop_all_capabilities=false"),
        ({"network": NetworkMode.OPEN}, "network=open"),
        (
            {"filesystem": FilesystemPolicy(read_only_root=False)},
            "read_only_root=false",
        ),
    ):
        relaxed = dataclasses.replace(strict, **change)
        assert relaxed.is_reduced_protection, change
        assert reason in relaxed.reduced_protection_reasons(), change


def test_dev_preset_is_honestly_flagged_as_reduced_protection():
    dev = get_preset("dev")
    assert dev.is_reduced_protection
    reasons = dev.reduced_protection_reasons()
    assert "network=open" in reasons
    assert "read_only_root=false" in reasons


def test_summary_is_human_readable():
    summary = get_preset("research-strict").summary()
    assert "research-strict" in summary
    assert "network=" in summary
    assert "root=" in summary
