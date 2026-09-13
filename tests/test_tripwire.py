"""Tripwires: canaries that end the session."""

from __future__ import annotations

from pathlib import Path

import pytest

from the_watcher import (
    Decision,
    Policy,
    Risk,
    Tripwire,
    TripwireRegistry,
)
from the_watcher.exceptions import WatcherError
from the_watcher.watcher import PoEWatcher

import the_watcher as watcher_package


@pytest.fixture()
def watcher(tmp_path):
    return PoEWatcher(
        policy=Policy(workspace_root=str(tmp_path)),
        workspace_root=str(tmp_path),
    )


# ---------------------------------------------------------------------------
# Registry contents
# ---------------------------------------------------------------------------


def test_default_registry_contains_the_documented_canaries():
    registry = TripwireRegistry.default()
    identities = {tripwire.id for tripwire in registry}
    assert {
        "watcher_protected_dir",
        "fake_root_token",
        "fake_admin_credentials",
        "watcher_configuration",
        "watcher_source",
        "protected_environment",
        "container_runtime_socket",
        "host_namespace",
    } <= identities


def test_registry_supports_add_and_get():
    registry = TripwireRegistry()
    tripwire = Tripwire(id="custom", description="custom canary")
    registry.add(tripwire)
    assert len(registry) == 1
    assert registry.get("custom") is tripwire
    assert registry.get("missing") is None


def test_tripwire_requires_an_id():
    with pytest.raises(WatcherError):
        Tripwire(id="", description="no id")


def test_tripwire_dict_round_trip():
    tripwire = Tripwire(
        id="x",
        description="d",
        paths=("/a",),
        decision=Decision.QUARANTINE,
        risk=Risk.HIGH,
    )
    restored = Tripwire.from_dict(tripwire.to_dict())
    assert restored.id == "x"
    assert restored.decision is Decision.QUARANTINE
    assert restored.risk is Risk.HIGH


# ---------------------------------------------------------------------------
# Canary activation
# ---------------------------------------------------------------------------


def test_fake_root_token_triggers_kill(watcher):
    evaluation = watcher.evaluate("file_access", "read", "/fake/root_token")

    assert evaluation.decision is Decision.KILL
    assert evaluation.risk is Risk.CRITICAL
    assert evaluation.tripwire_id == "fake_root_token"
    assert watcher.killed


def test_fake_admin_credentials_trigger_kill(watcher):
    evaluation = watcher.evaluate("file_access", "read", "/fake/admin_credentials")

    assert evaluation.decision is Decision.KILL
    assert evaluation.tripwire_id == "fake_admin_credentials"
    assert watcher.killed


def test_watcher_protected_directory_triggers_kill(watcher):
    evaluation = watcher.evaluate("file_access", "read", "/.watcher/protected/keys")

    assert evaluation.decision is Decision.KILL
    assert evaluation.tripwire_id == "watcher_protected_dir"
    assert watcher.killed


def test_protected_environment_variable_triggers_kill(watcher):
    evaluation = watcher.evaluate("env_access", "read", "WATCHER_POLICY_KEY")

    assert evaluation.decision is Decision.KILL
    assert evaluation.tripwire_id == "protected_environment"
    assert watcher.killed


def test_watcher_source_modification_triggers_kill(watcher):
    package_root = Path(watcher_package.__file__).resolve().parent
    target = package_root / "watcher" / "policy.py"

    evaluation = watcher.evaluate("file_modification", "write", str(target))

    assert evaluation.decision is Decision.KILL
    assert evaluation.tripwire_id == "watcher_source"
    assert watcher.killed


def test_watcher_configuration_access_triggers_kill(watcher):
    evaluation = watcher.evaluate(
        "file_modification", "write", "/.watcher/policy.json"
    )

    assert evaluation.decision is Decision.KILL
    assert evaluation.tripwire_id == "watcher_configuration"
    assert watcher.killed


def test_container_runtime_socket_triggers_kill(watcher):
    evaluation = watcher.evaluate("file_access", "read", "/var/run/docker.sock")

    assert evaluation.decision is Decision.KILL
    assert evaluation.tripwire_id in {"container_runtime_socket", "host_namespace"}
    assert watcher.killed


def test_host_namespace_access_triggers_kill(watcher):
    evaluation = watcher.evaluate("file_access", "read", "/proc/1/root/etc/shadow")

    assert evaluation.decision is Decision.KILL
    assert watcher.killed


# ---------------------------------------------------------------------------
# Non-matches
# ---------------------------------------------------------------------------


def test_ordinary_paths_do_not_trigger_tripwires(watcher, workspace):
    evaluation = watcher.evaluate(
        "file_access", "read", str(workspace / "notes.txt")
    )

    assert evaluation.decision is Decision.ALLOW
    assert evaluation.tripwire_id is None
    assert not watcher.killed


def test_ordinary_domains_do_not_trigger_tripwires(watcher):
    evaluation = watcher.evaluate(
        "network_request", "connect", "https://github.com/repo"
    )

    assert evaluation.decision is Decision.ALLOW
    assert not watcher.killed


def test_tripwire_event_type_scoping():
    """A path-only tripwire must not fire for unrelated event types."""
    tripwire = Tripwire(
        id="scoped",
        description="only file writes",
        paths=("/canary",),
        event_types=("file_modification",),
    )
    registry = TripwireRegistry([tripwire], base="/")

    assert registry.check("file_access", "read", "/canary") is None
    assert registry.check("file_modification", "write", "/canary") is tripwire


def test_custom_tripwire_can_be_registered(tmp_path):
    registry = TripwireRegistry.default(workspace_root=str(tmp_path))
    registry.add(
        Tripwire(
            id="custom_domain",
            description="exfiltration endpoint",
            domains=("exfil.example",),
            event_types=("network_request",),
        )
    )
    watcher = PoEWatcher(
        policy=Policy(workspace_root=str(tmp_path)),
        tripwires=registry,
        workspace_root=str(tmp_path),
    )

    evaluation = watcher.evaluate(
        "network_request", "connect", "https://exfil.example/drop"
    )
    assert evaluation.decision is Decision.KILL
    assert evaluation.tripwire_id == "custom_domain"


def test_check_all_returns_every_match(tmp_path):
    registry = TripwireRegistry.default(workspace_root=str(tmp_path))
    matches = registry.check_all("file_access", "read", "/fake/root_token")
    assert [tripwire.id for tripwire in matches] == ["fake_root_token"]


# ---------------------------------------------------------------------------
# Trace integration
# ---------------------------------------------------------------------------


def test_tripwire_activation_is_recorded_in_the_trace(watcher):
    watcher.evaluate("file_access", "read", "/fake/root_token")

    activations = [
        event
        for event in watcher.trace
        if event.event_type == "tripwire_activation"
    ]
    assert len(activations) == 1
    activation = activations[0]
    assert activation.decision == "KILL"
    assert activation.risk == "CRITICAL"
    assert activation.metadata["tripwire_id"] == "fake_root_token"
    assert activation.metadata["attempted_action"] == "read"


def test_tripwire_kill_event_lands_in_the_hash_chain(watcher):
    watcher.evaluate("file_access", "read", "/fake/root_token")
    watcher.evaluate("network_request", "connect", "https://github.com")

    events = [event.event_type for event in watcher.trace]
    assert "tripwire_activation" in events
    assert "kill_switch" in events
    assert watcher.verify().valid


def test_kill_records_the_tripwire_as_the_reason(watcher):
    watcher.evaluate("file_access", "read", "/fake/root_token")

    assert watcher.kill_record is not None
    assert watcher.kill_record.reason == "TRIPWIRE:fake_root_token"
