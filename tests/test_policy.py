"""Deterministic policy rules."""

from __future__ import annotations

import json

import pytest

from the_watcher import Decision, Policy, Risk
from the_watcher.exceptions import PolicyError
from the_watcher.watcher.matching import (
    domain_matches,
    extract_domain,
    normalise_path,
    path_is_within,
)


@pytest.fixture()
def policy(tmp_path):
    return Policy(
        workspace_root=str(tmp_path),
        allowed_paths=["./workspace"],
        forbidden_paths=["/etc/shadow", "/root", "~/.ssh"],
        allowed_domains=["github.com"],
        forbidden_domains=["evil.example"],
        allowed_tools=["search", "read_file"],
        forbidden_tools=["shell"],
        max_processes=10,
        protected_env_vars=["OPENAI_API_KEY", "WATCHER_POLICY_KEY"],
    )


# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------


def test_path_inside_the_allowed_root_is_permitted(policy):
    result = policy.evaluate("file_access", "read", "./workspace/notes.txt")
    assert result.decision is Decision.ALLOW
    assert result.rule == "default"


def test_path_outside_the_allowed_root_is_denied(policy):
    result = policy.evaluate("file_access", "read", "./elsewhere/notes.txt")
    assert result.decision is Decision.DENY
    assert result.rule == "path_not_allowed"
    assert result.risk is Risk.HIGH


def test_traversal_out_of_the_allowed_root_is_denied(policy):
    result = policy.evaluate(
        "file_access", "read", "./workspace/../../../etc/passwd"
    )
    assert result.decision is Decision.DENY
    assert result.rule == "path_not_allowed"


def test_forbidden_path_is_denied(policy):
    result = policy.evaluate("file_access", "read", "/etc/shadow")
    assert result.decision is Decision.DENY
    assert result.rule == "forbidden_path"


def test_forbidden_path_descendant_is_denied(policy):
    result = policy.evaluate("file_modification", "write", "/root/notes.txt")
    assert result.decision is Decision.DENY
    assert result.rule == "forbidden_path"


def test_home_relative_forbidden_path_is_denied(policy):
    result = policy.evaluate("file_access", "read", "~/.ssh/id_rsa")
    assert result.decision is Decision.DENY
    assert result.rule == "forbidden_path"


def test_similarly_named_path_is_not_confused_with_forbidden_path(policy):
    """``/etc/shadowed`` must not be treated as ``/etc/shadow``."""
    assert path_is_within(normalise_path("/etc/shadowed"), normalise_path("/etc/shadow")) is False


def test_unrestricted_paths_are_allowed_by_default():
    result = Policy().evaluate("file_access", "read", "/tmp/anything.txt")
    assert result.decision is Decision.ALLOW


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------


def test_allowed_domain_is_permitted(policy):
    result = policy.evaluate("network_request", "connect", "https://github.com/repo")
    assert result.decision is Decision.ALLOW


def test_unauthorized_domain_is_denied(policy):
    result = policy.evaluate(
        "network_request", "connect", "https://unknown-domain.example/exfil"
    )
    assert result.decision is Decision.DENY
    assert result.rule == "domain_not_allowed"


def test_forbidden_domain_is_denied_even_when_unrestricted():
    policy = Policy(forbidden_domains=["evil.example"])
    result = policy.evaluate("network_request", "connect", "https://evil.example/x")
    assert result.decision is Decision.DENY
    assert result.rule == "forbidden_domain"


def test_wildcard_domain_allow_list():
    policy = Policy(allowed_domains=["*.trusted.example"])
    assert policy.evaluate(
        "network_request", "connect", "https://api.trusted.example/v1"
    ).decision is Decision.ALLOW
    assert policy.evaluate(
        "network_request", "connect", "https://evil.com"
    ).decision is Decision.DENY


def test_api_request_is_treated_as_network_traffic(policy):
    result = policy.evaluate("api_request", "post", "https://unknown.example/v1")
    assert result.decision is Decision.DENY


def test_network_is_unrestricted_when_no_allow_list_is_configured():
    result = Policy().evaluate("network_request", "connect", "https://example.com")
    assert result.decision is Decision.ALLOW


def test_domain_extraction_handles_common_forms():
    assert extract_domain("https://API.GitHub.com/x") == "api.github.com"
    assert extract_domain("example.com:8443/path") == "example.com"
    assert extract_domain("http://user:pw@example.com/x") == "example.com"
    assert extract_domain("/etc/passwd") == ""
    assert domain_matches("github.com", "github.com")
    assert not domain_matches("github.com", "notgithub.com")


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def test_allowed_tool_is_permitted(policy):
    result = policy.evaluate("tool_request", "invoke", "search")
    assert result.decision is Decision.ALLOW


def test_forbidden_tool_is_denied(policy):
    result = policy.evaluate("tool_request", "invoke", "shell")
    assert result.decision is Decision.DENY
    assert result.rule == "forbidden_tool"


def test_tool_outside_the_allow_list_is_denied(policy):
    result = policy.evaluate("tool_request", "invoke", "browse")
    assert result.decision is Decision.DENY
    assert result.rule == "tool_not_allowed"


def test_tool_name_from_metadata_takes_precedence(policy):
    result = policy.evaluate(
        "tool_request", "invoke", "call-42", metadata={"tool": "shell"}
    )
    assert result.decision is Decision.DENY


# ---------------------------------------------------------------------------
# Processes, runtime, environment
# ---------------------------------------------------------------------------


def test_process_count_within_limit_is_allowed(policy):
    result = policy.evaluate(
        "process_creation", "spawn", "123", metadata={"process_count": 5}
    )
    assert result.decision is Decision.ALLOW


def test_process_count_over_limit_is_denied(policy):
    result = policy.evaluate(
        "process_creation", "spawn", "123", metadata={"process_count": 25}
    )
    assert result.decision is Decision.DENY
    assert result.rule == "max_processes"


def test_process_tree_explosion_is_killed(policy):
    result = policy.evaluate(
        "process_creation", "spawn", "123", metadata={"process_count": 5000}
    )
    assert result.decision is Decision.KILL
    assert result.risk is Risk.CRITICAL
    assert result.rule == "max_processes_hard"


def test_privilege_escalation_is_killed(policy):
    result = policy.evaluate("shell_command", "exec", "sudo cat /etc/shadow")
    assert result.decision is Decision.KILL
    assert result.risk is Risk.CRITICAL
    assert result.rule == "privilege_escalation"


def test_privilege_escalation_can_be_allowed_explicitly():
    policy = Policy(allow_privilege_escalation=True)
    result = policy.evaluate("shell_command", "exec", "sudo ls")
    assert result.decision is Decision.ALLOW


def test_destructive_command_is_killed(policy):
    result = policy.evaluate("shell_command", "exec", "rm -rf /")
    assert result.decision is Decision.KILL
    assert result.rule.startswith("critical_command")


def test_sandbox_escape_surface_is_killed(policy):
    result = policy.evaluate("shell_command", "exec", "nsenter --target 1 --mount")
    assert result.decision is Decision.KILL
    assert result.rule == "sandbox_escape"


def test_persistence_attempt_is_killed(policy):
    result = policy.evaluate("file_modification", "write", "~/.bashrc")
    assert result.decision is Decision.KILL
    assert result.rule == "persistence_attempt"


def test_cron_persistence_is_killed(policy):
    result = policy.evaluate(
        "shell_command", "exec", "crontab -l | crontab -"
    )
    assert result.decision is Decision.KILL
    assert result.rule == "persistence_attempt"


def test_protected_environment_variable_is_denied(policy):
    result = policy.evaluate("env_access", "read", "OPENAI_API_KEY")
    assert result.decision is Decision.DENY
    assert result.rule == "protected_env_var"


def test_protected_environment_variable_via_metadata(policy):
    result = policy.evaluate(
        "tool_request", "invoke", "env", metadata={"env_var": "OPENAI_API_KEY"}
    )
    assert result.decision is Decision.DENY


def test_unprotected_environment_variable_is_allowed(policy):
    result = policy.evaluate("env_access", "read", "PATH")
    assert result.decision is Decision.ALLOW


def test_runtime_limit_is_enforced(policy):
    result = policy.evaluate(
        "tool_request", "invoke", "search", metadata={"runtime_seconds": 99999}
    )
    assert result.decision is Decision.KILL
    assert result.rule == "max_runtime"


def test_host_resource_access_is_killed(policy):
    result = policy.evaluate(
        "file_access", "read", "/var/run/docker.sock"
    )
    assert result.decision is Decision.KILL


def test_host_resource_signal_is_killed(policy):
    result = policy.evaluate(
        "file_access", "read", "/tmp/x", metadata={"host_resource": True}
    )
    assert result.decision is Decision.KILL
    assert result.rule == "host_resource_access"


def test_allow_host_resource_access_flag_disables_that_rule():
    policy = Policy(allow_host_resource_access=True)
    result = policy.evaluate(
        "file_access", "read", "/tmp/x", metadata={"host_resource": True}
    )
    assert result.decision is Decision.ALLOW


# ---------------------------------------------------------------------------
# Configuration plumbing
# ---------------------------------------------------------------------------


def test_policy_survives_a_dict_round_trip(policy):
    restored = Policy.from_dict(policy.to_dict())
    assert restored.to_dict() == policy.to_dict()


def test_policy_loads_from_json_file(tmp_path, policy):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy.to_dict()), encoding="utf-8")
    loaded = Policy.load(str(path))
    assert loaded.allowed_domains == policy.allowed_domains
    assert loaded.max_processes == policy.max_processes


def test_policy_rejects_unknown_fields():
    with pytest.raises(PolicyError):
        Policy.from_dict({"not_a_field": True})


def test_policy_rejects_invalid_decision_value():
    with pytest.raises(PolicyError):
        Policy.from_dict({"unknown_domain": "MAYBE"})


def test_policy_rejects_invalid_limits():
    with pytest.raises(PolicyError):
        Policy(max_processes=-1)
    with pytest.raises(PolicyError):
        Policy(max_runtime_seconds=0)


def test_decision_values_are_strings():
    policy = Policy.from_dict({"unknown_domain": "QUARANTINE"})
    assert policy.unknown_domain is Decision.QUARANTINE
    assert policy.unknown_domain.value == "QUARANTINE"


def test_evaluation_is_stringifiable(policy):
    result = policy.evaluate("file_access", "read", "/etc/shadow")
    text = str(result)
    assert "DENY" in text
    assert "forbidden_path" in text
    assert result.blocked is True
    assert result.allowed is False
    assert result.to_metadata()["rule"] == "forbidden_path"
