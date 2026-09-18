"""Phase 0 Blocker C: authority of the facts a policy decision is built from.

The defect these tests exist for: the policy engine read almost every fact it
judged from client-supplied ``metadata``, and ``metadata["path"]`` *overrode*
the ``resource`` field. A client could therefore send
``resource="/etc/shadow"`` - the value actually written into the trace - with
``metadata={"path": "/workspace/harmless.txt"}``, and the path rule would check
the harmless file while the audit record showed the dangerous one.

The property asserted throughout:

    A client assertion may only ever *add* restriction. It can never override an
    authoritative fact, and it can never weaken a verdict derived from one.
"""

from __future__ import annotations

import sys


from conftest import PROJECT_ROOT

from the_watcher.watcher.authority import (
    AUTHORITATIVE_NAMESPACE,
    AUTHORITY_MAP,
    AuthoritativeFacts,
    Authority,
    authority_of,
    candidate_values,
    describe_authority,
    resolve_fact,
)
from the_watcher.watcher.decision import Decision
from the_watcher.watcher.policy import Policy


def _authoritative(**facts) -> dict:
    """Client metadata carrying the supervisor's own reserved namespace."""
    return {AUTHORITATIVE_NAMESPACE: AuthoritativeFacts(**facts).to_metadata()}


# ---------------------------------------------------------------------------
# The AuthorityMap itself
# ---------------------------------------------------------------------------


def test_every_metadata_key_the_engine_reads_is_classified():
    """No policy input may be unclassified; unknown keys are client-asserted."""
    # Every key the engine consults anywhere in policy.py.
    read_keys = {
        "path",
        "domain",
        "tool",
        "env_var",
        "privilege_escalation",
        "persistence",
        "host_resource",
        "process_count",
        "child_processes",
        "runtime_seconds",
        AUTHORITATIVE_NAMESPACE,
    }
    missing = read_keys - set(AUTHORITY_MAP)
    assert not missing, f"unclassified policy inputs: {sorted(missing)}"

    # And an unknown key is never silently promoted.
    assert authority_of("something_new") is Authority.CLIENT_ASSERTED


def test_supervisor_generated_facts_are_the_observable_ones():
    """Only facts the supervisor can really establish are marked authoritative."""
    from the_watcher.watcher.authority import SUPERVISOR_FACT_KEYS

    assert "process_count" in SUPERVISOR_FACT_KEYS
    assert "runtime_seconds" in SUPERVISOR_FACT_KEYS
    assert "resource" in SUPERVISOR_FACT_KEYS
    # These cannot be observed without instrumentation, so they must not be
    # presented as host facts.
    for cooperative in ("privilege_escalation", "persistence", "host_resource", "env_var"):
        assert cooperative not in SUPERVISOR_FACT_KEYS
        assert AUTHORITY_MAP[cooperative].cooperative is True
        assert AUTHORITY_MAP[cooperative].authority is Authority.CLIENT_ASSERTED


def test_authority_map_is_serialisable_for_documentation():
    payload = describe_authority()
    assert payload["namespace"] == AUTHORITATIVE_NAMESPACE
    assert payload["facts"]
    keys = {entry["key"] for entry in payload["facts"]}
    assert "path" in keys and "process_count" in keys
    assert "add restriction" in payload["rule"]


# ---------------------------------------------------------------------------
# Forged path metadata
# ---------------------------------------------------------------------------


def test_forged_path_metadata_cannot_hide_a_forbidden_resource():
    """The recorded resource is always checked, whatever metadata claims."""
    policy = Policy(forbidden_paths=["/etc"])
    review = policy.evaluate(
        "file_access",
        "read",
        "/etc/shadow",
        metadata={"path": "/workspace/harmless.txt"},
    )
    assert review.decision is Decision.DENY
    assert review.rule == "forbidden_path"
    assert review.facts["path"] == Authority.CLIENT_ASSERTED.value


def test_forged_path_metadata_is_evaluated_in_addition_not_instead():
    """A forbidden claimed path is caught even with a benign resource."""
    policy = Policy(forbidden_paths=["/etc"])
    review = policy.evaluate(
        "file_access",
        "read",
        "/workspace/harmless.txt",
        metadata={"path": "/etc/shadow"},
    )
    assert review.decision is Decision.DENY
    assert review.rule == "forbidden_path"


def test_authoritative_resource_is_labelled_authoritative():
    policy = Policy(forbidden_paths=["/etc"])
    review = policy.evaluate(
        "file_access",
        "read",
        "/etc/shadow",
        metadata=_authoritative(resource="/etc/shadow"),
    )
    assert review.decision is Decision.DENY
    assert review.facts["path"] == Authority.AUTHORITATIVE.value


def test_allow_list_path_cannot_be_bypassed_by_metadata():
    """``metadata.path`` cannot smuggle a path into an allowed root."""
    policy = Policy(allowed_paths=["/workspace"])
    review = policy.evaluate(
        "file_access",
        "read",
        "/etc/shadow",
        metadata={"path": "/workspace/notes.txt"},
    )
    assert review.decision is Decision.DENY
    assert review.rule == "path_not_allowed"


# ---------------------------------------------------------------------------
# Forged domain and tool metadata
# ---------------------------------------------------------------------------


def test_forged_domain_metadata_cannot_hide_a_forbidden_host():
    policy = Policy(forbidden_domains=["evil.example"])
    review = policy.evaluate(
        "network_request",
        "connect",
        "https://evil.example/exfil",
        metadata={"domain": "api.openai.com"},
    )
    assert review.decision is Decision.DENY
    assert review.rule == "forbidden_domain"


def test_forged_domain_metadata_is_evaluated_in_addition():
    policy = Policy(forbidden_domains=["evil.example"])
    review = policy.evaluate(
        "network_request",
        "connect",
        "https://api.openai.com/v1",
        metadata={"domain": "evil.example"},
    )
    assert review.decision is Decision.DENY


def test_forged_domain_cannot_escape_a_restricted_network():
    """A benign claimed domain must not launder a disallowed real host."""
    policy = Policy(allowed_domains=["api.openai.com"])
    review = policy.evaluate(
        "network_request",
        "connect",
        "https://attacker.example/steal",
        metadata={"domain": "api.openai.com"},
    )
    assert review.decision is Decision.DENY
    assert review.rule == "domain_not_allowed"


def test_forged_tool_metadata_cannot_hide_a_forbidden_tool():
    policy = Policy(forbidden_tools=["shell"])
    review = policy.evaluate(
        "tool_request", "invoke", "shell", metadata={"tool": "search"}
    )
    assert review.decision is Decision.DENY
    assert review.rule == "forbidden_tool"


def test_tool_can_still_be_named_by_metadata_when_the_resource_is_empty():
    """The legitimate case must keep working."""
    policy = Policy(forbidden_tools=["shell"])
    review = policy.evaluate("tool_request", "invoke", "", metadata={"tool": "shell"})
    assert review.decision is Decision.DENY


# ---------------------------------------------------------------------------
# Forged process count and runtime
# ---------------------------------------------------------------------------


def test_forged_process_count_cannot_evade_the_ceiling():
    policy = Policy(max_processes=8)
    # The supervisor measured 25; the client claims 1.
    review = policy.evaluate(
        "process_creation",
        "spawn",
        "4242",
        metadata={**_authoritative(process_count=10), "process_count": 1},
    )
    assert review.decision is Decision.DENY
    assert review.rule == "max_processes"
    assert review.facts["process_count"] == Authority.OBSERVED.value


def test_observed_process_count_is_used_when_the_client_says_nothing():
    policy = Policy(max_processes=8)
    review = policy.evaluate(
        "process_creation", "spawn", "4242", metadata=_authoritative(process_count=10)
    )
    assert review.decision is Decision.DENY


def test_client_asserted_process_count_still_works_without_an_observation():
    """V1 in-process use keeps its old behaviour."""
    policy = Policy(max_processes=8)
    review = policy.evaluate(
        "process_creation", "spawn", "4242", metadata={"process_count": 10}
    )
    assert review.decision is Decision.DENY
    assert review.facts["process_count"] == Authority.CLIENT_ASSERTED.value


def test_forged_runtime_cannot_evade_the_ceiling():
    policy = Policy(max_runtime_seconds=600)
    review = policy.evaluate(
        "tool_request",
        "invoke",
        "search",
        metadata={**_authoritative(runtime_seconds=99999), "runtime_seconds": 1},
    )
    assert review.decision is Decision.KILL
    assert review.rule == "max_runtime"
    assert review.facts["runtime_seconds"] == Authority.OBSERVED.value


def test_legacy_child_processes_alias_is_still_read():
    policy = Policy(max_processes=8)
    review = policy.evaluate(
        "process_creation", "spawn", "4242", metadata={"child_processes": 10}
    )
    assert review.decision is Decision.DENY


# ---------------------------------------------------------------------------
# Resolution semantics
# ---------------------------------------------------------------------------


def test_resolve_fact_reports_authority_for_each_case():
    assert resolve_fact({}, "process_count") == (None, Authority.OBSERVED)
    assert resolve_fact({"process_count": 3}, "process_count") == (
        3,
        Authority.CLIENT_ASSERTED,
    )
    value, authority = resolve_fact(_authoritative(process_count=7), "process_count")
    assert (value, authority) == (7, Authority.OBSERVED)

    value, authority = resolve_fact(
        {**_authoritative(resource="/etc/x"), "resource": "/tmp/y"}, "resource"
    )
    assert (value, authority) == ("/etc/x", Authority.AUTHORITATIVE)


def test_candidate_values_always_include_the_authoritative_resource():
    """The forged and the real value are both candidates, real one first."""
    metadata = {**_authoritative(resource="/etc/shadow"), "path": "/workspace/ok"}
    candidates = candidate_values(metadata, "/etc/shadow", "path")
    values = [value for _, value, _ in candidates]
    assert values[0] == "/etc/shadow"
    assert "/workspace/ok" in values


def test_authoritative_facts_ignore_malformed_payloads():
    """Garbage in the reserved namespace must not become a fact."""
    assert AuthoritativeFacts.from_metadata({"authoritative": "not a mapping"}) == (
        AuthoritativeFacts()
    )
    facts = AuthoritativeFacts.from_metadata(
        {"authoritative": {"process_count": "many", "runtime_seconds": True}}
    )
    assert facts.process_count is None
    assert facts.runtime_seconds is None


# ---------------------------------------------------------------------------
# End to end through the supervisor
# ---------------------------------------------------------------------------


def _running_daemon(tmp_path, policy=None):
    from the_watcher.ipc.server import ClientContext
    from the_watcher.supervisor import DaemonConfig, WatcherDaemon

    daemon = WatcherDaemon(
        DaemonConfig(
            command=[sys.executable, "-c", "import time; time.sleep(30)"],
            policy=policy or Policy(forbidden_paths=["/etc"]),
            workspace_root=str(PROJECT_ROOT),
            cwd=str(PROJECT_ROOT),
            storage_root=str(tmp_path / "watcher-home"),
        )
    )
    daemon._prepare()
    daemon._serve()
    context = ClientContext(
        session_id=daemon.session_id, connection_id="conn-1", authenticated=True
    )
    return daemon, context


def test_daemon_overwrites_a_client_supplied_reserved_namespace(tmp_path):
    """The supervisor's facts always win, and the attempt is recorded."""
    daemon, context = _running_daemon(tmp_path)
    try:
        payload = {
            "event_type": "file_access",
            "action": "read",
            "resource": "/etc/shadow",
            "metadata": {
                "path": "/workspace/harmless.txt",
                AUTHORITATIVE_NAMESPACE: {"resource": "/workspace/harmless.txt"},
            },
        }
        response = daemon.dispatch("EVALUATE", payload, context)
        assert response["decision"] == "DENY"
        assert response["rule"] == "forbidden_path"

        types = [event.event_type for event in daemon.trace.events]
        assert "client_field_rejected" in types, (
            "writing the supervisor's reserved namespace was not recorded"
        )
        rejected = [
            event
            for event in daemon.trace.events
            if event.event_type == "client_field_rejected"
        ]
        assert any(
            f"metadata.{AUTHORITATIVE_NAMESPACE}" in event.metadata["fields"]
            for event in rejected
        )
    finally:
        daemon._finalize(1)


def test_daemon_records_fact_authority_in_the_decision_event(tmp_path):
    daemon, context = _running_daemon(tmp_path)
    try:
        payload = {
            "event_type": "file_access",
            "action": "read",
            "resource": "/etc/shadow",
            "metadata": {"path": "/workspace/harmless.txt"},
        }
        daemon.dispatch("EVALUATE", payload, context)

        decisions = [
            event
            for event in daemon.trace.events
            if event.event_type == "policy_decision"
        ]
        assert decisions, "no policy decision was recorded"
        # In V2 the supervisor republishes the resource, so the path rule is
        # recorded as resting on an authoritative fact - not on the client's
        # claimed metadata.path.
        assert decisions[0].metadata["fact_authority"]["path"] == (
            Authority.AUTHORITATIVE.value
        )
    finally:
        daemon._finalize(1)


def test_daemon_supplies_an_observed_process_count(tmp_path):
    """The process ceiling is now judged on a measured tree size."""
    daemon, context = _running_daemon(tmp_path, policy=Policy(max_processes=0))
    try:
        payload = {
            "event_type": "process_creation",
            "action": "spawn",
            "resource": "4242",
            "metadata": {},  # the client asserts nothing at all
        }
        response = daemon.dispatch("EVALUATE", payload, context)
        # max_processes=0 with a live tree means the measured count exceeds it.
        assert response["decision"] in ("DENY", "KILL")
        assert response["rule"] in ("max_processes", "max_processes_hard")
    finally:
        daemon._finalize(1)


def test_authoritative_resource_cannot_be_redirected_by_metadata(tmp_path):
    daemon, context = _running_daemon(tmp_path)
    try:
        payload = {
            "event_type": "file_access",
            "action": "read",
            "resource": "/etc/shadow",
            "metadata": {"path": "/workspace/harmless.txt", "domain": "api.openai.com"},
        }
        response = daemon.dispatch("EVALUATE", payload, context)
        assert response["decision"] == "DENY"
        # The trace must record the dangerous resource, not the claimed one.
        events = [
            event for event in daemon.trace.events if event.resource == "/etc/shadow"
        ]
        assert events, "the recorded resource was replaced by client metadata"
    finally:
        daemon._finalize(1)
