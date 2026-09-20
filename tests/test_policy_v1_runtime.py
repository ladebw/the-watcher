"""Policy V1 runtime wiring: the projection boundary and the ``--policy`` CLI.

The document format is tested by ``test_policy_v1.py``. This module tests what
happens when a validated document meets the *running* supervisor: which fields
are enforced, which are refused rather than silently ignored, that the reviewed
Policy V1 pattern semantics survive into runtime decisions, and that the trace
records what was decided and under which policy.

Policy V1 patterns are absolute POSIX paths and the format refuses drive letters,
so filesystem-rule behaviour is asserted on POSIX only. On Windows the same
document must be *refused* instead of silently matching nothing, and that refusal
is asserted separately.
"""

from __future__ import annotations

import json
import os
import subprocess  # noqa: F401 - kept for parity with the CLI helpers
import sys

import pytest

from the_watcher.cli import main as cli_main
from the_watcher.exceptions import PolicyError
from the_watcher.policy_v1 import loads_policy
from the_watcher.policy_v1_runtime import (
    ENFORCED,
    NOT_APPLICABLE,
    REFUSED,
    project_policy_v1,
)
from the_watcher.watcher.decision import Decision
from the_watcher.watcher.policy import Policy
from the_watcher.watcher.watcher import PoEWatcher

POSIX_ONLY = pytest.mark.skipif(
    os.name == "nt",
    reason="Policy V1 patterns are absolute POSIX paths; on Windows the "
    "projection refuses them rather than matching nothing",
)

#: The end-to-end document from the phase brief.
E2E = {
    "version": 1,
    "filesystem": {
        "allow": ["/workspace/**"],
        "deny": ["/workspace/secret/**"],
    },
    "tripwires": ["/workspace/KILL"],
    "on_violation": {"filesystem": "DENY", "tripwire": "KILL"},
}


#: A document that projects on every platform: no filesystem rules, because
#: those are POSIX-only (see ``POSIX_ONLY``).
NEUTRAL = {"version": 1, "name": "acme", "process": {"max_runtime_seconds": 600}}


def document(payload: dict) -> str:
    return json.dumps(payload)


def build_document(payload: dict, workspace: str = "/workspace"):
    return project_policy_v1(loads_policy(document(payload)), workspace_root=workspace)


def write_policy(tmp_path, payload: dict, name: str = "watcher.json"):
    path = tmp_path / name
    path.write_text(document(payload), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# 1. the projection boundary
# ---------------------------------------------------------------------------


def test_the_projection_produces_a_runtime_policy_not_a_second_engine():
    """The projection hands back the runtime's own Policy type."""
    projection = build_document(NEUTRAL)
    assert isinstance(projection.policy, Policy)
    # The V1 document itself carries no runtime authority: it is a document.
    parsed = loads_policy(document(NEUTRAL))
    assert not hasattr(parsed, "evaluate")
    assert not hasattr(parsed, "path_rule")


def test_the_projection_is_a_function_of_the_document_digest():
    """Same digest -> same runtime configuration. No clock, no environment."""
    first = build_document(NEUTRAL)
    second = build_document(NEUTRAL)
    assert first.document_digest == second.document_digest
    assert first.policy.name == second.policy.name
    assert first.policy.max_processes == second.policy.max_processes
    assert first.policy.max_runtime_seconds == second.policy.max_runtime_seconds
    # Key order and whitespace are not part of the document's meaning.
    reordered = {
        "process": {"max_runtime_seconds": 600},
        "name": "acme",
        "version": 1,
    }
    assert build_document(reordered).document_digest == first.document_digest
    assert project_policy_v1(
        loads_policy("{  \"version\" : 1 ,\n \"name\":\"acme\","
                     "\"process\":{\"max_runtime_seconds\":600} }"),
        workspace_root="/workspace",
    ).document_digest == first.document_digest


def test_the_projection_refuses_a_non_document():
    with pytest.raises(PolicyError):
        project_policy_v1({"version": 1})


def test_every_policy_v1_field_is_classified():
    """No field may be absent from the classification table."""
    projection = build_document(E2E if os.name != "nt" else NEUTRAL)
    classified = {item.field for item in projection.dispositions}
    filesystem_fields = (
        {"filesystem.allow", "filesystem.deny"} if os.name != "nt" else {"filesystem"}
    )
    for field in (
        {
            "version",
            "name",
            "network.mode",
            "network.allow",
            "network.deny",
            "process.max_children",
            "process.max_runtime_seconds",
            "resources.memory_mb",
            "resources.cpu_seconds",
            "tripwires",
            "on_violation.filesystem",
            "on_violation.network",
            "on_violation.process",
            "on_violation.resources",
            "on_violation.tripwire",
        }
        | filesystem_fields
    ):
        assert field in classified, f"{field} is not classified"
    assert {item.disposition for item in projection.dispositions} <= {
        ENFORCED,
        REFUSED,
        NOT_APPLICABLE,
    }


def test_a_defaults_only_document_enforces_nothing_and_says_so():
    projection = build_document({"version": 1})
    for item in projection.dispositions:
        if item.field.startswith("filesystem"):
            assert item.disposition == NOT_APPLICABLE
    assert projection.policy.path_rule is None


# ---------------------------------------------------------------------------
# 2. fail-closed: unsupported configuration is refused, never ignored
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,section",
    [
        ("network restricted", {"network": {"mode": "restricted"}}),
        ("network open", {"network": {"mode": "open"}}),
        (
            "network allow list",
            {"network": {"mode": "restricted", "allow": ["api.example.com"]}},
        ),
        ("network deny list", {"network": {"deny": ["evil.example.com"]}}),
        ("memory ceiling", {"resources": {"memory_mb": 256}}),
        ("cpu ceiling", {"resources": {"cpu_seconds": 30}}),
        ("process decision escalate", {"on_violation": {"process": "KILL"}}),
        ("resources decision change", {"on_violation": {"resources": "KILL"}}),
        ("network decision change", {"on_violation": {"network": "QUARANTINE"}}),
        ("wildcard tripwire", {"tripwires": ["/var/run/**"]}),
        ("question tripwire", {"tripwires": ["/var/run/docker.soc?"]}),
    ],
)
def test_unenforceable_configuration_is_refused(label, section):
    payload = {**E2E, **section}
    with pytest.raises(PolicyError) as excinfo:
        build_document(payload)
    message = str(excinfo.value)
    assert "refusing to launch" in message
    assert "silently missing" in message


def test_a_refusal_names_the_field_and_the_reason():
    with pytest.raises(PolicyError) as excinfo:
        build_document({**E2E, "network": {"mode": "restricted"}})
    message = str(excinfo.value)
    assert "network.mode" in message
    assert "broker is Phase 8" in message


def test_the_classification_is_value_based_so_it_cannot_drift_from_the_digest():
    """Explicitly writing a default is the same document as omitting it."""
    omitted = loads_policy('{"version": 1}')
    explicit = loads_policy(
        '{"version": 1, "network": {"mode": "none"}, "filesystem": {"allow": [], '
        '"deny": []}, "tripwires": []}'
    )
    assert omitted.document_digest == explicit.document_digest
    assert [
        (item.field, item.disposition) for item in build_document({"version": 1}).dispositions
    ] == [
        (item.field, item.disposition)
        for item in project_policy_v1(explicit, workspace_root="/workspace").dispositions
    ]


# ---------------------------------------------------------------------------
# 3. filesystem semantics at runtime (POSIX)
# ---------------------------------------------------------------------------


@POSIX_ONLY
def test_deny_overrides_allow():
    rules = build_document(E2E).policy.path_rule
    assert rules("/workspace/secret/key.txt").decision is Decision.DENY
    # The same path is inside the allow root, so this only passes if DENY is
    # evaluated first.
    assert rules("/workspace/secret/deeper/key.txt").decision is Decision.DENY
    assert rules("/workspace/file.txt") is None


@POSIX_ONLY
def test_double_star_has_policy_v1_semantics_at_runtime():
    """``**`` must span segments. The V3 matcher cannot express this."""
    from the_watcher.watcher.matching import any_path_matches

    rules = build_document(E2E).policy.path_rule
    for allowed in (
        "/workspace/file.txt",
        "/workspace/a/b.txt",
        "/workspace/a/b/c/d.txt",
    ):
        assert rules(allowed) is None, allowed
    # The old matcher reads ``**`` as a literal segment, which is why these
    # rules must not be routed through it.
    assert any_path_matches("/workspace/a/b.txt", ["/workspace/**"]) is False


@POSIX_ONLY
def test_single_star_and_question_keep_their_policy_v1_meaning():
    rules = build_document(
        {"version": 1, "filesystem": {"deny": ["/workspace/*.key", "/workspace/?"]}}
    ).policy.path_rule
    assert rules("/workspace/server.key").decision is Decision.DENY
    assert rules("/workspace/nested/server.key") is None
    assert rules("/workspace/a").decision is Decision.DENY
    assert rules("/workspace/ab") is None


@POSIX_ONLY
def test_an_allow_list_without_a_deny_rule_is_default_deny():
    rules = build_document(
        {"version": 1, "filesystem": {"allow": ["/workspace/**"]}}
    ).policy.path_rule
    assert rules("/workspace/file.txt") is None
    assert rules("/etc/passwd").decision is Decision.DENY
    assert rules("/etc/passwd").rule == "policy_v1:filesystem.allow"


@POSIX_ONLY
def test_no_allow_list_means_no_allow_restriction():
    """Documented default behaviour: an absent allow-list restricts nothing."""
    projection = build_document({"version": 1, "filesystem": {"deny": ["/workspace/x"]}})
    rules = projection.policy.path_rule
    assert rules("/etc/passwd") is None


@POSIX_ONLY
def test_the_subject_is_canonicalised_once_and_reused():
    """One canonical subject per action, shared by every rule."""
    rules = build_document(E2E).policy.path_rule
    # A relative path resolves against the workspace root once and is then
    # matched against the absolute patterns.
    assert rules("secret/key.txt").decision is Decision.DENY
    assert rules("file.txt") is None
    assert rules("./file.txt") is None
    assert rules("/workspace/./a//b.txt") is None


@POSIX_ONLY
def test_the_verdict_records_the_canonical_subject():
    verdict = build_document(E2E).policy.path_rule("secret/key.txt")
    assert verdict.evidence["canonical_subject"] == "/workspace/secret/key.txt"
    assert verdict.evidence["policy_subsystem"] == "filesystem"


@POSIX_ONLY
def test_on_violation_decisions_are_applied_not_just_parsed():
    for decision in ("DENY", "QUARANTINE", "KILL"):
        rules = build_document(
            {**E2E, "on_violation": {"filesystem": decision, "tripwire": "KILL"}}
        ).policy.path_rule
        assert rules("/workspace/secret/key.txt").decision is Decision(decision)


# ---------------------------------------------------------------------------
# 4. tripwires use the existing kill path
# ---------------------------------------------------------------------------


@POSIX_ONLY
def test_a_tripwire_reaches_kill_through_the_existing_path():
    watcher = PoEWatcher(
        policy=build_document(E2E).policy,
        workspace_root="/workspace",
        tripwires=build_document(E2E).tripwires,
    )
    evaluation = watcher.evaluate(
        "file_access", "open", "/workspace/KILL", {"path": "/workspace/KILL"}
    )
    assert evaluation.decision is Decision.KILL
    assert evaluation.tripwire_id == "policy_v1.tripwire.0"
    assert watcher.killed is True
    kinds = [event.event_type for event in watcher.trace.events]
    assert "tripwire_activation" in kinds
    # The kill itself is recorded by the existing kill switch.
    assert "session_kill" in kinds or watcher.kill_record is not None


@POSIX_ONLY
def test_a_tripwire_does_not_fire_for_an_unrelated_path():
    projection = build_document(E2E)
    watcher = PoEWatcher(
        policy=projection.policy,
        workspace_root="/workspace",
        tripwires=projection.tripwires,
    )
    evaluation = watcher.evaluate(
        "file_access", "read", "/workspace/file.txt", {"path": "/workspace/file.txt"}
    )
    assert evaluation.decision is Decision.ALLOW
    assert watcher.killed is False


# ---------------------------------------------------------------------------
# 4b. network.mode = "none" means NO NETWORK ACCESS
#
# The design's legacy projection (docs/V4_DESIGN.md section 4.8) defines
# ``network.mode == none`` as ``restrict_network = True``, ``allowed_domains =
# ()`` plus the empty-network-namespace containment posture. "None" is therefore
# an affirmative no-egress posture, not "no network policy configured", and the
# projection must apply it rather than leaving the runtime's permissive default.
# ---------------------------------------------------------------------------


def test_network_mode_none_is_enforced_not_not_applicable():
    projection = build_document({"version": 1})
    mode = next(
        item for item in projection.dispositions if item.field == "network.mode"
    )
    assert mode.disposition == ENFORCED, mode.detail
    assert "no network access" in mode.detail


def test_network_mode_none_applies_the_documented_projection():
    projection = build_document({"version": 1})
    policy = projection.policy
    assert policy.restrict_network is True
    assert tuple(policy.allowed_domains) == ()
    assert policy.unknown_domain is Decision.DENY
    assert policy.network_is_restricted is True


def test_the_default_network_posture_denies_every_target():
    """The cooperative half of the documented mapping, through the real engine."""
    projection = build_document({"version": 1})
    watcher = PoEWatcher(policy=projection.policy, workspace_root="/workspace")
    for resource in ("api.openai.com", "example.com", "10.0.0.1"):
        evaluation = watcher.evaluate(
            "network_request", "connect", resource, {"domain": resource}
        )
        assert evaluation.decision is Decision.DENY, resource
        assert evaluation.rule in {"domain_not_allowed", "unresolvable_network_target"}


def test_an_explicit_none_is_the_same_as_omitting_the_section():
    """Digest-consistent: both are the same document and get the same posture."""
    omitted = build_document({"version": 1})
    explicit = build_document({"version": 1, "network": {"mode": "none"}})
    assert omitted.document_digest == explicit.document_digest
    assert explicit.policy.restrict_network is True
    assert explicit.policy.network_is_restricted is True


def test_a_document_without_the_policy_flag_is_unaffected():
    """The permissive engine default is untouched for non-Policy-V1 runs."""
    assert Policy().network_is_restricted is False
    assert Policy().restrict_network is None


def test_every_other_network_mode_is_still_refused():
    for mode in ("restricted", "open"):
        with pytest.raises(PolicyError):
            build_document({"version": 1, "network": {"mode": mode}})


# ---------------------------------------------------------------------------
# 4c. the process guard, pinned
# ---------------------------------------------------------------------------


def test_the_process_guard_escalates_beyond_the_documents_declared_decision():
    """A pre-existing runtime guard, not a Policy V1 field.

    ``process.max_children`` is projected onto the runtime process-tree ceiling
    and ``on_violation.process`` is refused unless it is the documented DENY. The
    runtime additionally KILLs when the tree exceeds the ceiling by its own
    multiplier (3). Policy V1 has no field for that guard, and it escalates in the
    stricter direction only - never weaker than the document - but it is a
    decision the document did not author, so it is pinned here rather than left
    to be discovered.
    """
    projection = build_document({"version": 1, "process": {"max_children": 2}})
    assert projection.policy.max_processes == 2
    assert projection.policy.kill_max_processes_multiplier == 3

    def verdict(count: int):
        watcher = PoEWatcher(policy=projection.policy, workspace_root="/workspace")
        return watcher.evaluate(
            "process_creation", "spawn", "child", {"process_count": count}
        )

    assert verdict(2).decision is Decision.ALLOW
    assert verdict(3).decision is Decision.DENY  # matches on_violation.process
    assert verdict(3).rule == "max_processes"
    # Above the guard's hard limit the runtime escalates on its own authority.
    assert verdict(7).decision is Decision.KILL
    assert verdict(7).rule == "max_processes_hard"


def test_max_children_zero_escalates_immediately_and_is_documented():
    """The degenerate ceiling: the guard's hard limit is 0 x 3, so any child KILLs."""
    projection = build_document({"version": 1, "process": {"max_children": 0}})
    watcher = PoEWatcher(policy=projection.policy, workspace_root="/workspace")
    evaluation = watcher.evaluate(
        "process_creation", "spawn", "child", {"process_count": 1}
    )
    assert evaluation.decision is Decision.KILL
    assert evaluation.rule == "max_processes_hard"


# ---------------------------------------------------------------------------
# 5. the trace records the decision and the supervisor-computed digest
# ---------------------------------------------------------------------------


@POSIX_ONLY
def test_the_trace_records_the_decision_and_the_policy_digest():
    projection = build_document(E2E)
    watcher = PoEWatcher(
        policy=projection.policy,
        workspace_root="/workspace",
        tripwires=projection.tripwires,
    )
    watcher.evaluate(
        "file_access", "open", "/workspace/secret/key.txt",
        {"path": "/workspace/secret/key.txt"},
    )
    decisions = [
        event
        for event in watcher.trace.events
        if event.event_type == "policy_decision"
    ]
    assert decisions, "no policy_decision event was recorded"
    metadata = decisions[-1].metadata
    evidence = metadata["policy_evidence"]
    assert evidence["policy_document_digest"] == projection.document_digest
    assert evidence["policy_format"] == "watcher-policy/1"
    assert evidence["policy_rule"] == "policy_v1:filesystem.deny[0]"
    assert evidence["canonical_subject"] == "/workspace/secret/key.txt"
    assert decisions[-1].decision == "DENY"


@POSIX_ONLY
def test_the_client_cannot_replace_the_authoritative_policy_digest():
    """A workload-supplied digest must never win over the supervisor's."""
    projection = build_document(E2E)
    watcher = PoEWatcher(
        policy=projection.policy,
        workspace_root="/workspace",
        tripwires=projection.tripwires,
    )
    forged = {
        "policy_evidence": {
            "policy_document_digest": "0" * 64,
            "policy_format": "forged",
        },
        "path": "/workspace/file.txt",
    }
    watcher.evaluate("file_access", "open", "/workspace/file.txt", forged)
    for event in watcher.trace.events:
        evidence = event.metadata.get("policy_evidence")
        if evidence:
            assert evidence["policy_document_digest"] == projection.document_digest
            assert evidence["policy_format"] == "watcher-policy/1"


@POSIX_ONLY
def test_the_client_cannot_weaken_a_filesystem_decision_with_metadata():
    """Every candidate path is judged and the strictest verdict wins."""
    projection = build_document(E2E)
    watcher = PoEWatcher(
        policy=projection.policy,
        workspace_root="/workspace",
        tripwires=projection.tripwires,
    )
    evaluation = watcher.evaluate(
        "file_access",
        "open",
        "/workspace/secret/key.txt",
        {"path": "/workspace/file.txt"},  # harmless path asserted by the client
    )
    assert evaluation.decision is Decision.DENY


# ---------------------------------------------------------------------------
# 6. the CLI: --policy, and failing closed before launch
# ---------------------------------------------------------------------------


def test_an_invalid_policy_starts_no_child(tmp_path, capsys):
    sentinel = tmp_path / "launched.txt"
    policy = write_policy(tmp_path, {"version": 1, "network": {"mode": "restricted"}})
    code = cli_main(
        [
            "run",
            "--policy",
            str(policy),
            "--workspace",
            str(tmp_path),
            "--",
            sys.executable,
            "-c",
            f"open(r'{sentinel}', 'w').write('launched')",
        ]
    )
    captured = capsys.readouterr()
    assert code == 2
    assert sentinel.exists() is False
    assert "refusing to launch" in captured.err


def test_a_malformed_policy_starts_no_child(tmp_path, capsys):
    sentinel = tmp_path / "launched.txt"
    path = tmp_path / "broken.json"
    path.write_text('{"version": 1, "filesystem": {"deny": ["/a"]}', encoding="utf-8")
    code = cli_main(
        [
            "run", "--policy", str(path), "--workspace", str(tmp_path), "--",
            sys.executable, "-c", f"open(r'{sentinel}', 'w').write('x')",
        ]
    )
    assert code == 2
    assert sentinel.exists() is False
    assert "watcher run:" in capsys.readouterr().err


def test_a_missing_policy_file_starts_no_child(tmp_path, capsys):
    code = cli_main(
        [
            "run", "--policy", str(tmp_path / "absent.json"),
            "--workspace", str(tmp_path), "--",
            sys.executable, "-c", "print('must not run')",
        ]
    )
    assert code == 2
    assert "cannot read policy file" in capsys.readouterr().err


def test_v3_shaping_flags_are_refused_with_a_v1_document(tmp_path, capsys):
    policy = write_policy(tmp_path, {"version": 1})
    code = cli_main(
        [
            "run", "--policy", str(policy), "--allow-path", "/workspace",
            "--workspace", str(tmp_path), "--",
            sys.executable, "-c", "print('must not run')",
        ]
    )
    assert code == 2
    assert "--allow-path" in capsys.readouterr().err


def test_a_v1_document_with_unsupported_fields_is_refused_by_the_strict_loader(
    tmp_path, capsys
):
    policy = write_policy(tmp_path, {"version": 1, "filesystem": {"read": ["/a"]}})
    code = cli_main(
        [
            "run", "--policy", str(policy), "--workspace", str(tmp_path), "--",
            sys.executable, "-c", "print('must not run')",
        ]
    )
    assert code == 2
    assert "unknown field" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# 7. backwards compatibility
# ---------------------------------------------------------------------------


def test_a_v3_policy_file_is_still_read_as_v3(tmp_path):
    """No ``version`` key means the V3 path, exactly as before."""
    from the_watcher.cli import _load_policy_source  # noqa: SLF001 - CLI wiring

    path = tmp_path / "v3.json"
    path.write_text(
        json.dumps({"name": "legacy", "forbidden_paths": ["/etc"], "max_processes": 7}),
        encoding="utf-8",
    )
    args = _arg_namespace(policy=str(path), workspace=str(tmp_path))
    source = _load_policy_source(args)
    assert source.projection is None
    assert source.tripwires is None
    assert source.policy.name == "legacy"
    assert source.policy.max_processes == 7
    assert tuple(source.policy.forbidden_paths) == ("/etc",)


def test_the_v3_loader_still_rejects_a_policy_v1_document(tmp_path):
    path = write_policy(tmp_path, E2E, name="v1.json")
    with pytest.raises(PolicyError):
        Policy.load(str(path))


def test_no_policy_flag_still_builds_the_default_policy(tmp_path):
    from the_watcher.cli import _load_policy_source  # noqa: SLF001

    args = _arg_namespace(policy=None, workspace=str(tmp_path))
    source = _load_policy_source(args)
    assert source.policy.path_rule is None
    assert source.projection is None
    assert source.policy.max_runtime_seconds == 3600


def _arg_namespace(**overrides):
    """The subset of ``watcher run`` arguments the policy loader reads."""
    base = {
        "policy": None,
        "workspace": os.getcwd(),
        "timeout": None,
        "allow_path": [],
        "forbid_path": [],
        "allow_domain": [],
        "forbid_domain": [],
        "max_processes": None,
    }
    base.update(overrides)
    return type("Args", (), base)()


# ---------------------------------------------------------------------------
# 8. the platform that cannot represent Policy V1 paths
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name != "nt", reason="Windows-specific refusal")
def test_windows_refuses_filesystem_rules_instead_of_matching_nothing():
    with pytest.raises(PolicyError) as excinfo:
        build_document(E2E)
    assert "absolute POSIX paths" in str(excinfo.value)
    # A document with no path rules still projects, so the refusal is specific.
    assert project_policy_v1(loads_policy('{"version": 1}')).policy.name == "default"
