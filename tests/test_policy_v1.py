"""Policy V1: the document format, its grammar, its digest, and its refusals.

The point of this module is that a policy document means exactly one thing. So
the tests are mostly about what gets **refused**: unknown fields, duplicate
keys, non-finite numbers, type mismatches, unsupported pattern syntax, ``..``
traversal, backslashes and BOMs. A policy format that accepts a document it does
not fully understand is worse than one that rejects it, because the author and
the enforcement engine then disagree silently.

Cases are grouped to match the phase brief's required list.
"""

from __future__ import annotations

import itertools
import json
import random
import tempfile
import time
from pathlib import Path

import pytest

from the_watcher import policy_v1
from the_watcher.exceptions import PolicyParseError, PolicyValidationError
from the_watcher.poe.canonical import canonical_bytes, sha256_hex
from the_watcher.policy_v1 import (
    DOCUMENT_DIGEST_DOMAIN,
    MAX_DOCUMENT_BYTES,
    MAX_PATTERN_LENGTH,
    MAX_RULE_COUNT,
    POLICY_VERSION,
    RESOLVED_DIGEST_DOMAIN,
    compile_pattern,
    load_policy,
    loads_policy,
    parse_policy,
)

# ---------------------------------------------------------------------------
# fixtures and helpers
# ---------------------------------------------------------------------------

MINIMAL = {"version": 1}

COMPLETE = {
    "version": 1,
    "name": "acme-project",
    "filesystem": {
        "allow": ["/workspace/**"],
        "deny": ["/etc/**", "/root/.ssh/**"],
    },
    "network": {"mode": "restricted", "allow": ["api.openai.com", "api.deepseek.com"]},
    "process": {"max_children": 8, "max_runtime_seconds": 600},
    "resources": {"memory_mb": 1024, "cpu_seconds": 600},
    "tripwires": ["/var/run/docker.sock", "/root/.ssh/id_rsa"],
    "on_violation": {
        "filesystem": "DENY",
        "network": "QUARANTINE",
        "process": "DENY",
        "resources": "QUARANTINE",
        "tripwire": "KILL",
    },
}


def load_text(text: str):
    return loads_policy(text)


def load_mapping(mapping) -> "policy_v1.PolicyV1":
    return parse_policy(mapping)


def issues_of(excinfo) -> "list[str]":
    return [str(issue) for issue in excinfo.value.issues]


def write_document(tmp_path: Path, text: str, name: str = "watcher.json") -> Path:
    """Write a document with no BOM, which is what the loader requires."""
    path = tmp_path / name
    path.write_bytes(text.encode("utf-8"))
    return path


@pytest.fixture()
def complete_policy():
    return load_mapping(COMPLETE)


# ---------------------------------------------------------------------------
# 1-2. valid documents
# ---------------------------------------------------------------------------


def test_a_minimal_document_is_valid():
    policy = load_mapping(MINIMAL)
    assert policy.version == POLICY_VERSION
    assert policy.name == "default"


def test_a_complete_document_is_valid(complete_policy):
    assert complete_policy.version == 1
    assert complete_policy.name == "acme-project"
    assert [p.pattern for p in complete_policy.filesystem.allow] == ["/workspace/**"]
    assert [p.pattern for p in complete_policy.filesystem.deny] == [
        "/etc/**",
        "/root/.ssh/**",
    ]
    assert complete_policy.network.mode == "restricted"
    assert complete_policy.network.allow == ("api.deepseek.com", "api.openai.com")
    assert complete_policy.process.max_children == 8
    assert complete_policy.process.max_runtime_seconds == 600
    assert complete_policy.resources.memory_mb == 1024
    assert complete_policy.resources.cpu_seconds == 600
    assert complete_policy.on_violation["tripwire"] == "KILL"


def test_an_omitted_section_equals_its_defaults():
    """Omitting a section and writing its defaults are the same document."""
    omitted = load_mapping({"version": 1})
    explicit = load_mapping(
        {
            "version": 1,
            "filesystem": {"allow": [], "deny": []},
            "network": {"mode": "none", "allow": [], "deny": []},
            "process": {"max_children": 32, "max_runtime_seconds": 3600},
            "resources": {},
            "tripwires": [],
            "on_violation": {
                "filesystem": "DENY",
                "network": "DENY",
                "process": "DENY",
                "resources": "QUARANTINE",
                "tripwire": "KILL",
            },
        }
    )
    assert omitted.document_digest == explicit.document_digest


# ---------------------------------------------------------------------------
# 3-4. unknown fields, at every level
# ---------------------------------------------------------------------------


def test_unknown_root_field_is_refused():
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({"version": 1, "polcy": {}})
    assert "polcy: unknown field" in issues_of(excinfo)[0]


def test_unknown_deeply_nested_field_is_refused():
    """The brief's example, and the exact error text it asks for."""
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({"version": 1, "filesystem": {"alow": ["/workspace/**"]}})
    assert issues_of(excinfo) == [
        "filesystem.alow: unknown field; did you mean 'allow'?"
    ]


def test_unknown_field_in_every_section_is_refused():
    cases = [
        ({"network": {"modes": "none"}}, "network.modes"),
        ({"process": {"max_childrenx": 1}}, "process.max_childrenx"),
        ({"resources": {"memory": 512}}, "resources.memory"),
        ({"on_violation": {"file": "DENY"}}, "on_violation.file"),
    ]
    for fragment, expected in cases:
        document = {"version": 1, **fragment}
        with pytest.raises(PolicyValidationError) as excinfo:
            load_mapping(document)
        assert any(line.startswith(expected) for line in issues_of(excinfo)), (
            fragment,
            issues_of(excinfo),
        )


def test_every_unknown_field_is_reported_not_just_the_first():
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({"version": 1, "aaa": 1, "bbb": 2, "ccc": 3})
    assert len(excinfo.value.issues) == 3
    assert [issue.path for issue in excinfo.value.issues] == ["aaa", "bbb", "ccc"]


def test_a_near_miss_is_suggested_only_when_it_is_plausible():
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({"version": 1, "versoin": 1})
    # 'versoin' is one transposition from 'version'.
    assert "did you mean" in issues_of(excinfo)[0]


# ---------------------------------------------------------------------------
# 5-6. version
# ---------------------------------------------------------------------------


def test_missing_version_is_refused():
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({})
    assert issues_of(excinfo) == ["version: missing required field"]


def test_wrong_version_is_refused():
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({"version": 2})
    assert "unsupported policy version 2" in issues_of(excinfo)[0]


@pytest.mark.parametrize("value", ["1", 1.0, True, None, [1], {}])
def test_a_version_that_is_not_the_integer_1_is_refused(value):
    with pytest.raises(PolicyValidationError):
        load_mapping({"version": value})


# ---------------------------------------------------------------------------
# 7-8. duplicate keys
# ---------------------------------------------------------------------------


def test_duplicate_root_key_is_refused():
    """``json.loads`` would silently keep the last one; policy must not."""
    with pytest.raises(PolicyValidationError) as excinfo:
        load_text('{"version": 1, "filesystem": {"allow": []}, "filesystem": {"deny": []}}')
    assert excinfo.value.issues[0].code == "duplicate_key"
    assert "filesystem" in issues_of(excinfo)[0]


def test_duplicate_nested_key_is_refused():
    with pytest.raises(PolicyValidationError) as excinfo:
        load_text('{"version": 1, "filesystem": {"allow": [], "allow": ["/x"]}}')
    assert excinfo.value.issues[0].code == "duplicate_key"


def test_duplicate_key_inside_a_rule_object_is_refused():
    with pytest.raises(PolicyValidationError) as excinfo:
        load_text('{"version": 1, "on_violation": {"tripwire": "KILL", "tripwire": "DENY"}}')
    assert excinfo.value.issues[0].code == "duplicate_key"


def test_the_plain_json_parser_would_have_accepted_the_duplicate():
    """The reason this defence exists, stated as a test.

    If CPython ever stops keeping the last duplicate, this test tells us the
    premise changed rather than leaving a comment that quietly rotted.
    """
    assert json.loads('{"a": 1, "a": 2}') == {"a": 2}


# ---------------------------------------------------------------------------
# 9-12. strict types and ranges
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fragment, location",
    [
        ({"process": {"max_children": "8"}}, "process.max_children"),
        ({"process": {"max_runtime_seconds": "600"}}, "process.max_runtime_seconds"),
        ({"resources": {"memory_mb": "1024"}}, "resources.memory_mb"),
        ({"resources": {"cpu_seconds": "600"}}, "resources.cpu_seconds"),
    ],
)
def test_a_string_where_an_integer_is_required_is_refused(fragment, location):
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({"version": 1, **fragment})
    assert any(
        line.startswith(location) and "expected an integer" in line
        for line in issues_of(excinfo)
    )


@pytest.mark.parametrize(
    "fragment",
    [
        {"process": {"max_children": True}},
        {"process": {"max_runtime_seconds": False}},
        {"resources": {"memory_mb": True}},
    ],
)
def test_a_boolean_where_an_integer_is_required_is_refused(fragment):
    """``isinstance(True, int)`` is True in Python; policy must not fall for it."""
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({"version": 1, **fragment})
    assert "expected an integer, got boolean" in issues_of(excinfo)[0]


@pytest.mark.parametrize(
    "fragment, location",
    [
        ({"process": {"max_children": -1}}, "process.max_children"),
        ({"resources": {"memory_mb": -1}}, "resources.memory_mb"),
        ({"resources": {"memory_mb": 8}}, "resources.memory_mb"),
    ],
)
def test_negative_and_too_small_values_are_refused(fragment, location):
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({"version": 1, **fragment})
    assert any(line.startswith(location) for line in issues_of(excinfo))


def test_zero_is_allowed_for_max_children_and_refused_for_runtime():
    """``max_children: 0`` means "no children"; a zero runtime is meaningless."""
    assert load_mapping({"version": 1, "process": {"max_children": 0}}).process.max_children == 0
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({"version": 1, "process": {"max_runtime_seconds": 0}})
    assert "must be >= 1" in issues_of(excinfo)[0]


def test_cpu_seconds_of_zero_is_refused():
    with pytest.raises(PolicyValidationError):
        load_mapping({"version": 1, "resources": {"cpu_seconds": 0}})


# ---------------------------------------------------------------------------
# 13. NaN and Infinity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_numbers_are_refused(literal):
    with pytest.raises(PolicyValidationError) as excinfo:
        load_text('{"version": 1, "resources": {"memory_mb": %s}}' % literal)
    assert excinfo.value.issues[0].code == "non_finite_number"


def test_an_overflowing_exponent_is_refused_as_a_type_error():
    """``1e999`` parses to ``inf`` without touching ``parse_constant``."""
    with pytest.raises(PolicyValidationError) as excinfo:
        load_text('{"version": 1, "resources": {"memory_mb": 1e999}}')
    assert "expected an integer, got number" in issues_of(excinfo)[0]


# ---------------------------------------------------------------------------
# 14. null
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text, location",
    [
        ('{"version": 1, "name": null}', "name"),
        ('{"version": 1, "filesystem": null}', "filesystem"),
        ('{"version": 1, "tripwires": null}', "tripwires"),
        ('{"version": 1, "on_violation": null}', "on_violation"),
        ('{"version": 1, "network": {"mode": null}}', "network.mode"),
        ('{"version": 1, "process": {"max_children": null}}', "process.max_children"),
        ('{"version": 1, "resources": {"memory_mb": null}}', "resources.memory_mb"),
        ('{"version": 1, "on_violation": {"tripwire": null}}', "on_violation.tripwire"),
    ],
)
def test_null_is_refused_wherever_it_appears(text, location):
    with pytest.raises(PolicyValidationError) as excinfo:
        load_text(text)
    assert any(
        line.startswith(location) and "null is not accepted" in line
        for line in issues_of(excinfo)
    ), issues_of(excinfo)


# ---------------------------------------------------------------------------
# 15-16. empty and duplicate rules
# ---------------------------------------------------------------------------


def test_empty_rule_lists_are_valid_and_meaningless():
    policy = load_mapping({"version": 1, "filesystem": {"allow": [], "deny": []}})
    assert policy.filesystem.allow == ()
    assert policy.filesystem.deny == ()


def test_an_empty_tripwire_list_is_valid():
    assert load_mapping({"version": 1, "tripwires": []}).tripwires == ()


@pytest.mark.parametrize(
    "text",
    [
        '{"version": 1, "filesystem": {"deny": ["/etc", "/etc"]}}',
        '{"version": 1, "filesystem": {"deny": ["/etc/", "/etc"]}}',
        '{"version": 1, "tripwires": ["/x", "/x"]}',
        '{"version": 1, "network": {"mode": "restricted", "allow": ["a.com", "A.com"]}}',
    ],
)
def test_duplicate_rules_are_refused(text):
    with pytest.raises(PolicyValidationError) as excinfo:
        load_text(text)
    assert any(
        issue.code == "duplicate_rule" or issue.code == "duplicate_entry"
        for issue in excinfo.value.issues
    ), issues_of(excinfo)


def test_a_pattern_in_both_allow_and_deny_is_reported():
    """Deny wins, so the allow entry has no effect; say so rather than hide it."""
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping(
            {"version": 1, "filesystem": {"allow": ["/etc"], "deny": ["/etc"]}}
        )
    assert excinfo.value.issues[0].code == "contradictory_rule"


# ---------------------------------------------------------------------------
# 17. pattern normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "written, canonical",
    [
        ("/etc", "/etc"),
        ("/etc/", "/etc"),
        ("/etc//passwd", "/etc/passwd"),
        ("/etc/./passwd", "/etc/passwd"),
        ("//etc///passwd//", "/etc/passwd"),
        ("/", "/"),
    ],
)
def test_patterns_are_canonicalised(written, canonical):
    assert compile_pattern(written, "p").pattern == canonical


def test_equivalent_spellings_share_a_digest():
    first = load_mapping({"version": 1, "filesystem": {"deny": ["/etc/passwd"]}})
    second = load_mapping({"version": 1, "filesystem": {"deny": ["/etc/./passwd/"]}})
    assert first.document_digest == second.document_digest


# ---------------------------------------------------------------------------
# 18-19. ** and * semantics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/workspace", True),
        ("/workspace/a.txt", True),
        ("/workspace/a/b.txt", True),
        ("/workspace/a/b/c/d.txt", True),
        ("/workspacex", False),
        ("/etc", False),
        ("/", False),
    ],
)
def test_double_star_matches_the_prefix_and_every_descendant(path, expected):
    assert compile_pattern("/workspace/**", "p").matches(path) is expected


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/workspace", True),
        ("/workspace/a.txt", True),
        ("/workspace/a/b.txt", True),
        ("/workspacex", False),
    ],
)
def test_a_literal_path_keeps_the_v3_implicit_subtree_meaning(path, expected):
    """Existing V3 semantics are preserved, not reinterpreted."""
    assert compile_pattern("/workspace", "p").matches(path) is expected


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/etc", False),
        ("/etc/a.conf", True),
        ("/etc/sub/a.conf", False),
        ("/etc/.conf", True),
        ("/etc/a.conf.d", False),
        ("/etc/a", False),
        ("/etc/a.conf.bak", False),
    ],
)
def test_a_single_star_never_crosses_a_separator(path, expected):
    assert compile_pattern("/etc/*.conf", "p").matches(path) is expected


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/etc", False),
        ("/etc/a", True),
        ("/etc/ab", False),
        ("/etc/a/b", False),
    ],
)
def test_question_mark_matches_exactly_one_character(path, expected):
    assert compile_pattern("/etc/?", "p").matches(path) is expected


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/a/x/b", True),
        ("/a/b", True),
        ("/a/x/y/b", True),
        ("/b", False),
    ],
)
def test_double_star_in_the_middle_spans_zero_or_more_segments(path, expected):
    assert compile_pattern("/a/**/b", "p").matches(path) is expected


def test_the_root_pattern_matches_everything():
    pattern = compile_pattern("/", "p")
    assert pattern.matches("/")
    assert pattern.matches("/etc/passwd")


# ---------------------------------------------------------------------------
# 20-21. traversal, expansion, mixed slashes, unsupported syntax
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, code",
    [
        ("/workspace/../etc", "parent_traversal"),
        ("/..", "parent_traversal"),
        ("/a/b/../../c", "parent_traversal"),
    ],
)
def test_parent_traversal_is_refused_not_resolved(pattern, code):
    """Collapsing ``..`` would change the rule, and resolving needs the disk."""
    with pytest.raises(PolicyValidationError) as excinfo:
        compile_pattern(pattern, "p")
    assert excinfo.value.issues[0].code == code


@pytest.mark.parametrize("pattern", ["/etc\\passwd", "C:/etc", "/a\\b"])
def test_backslashes_and_drive_letters_are_refused(pattern):
    with pytest.raises(PolicyValidationError):
        compile_pattern(pattern, "p")


@pytest.mark.parametrize("pattern", ["~/.ssh/**", "$HOME/.ssh", "%USERPROFILE%"])
def test_environment_and_home_expansion_is_refused(pattern):
    with pytest.raises(PolicyValidationError) as excinfo:
        compile_pattern(pattern, "p")
    assert excinfo.value.issues[0].code == "expansion_not_supported"


def test_a_relative_path_is_refused():
    with pytest.raises(PolicyValidationError) as excinfo:
        compile_pattern("etc/passwd", "p")
    assert excinfo.value.issues[0].code == "not_absolute"


@pytest.mark.parametrize(
    "pattern", ["/etc/[abc]", "/etc/{a,b}", "/etc/!(x)", "/etc/a**b", "/etc/***"]
)
def test_unsupported_pattern_syntax_is_refused(pattern):
    """A pattern the engine does not understand must never be a literal."""
    with pytest.raises(PolicyValidationError) as excinfo:
        compile_pattern(pattern, "p")
    assert excinfo.value.issues[0].code == "unsupported_pattern"


def test_a_control_character_in_a_pattern_is_refused():
    with pytest.raises(PolicyValidationError):
        compile_pattern("/etc/\x01", "p")


def test_the_matcher_refuses_a_subject_it_cannot_parse():
    """Returning "no match" for a question it cannot parse would be a lie."""
    pattern = compile_pattern("/etc/**", "p")
    for bad in ("etc/passwd", "/etc/../etc/passwd", "/etc\\passwd", ""):
        with pytest.raises(PolicyValidationError):
            pattern.matches(bad)


# ---------------------------------------------------------------------------
# 22. length and volume bounds
# ---------------------------------------------------------------------------


def test_an_overlong_pattern_is_refused():
    too_long = "/" + "a" * (MAX_PATTERN_LENGTH + 10)
    with pytest.raises(PolicyValidationError) as excinfo:
        compile_pattern(too_long, "p")
    assert excinfo.value.issues[0].code == "too_long"


def test_too_many_rules_is_refused():
    rules = ["/p/%d" % index for index in range(MAX_RULE_COUNT + 1)]
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({"version": 1, "filesystem": {"deny": rules}})
    assert excinfo.value.issues[0].code == "too_many_rules"


def test_an_oversized_document_is_refused_at_the_file_boundary(tmp_path):
    path = tmp_path / "big.json"
    path.write_bytes(b"x" * (MAX_DOCUMENT_BYTES + 1))
    with pytest.raises(PolicyParseError) as excinfo:
        load_policy(str(path))
    assert "larger than" in str(excinfo.value)


# ---------------------------------------------------------------------------
# 23. unicode
# ---------------------------------------------------------------------------


def test_unicode_paths_are_preserved_and_digest_stably():
    policy = load_mapping(
        {"version": 1, "filesystem": {"deny": ["/workspace/日本語/**"]}}
    )
    assert policy.filesystem.deny[0].pattern == "/workspace/日本語/**"
    assert policy.filesystem.deny[0].matches("/workspace/日本語/ファイル.txt")
    again = load_mapping({"version": 1, "filesystem": {"deny": ["/workspace/日本語/**"]}})
    assert policy.document_digest == again.document_digest


def test_a_non_ascii_hostname_is_refused_with_a_pointer_at_idna():
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping(
            {"version": 1, "network": {"mode": "restricted", "allow": ["bücher.de"]}}
        )
    assert excinfo.value.issues[0].code == "idna_not_supported"


def test_a_non_ascii_policy_name_is_refused():
    with pytest.raises(PolicyValidationError):
        load_mapping({"version": 1, "name": "näme"})


# ---------------------------------------------------------------------------
# 24. immutability
# ---------------------------------------------------------------------------


def test_the_policy_object_is_frozen(complete_policy):
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        complete_policy.name = "changed"  # type: ignore[misc]


def test_sections_and_rule_lists_cannot_be_mutated(complete_policy):
    with pytest.raises(TypeError):
        complete_policy.on_violation["tripwire"] = "DENY"  # type: ignore[index]
    assert isinstance(complete_policy.filesystem.deny, tuple)
    with pytest.raises(AttributeError):
        complete_policy.filesystem.deny.append("/x")  # type: ignore[attr-defined]


def test_the_digest_cannot_be_changed_through_the_normalised_view(complete_policy):
    normalised = complete_policy.normalized()
    with pytest.raises(TypeError):
        normalised["name"] = "changed"  # type: ignore[index]
    with pytest.raises(TypeError):
        normalised["filesystem"]["deny"] = []  # type: ignore[index]
    assert complete_policy.document_digest == complete_policy.document_digest


def test_mutating_the_source_mapping_after_parsing_does_not_change_the_policy():
    """The caller's input is not retained by reference."""
    source = {"version": 1, "filesystem": {"deny": ["/etc/**"]}}
    policy = load_mapping(source)
    before = policy.document_digest
    source["filesystem"]["deny"].append("/var/**")
    source["version"] = 99
    assert policy.document_digest == before
    assert [p.pattern for p in policy.filesystem.deny] == ["/etc/**"]


# ---------------------------------------------------------------------------
# 25-26. key order and whitespace invariance
# ---------------------------------------------------------------------------


def test_key_order_does_not_change_the_digest():
    text_one = json.dumps(COMPLETE)
    text_two = json.dumps(COMPLETE, sort_keys=True)
    assert load_text(text_one).document_digest == load_text(text_two).document_digest


def test_whitespace_and_formatting_do_not_change_the_digest():
    compact = json.dumps(COMPLETE, separators=(",", ":"))
    pretty = json.dumps(COMPLETE, indent=4)
    assert load_text(compact).document_digest == load_text(pretty).document_digest


def test_rule_order_does_not_change_the_digest():
    """Order carries no meaning: Policy V1 has no first-match-wins rule."""
    first = load_mapping({"version": 1, "filesystem": {"deny": ["/a", "/b"]}})
    second = load_mapping({"version": 1, "filesystem": {"deny": ["/b", "/a"]}})
    assert first.document_digest == second.document_digest


def test_hostname_case_does_not_change_the_digest():
    first = load_mapping(
        {"version": 1, "network": {"mode": "restricted", "allow": ["API.OpenAI.com"]}}
    )
    second = load_mapping(
        {"version": 1, "network": {"mode": "restricted", "allow": ["api.openai.com"]}}
    )
    assert first.document_digest == second.document_digest


def test_load_from_file_matches_load_from_text(tmp_path, complete_policy):
    path = write_document(tmp_path, json.dumps(COMPLETE))
    assert load_policy(str(path)).document_digest == complete_policy.document_digest


# ---------------------------------------------------------------------------
# 27-29. digest stability and domain separation
# ---------------------------------------------------------------------------


def test_the_same_document_always_has_the_same_digest():
    digests = {load_mapping(COMPLETE).document_digest for _ in range(25)}
    assert len(digests) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"name": "other"},
        {"filesystem": {"allow": ["/workspace/**"], "deny": ["/etc/**", "/root/.ssh/**", "/var/**"]}},
        {"process": {"max_children": 9, "max_runtime_seconds": 600}},
        {"resources": {"memory_mb": 1025, "cpu_seconds": 600}},
        {"tripwires": ["/var/run/docker.sock"]},
        {"on_violation": {"filesystem": "QUARANTINE"}},
    ],
)
def test_a_meaningful_change_changes_the_digest(change):
    baseline = load_mapping(COMPLETE).document_digest
    changed = load_mapping({**COMPLETE, **change}).document_digest
    assert changed != baseline, change


def test_the_digest_is_domain_separated_from_a_bare_canonical_hash(complete_policy):
    bare = sha256_hex(canonical_bytes(complete_policy.normalized()))
    assert complete_policy.document_digest != bare
    assert DOCUMENT_DIGEST_DOMAIN == b"watcher-policy-document/1"


def test_the_digest_is_domain_separated_from_the_poe_namespace(complete_policy):
    """A policy digest must never be mistakable for an event hash."""
    from the_watcher.poe.canonical import GENESIS_HASH

    assert complete_policy.document_digest != GENESIS_HASH
    assert len(complete_policy.document_digest) == 64


def test_the_resolved_policy_namespace_is_reserved_but_unused():
    """Phase 2 owns it; Phase 1 must not fake it."""
    assert RESOLVED_DIGEST_DOMAIN == b"watcher-policy-resolved/1"
    assert RESOLVED_DIGEST_DOMAIN != DOCUMENT_DIGEST_DOMAIN
    assert not hasattr(policy_v1.PolicyV1, "resolved_policy_digest")


# ---------------------------------------------------------------------------
# 30. encoding at the file boundary
# ---------------------------------------------------------------------------


def test_a_file_that_is_not_utf8_is_refused(tmp_path):
    path = tmp_path / "bad.json"
    path.write_bytes(b'{"version": 1, "name": "\xff\xfe"}')
    with pytest.raises(PolicyParseError) as excinfo:
        load_policy(str(path))
    assert "not valid UTF-8" in str(excinfo.value)


def test_a_utf8_bom_is_refused_with_a_clear_remedy(tmp_path):
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(MINIMAL).encode("utf-8"))
    with pytest.raises(PolicyParseError) as excinfo:
        load_policy(str(path))
    assert "byte-order mark" in str(excinfo.value)


def test_a_missing_file_is_a_parse_error(tmp_path):
    with pytest.raises(PolicyParseError):
        load_policy(str(tmp_path / "absent.json"))


@pytest.mark.parametrize(
    "text", ["", "null", "[]", "[1,2]", "{} trailing", '{"version": 1,}']
)
def test_malformed_documents_are_refused(text):
    with pytest.raises((PolicyParseError, PolicyValidationError)):
        load_text(text)


def test_a_non_object_root_is_refused():
    with pytest.raises(PolicyValidationError) as excinfo:
        load_text("[1, 2, 3]")
    assert "must be a JSON object" in str(excinfo.value)


# ---------------------------------------------------------------------------
# network, on_violation and cross-section rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["none", "restricted", "open"])
def test_every_documented_network_mode_parses(mode):
    fragment = {"network": {"mode": mode}}
    if mode == "restricted":
        fragment["network"]["allow"] = ["a.com"]
    assert load_mapping({"version": 1, **fragment}).network.mode == mode


def test_an_unknown_network_mode_is_refused():
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({"version": 1, "network": {"mode": "closed"}})
    assert excinfo.value.issues[0].code == "invalid_enum"


def test_an_allow_list_without_restricted_mode_is_refused():
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({"version": 1, "network": {"mode": "none", "allow": ["a.com"]}})
    assert excinfo.value.issues[0].code == "contradictory_setting"


def test_a_cidr_in_network_allow_is_refused_with_a_pointer_at_the_profile():
    """One field must not mean two things: hostnames here, CIDRs in the profile."""
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping(
            {"version": 1, "network": {"mode": "restricted", "allow": ["10.0.0.0/8"]}}
        )
    assert excinfo.value.issues[0].code == "address_not_supported"


def test_a_wildcard_hostname_is_accepted():
    policy = load_mapping(
        {"version": 1, "network": {"mode": "restricted", "allow": ["*.example.com"]}}
    )
    assert policy.network.allow == ("*.example.com",)


@pytest.mark.parametrize("decision", ["DENY", "QUARANTINE", "KILL"])
def test_every_permitted_violation_decision_parses(decision):
    policy = load_mapping({"version": 1, "on_violation": {"filesystem": decision}})
    assert policy.on_violation["filesystem"] == decision


def test_allow_is_refused_as_a_violation_decision():
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({"version": 1, "on_violation": {"filesystem": "ALLOW"}})
    assert excinfo.value.issues[0].code == "allow_not_permitted"


def test_a_tripwire_cannot_be_downgraded_below_kill():
    for decision in ("DENY", "QUARANTINE"):
        with pytest.raises(PolicyValidationError) as excinfo:
            load_mapping({"version": 1, "on_violation": {"tripwire": decision}})
        assert excinfo.value.issues[0].code == "unsupported_decision"


def test_a_lowercase_decision_is_accepted_and_canonicalised():
    policy = load_mapping({"version": 1, "on_violation": {"filesystem": "deny"}})
    assert policy.on_violation["filesystem"] == "DENY"


def test_the_object_form_of_a_tripwire_is_refused_with_a_pointer():
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping(
            {"version": 1, "tripwires": [{"id": "x", "paths": ["/etc"]}]}
        )
    assert excinfo.value.issues[0].code == "wrong_type"


def test_fields_that_exist_elsewhere_are_redirected():
    """A name that belongs to another subsystem gets a pointer, not a shrug."""
    cases = {
        "resources": {"pids": 32},
        "process": {"max_processes": 8},
        "filesystem": {"allowed_paths": ["/x"]},
        "network": {"allowed_networks": ["10.0.0.0/8"]},
    }
    for section, payload in cases.items():
        with pytest.raises(PolicyValidationError) as excinfo:
            load_mapping({"version": 1, section: payload})
        assert "unknown field" in issues_of(excinfo)[0]


# ---------------------------------------------------------------------------
# reporting and honesty
# ---------------------------------------------------------------------------


def test_every_issue_carries_a_path_and_a_machine_code():
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping(
            {
                "version": 1,
                "filesystem": {"allow": ["/x"], "deny": ["/x"]},
                "process": {"max_children": -1},
            }
        )
    assert len(excinfo.value.issues) >= 2
    for issue in excinfo.value.issues:
        assert issue.path
        assert issue.code
        assert issue.message
        assert str(issue).startswith(issue.path)


def test_errors_do_not_echo_whole_documents():
    """A policy may name sensitive paths; an error must not dump the file."""
    secret = "/workspace/very-secret-customer-name/keys"
    with pytest.raises(PolicyValidationError) as excinfo:
        load_mapping({"version": 1, "filesystem": {"alow": [secret]}})
    text = str(excinfo.value)
    assert "very-secret-customer-name" not in text


def test_phase_1_claims_no_enforcement():
    """The module must not imply that anything here is enforced yet."""
    assert policy_v1.ENFORCED_IN_PHASE_1
    for section, statement in policy_v1.ENFORCED_IN_PHASE_1.items():
        assert "no runtime enforcement" in statement, section


def test_there_is_no_evaluation_helper_on_the_document():
    """Phase 1 is schema, not decisions: no allow/deny verdict API exists."""
    for name in ("evaluate", "decide", "allows", "denies", "check"):
        assert not hasattr(policy_v1.PolicyV1, name), name


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def run_cli(argv, capsys):
    from the_watcher.cli import main

    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_validate_reports_success(tmp_path, capsys):
    path = write_document(tmp_path, json.dumps(COMPLETE))
    code, out, err = run_cli(["policy", "validate", str(path)], capsys)
    assert code == 0
    assert out.strip() == "VALID Policy V1"
    assert err == ""


def test_cli_validate_prints_one_located_line_per_issue(tmp_path, capsys):
    """The brief's required error shape: ``filesystem.alow: unknown field``."""
    path = write_document(
        tmp_path, json.dumps({"version": 1, "filesystem": {"alow": ["/x"]}})
    )
    code, out, err = run_cli(["policy", "validate", str(path)], capsys)
    assert code == 2
    assert out == ""
    assert err.strip() == "filesystem.alow: unknown field; did you mean 'allow'?"


def test_cli_validate_reports_a_parse_error_plainly(tmp_path, capsys):
    path = write_document(tmp_path, "{not json}")
    code, out, err = run_cli(["policy", "validate", str(path)], capsys)
    assert code == 2
    assert "not valid JSON" in err


def test_cli_digest_prints_only_the_digest(tmp_path, capsys):
    """Scriptable by default: no label, no JSON, one line."""
    path = write_document(tmp_path, json.dumps(COMPLETE))
    code, out, err = run_cli(["policy", "digest", str(path)], capsys)
    assert code == 0
    assert err == ""
    assert out.strip() == load_mapping(COMPLETE).document_digest
    assert len(out.strip().splitlines()) == 1


def test_cli_digest_json_matches_the_bare_digest(tmp_path, capsys):
    path = write_document(tmp_path, json.dumps(COMPLETE))
    code, out, _err = run_cli(["policy", "digest", str(path), "--json"], capsys)
    assert code == 0
    payload = json.loads(out)
    assert payload["document_digest"] == load_mapping(COMPLETE).document_digest
    assert payload["version"] == 1
    assert payload["name"] == "acme-project"


def test_cli_digest_refuses_an_invalid_document(tmp_path, capsys):
    path = write_document(tmp_path, json.dumps({"version": 99}))
    code, out, err = run_cli(["policy", "digest", str(path)], capsys)
    assert code == 2
    assert out == ""
    assert "unsupported policy version" in err


def test_cli_policy_subcommands_are_registered():
    from the_watcher.cli import build_parser

    parser = build_parser()
    choices = set()
    for action in parser._actions:  # noqa: SLF001 - argparse offers no public API
        if hasattr(action, "choices") and action.choices:
            choices.update(action.choices)
    assert "policy" in choices


def test_policy_v1_is_not_wired_into_watcher_run():
    """Phase 1 stops at the document boundary on purpose.

    ``watcher run --policy`` still loads the existing V3 policy JSON. Feeding it
    a Policy V1 document must fail loudly rather than be half-understood, which
    is what "not wired in yet" has to mean in practice.
    """
    from the_watcher.exceptions import PolicyError
    from the_watcher.watcher import Policy

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "watcher-v1.json"
        path.write_bytes(json.dumps(COMPLETE).encode("utf-8"))
        with pytest.raises(PolicyError):
            Policy.load(str(path))


# ---------------------------------------------------------------------------
# 36. adversarial matcher review
#
# The matcher runs in the trusted path, so its cost is a security property: the
# subject is chosen by the agent being supervised, and the pattern is chosen by
# the operator. A pattern whose cost is superlinear in the subject lets the
# supervised party spend the supervisor's CPU. These tests pin both the cost
# bound and the exact semantics the cost bound was bought without changing.
# ---------------------------------------------------------------------------

#: Wall-clock ceiling for one match attempt on a worst-case shape. The measured
#: cost of the slowest shape here is ~0.5 ms, so this leaves a ~500x margin for a
#: heavily contended machine. It is also a real regression detector: the
#: single-backtrack-point matcher this replaced took ~1.7 s on the same input, so
#: it fails this bound by roughly 7x.
MATCH_BUDGET_SECONDS = 0.25


def _worst(pattern: str, subject: str) -> float:
    compiled = compile_pattern(pattern, "p")
    start = time.perf_counter()
    compiled.matches(subject)
    return time.perf_counter() - start


def test_the_matcher_does_not_backtrack_combinatorially():
    """The shape that used to cost 1.7 s of CPU for one match attempt.

    ``'*'`` followed by a long run of ``?`` made the old matcher re-scan the
    whole pattern tail once per subject character, so cost grew with
    ``pattern x subject``. With a subject at the length cap and an operator-chosen
    pattern near it, a supervised agent could burn seconds of supervisor CPU per
    path it tried, repeatedly.
    """
    pattern = "/" + "*" + "?" * 2040
    subject = "/" + "a" * 4095
    compiled = compile_pattern(pattern, "p")
    # Correctness first: the star absorbs 2055 characters, the ? run the last 2040.
    assert compiled.matches(subject) is True
    assert compiled.matches("/" + "a" * 2039) is False
    elapsed = _worst(pattern, subject)
    assert elapsed < MATCH_BUDGET_SECONDS, f"quadratic blow-up: {elapsed:.3f}s"


@pytest.mark.parametrize(
    "pattern",
    [
        "/" + "*" + "?" * 2040,
        "/" + "*?" * 1020,
        "/" + "*a" * 1020 + "*",
        "/" + "*a" * 1020 + "z",
        "/**/" + "*" + "?" * 2040,
        "/" + "?*" * 1020,
        "/" + "*" + "a?" * 1020,
    ],
)
def test_every_adversarial_shape_is_bounded(pattern):
    """No adversarial shape may approach the ceiling, whatever it looks like."""
    subject = "/" + "a" * 4095
    elapsed = _worst(pattern, subject)
    assert elapsed < MATCH_BUDGET_SECONDS, f"{pattern[:24]}... took {elapsed:.3f}s"


def test_cost_does_not_grow_with_pattern_length_at_fixed_subject():
    """Cost must stay flat as the pattern grows, not track it.

    Only an absolute bound is asserted. A ratio test cannot separate the two
    shapes here: the old quadratic cost peaks in the middle of the pattern
    length range, so its ratio between two sizes can look *better* than a linear
    one. The measured cost of both sizes is sub-millisecond.
    """
    subject = "/" + "a" * 4095
    assert _worst("/" + "*" + "?" * 256, subject) < MATCH_BUDGET_SECONDS
    assert _worst("/" + "*" + "?" * 2040, subject) < MATCH_BUDGET_SECONDS


def test_a_path_that_does_not_exist_is_still_matched():
    """A pattern constrains strings; it must not consult the filesystem.

    Matching a path that certainly does not exist - and one whose prefix is a
    symlink-free string that was never resolved - shows the matcher answers from
    the string alone. No ``stat``, no existence check, no symlink resolution.
    """
    assert compile_pattern("/does/not/exist/**", "p").matches(
        "/does/not/exist/at/all"
    ) is True
    assert compile_pattern("/does/not/exist/*", "p").matches(
        "/does/not/exist/one"
    ) is True
    # ".." is refused rather than resolved, which is only possible if the
    # filesystem is never consulted.
    with pytest.raises(PolicyValidationError):
        compile_pattern("/does/../exist/**", "p")


def test_a_subject_at_the_length_cap_is_accepted_and_beyond_it_is_refused():
    pattern = compile_pattern("/a/**", "p")
    assert pattern.matches("/" + "x" * 4095) is False  # length 4096, allowed
    with pytest.raises(PolicyValidationError) as excinfo:
        pattern.matches("/" + "x" * 4096)  # length 4097
    assert excinfo.value.issues[0].code == "too_long"


# --- differential testing against a deliberately exponential reference -------


def _reference_segment(pattern: str, text: str) -> bool:
    """Brute-force ``*``/``?`` segment match: obviously correct, not fast."""
    if not pattern:
        return not text
    if pattern[0] == "*":
        return _reference_segment(pattern[1:], text) or (
            bool(text) and _reference_segment(pattern, text[1:])
        )
    if not text:
        return False
    if pattern[0] == "?" or pattern[0] == text[0]:
        return _reference_segment(pattern[1:], text[1:])
    return False


def _reference_segments(pattern: "list[str]", text: "list[str]") -> bool:
    """Brute-force ``**`` block match, by construction correct."""
    if not pattern:
        return not text
    if pattern[0] == "**":
        return _reference_segments(pattern[1:], text) or (
            bool(text) and _reference_segments(pattern, text[1:])
        )
    if not text:
        return False
    return _reference_segment(pattern[0], text[0]) and _reference_segments(
        pattern[1:], text[1:]
    )


def test_the_segment_matcher_agrees_with_a_brute_force_reference():
    """Exhaustive small cases: the fast matcher must equal the slow one.

    The reference is the naive exponential recursion, so it is slow but hard to
    get wrong. Every pattern/text pair over a tiny alphabet is compared, which is
    what makes the linear rewrite safe to trust.
    """
    checked = 0
    alphabet = "ab*?"
    for length in range(1, 5):
        for parts in itertools.product(alphabet, repeat=length):
            segment = "".join(parts)
            if "**" in segment or not ("*" in segment or "?" in segment):
                continue  # refused syntax, or the subtree branch
            try:
                compiled = compile_pattern("/" + segment, "p")
            except PolicyValidationError:
                continue
            for text_length in range(1, 4):
                for text_parts in itertools.product("ab", repeat=text_length):
                    text = "".join(text_parts)
                    checked += 1
                    assert compiled.matches("/" + text) == _reference_segment(
                        segment, text
                    ), f"pattern={segment!r} text={text!r}"
    assert checked > 3000


def test_the_block_matcher_agrees_with_a_brute_force_reference():
    """Same exhaustive comparison at the ``**`` block level."""
    checked = 0
    pieces = ["a", "b", "**", "*", "?"]
    for length in range(1, 4):
        for parts in itertools.product(pieces, repeat=length):
            if not any("*" in piece or "?" in piece for piece in parts):
                continue  # no wildcard: this is the subtree branch
            try:
                compiled = compile_pattern("/" + "/".join(parts), "p")
            except PolicyValidationError:
                continue
            for text_length in range(0, 4):
                for text_parts in itertools.product(["a", "b"], repeat=text_length):
                    text = "/" + "/".join(text_parts) if text_parts else "/"
                    checked += 1
                    assert compiled.matches(text) == _reference_segments(
                        list(parts), list(text_parts)
                    ), f"pattern={parts!r} text={text_parts!r}"
    assert checked > 700


# --- segment-level (`**`) bound: deterministic, no wall clock -----------------

#: Many-``**`` patterns at the caps, each matched against the longest near-miss
#: subject a capped document allows (256 segments, 4096 characters). These are
#: the worst segment-level shapes that can be constructed at all.
SEGMENT_ADVERSARIAL: dict[str, tuple[list[str], bool]] = {
    "many_double_star": (["**", "a" * 28] * 128, False),
    "star_before_every_segment": (["**", "?" * 14] * 128, False),
    "dense_double_star_pairs": (["**", "**", "a" * 14] * 85, False),
    "star_then_question_segments": (["**"] * 128 + ["?" * 15] * 128, True),
}

#: ``["a" * 15] * 255 + ["b" * 15]``: 256 segments, 4096 characters, and a
#: trailing segment that makes most of the patterns above fail at the very end.
SEGMENT_ADVERSARIAL_SUBJECT = ["a" * 15] * 255 + ["b" * 15]

#: Generous; the measured worst shape is ~23 ms, and the deterministic
#: comparison bound below is the real guard.
SEGMENT_MATCH_BUDGET_SECONDS = 2.0


class _CountingText:
    """A segment sequence that counts how often the loop asks for its length.

    ``_segments_match`` evaluates ``len(text)`` once per iteration it enters, plus
    one final time when the loop exits on its condition (but not when it leaves
    via the early ``return False``). The count is therefore the number of visited
    states, or exactly one more - never less. Asserting on it is a valid way to
    bound the visit count from above, and it needs no timing and no change to the
    matcher.
    """

    def __init__(self, segments) -> None:
        self._segments = list(segments)
        self.length_calls = 0

    def __len__(self) -> int:
        self.length_calls += 1
        return len(self._segments)

    def __getitem__(self, index):
        return self._segments[index]


#: The state-space edges, including the ones the public API cannot reach
#: (``P = 0``: a wildcard-free pattern takes the subtree branch instead).
#: Each entry is (label, pattern_segments, subject_segments).
SEGMENT_BOUND_CASES: "list[tuple[str, list[str], list[str]]]" = [
    ("P=0, T=0", [], []),
    ("P=0, T=1", [], ["a"]),
    ("P=0, T=5", [], ["a"] * 5),
    ("P=1, T=0", ["a"], []),
    ("P=1, T=0, star", ["**"], []),
    ("P=1, T=1", ["a"], ["a"]),
    ("P=1, T=1, star", ["**"], ["a"]),
    ("P=1, T=2, near miss", ["z"], ["a", "b"]),
    ("only **", ["**"], ["a"] * 8),
    ("only ** repeated", ["**", "**", "**"], ["a"] * 8),
    ("trailing **", ["a", "**"], ["a"] * 8),
    ("trailing **, near miss", ["z", "**"], ["a"] * 8),
    ("empty subject, star present", ["**", "a"], []),
    ("empty subject, literal only", ["a"], []),
    ("leading **, one subject segment", ["**", "a"], ["a"]),
    ("long subject, one pattern segment", ["**"], ["a"] * 256),
    ("terminal transition, ** then literal", ["**", "z"], ["a"] * 255 + ["b"]),
    ("two ** , near miss", ["**", "a", "**", "b"], ["a"] * 7 + ["c"]),
    ("** between literals", ["a", "**", "b"], ["a"] + ["x"] * 6 + ["b"]),
    ("dense ** pairs", ["**", "**", "a"] * 6, ["a"] * 17 + ["b"]),
]

_SEGMENT_BOUND_IDS = [case[0] for case in SEGMENT_BOUND_CASES]


def _proven_visit_bound(pattern_segments: int, subject_segments: int) -> int:
    """Proven upper bound on states visited by ``_segments_match``.

    ``(P + 1) * (T + 1)``, from the potential-function argument recorded on the
    function. Note this is **not** ``P * T``: a lone ``**`` against 77 segments
    visits 78 states, so ``P * T`` is false as an absolute bound. The asymptotic
    cost is still ``O(P * T)``, since ``(P+1)(T+1) = PT + P + T + 1``.
    """
    return (pattern_segments + 1) * (subject_segments + 1)


@pytest.mark.parametrize(
    "label,pattern,subject", SEGMENT_BOUND_CASES, ids=_SEGMENT_BOUND_IDS
)
def test_segment_state_visits_stay_within_the_proven_bound(
    monkeypatch, label, pattern, subject
):
    """Deterministic, timing-free bound on the states the ``**`` matcher visits.

    This asserts the proven bound ``(P + 1) * (T + 1)`` rather than ``P * T``,
    which the previous revision of this test (and of the docstring) claimed and
    which is simply false: see ``test_the_naive_pattern_times_subject_bound_is_false``.
    """
    comparisons: list[tuple[str, str]] = []
    original = policy_v1._segment_matches

    def counting(pattern_segment: str, subject_segment: str) -> bool:
        comparisons.append((pattern_segment, subject_segment))
        return original(pattern_segment, subject_segment)

    monkeypatch.setattr(policy_v1, "_segment_matches", counting)

    text = _CountingText(subject)
    policy_v1._segments_match(list(pattern), text)

    P, T = len(pattern), len(subject)
    bound = _proven_visit_bound(P, T)
    # len(text) is called once per visited state, or once more when the loop
    # exits on its condition, so bounding it bounds the visit count.
    assert text.length_calls <= bound, (
        f"{label}: {text.length_calls} length checks exceeds "
        f"(P+1)(T+1) = {bound}"
    )
    # Liveness: each compared element sits inside one visited state, so the
    # instrumentation cannot be passing vacuously if this holds.
    assert len(comparisons) <= text.length_calls


def test_the_naive_pattern_times_subject_bound_is_false():
    """Pin the counterexample, so the wrong bound cannot creep back.

    A lone ``**`` against 77 segments **visits 78 states**: the loop enters once
    to read the ``**``, then once per subsequent subject position. So ``P * T =
    77`` is not a valid absolute bound, even though the cost is still ``O(P * T)``.
    ``len(text)`` is evaluated 79 times here, because the loop also tests its
    condition once more before exiting.
    """
    text = _CountingText(["a"] * 77)
    policy_v1._segments_match(["**"], text)
    assert text.length_calls == 79
    assert text.length_calls > 1 * 77  # P * T is violated
    assert text.length_calls <= _proven_visit_bound(1, 77)


def test_the_proven_bound_grows_as_quadratically_as_claimed():
    """``(P+1)(T+1)`` is ``O(P*T)``: doubling both sides roughly quadruples it."""
    assert _proven_visit_bound(256, 256) == 66049
    assert _proven_visit_bound(128, 128) == 16641
    # ~3.97x, i.e. quadratic growth, not exponential.
    assert 3.9 < _proven_visit_bound(256, 256) / _proven_visit_bound(128, 128) < 4.0


def _segment_shape(name: str) -> "tuple[str, str, list[str]]":
    pattern_segments, _expected = SEGMENT_ADVERSARIAL[name]
    return (
        "/" + "/".join(pattern_segments),
        "/" + "/".join(SEGMENT_ADVERSARIAL_SUBJECT),
        pattern_segments,
    )


@pytest.mark.parametrize("name", sorted(SEGMENT_ADVERSARIAL))
def test_segment_matching_stays_within_the_state_bound(monkeypatch, name):
    """Comparisons never exceed the proven state bound at the caps.

    Each character-level comparison corresponds to exactly one visited state and
    there is no comparison cache that could hide a repeat, so this is a
    timing-free measure of the state bound: a matcher that started revisiting
    states would blow past it.
    """
    pattern, subject, pattern_segments = _segment_shape(name)
    original = policy_v1._segment_matches
    comparisons = []

    def counting(pattern_segment: str, subject_segment: str) -> bool:
        comparisons.append((pattern_segment, subject_segment))
        return original(pattern_segment, subject_segment)

    monkeypatch.setattr(policy_v1, "_segment_matches", counting)
    compile_pattern(pattern, "p").matches(subject)

    bound = _proven_visit_bound(
        len(pattern_segments), len(SEGMENT_ADVERSARIAL_SUBJECT)
    )
    assert len(comparisons) <= bound, (
        f"{name}: {len(comparisons)} comparisons exceeds "
        f"(P+1)(T+1) = {bound}"
    )
    # The bound must be the caps' bound, not accidentally trivial.
    assert bound >= 256 * 257


@pytest.mark.parametrize("name", sorted(SEGMENT_ADVERSARIAL))
def test_segment_adversarial_shapes_decide_correctly(name):
    """Bounded must not mean wrong: the decisions at the caps are pinned.

    Three of these fail only on the final segment, which is exactly the shape
    that forces the matcher to try the most placements.
    """
    pattern, subject, _pattern_segments = _segment_shape(name)
    expected = SEGMENT_ADVERSARIAL[name][1]
    assert compile_pattern(pattern, "p").matches(subject) is expected


@pytest.mark.parametrize("name", sorted(SEGMENT_ADVERSARIAL))
def test_segment_adversarial_shapes_are_bounded_in_time(name):
    """A secondary wall-clock guard over the same shapes."""
    pattern, subject, _pattern_segments = _segment_shape(name)
    compiled = compile_pattern(pattern, "p")
    started = time.perf_counter()
    compiled.matches(subject)
    elapsed = time.perf_counter() - started
    assert elapsed < SEGMENT_MATCH_BUDGET_SECONDS, f"{name}: {elapsed:.3f}s"


def test_the_segment_matcher_carries_no_state_proportional_to_pattern_x_subject():
    """No comparison memo: extra memory must not scale with pattern x subject.

    An earlier revision cached every element comparison in a dict keyed by
    ``(pattern_position, subject_position)``. Measurement showed the cache could
    never hit - the matcher never re-enters a state - so it was removed. This
    pins the removal, because reintroducing it would silently restore an
    O(P x T) allocation in the trusted path.
    """
    assert not hasattr(policy_v1, "_element_matches")


# --- lone surrogates --------------------------------------------------------


@pytest.mark.parametrize("escape", [r"\ud800", r"\udcff", r"\udfff", r"\ud83d"])
def test_a_lone_surrogate_in_a_pattern_is_refused(escape):
    """A surrogate cannot occur in a UTF-8 path, so such a rule is a no-op.

    Only a JSON escape can produce one. Left alone it would sit in the document
    looking like a working rule while matching nothing, which is the precise
    failure this format refuses everywhere else.
    """
    document = '{"version": 1, "filesystem": {"deny": ["/tmp/' + escape + '/**"]}}'
    with pytest.raises(PolicyValidationError) as excinfo:
        loads_policy(document)
    assert excinfo.value.issues[0].code == "lone_surrogate"


def test_a_lone_surrogate_in_a_subject_is_refused():
    """Not answered with a silent "no" - the same rule as every other subject."""
    pattern = compile_pattern("/tmp/**", "p")
    for subject in ("/tmp/\ud800/x", "/tmp/\udcff", "/tmp/a\udfffb"):
        with pytest.raises(PolicyValidationError) as excinfo:
            pattern.matches(subject)
        assert excinfo.value.issues[0].code == "lone_surrogate"


def test_astral_characters_are_still_accepted():
    """The surrogate refusal must not refuse real characters above U+FFFF."""
    document = json.dumps({"version": 1, "filesystem": {"deny": ["/tmp/\U0001f600/**"]}})
    policy = loads_policy(document)
    pattern = policy.filesystem.deny[0]
    assert pattern.pattern == "/tmp/\U0001f600/**"
    assert pattern.matches("/tmp/\U0001f600/x") is True


def test_a_surrogate_pair_escape_is_decoded_not_refused():
    """``\\ud83d\\ude00`` is a valid encoding of U+1F600, not a lone surrogate."""
    document = '{"version": 1, "filesystem": {"deny": ["/tmp/\\ud83d\\ude00/**"]}}'
    pattern = loads_policy(document).filesystem.deny[0]
    assert pattern.pattern == "/tmp/\U0001f600/**"
    assert pattern.matches("/tmp/\U0001f600/x") is True


# --- malformed UTF-8 --------------------------------------------------------


def test_malformed_utf8_never_escapes_as_another_exception(tmp_path):
    """Fuzzed byte soup must always surface as a located parse error.

    A ``UnicodeDecodeError`` or ``IndexError`` leaking out of the loader would
    crash a caller that only knows how to handle the documented error type.
    """
    rng = random.Random(20260919)
    for index in range(300):
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        path = tmp_path / f"fuzz-{index}.json"
        path.write_bytes(payload)
        try:
            load_policy(str(path))
        except PolicyParseError:
            pass  # the documented outcome
        except PolicyValidationError:
            pass  # also documented: valid UTF-8 that is not a valid document


@pytest.mark.parametrize(
    "payload",
    [
        b'{"version":1,"name":"a\x80b"}',  # lone continuation byte
        b'{"version":1,"name":"\xe2\x82"}',  # truncated 3-byte sequence
        b'{"version":1,"name":"\xc0\xaf"}',  # overlong encoding
        b'{"version":1,"name":"\xed\xa0\x80"}',  # CESU-8 surrogate
        b'{"version":1,"name":"\xff"}',  # invalid start byte
        b'{"version":1}\xf0\x9f',  # truncated at EOF
    ],
)
def test_malformed_utf8_reports_a_byte_offset(tmp_path, payload):
    path = tmp_path / "bad.json"
    path.write_bytes(payload)
    with pytest.raises(PolicyParseError) as excinfo:
        load_policy(str(path))
    message = str(excinfo.value)
    assert "not valid UTF-8" in message
    assert "offset" in message


# --- Unicode normalisation, documented rather than silent -------------------


def test_path_normalisation_is_not_unicode_normalised():
    """NFC and NFD spellings are different rules, deliberately.

    Applying a Unicode normalisation would silently rewrite an operator's rule,
    and normalisation is itself a source of collisions. The cost is that a rule
    copied out of a normalising editor may not match a differently-encoded path,
    so the behaviour is pinned here and documented in docs/policy.md rather than
    left to be discovered.
    """
    nfc = "/tmp/caf\u00e9/**"
    nfd = "/tmp/cafe\u0301/**"
    assert nfc != nfd
    assert compile_pattern(nfc, "p").matches("/tmp/caf\u00e9/x") is True
    assert compile_pattern(nfc, "p").matches("/tmp/cafe\u0301/x") is False
    assert compile_pattern(nfd, "p").matches("/tmp/cafe\u0301/x") is True
    assert compile_pattern(nfd, "p").matches("/tmp/caf\u00e9/x") is False


def test_case_is_not_folded_and_the_matcher_does_not_ask_the_os():
    """Case-sensitive on every platform, so the digest is portable."""
    pattern = compile_pattern("/etc/PASSWD", "p")
    assert pattern.matches("/etc/PASSWD") is True
    assert pattern.matches("/etc/passwd") is False

