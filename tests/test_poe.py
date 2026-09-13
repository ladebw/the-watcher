"""Proof of Execution layer: recording, canonicalisation, hashing, redaction."""

from __future__ import annotations

import dataclasses
import hashlib
import re
import sys
from pathlib import Path

import pytest

from the_watcher import (
    REDACTED,
    EventType,
    ExecutionTrace,
    PoEEvent,
    Recorder,
    TraceVerifier,
    canonical_json,
    hash_value,
)
from the_watcher.exceptions import CanonicalizationError, TraceError
from the_watcher.poe import sha256_hex


# ---------------------------------------------------------------------------
# Event shape and ordering
# ---------------------------------------------------------------------------


def test_event_contains_the_documented_fields(clock):
    recorder = Recorder(clock=clock)
    event = recorder.record(
        EventType.NETWORK_REQUEST,
        action="connect",
        resource="example.com",
        decision="ALLOW",
        risk="NORMAL",
    )

    payload = event.to_dict()
    for field in (
        "sequence",
        "timestamp",
        "event_type",
        "action",
        "resource",
        "decision",
        "risk",
        "previous_hash",
        "event_hash",
    ):
        assert field in payload, f"missing event field: {field}"

    assert payload["sequence"] == 0
    assert payload["event_type"] == "network_request"
    assert payload["action"] == "connect"
    assert payload["resource"] == "example.com"
    assert payload["decision"] == "ALLOW"
    assert payload["risk"] == "NORMAL"


def test_events_are_sequenced_in_recording_order(clock):
    recorder = Recorder(clock=clock)
    for index in range(5):
        recorder.record("tool_request", f"call-{index}", f"tool-{index}")

    sequences = [event.sequence for event in recorder.trace]
    assert sequences == [0, 1, 2, 3, 4]


def test_timestamps_are_unix_seconds(clock):
    recorder = Recorder(clock=clock)
    event = recorder.record("file_access", "read", "/tmp/x")
    assert isinstance(event.timestamp, int)
    assert 1_500_000_000 < event.timestamp < 2_500_000_000


def test_trace_length_and_iteration(clock):
    recorder = Recorder(clock=clock)
    recorder.record("policy_decision", "evaluate", "x", decision="ALLOW")
    recorder.record("denied_action", "write", "y", decision="DENY")

    assert len(recorder.trace) == 2
    assert [e.sequence for e in recorder.trace] == [0, 1]
    assert recorder.trace[-1].decision == "DENY"


def test_event_summary_is_human_readable(clock):
    recorder = Recorder(clock=clock)
    event = recorder.record("shell_command", "exec", "echo hello")
    summary = event.summary()
    assert "shell_command" in summary
    assert "echo hello" in summary
    assert event.event_hash[:12] in summary


# ---------------------------------------------------------------------------
# Canonicalisation
# ---------------------------------------------------------------------------


def test_canonical_json_is_independent_of_key_order():
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_canonical_json_has_no_insignificant_whitespace():
    assert canonical_json({"a": [1, 2], "b": {"c": True}}) == '{"a":[1,2],"b":{"c":true}}'


def test_canonical_json_normalises_helper_types():
    assert canonical_json(b"\x00\xff") == '"00ff"'
    assert canonical_json({3, 1, 2}) == "[1,2,3]"
    assert canonical_json((1, 2)) == "[1,2]"
    assert canonical_json(0.0) == "0.0"
    assert canonical_json(-0.0) == "0.0"


def test_canonical_json_rejects_non_finite_floats():
    with pytest.raises(CanonicalizationError):
        canonical_json({"value": float("nan")})
    with pytest.raises(CanonicalizationError):
        canonical_json({"value": float("inf")})


def test_canonical_json_rejects_unsupported_types():
    class Custom:
        pass

    with pytest.raises(CanonicalizationError):
        canonical_json({"value": Custom()})


def test_hash_value_matches_raw_sha256_for_strings():
    assert hash_value("hello") == hashlib.sha256(b"hello").hexdigest()


def test_sha256_hex_accepts_text_and_bytes():
    assert sha256_hex("abc") == sha256_hex(b"abc")
    with pytest.raises(CanonicalizationError):
        sha256_hex(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Event hashing
# ---------------------------------------------------------------------------


def test_event_hash_is_a_sha256_hex_digest(clock):
    recorder = Recorder(clock=clock)
    event = recorder.record("model_call", "invoke", "gpt-x")
    assert len(event.event_hash) == 64
    assert all(character in "0123456789abcdef" for character in event.event_hash)


def test_event_hash_is_deterministic_for_identical_content():
    first = PoEEvent(
        sequence=3,
        timestamp=1_760_000_000,
        event_type="file_access",
        action="read",
        resource="/tmp/a",
        decision="ALLOW",
        risk="NORMAL",
        reason="",
        metadata={"x": 1},
        previous_hash="a" * 64,
    )
    second = dataclasses.replace(first)
    assert first.compute_hash() == second.compute_hash()
    assert first.with_hash().event_hash == second.with_hash().event_hash


def test_event_hash_changes_when_any_hashed_field_changes():
    base = PoEEvent(
        sequence=1,
        timestamp=1_760_000_000,
        event_type="file_access",
        action="read",
        resource="/tmp/a",
        previous_hash="a" * 64,
    )
    original = base.compute_hash()

    mutators = [
        {"resource": "/tmp/b"},
        {"action": "write"},
        {"decision": "DENY"},
        {"risk": "HIGH"},
        {"reason": "because"},
        {"metadata": {"k": "v"}},
        {"timestamp": 1_760_000_001},
        {"previous_hash": "b" * 64},
        {"event_type": "file_modification"},
    ]
    for changes in mutators:
        assert dataclasses.replace(base, **changes).compute_hash() != original


def test_event_rejects_negative_sequence():
    with pytest.raises(TraceError):
        PoEEvent(sequence=-1, timestamp=1_760_000_000, event_type="x", action="y")


def test_event_from_dict_requires_core_fields():
    with pytest.raises(TraceError):
        PoEEvent.from_dict({"sequence": 0})


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def test_recorder_redacts_sensitive_metadata_keys(clock):
    recorder = Recorder(clock=clock)
    event = recorder.record(
        "api_request",
        "post",
        "https://api.example.com/v1",
        metadata={
            "api_key": "value-that-must-not-leak",
            "headers": {"Authorization": "value-that-must-not-leak"},
            "nested": {"password": "value-that-must-not-leak"},
            "safe": "visible",
        },
    )

    assert event.metadata["api_key"] == REDACTED
    assert event.metadata["headers"]["Authorization"] == REDACTED
    assert event.metadata["nested"]["password"] == REDACTED
    assert event.metadata["safe"] == "visible"


@pytest.mark.parametrize(
    "secret",
    [
        "sk-" + "A" * 40,
        "ghp_" + "b" * 30,
        "AKIAIOSFODNN7EXAMPLE",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
    ],
)
def test_recorder_redacts_credential_shapes_in_values(clock, secret):
    recorder = Recorder(clock=clock)
    event = recorder.record(
        "api_request",
        "post",
        "https://example.com",
        metadata={"body": f"payload={secret};"},
    )
    assert secret not in event.metadata["body"]
    assert REDACTED in event.metadata["body"]


def test_recorder_redacts_bearer_headers(clock):
    recorder = Recorder(clock=clock)
    event = recorder.record(
        "network_request",
        "connect",
        "https://example.com",
        metadata={"header": "Bearer abcdefghijklmnopqrstuvwxyz"},
    )
    assert "abcdefghijklmnopqrstuvwxyz" not in event.metadata["header"]
    assert "Bearer [REDACTED]" == event.metadata["header"]


def test_recorder_redacts_url_userinfo(clock):
    recorder = Recorder(clock=clock)
    event = recorder.record(
        "network_request",
        "connect",
        "https://user:sup3rs3cr3t@example.com/path",
    )
    assert "sup3rs3cr3t" not in event.resource
    assert "example.com" in event.resource


def test_recorder_keeps_ordinary_values(clock):
    recorder = Recorder(clock=clock)
    event = recorder.record(
        "file_access",
        "read",
        "/workspace/notes.txt",
        metadata={"path": "/workspace/notes.txt", "size": 128, "monkey": "banana"},
    )
    assert event.metadata["monkey"] == "banana"
    assert event.metadata["size"] == 128
    assert event.resource == "/workspace/notes.txt"


def test_redaction_does_not_break_trace_verification(clock):
    recorder = Recorder(clock=clock)
    recorder.record(
        "api_request",
        "post",
        "https://api.example.com",
        metadata={"api_key": "sk-" + "A" * 40},
    )
    recorder.record("file_access", "read", "/workspace/a.txt")
    recorder.seal()
    assert recorder.trace.verify().valid


# ---------------------------------------------------------------------------
# Wrappers / decorators
# ---------------------------------------------------------------------------


def test_track_tool_decorator_records_tool_request(clock):
    recorder = Recorder(clock=clock)

    @recorder.track_tool("web_search")
    def web_search(query: str) -> str:
        return f"results for {query}"

    assert web_search("watcher") == "results for watcher"
    assert len(recorder.trace) == 1
    assert recorder.trace[0].event_type == "tool_request"
    assert recorder.trace[0].resource == "web_search"


def test_track_tool_decorator_records_failures(clock):
    recorder = Recorder(clock=clock)

    @recorder.track_tool("explode")
    def explode() -> None:
        raise ValueError("boom")

    with pytest.raises(ValueError):
        explode()

    assert len(recorder.trace) == 2
    assert recorder.trace[1].action == "error:explode"
    assert recorder.trace[1].risk == "ELEVATED"
    assert "ValueError" in recorder.trace[1].reason


def test_record_tool_writes_a_tool_request_event(clock):
    recorder = Recorder(clock=clock)
    event = recorder.record_tool("shell")
    assert event.event_type == "tool_request"
    assert event.resource == "shell"


# ---------------------------------------------------------------------------
# Serialisation round-trip and independence
# ---------------------------------------------------------------------------


def test_trace_survives_a_json_round_trip(clock):
    recorder = Recorder(clock=clock)
    recorder.record("session_start", "start", "python agent.py")
    recorder.record("file_access", "read", "/workspace/a.txt")
    recorder.record("network_request", "connect", "https://github.com")
    recorder.seal()

    serialised = recorder.trace.to_json()
    restored = ExecutionTrace.from_json(serialised)

    assert restored.session_id == recorder.trace.session_id
    assert len(restored) == 3
    assert TraceVerifier().verify(restored).valid


def test_trace_load_export_round_trip(clock, tmp_path):
    recorder = Recorder(clock=clock)
    recorder.record("session_start", "start", "agent.py")
    recorder.seal()

    path = tmp_path / "trace.json"
    recorder.trace.export(str(path))
    restored = ExecutionTrace.load(str(path))

    assert TraceVerifier().verify_file(str(path)).valid
    assert TraceVerifier().verify(restored).valid


def test_trace_rejects_missing_session_id():
    with pytest.raises(TraceError):
        ExecutionTrace.from_dict({"events": []})


def test_poe_layer_is_standalone_and_has_no_aaip_dependency():
    """The PoE layer must work with AAIP absent and never import it."""
    assert not [name for name in sys.modules if name == "aaip" or name.startswith("aaip.")]

    import the_watcher

    package_root = Path(the_watcher.__file__).resolve().parent
    pattern = re.compile(r"^\s*(?:from|import)\s+aaip\b", re.MULTILINE)
    offenders = [
        str(path.relative_to(package_root))
        for path in package_root.rglob("*.py")
        if pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], f"modules importing AAIP: {offenders}"
