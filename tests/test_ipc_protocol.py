"""IPC protocol: framing, bounds, versioning and authority stripping."""

from __future__ import annotations

import json

import pytest

from the_watcher.exceptions import ProtocolError
from the_watcher.ipc.protocol import (
    AUTHORITATIVE_FIELDS,
    CLIENT_MESSAGE_TYPES,
    ENVELOPE_KEYS,
    WATCHER_IPC_VERSION,
    ErrorCode,
    IpcLimits,
    MessageType,
    build_error,
    build_request,
    build_response,
    decode_message,
    encode_message,
    strip_authoritative_fields,
    validate_payload,
)

LIMITS = IpcLimits()


def code_of(exc_info) -> str:
    return exc_info.value.code


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


def test_encode_is_deterministic_and_key_order_independent():
    first = encode_message({"b": 1, "a": 2})
    second = encode_message({"a": 2, "b": 1})
    assert first == second == b'{"a":2,"b":1}'


def test_encode_is_ascii_only_and_json():
    raw = encode_message({"text": "caf\u00e9 \u2713"})
    raw.decode("ascii")  # must not raise
    assert json.loads(raw.decode("ascii"))["text"] == "caf\u00e9 \u2713"


def test_encode_rejects_unsupported_python_objects():
    """No pickling: an arbitrary object is an error, not a serialised blob."""
    with pytest.raises(ProtocolError) as excinfo:
        encode_message({"payload": {"obj": object()}})
    assert code_of(excinfo) == ErrorCode.INVALID_VALUE.value
    assert b"pickle" not in str(excinfo.value).encode()


def test_encode_rejects_nan():
    with pytest.raises(ProtocolError, match="INVALID_VALUE"):
        encode_message({"value": float("nan")})


# ---------------------------------------------------------------------------
# Decoding and version negotiation
# ---------------------------------------------------------------------------


def test_round_trip_of_a_valid_request():
    request = build_request(
        MessageType.EVALUATE,
        {"event_type": "file_access", "action": "read"},
        session_id="session-1",
    )
    decoded = decode_message(encode_message(request), LIMITS)
    assert decoded["type"] == "EVALUATE"
    assert decoded["version"] == WATCHER_IPC_VERSION
    assert decoded["session_id"] == "session-1"


def test_malformed_json_is_rejected():
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(b"{not json", LIMITS)
    assert code_of(excinfo) == ErrorCode.MALFORMED_JSON.value


def test_non_object_json_is_rejected():
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(b"[1,2,3]", LIMITS)
    assert code_of(excinfo) == ErrorCode.BAD_REQUEST.value


def test_empty_message_is_rejected():
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(b"", LIMITS)
    assert code_of(excinfo) == ErrorCode.BAD_REQUEST.value


def test_oversized_message_is_rejected():
    limits = IpcLimits(max_message_bytes=512)
    raw = b"x" * 2048
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(raw, limits)
    assert code_of(excinfo) == ErrorCode.MESSAGE_TOO_LARGE.value


def test_unsupported_protocol_version_is_rejected():
    message = {"version": 99, "type": "HEARTBEAT", "request_id": "req-1"}
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(encode_message(message), LIMITS)
    assert code_of(excinfo) == ErrorCode.UNSUPPORTED_VERSION.value


def test_missing_version_is_rejected():
    message = {"type": "HEARTBEAT", "request_id": "req-1"}
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(encode_message(message), LIMITS)
    assert code_of(excinfo) == ErrorCode.UNSUPPORTED_VERSION.value


def test_unknown_message_type_is_rejected():
    message = {
        "version": 1,
        "type": "DROP_TABLES",
        "request_id": "req-1",
        "session_id": "session-1",
    }
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(encode_message(message), LIMITS)
    assert code_of(excinfo) == ErrorCode.UNKNOWN_MESSAGE.value


def test_unexpected_envelope_keys_are_rejected():
    message = {
        "version": 1,
        "type": "HEARTBEAT",
        "request_id": "req-1",
        "session_id": "session-1",
        "administrator": True,
    }
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(encode_message(message), LIMITS)
    assert code_of(excinfo) == ErrorCode.BAD_REQUEST.value


def test_all_protocol_envelope_keys_are_recognised():
    assert ENVELOPE_KEYS == {
        "version",
        "request_id",
        "type",
        "session_id",
        "payload",
        "ok",
        "error_code",
        "message",
    }


def test_server_message_types_are_not_accepted_as_client_requests():
    message = encode_message(build_response("req-1", {}))
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(message, LIMITS, allowed_types=CLIENT_MESSAGE_TYPES)
    assert code_of(excinfo) == ErrorCode.UNKNOWN_MESSAGE.value


# ---------------------------------------------------------------------------
# Malformed Unicode and numeric edge cases
# ---------------------------------------------------------------------------


def test_invalid_utf8_is_rejected():
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(b'{"type":"HEARTBEAT","x":"\xff\xfe"}', LIMITS)
    assert code_of(excinfo) == ErrorCode.INVALID_UNICODE.value


def test_nul_byte_is_rejected():
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(b'{"type":"HEARTBEAT","x":"a\x00b"}', LIMITS)
    assert code_of(excinfo) == ErrorCode.INVALID_UNICODE.value


def test_lone_surrogate_is_rejected():
    message = {
        "version": 1,
        "type": "HEARTBEAT",
        "request_id": "req-1",
        "session_id": "session-1",
        "payload": {"note": "\ud800"},
    }
    # json.dumps(ensure_ascii=True) escapes it, so build the bytes directly.
    raw = json.dumps(message).encode("ascii")
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(raw, LIMITS)
    assert code_of(excinfo) == ErrorCode.INVALID_UNICODE.value


def test_nan_and_infinity_in_json_text_are_rejected():
    for literal in (b"NaN", b"Infinity", b"-Infinity"):
        raw = (
            b'{"version":1,"type":"HEARTBEAT","request_id":"req-1",'
            b'"session_id":"session-1","payload":{"v":' + literal + b"}}"
        )
        with pytest.raises(ProtocolError) as excinfo:
            decode_message(raw, LIMITS)
        assert code_of(excinfo) == ErrorCode.INVALID_VALUE.value


# ---------------------------------------------------------------------------
# Payload bounds
# ---------------------------------------------------------------------------


def test_deeply_nested_payload_is_rejected():
    limits = IpcLimits(max_metadata_depth=3)
    nested: dict = {"a": {}}
    cursor = nested["a"]
    for _ in range(8):
        cursor["a"] = {}
        cursor = cursor["a"]

    with pytest.raises(ProtocolError) as excinfo:
        validate_payload(nested, limits)
    assert code_of(excinfo) == ErrorCode.PAYLOAD_TOO_DEEP.value


def test_oversized_string_is_rejected():
    limits = IpcLimits(max_string_length=64)
    with pytest.raises(ProtocolError) as excinfo:
        validate_payload({"note": "x" * 500}, limits)
    assert code_of(excinfo) == ErrorCode.STRING_TOO_LONG.value


def test_too_many_keys_is_rejected():
    limits = IpcLimits(max_container_items=5)
    with pytest.raises(ProtocolError) as excinfo:
        validate_payload({f"k{i}": i for i in range(50)}, limits)
    assert code_of(excinfo) == ErrorCode.PAYLOAD_TOO_LARGE.value


def test_too_many_list_items_is_rejected():
    limits = IpcLimits(max_container_items=5)
    with pytest.raises(ProtocolError) as excinfo:
        validate_payload({"items": list(range(50))}, limits)
    assert code_of(excinfo) == ErrorCode.PAYLOAD_TOO_LARGE.value


def test_payload_must_be_an_object():
    message = {
        "version": 1,
        "type": "EVALUATE",
        "request_id": "req-1",
        "session_id": "session-1",
        "payload": ["not", "an", "object"],
    }
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(encode_message(message), LIMITS)
    assert code_of(excinfo) == ErrorCode.BAD_REQUEST.value


def test_ordinary_nested_payload_is_accepted():
    validate_payload(
        {
            "event_type": "tool_request",
            "action": "invoke",
            "metadata": {"args": ["a", "b"], "nested": {"count": 3, "flag": True}},
        },
        LIMITS,
    )


# ---------------------------------------------------------------------------
# Request ids
# ---------------------------------------------------------------------------


def test_missing_request_id_is_rejected_when_required():
    message = {"version": 1, "type": "HEARTBEAT", "session_id": "session-1"}
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(encode_message(message), LIMITS, require_request_id=True)
    assert code_of(excinfo) == ErrorCode.BAD_REQUEST.value


@pytest.mark.parametrize(
    "bad", ["has space", "semi;colon", "x" * 200, "", "../etc/passwd", "newline\n"]
)
def test_malformed_request_ids_are_rejected(bad):
    message = {
        "version": 1,
        "type": "HEARTBEAT",
        "request_id": bad,
        "session_id": "session-1",
    }
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(encode_message(message), LIMITS)
    assert code_of(excinfo) == ErrorCode.BAD_REQUEST.value


def test_well_formed_request_ids_are_accepted():
    for good in ("req-1", "abc.def_ghi-123", "x" * 128):
        message = {
            "version": 1,
            "type": "HEARTBEAT",
            "request_id": good,
            "session_id": "session-1",
        }
        assert decode_message(encode_message(message), LIMITS)["request_id"] == good


def test_malformed_session_ids_are_rejected():
    message = {
        "version": 1,
        "type": "HEARTBEAT",
        "request_id": "req-1",
        "session_id": "bad session id!",
    }
    with pytest.raises(ProtocolError) as excinfo:
        decode_message(encode_message(message), LIMITS)
    assert code_of(excinfo) == ErrorCode.BAD_REQUEST.value


# ---------------------------------------------------------------------------
# Client authority stripping
# ---------------------------------------------------------------------------


def test_authoritative_field_set_is_stable():
    assert AUTHORITATIVE_FIELDS == {
        "sequence",
        "timestamp",
        "previous_hash",
        "event_hash",
        "final_hash",
        "decision",
        "risk",
    }


@pytest.mark.parametrize("field", sorted(AUTHORITATIVE_FIELDS))
def test_every_authoritative_field_is_stripped(field):
    payload = {"event_type": "file_access", "action": "read", field: "forged"}
    cleaned, rejected = strip_authoritative_fields(payload)

    assert field not in cleaned
    assert rejected == [field]
    assert cleaned["event_type"] == "file_access"


def test_client_cannot_supply_a_sequence_number():
    cleaned, rejected = strip_authoritative_fields(
        {"event_type": "file_access", "action": "read", "sequence": 999}
    )
    assert "sequence" not in cleaned
    assert "sequence" in rejected


def test_client_cannot_supply_an_event_hash():
    cleaned, rejected = strip_authoritative_fields(
        {
            "event_type": "file_access",
            "action": "read",
            "event_hash": "f" * 64,
            "previous_hash": "e" * 64,
        }
    )
    assert "event_hash" not in cleaned
    assert "previous_hash" not in cleaned
    assert set(rejected) == {"event_hash", "previous_hash"}


def test_client_cannot_supply_a_decision_or_risk():
    cleaned, rejected = strip_authoritative_fields(
        {"event_type": "file_access", "action": "read", "decision": "ALLOW", "risk": "NORMAL"}
    )
    assert "decision" not in cleaned
    assert "risk" not in cleaned
    assert set(rejected) == {"decision", "risk"}


def test_nested_authoritative_fields_are_stripped_too():
    cleaned, rejected = strip_authoritative_fields(
        {
            "event_type": "tool_request",
            "action": "invoke",
            "metadata": {"inner": {"decision": "ALLOW", "note": "keep me"}},
        }
    )
    assert cleaned["metadata"]["inner"] == {"note": "keep me"}
    assert rejected == ["metadata.inner.decision"]


def test_legitimate_fields_survive_stripping():
    cleaned, rejected = strip_authoritative_fields(
        {"event_type": "shell_command", "action": "exec", "resource": "pytest", "metadata": {"cwd": "/tmp"}}
    )
    assert rejected == []
    assert cleaned["action"] == "exec"
    assert cleaned["metadata"] == {"cwd": "/tmp"}


# ---------------------------------------------------------------------------
# Response envelopes
# ---------------------------------------------------------------------------


def test_build_response_shape():
    response = build_response("req-7", {"decision": "ALLOW"})
    assert response["ok"] is True
    assert response["type"] == "RESPONSE"
    assert response["request_id"] == "req-7"
    assert decode_message(
        encode_message(response), LIMITS, allowed_types=["RESPONSE"]
    )["payload"] == {"decision": "ALLOW"}


def test_build_error_shape_and_safe_message():
    error = build_error("req-7", ErrorCode.BAD_TOKEN, "authentication failed")
    assert error["ok"] is False
    assert error["error_code"] == "BAD_TOKEN"
    assert error["message"] == "authentication failed"


def test_error_messages_are_sanitised():
    error = build_error("req-7", ErrorCode.INTERNAL_ERROR, "boom\nTraceback (most recent call last)")
    assert "\n" not in error["message"]


def test_response_request_id_must_match_for_correlation():
    response = build_response("req-other", {})
    assert response["request_id"] == "req-other"
