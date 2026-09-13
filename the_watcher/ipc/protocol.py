"""Versioned, deterministic IPC protocol.

Design rules
------------
* **JSON only.** The protected process is untrusted, so nothing is ever
  unpickled from it. Messages are UTF-8 JSON with a fixed envelope.
* **Narrow.** A small, closed set of message types and a closed set of
  envelope keys. Unknown types and unknown envelope keys are rejected.
* **Bounded.** Message size, nesting depth, key count and string length are all
  capped before anything reaches the policy engine.
* **No client authority.** Fields that decide *what actually happened*
  (``sequence``, ``timestamp``, ``previous_hash``, ``event_hash``,
  ``final_hash``, ``decision``, ``risk``) are stripped from client input. The
  daemon constructs them itself.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any, Iterable, Mapping

from ..exceptions import ProtocolError

__all__ = [
    "WATCHER_IPC_VERSION",
    "MessageType",
    "ErrorCode",
    "IpcLimits",
    "AUTHORITATIVE_FIELDS",
    "ENVELOPE_KEYS",
    "CLIENT_MESSAGE_TYPES",
    "SERVER_MESSAGE_TYPES",
    "encode_message",
    "decode_message",
    "validate_payload",
    "strip_authoritative_fields",
    "build_request",
    "build_response",
    "build_error",
    "new_request_id",
    "sanitize_text",
    "is_valid_session_id",
    "is_valid_request_id",
]

#: Bump only for incompatible envelope changes.
WATCHER_IPC_VERSION = 1


class MessageType(str, Enum):
    """Every message the protocol understands."""

    # client -> server
    HELLO = "HELLO"
    EVALUATE = "EVALUATE"
    EVENT = "EVENT"
    HEARTBEAT = "HEARTBEAT"
    SESSION_STATUS = "SESSION_STATUS"
    TRACE_INFO = "TRACE_INFO"
    KILL_REQUEST = "KILL_REQUEST"
    SESSION_END = "SESSION_END"

    # server -> client
    RESPONSE = "RESPONSE"
    ERROR = "ERROR"


CLIENT_MESSAGE_TYPES: frozenset[str] = frozenset(
    {
        MessageType.HELLO.value,
        MessageType.EVALUATE.value,
        MessageType.EVENT.value,
        MessageType.HEARTBEAT.value,
        MessageType.SESSION_STATUS.value,
        MessageType.TRACE_INFO.value,
        MessageType.KILL_REQUEST.value,
        MessageType.SESSION_END.value,
    }
)

SERVER_MESSAGE_TYPES: frozenset[str] = frozenset(
    {MessageType.RESPONSE.value, MessageType.ERROR.value}
)


class ErrorCode(str, Enum):
    """Machine-readable failure reasons. Safe to return to the client."""

    BAD_REQUEST = "BAD_REQUEST"
    MALFORMED_JSON = "MALFORMED_JSON"
    MESSAGE_TOO_LARGE = "MESSAGE_TOO_LARGE"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    UNKNOWN_MESSAGE = "UNKNOWN_MESSAGE"
    PAYLOAD_TOO_DEEP = "PAYLOAD_TOO_DEEP"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    STRING_TOO_LONG = "STRING_TOO_LONG"
    INVALID_UNICODE = "INVALID_UNICODE"
    INVALID_VALUE = "INVALID_VALUE"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    BAD_TOKEN = "BAD_TOKEN"
    SESSION_MISMATCH = "SESSION_MISMATCH"
    REPLAYED_REQUEST = "REPLAYED_REQUEST"
    TOO_MANY_CONNECTIONS = "TOO_MANY_CONNECTIONS"
    SESSION_TERMINAL = "SESSION_TERMINAL"
    NOT_READY = "NOT_READY"
    INTERNAL_ERROR = "INTERNAL_ERROR"


#: Fields only the daemon may set. Anything a client sends under these names is
#: discarded and reported as a security signal.
AUTHORITATIVE_FIELDS: frozenset[str] = frozenset(
    {
        "sequence",
        "timestamp",
        "previous_hash",
        "event_hash",
        "final_hash",
        "decision",
        "risk",
    }
)

#: The complete set of allowed envelope keys. Anything else is rejected.
ENVELOPE_KEYS: frozenset[str] = frozenset(
    {
        "version",
        "request_id",
        "type",
        "session_id",
        "payload",
        "ok",
        "error_code",
        "message",
    }
)

_REQUEST_ID_RE = re.compile(r"\A[A-Za-z0-9_\-.]{1,128}\Z")
_SESSION_ID_RE = re.compile(r"\A[A-Za-z0-9_\-]{4,64}\Z")


def is_valid_session_id(value: Any) -> bool:
    """Return ``True`` for a well-formed session identifier.

    Deliberately strict: the identifier becomes part of a filename and an IPC
    endpoint name, so dots and path separators must not be accepted.
    """
    return isinstance(value, str) and _SESSION_ID_RE.match(value) is not None


def is_valid_request_id(value: Any) -> bool:
    """Return ``True`` for a well-formed request identifier."""
    return isinstance(value, str) and _REQUEST_ID_RE.match(value) is not None


@dataclass(frozen=True)
class IpcLimits:
    """Conservative, configurable bounds for everything crossing the boundary."""

    max_message_bytes: int = 256 * 1024
    max_metadata_depth: int = 6
    max_string_length: int = 4096
    max_container_items: int = 64
    max_connections_per_session: int = 4
    request_timeout: float = 5.0
    handshake_timeout: float = 5.0
    idle_poll: float = 0.25
    replay_cache_size: int = 4096

    def validate(self) -> None:
        if self.max_message_bytes < 1024:
            raise ProtocolError(ErrorCode.BAD_REQUEST, "max_message_bytes too small")
        if self.max_metadata_depth < 1:
            raise ProtocolError(ErrorCode.BAD_REQUEST, "max_metadata_depth too small")
        if self.max_string_length < 16:
            raise ProtocolError(ErrorCode.BAD_REQUEST, "max_string_length too small")
        if self.max_connections_per_session < 1:
            raise ProtocolError(ErrorCode.BAD_REQUEST, "max_connections_per_session < 1")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _reject_constant(value: str) -> Any:
    """Reject NaN/Infinity, which ``json.loads`` accepts by default."""
    raise ProtocolError(
        ErrorCode.INVALID_VALUE, f"non-finite number not permitted: {value}"
    )


def sanitize_text(text: Any, limit: int = 200) -> str:
    """Return a short, control-character-free string safe to log or return."""
    if not isinstance(text, str):
        text = str(text)
    cleaned = "".join(
        character if character.isprintable() else " " for character in text
    )
    cleaned = " ".join(cleaned.split())
    return cleaned[:limit]


def new_request_id(prefix: str = "req") -> str:
    """Build a request id: short, ascii-safe and non-guessable."""
    import secrets

    return f"{prefix}-{secrets.token_hex(8)}"


# ---------------------------------------------------------------------------
# Encoding / decoding
# ---------------------------------------------------------------------------


def encode_message(message: Mapping[str, Any]) -> bytes:
    """Serialise a message deterministically to UTF-8 JSON bytes."""
    if not isinstance(message, Mapping):
        raise ProtocolError(ErrorCode.BAD_REQUEST, "message must be a mapping")
    try:
        return json.dumps(
            dict(message),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError(
            ErrorCode.INVALID_VALUE, f"message is not serialisable: {exc}"
        ) from exc


def decode_message(
    raw: bytes,
    limits: IpcLimits,
    allowed_types: "Iterable[str] | None" = None,
    require_request_id: bool = False,
) -> dict[str, Any]:
    """Parse and validate one framed message.

    Raises :class:`ProtocolError` with a safe ``code`` for every rejection.
    """
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise ProtocolError(ErrorCode.BAD_REQUEST, "message must be bytes")

    payload_bytes = bytes(raw)
    if not payload_bytes:
        raise ProtocolError(ErrorCode.BAD_REQUEST, "empty message")
    if len(payload_bytes) > limits.max_message_bytes:
        raise ProtocolError(
            ErrorCode.MESSAGE_TOO_LARGE,
            f"message exceeds {limits.max_message_bytes} bytes",
        )

    try:
        text = payload_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError(
            ErrorCode.INVALID_UNICODE, f"message is not valid UTF-8 at byte {exc.start}"
        ) from exc

    if "\x00" in text:
        raise ProtocolError(ErrorCode.INVALID_UNICODE, "message contains a NUL byte")

    try:
        message = json.loads(text, parse_constant=_reject_constant)
    except ProtocolError:
        raise
    except json.JSONDecodeError as exc:
        raise ProtocolError(
            ErrorCode.MALFORMED_JSON, f"invalid JSON at position {exc.pos}"
        ) from exc

    if not isinstance(message, dict):
        raise ProtocolError(ErrorCode.BAD_REQUEST, "message must be a JSON object")

    unknown_keys = set(message) - ENVELOPE_KEYS
    if unknown_keys:
        raise ProtocolError(
            ErrorCode.BAD_REQUEST,
            "unexpected envelope keys: " + ",".join(sorted(unknown_keys))[:120],
        )

    version = message.get("version")
    if version != WATCHER_IPC_VERSION:
        raise ProtocolError(
            ErrorCode.UNSUPPORTED_VERSION, f"protocol version {version!r} is not supported"
        )

    message_type = message.get("type")
    if not isinstance(message_type, str) or not message_type:
        raise ProtocolError(ErrorCode.BAD_REQUEST, "missing message type")

    permitted = (
        set(allowed_types)
        if allowed_types is not None
        else CLIENT_MESSAGE_TYPES | SERVER_MESSAGE_TYPES
    )
    if message_type not in permitted:
        raise ProtocolError(ErrorCode.UNKNOWN_MESSAGE, "unsupported message type")

    request_id = message.get("request_id")
    if request_id is None:
        if require_request_id:
            raise ProtocolError(ErrorCode.BAD_REQUEST, "missing request_id")
    elif not is_valid_request_id(request_id):
        raise ProtocolError(ErrorCode.BAD_REQUEST, "malformed request_id")

    session_id = message.get("session_id")
    if session_id is not None and not is_valid_session_id(session_id):
        raise ProtocolError(ErrorCode.BAD_REQUEST, "malformed session_id")

    if "payload" in message and message["payload"] is not None:
        if not isinstance(message["payload"], dict):
            raise ProtocolError(ErrorCode.BAD_REQUEST, "payload must be an object")
        validate_payload(message["payload"], limits)

    return message


def validate_payload(
    payload: Mapping[str, Any], limits: IpcLimits, path: str = "payload"
) -> None:
    """Reject hostile payload shapes before they reach the policy engine."""
    if not isinstance(payload, Mapping):
        raise ProtocolError(ErrorCode.BAD_REQUEST, f"{path} must be an object")
    _validate_value(payload, limits, 0, path)


def _validate_value(value: Any, limits: IpcLimits, depth: int, path: str) -> None:
    if depth > limits.max_metadata_depth:
        raise ProtocolError(
            ErrorCode.PAYLOAD_TOO_DEEP,
            f"{path} nests deeper than {limits.max_metadata_depth}",
        )

    if value is None or isinstance(value, bool):
        return

    if isinstance(value, int):
        return

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ProtocolError(ErrorCode.INVALID_VALUE, f"{path} is not finite")
        return

    if isinstance(value, str):
        _validate_string(value, limits, path)
        return

    if isinstance(value, Mapping):
        if len(value) > limits.max_container_items:
            raise ProtocolError(
                ErrorCode.PAYLOAD_TOO_LARGE,
                f"{path} has more than {limits.max_container_items} keys",
            )
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolError(ErrorCode.INVALID_VALUE, f"{path} has a non-string key")
            _validate_string(key, limits, f"{path} key")
            _validate_value(item, limits, depth + 1, f"{path}.{key}")
        return

    if isinstance(value, (list, tuple)):
        if len(value) > limits.max_container_items:
            raise ProtocolError(
                ErrorCode.PAYLOAD_TOO_LARGE,
                f"{path} has more than {limits.max_container_items} items",
            )
        for index, item in enumerate(value):
            _validate_value(item, limits, depth + 1, f"{path}[{index}]")
        return

    raise ProtocolError(
        ErrorCode.INVALID_VALUE, f"{path} has unsupported type {type(value).__name__}"
    )


def _validate_string(value: str, limits: IpcLimits, path: str) -> None:
    if len(value) > limits.max_string_length:
        raise ProtocolError(
            ErrorCode.STRING_TOO_LONG,
            f"{path} exceeds {limits.max_string_length} characters",
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        # Lone surrogates survive json.loads but cannot be encoded or hashed.
        raise ProtocolError(
            ErrorCode.INVALID_UNICODE, f"{path} contains an unpaired surrogate"
        ) from exc


# ---------------------------------------------------------------------------
# Client-authority stripping
# ---------------------------------------------------------------------------


def strip_authoritative_fields(
    payload: Mapping[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    """Remove daemon-owned fields from client input.

    Returns ``(cleaned_payload, rejected_field_names)``. The rejected names are
    recorded as a security signal; the values are never used.
    """
    cleaned: dict[str, Any] = {}
    rejected: list[str] = []

    for key, value in payload.items():
        if key in AUTHORITATIVE_FIELDS:
            rejected.append(key)
            continue
        if isinstance(value, Mapping):
            nested, nested_rejected = strip_authoritative_fields(value)
            cleaned[key] = nested
            rejected.extend(f"{key}.{name}" for name in nested_rejected)
            continue
        cleaned[key] = value

    return cleaned, rejected


# ---------------------------------------------------------------------------
# Envelope builders
# ---------------------------------------------------------------------------


def build_request(
    message_type: "MessageType | str",
    payload: "Mapping[str, Any] | None" = None,
    session_id: "str | None" = None,
    request_id: "str | None" = None,
) -> dict[str, Any]:
    """Build a client request envelope."""
    message: dict[str, Any] = {
        "version": WATCHER_IPC_VERSION,
        "type": getattr(message_type, "value", str(message_type)),
        "request_id": request_id or new_request_id(),
        "payload": dict(payload or {}),
    }
    if session_id:
        message["session_id"] = session_id
    return message


def build_response(request_id: "str | None", payload: "Mapping[str, Any] | None" = None) -> dict[str, Any]:
    """Build a success response envelope."""
    return {
        "version": WATCHER_IPC_VERSION,
        "type": MessageType.RESPONSE.value,
        "request_id": request_id,
        "ok": True,
        "payload": dict(payload or {}),
    }


def build_error(
    request_id: "str | None",
    code: "ErrorCode | str",
    message: str = "",
) -> dict[str, Any]:
    """Build an error response envelope with a safe, non-leaking message."""
    return {
        "version": WATCHER_IPC_VERSION,
        "type": MessageType.ERROR.value,
        "request_id": request_id,
        "ok": False,
        "error_code": getattr(code, "value", str(code)),
        "message": sanitize_text(message),
    }
