"""Local IPC for The Watcher.

Trusted side (external supervisor):

    from the_watcher.ipc import IpcServer, IpcListener, create_endpoint

Untrusted side (protected process):

    from the_watcher.ipc import WatcherClient

    client = WatcherClient.from_environment()
    decision = client.evaluate("network_request", "connect", "example.com")
    if decision.blocked:
        raise RuntimeError(decision.reason)

Transport is a Windows named pipe or a POSIX Unix domain socket, in both cases
reachable only from this machine and only by this user. Messages are JSON over
a length-prefixed frame; nothing is ever unpickled.
"""

from __future__ import annotations

from .client import (
    ClientEvaluation,
    FailMode,
    WatcherClient,
)
from .protocol import (
    AUTHORITATIVE_FIELDS,
    CLIENT_MESSAGE_TYPES,
    ENVELOPE_KEYS,
    ErrorCode,
    IpcLimits,
    MessageType,
    WATCHER_IPC_VERSION,
    build_error,
    build_request,
    build_response,
    decode_message,
    encode_message,
    sanitize_text,
    strip_authoritative_fields,
)
from .server import ClientContext, IpcServer
from .transport import (
    IpcConnection,
    IpcListener,
    LocalEndpoint,
    connect,
    create_endpoint,
    default_family,
    endpoint_from_values,
)

__all__ = [
    # client
    "WatcherClient",
    "ClientEvaluation",
    "FailMode",
    # server
    "IpcServer",
    "ClientContext",
    # transport
    "IpcListener",
    "IpcConnection",
    "LocalEndpoint",
    "create_endpoint",
    "connect",
    "default_family",
    "endpoint_from_values",
    # protocol
    "WATCHER_IPC_VERSION",
    "MessageType",
    "ErrorCode",
    "IpcLimits",
    "AUTHORITATIVE_FIELDS",
    "ENVELOPE_KEYS",
    "CLIENT_MESSAGE_TYPES",
    "encode_message",
    "decode_message",
    "build_request",
    "build_response",
    "build_error",
    "strip_authoritative_fields",
    "sanitize_text",
]
