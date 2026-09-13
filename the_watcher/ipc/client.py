"""Thin, untrusted-side IPC client.

This is the *only* Watcher code the protected process runs, and it is designed
to be disposable: it holds a connection and nothing else. It has no policy, no
kill switch, no tripwire definitions, no authoritative recorder, no trace and
no process-termination logic. Every decision it returns came from the external
daemon.

It does import :class:`Decision` and :class:`Risk`, but only as a *vocabulary*
for interpreting the daemon's answer — it never evaluates anything itself.

Failure behaviour
-----------------
``FAIL_CLOSED`` (the default) means that if the daemon cannot be reached the
client returns ``DENY`` and the caller must not perform the action.
``FAIL_OPEN`` exists only as an explicit opt-in for low-risk development.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from ..exceptions import IpcTransportError, ProtocolError
from ..watcher.decision import Decision, Risk
from .protocol import (
    WATCHER_IPC_VERSION,
    IpcLimits,
    MessageType,
    build_request,
    sanitize_text,
)
from .transport import (
    CLIENT_RECEIVE_TYPES,
    IpcConnection,
    connect,
    default_family,
    endpoint_from_values,
)

__all__ = [
    "FailMode",
    "ClientEvaluation",
    "WatcherClient",
    "ENV_SESSION_ID",
    "ENV_ENDPOINT",
    "ENV_TOKEN",
    "ENV_PROTOCOL_VERSION",
    "ENV_FAMILY",
    "ENV_TIMEOUT",
    "ENV_FAIL_MODE",
    "ENV_HEARTBEAT_INTERVAL",
]

ENV_SESSION_ID = "WATCHER_SESSION_ID"
ENV_ENDPOINT = "WATCHER_IPC_ENDPOINT"
ENV_TOKEN = "WATCHER_SESSION_TOKEN"
ENV_PROTOCOL_VERSION = "WATCHER_PROTOCOL_VERSION"
ENV_FAMILY = "WATCHER_IPC_FAMILY"
ENV_TIMEOUT = "WATCHER_IPC_TIMEOUT"
ENV_FAIL_MODE = "WATCHER_FAIL_MODE"
ENV_HEARTBEAT_INTERVAL = "WATCHER_HEARTBEAT_INTERVAL"


class FailMode(str, Enum):
    """What to do when the Watcher cannot be reached."""

    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"


@dataclass(frozen=True)
class ClientEvaluation:
    """The daemon's answer, as seen by the protected process."""

    decision: Decision
    risk: Risk
    reason: str
    rule: str = "ipc"
    ipc_ok: bool = True

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def blocked(self) -> bool:
        return self.decision is not Decision.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "risk": self.risk.value,
            "reason": self.reason,
            "rule": self.rule,
            "ipc_ok": self.ipc_ok,
        }

    def __str__(self) -> str:
        suffix = "" if self.ipc_ok else " [ipc-degraded]"
        return (
            f"{self.decision.value}/{self.risk.value} ({self.rule}): {self.reason}{suffix}"
        )


def _env_float(
    env: Mapping[str, str], name: str, default: float, minimum: float = 0.0
) -> float:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return max(minimum, value)


class WatcherClient:
    """Client handle for one protected session."""

    def __init__(
        self,
        session_id: str,
        endpoint_address: str,
        token: str,
        family: "str | None" = None,
        timeout: float = 5.0,
        fail_mode: "FailMode | str" = FailMode.FAIL_CLOSED,
        heartbeat_interval: float = 0.0,
        limits: "IpcLimits | None" = None,
        connect_now: bool = True,
        strict: bool = False,
        clock: "Any | None" = None,
    ) -> None:
        if not session_id or not endpoint_address or not token:
            raise IpcTransportError(
                "session id, endpoint and token are all required"
            )

        self._session_id = session_id
        self._token = token
        self._endpoint = endpoint_from_values(endpoint_address, family, session_id)
        self._timeout = max(0.05, float(timeout))
        self._fail_mode = (
            fail_mode if isinstance(fail_mode, FailMode) else FailMode(str(fail_mode).lower())
        )
        self._heartbeat_interval = max(0.0, float(heartbeat_interval))
        self._limits = limits or IpcLimits(request_timeout=self._timeout)
        self._clock = clock or time.time

        self._lock = threading.RLock()
        self._connection: "IpcConnection | None" = None
        self._closed = False
        self._last_error = ""
        self._failures = 0
        self._requests = 0
        self._handshake: dict[str, Any] = {}

        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: "threading.Thread | None" = None

        if connect_now:
            try:
                self._ensure_connection()
            except IpcTransportError as exc:
                self._last_error = sanitize_text(str(exc))
                if strict:
                    raise
            else:
                self._start_heartbeat()

    # -- construction ----------------------------------------------------

    @classmethod
    def from_environment(
        cls,
        env: "Mapping[str, str] | None" = None,
        **overrides: Any,
    ) -> "WatcherClient":
        """Build a client from the ``WATCHER_*`` variables set by the daemon."""
        source = dict(os.environ if env is None else env)

        session_id = source.get(ENV_SESSION_ID, "")
        endpoint = source.get(ENV_ENDPOINT, "")
        token = source.get(ENV_TOKEN, "")
        if not session_id or not endpoint or not token:
            raise IpcTransportError(
                "missing Watcher IPC configuration: expected "
                f"{ENV_SESSION_ID}, {ENV_ENDPOINT} and {ENV_TOKEN}"
            )

        version_raw = source.get(ENV_PROTOCOL_VERSION, "")
        if version_raw:
            try:
                version = int(version_raw)
            except ValueError as exc:
                raise IpcTransportError("invalid WATCHER_PROTOCOL_VERSION") from exc
            if version != WATCHER_IPC_VERSION:
                raise IpcTransportError(
                    f"unsupported Watcher protocol version {version}"
                )

        defaults: dict[str, Any] = {
            "session_id": session_id,
            "endpoint_address": endpoint,
            "token": token,
            "family": source.get(ENV_FAMILY) or default_family(),
            "timeout": _env_float(source, ENV_TIMEOUT, 5.0, minimum=0.05),
            "fail_mode": source.get(ENV_FAIL_MODE) or FailMode.FAIL_CLOSED.value,
            "heartbeat_interval": _env_float(source, ENV_HEARTBEAT_INTERVAL, 0.0),
        }
        defaults.update(overrides)
        return cls(**defaults)

    # -- state -----------------------------------------------------------

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def connected(self) -> bool:
        with self._lock:
            return self._connection is not None and not self._connection.closed

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def fail_mode(self) -> FailMode:
        return self._fail_mode

    @property
    def last_error(self) -> str:
        return self._last_error

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "requests": self._requests,
            "failures": self._failures,
            "connected": self.connected,
            "fail_mode": self._fail_mode.value,
        }

    def handshake_info(self) -> dict[str, Any]:
        """What the daemon said at handshake time (heartbeat config, state)."""
        return dict(self._handshake)

    # -- connection management -------------------------------------------

    def _ensure_connection(self) -> IpcConnection:
        with self._lock:
            if self._closed:
                raise IpcTransportError("client is closed")
            if self._connection is not None and not self._connection.closed:
                return self._connection

            connection = connect(self._endpoint, timeout=self._timeout)
            try:
                connection.send(
                    build_request(
                        MessageType.HELLO,
                        {
                            "token": self._token,
                            "pid": os.getpid(),
                            "protocol_version": WATCHER_IPC_VERSION,
                            "client": {
                                "python": sys.version.split()[0],
                                "platform": sys.platform,
                            },
                        },
                        session_id=self._session_id,
                    ),
                    self._limits,
                )
                if not connection.poll(self._timeout):
                    raise IpcTransportError("handshake timed out")
                response = connection.receive(
                    self._limits, allowed_types=CLIENT_RECEIVE_TYPES
                )
            except (IpcTransportError, ProtocolError):
                connection.close()
                raise

            if not response.get("ok"):
                code = response.get("error_code", "UNKNOWN")
                connection.close()
                raise IpcTransportError(f"handshake rejected: {code}")

            self._connection = connection
            self._handshake = dict(response.get("payload") or {})
            return connection

    def _drop_connection(self) -> None:
        with self._lock:
            connection, self._connection = self._connection, None
        if connection is not None:
            connection.close()

    def _request(self, message_type: "MessageType | str", payload: Mapping[str, Any]) -> dict:
        """Send one request and return the response. Raises on IPC failure."""
        with self._lock:
            connection = self._ensure_connection()
            message = build_request(message_type, payload, session_id=self._session_id)
            try:
                connection.send(message, self._limits)
                if not connection.poll(self._timeout):
                    raise IpcTransportError(
                        f"request timed out after {self._timeout:g}s"
                    )
                response = connection.receive(
                    self._limits, allowed_types=CLIENT_RECEIVE_TYPES
                )
            except (IpcTransportError, ProtocolError) as exc:
                self._last_error = sanitize_text(str(exc))
                self._failures += 1
                self._drop_connection()
                raise

            expected = message["request_id"]
            returned = response.get("request_id")
            if returned not in (None, expected):
                self._failures += 1
                self._drop_connection()
                raise IpcTransportError("response did not match the request")

            self._requests += 1
            return response

    def _degraded(self, reason: str) -> ClientEvaluation:
        """Build the decision used when the daemon cannot be consulted."""
        if self._fail_mode is FailMode.FAIL_OPEN:
            return ClientEvaluation(
                Decision.ALLOW,
                Risk.ELEVATED,
                f"{reason}; failing OPEN by configuration",
                "ipc_unavailable",
                ipc_ok=False,
            )
        return ClientEvaluation(
            Decision.DENY,
            Risk.HIGH,
            f"{reason}; failing CLOSED",
            "ipc_unavailable",
            ipc_ok=False,
        )

    # -- API -------------------------------------------------------------

    def evaluate(
        self,
        event_type: str,
        action: str,
        resource: str = "",
        metadata: "Mapping[str, Any] | None" = None,
    ) -> ClientEvaluation:
        """Ask the daemon whether an action may proceed.

        Never raises for IPC problems: it returns a fail-closed (or fail-open)
        decision instead, so a protected agent cannot accidentally treat an
        unreachable Watcher as permission.
        """
        payload: dict[str, Any] = {
            "event_type": str(event_type),
            "action": str(action),
            "resource": "" if resource is None else str(resource),
        }
        if metadata:
            payload["metadata"] = dict(metadata)

        try:
            response = self._request(MessageType.EVALUATE, payload)
        except (IpcTransportError, ProtocolError) as exc:
            return self._degraded(f"watcher unreachable ({sanitize_text(str(exc), 80)})")

        if not response.get("ok"):
            code = sanitize_text(response.get("error_code", "UNKNOWN"), 40)
            return self._degraded(f"watcher rejected the request ({code})")

        data = response.get("payload") or {}
        try:
            decision = Decision(str(data.get("decision", "")))
            risk = Risk(str(data.get("risk", "")))
        except ValueError:
            return self._degraded("watcher returned a malformed decision")

        return ClientEvaluation(
            decision=decision,
            risk=risk,
            reason=str(data.get("reason", "")),
            rule=str(data.get("rule", "ipc")),
            ipc_ok=True,
        )

    def observe(
        self,
        event_type: str,
        action: str,
        resource: str = "",
        metadata: "Mapping[str, Any] | None" = None,
    ) -> bool:
        """Report an event that already happened. Returns ``False`` on failure."""
        payload: dict[str, Any] = {
            "event_type": str(event_type),
            "action": str(action),
            "resource": "" if resource is None else str(resource),
        }
        if metadata:
            payload["metadata"] = dict(metadata)
        try:
            response = self._request(MessageType.EVENT, payload)
        except (IpcTransportError, ProtocolError):
            return False
        return bool(response.get("ok"))

    def heartbeat(self) -> bool:
        """Send one heartbeat. Returns ``False`` when the daemon is unreachable."""
        try:
            response = self._request(MessageType.HEARTBEAT, {})
        except (IpcTransportError, ProtocolError):
            return False
        return bool(response.get("ok"))

    def status(self) -> dict[str, Any]:
        """Current session state as reported by the daemon."""
        try:
            response = self._request(MessageType.SESSION_STATUS, {})
        except (IpcTransportError, ProtocolError):
            return {}
        return dict(response.get("payload") or {}) if response.get("ok") else {}

    def trace_info(self) -> dict[str, Any]:
        """Sealed-trace summary (hash, event count). Never the full trace."""
        try:
            response = self._request(MessageType.TRACE_INFO, {})
        except (IpcTransportError, ProtocolError):
            return {}
        return dict(response.get("payload") or {}) if response.get("ok") else {}

    def request_kill(self, reason: str = "CLIENT_REQUESTED_TERMINATION") -> bool:
        """Ask the daemon to terminate this session.

        The daemon performs the termination; the client cannot do it, and
        cannot undo a kill that has already happened.
        """
        try:
            response = self._request(
                MessageType.KILL_REQUEST, {"reason": sanitize_text(reason, 200)}
            )
        except (IpcTransportError, ProtocolError):
            return False
        return bool(response.get("ok"))

    def session_end(self) -> bool:
        """Tell the daemon this client is finished."""
        try:
            response = self._request(MessageType.SESSION_END, {})
        except (IpcTransportError, ProtocolError):
            return False
        return bool(response.get("ok"))

    # -- heartbeat thread ------------------------------------------------

    def _start_heartbeat(self) -> None:
        if self._heartbeat_interval <= 0 or self._heartbeat_thread is not None:
            return
        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, name="watcher-heartbeat", daemon=True
        )
        self._heartbeat_thread.start()

    def _heartbeat_loop(self) -> None:
        while not self._heartbeat_stop.wait(self._heartbeat_interval):
            self.heartbeat()

    # -- shutdown --------------------------------------------------------

    def close(self, notify: bool = True) -> None:
        """Stop heartbeats and close the connection."""
        self._heartbeat_stop.set()
        thread = self._heartbeat_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=min(2.0, self._heartbeat_interval + 0.5))
        self._heartbeat_thread = None

        if notify and self.connected:
            try:
                self.session_end()
            except Exception:  # noqa: BLE001 - shutdown must not raise
                pass

        self._closed = True
        self._drop_connection()

    def __enter__(self) -> "WatcherClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False

    def __repr__(self) -> str:
        return (
            f"<WatcherClient session={self._session_id[:8]} "
            f"connected={self.connected} fail_mode={self._fail_mode.value}>"
        )
