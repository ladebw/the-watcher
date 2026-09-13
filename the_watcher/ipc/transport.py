"""Local-only IPC transport.

Chosen implementation: :mod:`multiprocessing.connection`, used *only* for its
framing and its two local address families:

* **Windows** — ``AF_PIPE``, i.e. a real named pipe (``\\\\.\\pipe\\...``).
* **POSIX** — ``AF_UNIX``, i.e. a Unix domain socket inside a private
  ``0700`` directory.

Why this and not a hand-rolled socket layer:

* it is standard library, so no dependency is added;
* it gives one identical code path on both platforms;
* ``send_bytes``/``recv_bytes`` frame raw bytes with a length prefix and do
  **no pickling**, which is the property that matters here — the protected
  process is untrusted and arbitrary deserialisation is exactly what we must
  not do;
* ``recv_bytes(maxlength)`` refuses oversized frames *before* allocating, and
  raises ``OSError('bad message length')``, which we convert into a protocol
  error and a closed connection.

There is deliberately no TCP listener. A loopback fallback would widen the
attack surface for no benefit, so it is not implemented at all.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import threading
from dataclasses import dataclass
from multiprocessing.connection import Client as _MpClient
from multiprocessing.connection import Listener as _MpListener
from typing import Any, Mapping

from ..exceptions import IpcTransportError, ProtocolError
from .protocol import (
    CLIENT_MESSAGE_TYPES,
    SERVER_MESSAGE_TYPES,
    IpcLimits,
    decode_message,
    encode_message,
    is_valid_session_id,
)

__all__ = [
    "default_family",
    "LocalEndpoint",
    "IpcListener",
    "IpcConnection",
    "connect",
    "LOCAL_FAMILIES",
    "PIPE_PREFIX",
]

PIPE_PREFIX = r"\\.\pipe"
PATH_MAX_HINT = 100  # POSIX sun_path is typically 108 bytes including the NUL


def default_family() -> str:
    """The local IPC family for this platform."""
    return "AF_PIPE" if os.name == "nt" else "AF_UNIX"


LOCAL_FAMILIES = frozenset({"AF_PIPE", "AF_UNIX"})


@dataclass(frozen=True)
class LocalEndpoint:
    """A resolved local IPC endpoint plus whatever cleanup it needs."""

    family: str
    address: str
    session_id: str
    private_dir: "str | None" = None

    @property
    def display(self) -> str:
        """A short, safe description for logs (never includes a token)."""
        if self.family == "AF_PIPE":
            return f"pipe:{self.address.rsplit(chr(92), 1)[-1]}"
        return f"unix:{self.address}"

    def cleanup(self) -> None:
        """Remove the socket file / private directory. Never raises."""
        if self.private_dir:
            shutil.rmtree(self.private_dir, ignore_errors=True)
        elif self.family == "AF_UNIX":
            try:
                os.unlink(self.address)
            except OSError:
                pass


def _validate_session_id(session_id: str) -> str:
    if not is_valid_session_id(session_id):
        raise IpcTransportError("session id must be 4-64 characters of [A-Za-z0-9_-]")
    return session_id


def create_endpoint(
    session_id: str,
    family: "str | None" = None,
    runtime_dir: "str | None" = None,
) -> LocalEndpoint:
    """Create (but do not yet bind) an endpoint for ``session_id``."""
    import secrets

    session_id = _validate_session_id(session_id)
    family = family or default_family()
    if family not in LOCAL_FAMILIES:
        raise IpcTransportError(f"unsupported IPC family: {family!r}")

    if family == "AF_PIPE":
        # A random suffix avoids collisions between concurrent daemons while
        # remaining short enough for the Windows pipe namespace.
        name = f"the-watcher-{session_id[:24]}-{secrets.token_hex(4)}"
        return LocalEndpoint(family=family, address=f"{PIPE_PREFIX}\\{name}", session_id=session_id)

    if runtime_dir is not None:
        os.makedirs(runtime_dir, mode=0o700, exist_ok=True)
        private_dir = runtime_dir
        owned = False
    else:
        # mkdtemp creates the directory with mode 0700, so only this user can
        # traverse it and therefore only this user can reach the socket.
        private_dir = tempfile.mkdtemp(prefix="the-watcher-")
        owned = True

    address = os.path.join(private_dir, "watcher.sock")
    if len(address) >= PATH_MAX_HINT:
        if owned:
            shutil.rmtree(private_dir, ignore_errors=True)
        raise IpcTransportError(
            "the IPC socket path is too long for this platform; "
            "set a shorter runtime directory"
        )

    return LocalEndpoint(
        family=family,
        address=address,
        session_id=session_id,
        private_dir=private_dir,
    )


class IpcConnection:
    """One framed, JSON-only, pickle-free connection."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection
        self._send_lock = threading.Lock()
        self._recv_lock = threading.Lock()
        self._closed = False

    # -- lifecycle -------------------------------------------------------

    @property
    def closed(self) -> bool:
        return self._closed

    def fileno(self) -> int:
        try:
            return int(self._connection.fileno())
        except Exception:  # noqa: BLE001 - some backends do not expose one
            return -1

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._connection.close()
        except Exception:  # noqa: BLE001
            pass

    # -- framing ---------------------------------------------------------

    def send(self, message: Mapping[str, Any], limits: IpcLimits) -> None:
        """Encode and send one message."""
        if self._closed:
            raise IpcTransportError("connection is closed")
        raw = encode_message(message)
        if len(raw) > limits.max_message_bytes:
            raise ProtocolError(
                "MESSAGE_TOO_LARGE",
                f"refusing to send {len(raw)} bytes",
            )
        with self._send_lock:
            try:
                self._connection.send_bytes(raw)
            except (BrokenPipeError, EOFError, OSError) as exc:
                self._closed = True
                raise IpcTransportError(f"send failed: {type(exc).__name__}") from exc

    def receive(
        self,
        limits: IpcLimits,
        allowed_types: "Any | None" = None,
        require_request_id: bool = False,
    ) -> dict[str, Any]:
        """Receive and validate exactly one message."""
        if self._closed:
            raise IpcTransportError("connection is closed")

        with self._recv_lock:
            try:
                raw = self._connection.recv_bytes(limits.max_message_bytes)
            except ProtocolError:
                raise
            except (EOFError, BrokenPipeError) as exc:
                self._closed = True
                raise IpcTransportError(
                    f"peer disconnected ({type(exc).__name__})"
                ) from exc
            except OSError as exc:
                text = str(exc)
                if "message length" in text:
                    # The framing layer reads the length prefix and refuses the
                    # frame *without draining its body*, so the stream is no
                    # longer in sync. Deliberately do NOT mark the connection
                    # closed here: the caller still gets one chance to write a
                    # final error to the peer before closing it.
                    raise ProtocolError(
                        "MESSAGE_TOO_LARGE",
                        f"frame exceeds {limits.max_message_bytes} bytes",
                        fatal=True,
                    ) from exc
                self._closed = True
                raise IpcTransportError(f"receive failed: {type(exc).__name__}") from exc

        return decode_message(
            raw, limits, allowed_types=allowed_types, require_request_id=require_request_id
        )

    def poll(self, timeout: "float | None" = 0.0) -> bool:
        """Return ``True`` when a message is ready. Never raises."""
        if self._closed:
            return False
        try:
            return bool(self._connection.poll(timeout))
        except (BrokenPipeError, EOFError, OSError, ValueError):
            # The probe showed poll() raising BrokenPipeError once the peer
            # closes on Windows; treat any of these as "nothing to read".
            return False

    def __repr__(self) -> str:
        return f"<IpcConnection fd={self.fileno()} closed={self._closed}>"


class IpcListener:
    """A bound local endpoint that accepts connections."""

    def __init__(
        self,
        endpoint: LocalEndpoint,
        backlog: int = 8,
        permissions: int = 0o600,
    ) -> None:
        self._endpoint = endpoint
        self._listener: "Any | None" = None
        self._closed = False
        try:
            self._listener = _MpListener(endpoint.address, family=endpoint.family, backlog=backlog)
        except Exception as exc:  # noqa: BLE001 - normalised to one error type
            raise IpcTransportError(
                f"cannot bind {endpoint.display}: {type(exc).__name__}: {exc}"
            ) from exc

        if endpoint.family == "AF_UNIX":
            # Restrict the socket to this user only.
            try:
                os.chmod(endpoint.address, permissions)
            except OSError:
                pass

    @property
    def endpoint(self) -> LocalEndpoint:
        return self._endpoint

    @property
    def address(self) -> str:
        return self._endpoint.address

    def accept(self) -> IpcConnection:
        """Block until a client connects."""
        if self._closed or self._listener is None:
            raise IpcTransportError("listener is closed")
        try:
            connection = self._listener.accept()
        except (OSError, EOFError) as exc:
            if self._closed:
                raise IpcTransportError("listener is closed") from exc
            raise IpcTransportError(f"accept failed: {type(exc).__name__}") from exc
        return IpcConnection(connection)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._listener is not None:
                self._listener.close()
        except Exception:  # noqa: BLE001
            pass
        self._endpoint.cleanup()

    def __repr__(self) -> str:
        return f"<IpcListener {self._endpoint.display} closed={self._closed}>"


def connect(
    endpoint: LocalEndpoint,
    timeout: float = 5.0,
) -> IpcConnection:
    """Connect to a local endpoint with a bounded timeout.

    ``multiprocessing.connection``'s Windows pipe client retries forever when
    the pipe does not exist, so the connect is performed on a short-lived
    daemon thread and abandoned once ``timeout`` elapses. That keeps a dead or
    unreachable daemon from hanging the protected process.
    """
    result: dict[str, Any] = {}

    def _target() -> None:
        try:
            result["connection"] = _MpClient(endpoint.address, family=endpoint.family)
        except BaseException as exc:  # noqa: BLE001 - reported to the caller
            result["error"] = exc

    thread = threading.Thread(
        target=_target, name="watcher-ipc-connect", daemon=True
    )
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        raise IpcTransportError(
            f"connection to {endpoint.display} timed out after {timeout:g}s"
        )

    error = result.get("error")
    if error is not None:
        raise IpcTransportError(
            f"cannot connect to {endpoint.display}: {type(error).__name__}"
        )

    connection = result.get("connection")
    if connection is None:
        raise IpcTransportError(f"cannot connect to {endpoint.display}")

    return IpcConnection(connection)


def endpoint_from_values(address: str, family: "str | None" = None, session_id: str = "") -> LocalEndpoint:
    """Rebuild an endpoint descriptor from environment values (client side)."""
    resolved_family = family or ("AF_PIPE" if address.startswith(PIPE_PREFIX) else default_family())
    if resolved_family not in LOCAL_FAMILIES:
        raise IpcTransportError(f"unsupported IPC family: {resolved_family!r}")
    return LocalEndpoint(family=resolved_family, address=str(address), session_id=session_id)


#: Message types a client may receive from the server.
CLIENT_RECEIVE_TYPES = SERVER_MESSAGE_TYPES
#: Message types a server may receive from a client.
SERVER_RECEIVE_TYPES = CLIENT_MESSAGE_TYPES
