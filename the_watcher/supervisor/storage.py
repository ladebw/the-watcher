"""Authoritative trace storage, outside the protected process's reach.

Layout::

    <root>/sessions/<session-id>/
        trace.json        the hash-chained Proof of Execution
        metadata.json     lifecycle, hashes, verification summary

The root is an application-data location, never the protected process's
working directory, so an agent that can write to its cwd cannot rewrite its
own audit trail. Writes are atomic (temp file + ``os.replace``) so a crash
mid-write cannot leave a truncated trace.

Permissions
-----------
POSIX: the session directory is created ``0700`` and files ``0600``.
Windows: best-effort. Standard Windows ACL inheritance means another process
running as the *same user* can still read the files — a limitation of running
without a separate service account, and documented rather than papered over.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..exceptions import StorageError
from ..ipc.protocol import is_valid_session_id
from ..poe.trace import ExecutionTrace

__all__ = ["SessionPaths", "SessionStorage", "default_root"]

_DIR_MODE = 0o700
_FILE_MODE = 0o600


def default_root() -> str:
    """Return the default authoritative storage root for this platform."""
    override = os.environ.get("WATCHER_HOME")
    if override:
        return os.path.abspath(os.path.expanduser(override))

    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "TheWatcher")

    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        return os.path.join(state_home, "the-watcher")
    return os.path.join(os.path.expanduser("~"), ".local", "state", "the-watcher")


@dataclass(frozen=True)
class SessionPaths:
    """Where one session's authoritative artefacts live."""

    root: str
    session_dir: str
    trace_path: str
    metadata_path: str
    session_id: str

    def to_dict(self) -> dict[str, str]:
        return {
            "root": self.root,
            "session_dir": self.session_dir,
            "trace": self.trace_path,
            "metadata": self.metadata_path,
            "session_id": self.session_id,
        }


def _atomic_write(path: str, text: str, mode: int = _FILE_MODE) -> None:
    """Write ``text`` to ``path`` atomically, restricting permissions."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)

    temp_path = f"{path}.tmp-{os.getpid()}-{secrets.token_hex(4)}"
    try:
        # Create with restrictive permissions from the start: on POSIX the
        # mode argument is subject to umask, so chmod afterwards too.
        descriptor = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_path, mode)
        except OSError:
            pass
        os.replace(temp_path, path)
    except OSError as exc:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise StorageError(f"cannot write {path}: {type(exc).__name__}: {exc}") from exc


class SessionStorage:
    """Creates and reads authoritative session artefacts."""

    def __init__(self, root: "str | None" = None) -> None:
        resolved = os.path.abspath(os.path.expanduser(root or default_root()))
        self._root = resolved

    @property
    def root(self) -> str:
        return self._root

    @property
    def sessions_root(self) -> str:
        return os.path.join(self._root, "sessions")

    # -- paths -----------------------------------------------------------

    def session_paths(self, session_id: str) -> SessionPaths:
        # The identifier becomes a path component, so it is validated with the
        # same pattern the protocol uses: no dots, no separators, no traversal.
        if not is_valid_session_id(session_id):
            raise StorageError(
                "invalid session id: expected 4-64 characters of [A-Za-z0-9_-]"
            )
        session_dir = os.path.join(self.sessions_root, session_id)
        return SessionPaths(
            root=self._root,
            session_dir=session_dir,
            trace_path=os.path.join(session_dir, "trace.json"),
            metadata_path=os.path.join(session_dir, "metadata.json"),
            session_id=session_id,
        )

    def create_session(self, session_id: str) -> SessionPaths:
        """Create the session directory with restrictive permissions."""
        paths = self.session_paths(session_id)
        try:
            os.makedirs(paths.session_dir, mode=_DIR_MODE, exist_ok=True)
            try:
                os.chmod(paths.session_dir, _DIR_MODE)
            except OSError:
                pass
            # Create the root marker once so the layout is discoverable.
            try:
                os.makedirs(self.sessions_root, mode=_DIR_MODE, exist_ok=True)
                os.chmod(self._root, _DIR_MODE)
            except OSError:
                pass
        except OSError as exc:
            raise StorageError(
                f"cannot create session storage: {type(exc).__name__}: {exc}"
            ) from exc
        return paths

    # -- writing ---------------------------------------------------------

    def write_trace(self, session_id: str, trace: ExecutionTrace) -> str:
        paths = self.session_paths(session_id)
        _atomic_write(paths.trace_path, trace.to_json())
        return paths.trace_path

    def write_metadata(self, session_id: str, metadata: Mapping[str, Any]) -> str:
        paths = self.session_paths(session_id)
        try:
            # Strict on purpose: silently stringifying an unserialisable value
            # would write a misleading audit record.
            text = json.dumps(dict(metadata), indent=2, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise StorageError(f"metadata is not serialisable: {exc}") from exc
        _atomic_write(paths.metadata_path, text)
        return paths.metadata_path

    # -- reading ---------------------------------------------------------

    def read_metadata(self, session_id: str) -> dict[str, Any]:
        paths = self.session_paths(session_id)
        try:
            with open(paths.metadata_path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except FileNotFoundError as exc:
            raise StorageError(f"no metadata for session {session_id}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise StorageError(f"cannot read metadata: {type(exc).__name__}") from exc

    def read_trace(self, session_id: str) -> ExecutionTrace:
        paths = self.session_paths(session_id)
        try:
            return ExecutionTrace.load(paths.trace_path)
        except FileNotFoundError as exc:
            raise StorageError(f"no trace for session {session_id}") from exc

    def list_sessions(self) -> list[str]:
        try:
            entries = os.listdir(self.sessions_root)
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise StorageError(f"cannot list sessions: {exc}") from exc
        return sorted(
            entry
            for entry in entries
            if os.path.isdir(os.path.join(self.sessions_root, entry))
        )

    def delete_session(self, session_id: str) -> None:
        """Remove a session directory. Intended for tests and explicit cleanup."""
        paths = self.session_paths(session_id)
        shutil.rmtree(paths.session_dir, ignore_errors=True)

    # -- guarantees ------------------------------------------------------

    @staticmethod
    def is_outside(path: str, directory: str) -> bool:
        """Return ``True`` when ``path`` is not inside ``directory``."""
        target = Path(os.path.abspath(path))
        base = Path(os.path.abspath(directory))
        try:
            target.relative_to(base)
        except ValueError:
            return True
        return False

    def assert_outside(self, directory: str) -> None:
        """Raise unless the storage root is outside ``directory``."""
        if not self.is_outside(self._root, directory):
            raise StorageError(
                "authoritative storage must live outside the protected "
                "process's working directory"
            )

    def __repr__(self) -> str:
        return f"<SessionStorage root={self._root}>"
