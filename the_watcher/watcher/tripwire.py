"""Tripwires — things an agent has no legitimate reason to touch.

A tripwire is stricter than a policy rule. A policy rule decides *whether* an
action may proceed; a tripwire asserts that the action itself is evidence of
compromise and should end the session. Because of that, tripwire definitions
are configuration owned by the operator, never by the watched agent.

Default tripwires cover the canaries from the project brief:

* ``./.watcher/protected``      — the Watcher's protected area
* ``/fake/root_token``          — canary credential
* ``/fake/admin_credentials``   — canary credential
* the Watcher's own source tree — tamper attempt
* protected environment names   — credential exfiltration
* the container runtime socket  — sandbox escape surface
* host namespace paths          — sandbox escape surface
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Sequence

from ..exceptions import WatcherError
from ..poe.event import as_text, coerce_event_type
from .decision import Decision, Risk
from .matching import (
    domain_matches_any,
    extract_domain,
    normalise_path,
    normalise_tool,
    path_is_within,
)

__all__ = ["Tripwire", "TripwireRegistry"]

_ENV_EVENT_TYPES = ("env_access", "environment_access")
_FILE_EVENT_TYPES = ("file_access", "file_modification")


def _default_package_root() -> str:
    """Absolute path of the installed ``the_watcher`` package directory."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@dataclass(frozen=True)
class Tripwire:
    """A single canary or boundary marker."""

    id: str
    description: str
    paths: Sequence[str] = field(default_factory=tuple)
    domains: Sequence[str] = field(default_factory=tuple)
    tools: Sequence[str] = field(default_factory=tuple)
    env_vars: Sequence[str] = field(default_factory=tuple)
    patterns: Sequence[str] = field(default_factory=tuple)
    event_types: Sequence[str] = field(default_factory=tuple)
    decision: Decision = Decision.KILL
    risk: Risk = Risk.CRITICAL

    def __post_init__(self) -> None:
        if not self.id:
            raise WatcherError("tripwire requires an id")
        object.__setattr__(self, "paths", tuple(self.paths or ()))
        object.__setattr__(self, "domains", tuple(self.domains or ()))
        object.__setattr__(self, "tools", tuple(self.tools or ()))
        object.__setattr__(self, "env_vars", tuple(self.env_vars or ()))
        object.__setattr__(self, "patterns", tuple(self.patterns or ()))
        object.__setattr__(
            self,
            "event_types",
            tuple(coerce_event_type(t) for t in (self.event_types or ())),
        )

    def matches(
        self,
        event_type: "str",
        action: str,
        resource: str,
        metadata: Mapping[str, Any],
        base: "str | None" = None,
    ) -> bool:
        """Return ``True`` when this tripwire is touched by the event."""
        kind = coerce_event_type(event_type)
        if self.event_types and kind not in self.event_types:
            return False

        meta = dict(metadata or {})

        if self.env_vars:
            name = meta.get("env_var")
            if not name and kind in _ENV_EVENT_TYPES:
                name = resource
            if name and str(name).upper() in {
                candidate.upper() for candidate in self.env_vars
            }:
                return True

        if self.paths:
            raw_path = meta.get("path") or resource
            candidate = normalise_path(raw_path, base=base)
            if candidate:
                for entry in self.paths:
                    if path_is_within(candidate, normalise_path(entry, base=base)):
                        return True

        if self.domains:
            domain = extract_domain(meta.get("domain") or resource)
            if domain and domain_matches_any(domain, self.domains):
                return True

        if self.tools:
            tool = normalise_tool(meta.get("tool") or resource)
            if tool and tool in {normalise_tool(name) for name in self.tools}:
                return True

        if self.patterns:
            haystack = f"{action} {resource}".lower()
            if any(pattern.lower() in haystack for pattern in self.patterns):
                return True

        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "paths": list(self.paths),
            "domains": list(self.domains),
            "tools": list(self.tools),
            "env_vars": list(self.env_vars),
            "patterns": list(self.patterns),
            "event_types": list(self.event_types),
            "decision": self.decision.value,
            "risk": self.risk.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Tripwire":
        if not isinstance(data, Mapping):
            raise WatcherError(f"tripwire must be a mapping, got {type(data).__name__}")
        payload = dict(data)
        for key in ("decision", "risk"):
            if key in payload and payload[key] is not None:
                enum_type = Decision if key == "decision" else Risk
                try:
                    payload[key] = enum_type(as_text(payload[key]).upper())
                except ValueError as exc:
                    raise WatcherError(f"invalid tripwire {key}: {payload[key]!r}") from exc
        try:
            return cls(**payload)
        except TypeError as exc:
            raise WatcherError(f"invalid tripwire definition: {exc}") from exc


class TripwireRegistry:
    """An ordered collection of tripwires, consulted before any policy."""

    def __init__(
        self,
        tripwires: Sequence[Tripwire] = (),
        base: "str | None" = None,
    ) -> None:
        if base is None:
            base = os.getcwd()
        self._base = os.path.abspath(base)
        self._tripwires: list[Tripwire] = list(tripwires)

    # -- accessors -------------------------------------------------------

    @property
    def base(self) -> str:
        return self._base

    def __len__(self) -> int:
        return len(self._tripwires)

    def __iter__(self) -> Iterator[Tripwire]:
        return iter(self._tripwires)

    # -- composition -----------------------------------------------------

    def add(self, tripwire: Tripwire) -> "TripwireRegistry":
        self._tripwires.append(tripwire)
        return self

    def extend(self, tripwires: Sequence[Tripwire]) -> "TripwireRegistry":
        self._tripwires.extend(tripwires)
        return self

    def get(self, tripwire_id: str) -> "Tripwire | None":
        for tripwire in self._tripwires:
            if tripwire.id == tripwire_id:
                return tripwire
        return None

    # -- checking --------------------------------------------------------

    def check(
        self,
        event_type: "str",
        action: str,
        resource: str = "",
        metadata: "Mapping[str, Any] | None" = None,
    ) -> "Tripwire | None":
        """Return the first tripwire touched by the event, or ``None``."""
        for tripwire in self._tripwires:
            if tripwire.matches(event_type, action, resource, metadata or {}, self._base):
                return tripwire
        return None

    def check_all(
        self,
        event_type: "str",
        action: str,
        resource: str = "",
        metadata: "Mapping[str, Any] | None" = None,
    ) -> list[Tripwire]:
        """Return every tripwire touched by the event."""
        return [
            tripwire
            for tripwire in self._tripwires
            if tripwire.matches(event_type, action, resource, metadata or {}, self._base)
        ]

    # -- defaults --------------------------------------------------------

    @classmethod
    def default(
        cls,
        workspace_root: "str | None" = None,
        package_root: "str | None" = None,
        extra_env_vars: Sequence[str] = (),
    ) -> "TripwireRegistry":
        """Build the standard tripwire set."""
        workspace = os.path.abspath(workspace_root or os.getcwd())
        package = os.path.abspath(package_root or _default_package_root())

        tripwires = [
            Tripwire(
                id="watcher_protected_dir",
                description="The Watcher's protected directory",
                paths=(
                    os.path.join(workspace, ".watcher", "protected"),
                    "/.watcher/protected",
                    "./.watcher/protected",
                ),
                patterns=(".watcher/protected", ".watcher\\protected"),
                event_types=(
                    "file_access",
                    "file_modification",
                    "process_creation",
                    "shell_command",
                ),
            ),
            Tripwire(
                id="fake_root_token",
                description="Canary root token",
                paths=("/fake/root_token", "./fake/root_token"),
                patterns=("/fake/root_token",),
                event_types=(
                    "file_access",
                    "file_modification",
                    "process_creation",
                    "shell_command",
                ),
            ),
            Tripwire(
                id="fake_admin_credentials",
                description="Canary administrator credentials",
                paths=("/fake/admin_credentials", "./fake/admin_credentials"),
                patterns=("/fake/admin_credentials",),
                event_types=(
                    "file_access",
                    "file_modification",
                    "process_creation",
                    "shell_command",
                ),
            ),
            Tripwire(
                id="watcher_configuration",
                description="The Watcher's policy and configuration",
                paths=(
                    os.path.join(workspace, ".watcher", "policy.json"),
                    os.path.join(workspace, ".watcher", "tripwires.json"),
                    "./.watcher/policy.json",
                    "/.watcher/policy.json",
                ),
                patterns=(".watcher/policy", ".watcher\\policy", "tripwires.json"),
                event_types=(
                    "file_access",
                    "file_modification",
                    "process_creation",
                ),
            ),
            Tripwire(
                id="watcher_source",
                description="The Watcher's own source tree (tamper attempt)",
                paths=(package,),
                event_types=("file_modification",),
            ),
            Tripwire(
                id="protected_environment",
                description="Watcher-protected environment variable",
                env_vars=(
                    "WATCHER_POLICY_KEY",
                    "WATCHER_KILL_TOKEN",
                    "WATCHER_POE_KEY",
                    *tuple(extra_env_vars),
                ),
            ),
            Tripwire(
                id="container_runtime_socket",
                description="Container runtime control socket",
                paths=("/var/run/docker.sock", "./var/run/docker.sock"),
                patterns=("docker.sock", "containerd.sock", "crio.sock"),
                event_types=(
                    "file_access",
                    "file_modification",
                    "network_request",
                    "shell_command",
                    "process_creation",
                ),
            ),
            Tripwire(
                id="host_namespace",
                description="Host namespace escape surface",
                paths=("/proc/1/root", "/proc/1/ns", "/proc/1/cwd"),
                patterns=("nsenter", "unshare", "/proc/1/root"),
                event_types=(
                    "file_access",
                    "file_modification",
                    "shell_command",
                    "process_creation",
                ),
            ),
        ]
        return cls(tripwires, base=workspace)
