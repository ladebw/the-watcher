"""Deterministic safety policies.

Deliberately not intelligent. Every decision here is a function of the event
and the configuration: no model, no heuristics, no learning. The watched agent
must never be consulted about whether its own action is safe, so the policy
engine is pure, synchronous and local.

The rule set covers the boundaries called out in the project brief:
allowed/forbidden filesystem paths, allowed/forbidden network domains, allowed
/forbidden tools, child-process limits, runtime limits, protected environment
variables, privilege escalation, host-resource access, persistence and
sandbox-escape surfaces.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from ..exceptions import PolicyError
from ..poe.event import EventType, as_text, coerce_event_type
from .decision import Decision, Evaluation, Risk
from .matching import (
    any_path_matches,
    domain_matches_any,
    extract_domain,
    normalise_path,
    normalise_tool,
)

__all__ = ["Policy", "DEFAULT_PROTECTED_ENV_VARS"]

#: Environment variables protected by default. Names only — never values.
DEFAULT_PROTECTED_ENV_VARS: tuple[str, ...] = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_OPENAI_API_KEY",
    "DATABASE_URL",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GOOGLE_API_KEY",
    "NPM_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "PYPI_TOKEN",
    "SLACK_TOKEN",
    "SSH_AUTH_SOCK",
    "STRIPE_SECRET_KEY",
)

_FILE_EVENTS = frozenset({EventType.FILE_ACCESS.value, EventType.FILE_MODIFICATION.value})
_NETWORK_EVENTS = frozenset(
    {EventType.NETWORK_REQUEST.value, EventType.API_REQUEST.value}
)
_TOOL_EVENTS = frozenset({EventType.TOOL_REQUEST.value, EventType.MODEL_CALL.value})

# Commands that have no legitimate place inside a sandbox.
_CRITICAL_COMMAND_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(^|\s)rm\s+(-[A-Za-z]+\s+)*/(\s|$)"), "destructive_rm"),
    (re.compile(r"\bmkfs(\.\w+)?\b"), "filesystem_format"),
    (re.compile(r":\(\)\s*\{.*\|.*&.*\}\s*;?\s*:"), "fork_bomb"),
    (re.compile(r"\bdd\b[^\n]*\bof=/dev/[sn]?[vh]d"), "raw_disk_write"),
    (re.compile(r"\b(shutdown|reboot|halt|poweroff)\b"), "host_shutdown"),
    (re.compile(r"\b(iptables|nft)\b[^\n]*\b(flush|-F)\b"), "firewall_flush"),
    (re.compile(r"\bchmod\s+[0-7]*[0-7]7[0-7]*\s+/(\s|$)"), "broad_permissions"),
)

_PRIVILEGE_ESCALATION = re.compile(
    r"(^|[\s|;&(`])(sudo|su|doas|pkexec|runas|gsudo)(\s|$)"
)
_PERSISTENCE = re.compile(
    r"(\bcrontab\b|/etc/cron|/etc/systemd|systemctl\s+enable|\blaunchctl\b|"
    r"rc\.local|/etc/rc\d|\.bashrc|\.bash_profile|\.profile\b|\.zshrc|"
    r"\bschtasks\b|reg\s+add[^\n]*\\Run\b)"
)
_SANDBOX_ESCAPE = re.compile(
    r"(\bnsenter\b|\bunshare\b|/proc/1/(root|ns)|\bdocker\.sock\b|"
    r"/var/run/docker\.sock|\bmount\s+--bind\b|/host/|chroot\s+/)"
)

_DEFAULT_KILL_MAX_PROCESSES_MULTIPLIER = 3


@dataclass
class Policy:
    """A deterministic rule set evaluated against every attempted action."""

    name: str = "default"
    workspace_root: str = "."

    # Filesystem
    allowed_paths: Sequence[str] = field(default_factory=tuple)
    forbidden_paths: Sequence[str] = field(default_factory=tuple)

    # Network
    allowed_domains: Sequence[str] = field(default_factory=tuple)
    forbidden_domains: Sequence[str] = field(default_factory=tuple)
    restrict_network: "bool | None" = None
    unknown_domain: Decision = Decision.DENY

    # Tools
    allowed_tools: Sequence[str] = field(default_factory=tuple)
    forbidden_tools: Sequence[str] = field(default_factory=tuple)
    unknown_tool: Decision = Decision.DENY

    # Processes and time
    max_processes: int = 32
    max_runtime_seconds: int = 3600
    kill_max_processes_multiplier: int = _DEFAULT_KILL_MAX_PROCESSES_MULTIPLIER

    # Host boundaries
    protected_env_vars: Sequence[str] = field(
        default_factory=lambda: DEFAULT_PROTECTED_ENV_VARS
    )
    allow_privilege_escalation: bool = False
    allow_host_resource_access: bool = False
    allow_persistence: bool = False

    def __post_init__(self) -> None:
        self.allowed_paths = tuple(self.allowed_paths or ())
        self.forbidden_paths = tuple(self.forbidden_paths or ())
        self.allowed_domains = tuple(self.allowed_domains or ())
        self.forbidden_domains = tuple(self.forbidden_domains or ())
        self.allowed_tools = tuple(self.allowed_tools or ())
        self.forbidden_tools = tuple(self.forbidden_tools or ())
        self.protected_env_vars = tuple(name.upper() for name in self.protected_env_vars)
        self.unknown_domain = Decision(as_text(self.unknown_domain).upper())
        self.unknown_tool = Decision(as_text(self.unknown_tool).upper())

        if self.max_processes < 0:
            raise PolicyError("max_processes must be >= 0")
        if self.max_runtime_seconds <= 0:
            raise PolicyError("max_runtime_seconds must be > 0")
        if self.kill_max_processes_multiplier < 1:
            raise PolicyError("kill_max_processes_multiplier must be >= 1")

    # -- derived configuration ------------------------------------------

    @property
    def network_is_restricted(self) -> bool:
        """Whether unknown domains are refused."""
        if self.restrict_network is not None:
            return bool(self.restrict_network)
        return bool(self.allowed_domains)

    @property
    def tools_are_restricted(self) -> bool:
        return bool(self.allowed_tools)

    # -- evaluation ------------------------------------------------------

    def evaluate(
        self,
        event_type: "EventType | str",
        action: str,
        resource: str = "",
        metadata: "Mapping[str, Any] | None" = None,
    ) -> Evaluation:
        """Return the deterministic verdict for one attempted action."""
        kind = coerce_event_type(event_type)
        meta = dict(metadata or {})
        action_text = "" if action is None else str(action)
        resource_text = "" if resource is None else str(resource)

        for check in (
            self._check_privilege_escalation,
            self._check_critical_command,
            self._check_sandbox_escape,
            self._check_persistence,
            self._check_host_resources,
            self._check_env_var,
            self._check_paths,
            self._check_network,
            self._check_tools,
            self._check_processes,
            self._check_runtime,
        ):
            result = check(kind, action_text, resource_text, meta)
            if result is not None:
                return result

        return Evaluation(
            decision=Decision.ALLOW,
            risk=Risk.NORMAL,
            reason=f"no policy rule matched for {kind}",
            rule="default",
        )

    # -- individual rules ------------------------------------------------

    def _check_privilege_escalation(
        self, kind: str, action: str, resource: str, meta: Mapping[str, Any]
    ) -> "Evaluation | None":
        if self.allow_privilege_escalation:
            return None
        if meta.get("privilege_escalation"):
            return Evaluation(
                Decision.KILL,
                Risk.CRITICAL,
                "privilege escalation reported by runtime",
                "privilege_escalation",
            )
        if kind in (EventType.SHELL_COMMAND.value, EventType.PROCESS_CREATION.value):
            if _PRIVILEGE_ESCALATION.search(resource) or _PRIVILEGE_ESCALATION.search(action):
                return Evaluation(
                    Decision.KILL,
                    Risk.CRITICAL,
                    "attempt to raise privileges (sudo/su/pkexec)",
                    "privilege_escalation",
                )
        return None

    def _check_critical_command(
        self, kind: str, action: str, resource: str, meta: Mapping[str, Any]
    ) -> "Evaluation | None":
        if kind != EventType.SHELL_COMMAND.value:
            return None
        haystack = f"{action} {resource}"
        for pattern, label in _CRITICAL_COMMAND_PATTERNS:
            if pattern.search(haystack):
                return Evaluation(
                    Decision.KILL,
                    Risk.CRITICAL,
                    f"destructive host-level command detected ({label})",
                    f"critical_command:{label}",
                )
        return None

    def _check_sandbox_escape(
        self, kind: str, action: str, resource: str, meta: Mapping[str, Any]
    ) -> "Evaluation | None":
        if meta.get("host_resource") and not self.allow_host_resource_access:
            return Evaluation(
                Decision.KILL,
                Risk.CRITICAL,
                "host resource access reported by runtime",
                "host_resource_access",
            )
        haystack = f"{action} {resource}"
        if _SANDBOX_ESCAPE.search(haystack):
            return Evaluation(
                Decision.KILL,
                Risk.CRITICAL,
                "sandbox escape surface touched (namespace/socket/mount)",
                "sandbox_escape",
            )
        return None

    def _check_persistence(
        self, kind: str, action: str, resource: str, meta: Mapping[str, Any]
    ) -> "Evaluation | None":
        if self.allow_persistence:
            return None
        if meta.get("persistence"):
            return Evaluation(
                Decision.KILL,
                Risk.CRITICAL,
                "persistence attempt reported by runtime",
                "persistence_attempt",
            )
        if kind in (
            EventType.SHELL_COMMAND.value,
            EventType.FILE_MODIFICATION.value,
            EventType.PROCESS_CREATION.value,
        ) and _PERSISTENCE.search(f"{action} {resource}"):
            return Evaluation(
                Decision.KILL,
                Risk.CRITICAL,
                "persistence mechanism touched (cron/systemd/rc/profile)",
                "persistence_attempt",
            )
        return None

    def _check_host_resources(
        self, kind: str, action: str, resource: str, meta: Mapping[str, Any]
    ) -> "Evaluation | None":
        if self.allow_host_resource_access:
            return None
        if kind in _FILE_EVENTS:
            path = normalise_path(meta.get("path") or resource, base=self.workspace_root)
            if path and (
                path.startswith("/proc/1")
                or path.startswith("/sys/")
                or path == "/var/run/docker.sock"
            ):
                return Evaluation(
                    Decision.KILL,
                    Risk.CRITICAL,
                    "host-level filesystem resource accessed",
                    "host_resource_access",
                )
        return None

    def _check_env_var(
        self, kind: str, action: str, resource: str, meta: Mapping[str, Any]
    ) -> "Evaluation | None":
        name = meta.get("env_var")
        if not name and kind in ("env_access", "environment_access"):
            name = resource
        if not name:
            return None
        if str(name).upper() in self.protected_env_vars:
            return Evaluation(
                Decision.DENY,
                Risk.HIGH,
                f"environment variable is protected: {name}",
                "protected_env_var",
            )
        return None

    def _check_paths(
        self, kind: str, action: str, resource: str, meta: Mapping[str, Any]
    ) -> "Evaluation | None":
        if kind not in _FILE_EVENTS and not meta.get("path"):
            return None

        raw_path = meta.get("path") or resource
        path = normalise_path(raw_path, base=self.workspace_root)
        if not path:
            return None

        forbidden = [
            normalise_path(entry, base=self.workspace_root)
            for entry in self.forbidden_paths
        ]
        if any_path_matches(path, forbidden):
            return Evaluation(
                Decision.DENY,
                Risk.HIGH,
                f"path is forbidden by policy: {raw_path}",
                "forbidden_path",
            )

        if self.allowed_paths:
            allowed = [
                normalise_path(entry, base=self.workspace_root)
                for entry in self.allowed_paths
            ]
            if not any_path_matches(path, allowed):
                return Evaluation(
                    Decision.DENY,
                    Risk.HIGH,
                    f"path is outside the allowed roots: {raw_path}",
                    "path_not_allowed",
                )
        return None

    def _check_network(
        self, kind: str, action: str, resource: str, meta: Mapping[str, Any]
    ) -> "Evaluation | None":
        if kind not in _NETWORK_EVENTS:
            return None

        domain = extract_domain(meta.get("domain") or resource)
        if not domain:
            if self.network_is_restricted:
                return Evaluation(
                    Decision.DENY,
                    Risk.HIGH,
                    f"network target is not a resolvable host: {resource}",
                    "unresolvable_network_target",
                )
            return None

        if self.forbidden_domains and domain_matches_any(domain, self.forbidden_domains):
            return Evaluation(
                Decision.DENY,
                Risk.HIGH,
                f"domain is forbidden by policy: {domain}",
                "forbidden_domain",
            )

        if self.network_is_restricted and not domain_matches_any(
            domain, self.allowed_domains
        ):
            return Evaluation(
                self.unknown_domain,
                Risk.HIGH,
                f"domain is not on the allow-list: {domain}",
                "domain_not_allowed",
            )
        return None

    def _check_tools(
        self, kind: str, action: str, resource: str, meta: Mapping[str, Any]
    ) -> "Evaluation | None":
        if kind not in _TOOL_EVENTS:
            return None

        tool = normalise_tool(meta.get("tool") or resource or action)
        if not tool:
            return None

        forbidden = {normalise_tool(name) for name in self.forbidden_tools}
        if tool in forbidden:
            return Evaluation(
                Decision.DENY,
                Risk.HIGH,
                f"tool is forbidden by policy: {tool}",
                "forbidden_tool",
            )

        if self.tools_are_restricted:
            allowed = {normalise_tool(name) for name in self.allowed_tools}
            if tool not in allowed:
                return Evaluation(
                    self.unknown_tool,
                    Risk.ELEVATED,
                    f"tool is not on the allow-list: {tool}",
                    "tool_not_allowed",
                )
        return None

    def _check_processes(
        self, kind: str, action: str, resource: str, meta: Mapping[str, Any]
    ) -> "Evaluation | None":
        if kind != EventType.PROCESS_CREATION.value:
            return None

        counter = meta.get("process_count")
        if counter is None:
            counter = meta.get("child_processes")
        try:
            count = int(counter) if counter is not None else 0
        except (TypeError, ValueError):
            return None

        if count > self.max_processes:
            hard_limit = self.max_processes * self.kill_max_processes_multiplier
            if count > hard_limit:
                return Evaluation(
                    Decision.KILL,
                    Risk.CRITICAL,
                    f"process tree exploded ({count} > {hard_limit})",
                    "max_processes_hard",
                )
            return Evaluation(
                Decision.DENY,
                Risk.HIGH,
                f"child process limit exceeded ({count} > {self.max_processes})",
                "max_processes",
            )
        return None

    def _check_runtime(
        self, kind: str, action: str, resource: str, meta: Mapping[str, Any]
    ) -> "Evaluation | None":
        seconds = meta.get("runtime_seconds")
        if seconds is None:
            return None
        try:
            elapsed = float(seconds)
        except (TypeError, ValueError):
            return None
        if elapsed > self.max_runtime_seconds:
            return Evaluation(
                Decision.KILL,
                Risk.HIGH,
                f"runtime limit exceeded ({elapsed:.0f}s > {self.max_runtime_seconds}s)",
                "max_runtime",
            )
        return None

    # -- serialisation ---------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "workspace_root": self.workspace_root,
            "allowed_paths": list(self.allowed_paths),
            "forbidden_paths": list(self.forbidden_paths),
            "allowed_domains": list(self.allowed_domains),
            "forbidden_domains": list(self.forbidden_domains),
            "allowed_tools": list(self.allowed_tools),
            "forbidden_tools": list(self.forbidden_tools),
            "restrict_network": self.restrict_network,
            "unknown_domain": self.unknown_domain.value,
            "unknown_tool": self.unknown_tool.value,
            "max_processes": self.max_processes,
            "max_runtime_seconds": self.max_runtime_seconds,
            "kill_max_processes_multiplier": self.kill_max_processes_multiplier,
            "protected_env_vars": list(self.protected_env_vars),
            "allow_privilege_escalation": self.allow_privilege_escalation,
            "allow_host_resource_access": self.allow_host_resource_access,
            "allow_persistence": self.allow_persistence,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Policy":
        if not isinstance(data, Mapping):
            raise PolicyError(f"policy must be a mapping, got {type(data).__name__}")

        known = {
            "name",
            "workspace_root",
            "allowed_paths",
            "forbidden_paths",
            "allowed_domains",
            "forbidden_domains",
            "allowed_tools",
            "forbidden_tools",
            "restrict_network",
            "unknown_domain",
            "unknown_tool",
            "max_processes",
            "max_runtime_seconds",
            "kill_max_processes_multiplier",
            "protected_env_vars",
            "allow_privilege_escalation",
            "allow_host_resource_access",
            "allow_persistence",
        }
        unknown = set(data) - known
        if unknown:
            raise PolicyError(
                "unknown policy fields: " + ", ".join(sorted(unknown))
            )

        payload = dict(data)
        for key in ("unknown_domain", "unknown_tool"):
            if key in payload and payload[key] is not None:
                try:
                    payload[key] = Decision(str(payload[key]).upper())
                except ValueError as exc:
                    raise PolicyError(f"invalid {key}: {payload[key]!r}") from exc

        try:
            return cls(**payload)
        except TypeError as exc:
            raise PolicyError(f"invalid policy: {exc}") from exc

    @classmethod
    def from_json(cls, raw: str) -> "Policy":
        try:
            return cls.from_dict(json.loads(raw))
        except json.JSONDecodeError as exc:
            raise PolicyError(f"policy is not valid JSON: {exc}") from exc

    @classmethod
    def load(cls, path: str) -> "Policy":
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return cls.from_json(handle.read())
        except OSError as exc:
            raise PolicyError(f"cannot read policy file {path}: {exc}") from exc

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
