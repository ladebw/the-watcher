"""Authority classification for everything the policy engine reads.

The engine is deterministic, but determinism is not the same thing as truth. A
rule is only as trustworthy as the fact it consumes, and in V2/V3 almost every
fact arrives from the untrusted workload as free-form ``metadata``. The engine
was therefore making sound deductions from unverified assertions: the
supervisor's own documentation called these decisions "deterministic" without
saying whose facts they were built from.

This module names the distinction, once, in code:

``AUTHORITATIVE``
    Produced by the trusted supervisor or observed from the operating system.
    The protected process cannot influence it, and it always wins.
``OBSERVED``
    Derived by the supervisor from its own authoritative state (its clock, its
    process handle). The supervisor can generate it; the client's version is
    never trusted over it.
``CLIENT_ASSERTED``
    Supplied by the untrusted workload. It may be *recorded* as what the client
    claimed. It may never masquerade as host state, and it may never override or
    weaken a decision derived from an authoritative value.

The governing rule for evaluation is **monotone in restriction**: a client
assertion may only ever add restriction, never remove it. So a rule whose input
has both an authoritative and a client-asserted candidate is evaluated against
both and the most severe outcome is taken. A forged ``metadata.path`` can
therefore point the check at a harmless file all it likes; the recorded
``resource`` is still checked.

This module deliberately does **not** invent facts. ``privilege_escalation``,
``persistence`` and ``host_resource`` cannot be observed without syscall-level
instrumentation or a cooperating runtime, so they stay ``CLIENT_ASSERTED`` and
are labelled as cooperative rather than authoritative.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

__all__ = [
    "Authority",
    "FactSpec",
    "AUTHORITATIVE_NAMESPACE",
    "AUTHORITY_MAP",
    "POLICY_FACTS",
    "SUPERVISOR_FACT_KEYS",
    "AuthoritativeFacts",
    "resolve_fact",
    "candidate_values",
    "client_forged_reserved_namespace",
    "describe_authority",
    "authority_of",
]


class Authority(str, enum.Enum):
    """Where a fact came from, and therefore how much it may be trusted."""

    #: Trusted supervisor or operating-system observation.
    AUTHORITATIVE = "AUTHORITATIVE"
    #: Derived by the supervisor from its own authoritative state.
    OBSERVED = "OBSERVED"
    #: Provided by the untrusted workload. Recordable, never authoritative.
    CLIENT_ASSERTED = "CLIENT_ASSERTED"


#: Reserved metadata key holding the facts the supervisor generated. The client
#: may not write it; the supervisor writes it last, and any client attempt to
#: supply it is recorded as a rejected field.
AUTHORITATIVE_NAMESPACE = "authoritative"


@dataclass(frozen=True)
class FactSpec:
    """One policy input, and what it is worth."""

    key: str
    authority: Authority
    description: str
    #: ``True`` when the supervisor produces this fact itself, so a client value
    #: can only ever be a fallback and can never override it.
    supervisor_generated: bool = False
    #: ``True`` when the fact is only meaningful with cooperative
    #: instrumentation. Such rules are advisory and are labelled as such.
    cooperative: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "authority": self.authority.value,
            "description": self.description,
            "supervisor_generated": self.supervisor_generated,
            "cooperative": self.cooperative,
        }


#: Every policy input that is not the request's own action string.
POLICY_FACTS: tuple[FactSpec, ...] = (
    FactSpec(
        "resource",
        Authority.CLIENT_ASSERTED,
        "the request's target; the supervisor republishes it as an "
        "authoritative fact because it is the value written into the trace",
        supervisor_generated=True,
    ),
    FactSpec(
        "path",
        Authority.CLIENT_ASSERTED,
        "a path the client claims the action concerns; never overrides the "
        "recorded resource, and is evaluated in addition to it",
    ),
    FactSpec(
        "domain",
        Authority.CLIENT_ASSERTED,
        "a host the client claims the action targets; evaluated in addition to "
        "any host in the recorded resource",
    ),
    FactSpec(
        "tool",
        Authority.CLIENT_ASSERTED,
        "a tool name the client claims to invoke; evaluated in addition to the "
        "recorded resource",
    ),
    FactSpec(
        "env_var",
        Authority.CLIENT_ASSERTED,
        "an environment variable name the client says it touched; requires "
        "cooperative instrumentation to observe",
        cooperative=True,
    ),
    FactSpec(
        "privilege_escalation",
        Authority.CLIENT_ASSERTED,
        "a privilege-escalation claim from the runtime; requires cooperative "
        "instrumentation or a host monitor to observe",
        cooperative=True,
    ),
    FactSpec(
        "persistence",
        Authority.CLIENT_ASSERTED,
        "a persistence claim from the runtime; requires cooperative "
        "instrumentation or a host monitor to observe",
        cooperative=True,
    ),
    FactSpec(
        "host_resource",
        Authority.CLIENT_ASSERTED,
        "a host-resource claim from the runtime; requires cooperative "
        "instrumentation or a host monitor to observe",
        cooperative=True,
    ),
    FactSpec(
        "process_count",
        Authority.OBSERVED,
        "the live size of the protected process tree, measured by the supervisor",
        supervisor_generated=True,
    ),
    FactSpec(
        "child_processes",
        Authority.CLIENT_ASSERTED,
        "legacy alias for process_count; superseded by the supervisor's own "
        "measurement and only used when no measurement is available",
    ),
    FactSpec(
        "runtime_seconds",
        Authority.OBSERVED,
        "elapsed session time, measured by the supervisor's authoritative clock",
        supervisor_generated=True,
    ),
    FactSpec(
        "ipc",
        Authority.AUTHORITATIVE,
        "supervisor-injected connection context",
        supervisor_generated=True,
    ),
    FactSpec(
        AUTHORITATIVE_NAMESPACE,
        Authority.AUTHORITATIVE,
        "reserved namespace holding the facts the supervisor generated; a "
        "client-supplied value is rejected",
        supervisor_generated=True,
    ),
)

AUTHORITY_MAP: dict[str, FactSpec] = {spec.key: spec for spec in POLICY_FACTS}

#: Facts the supervisor can generate for itself.
SUPERVISOR_FACT_KEYS: frozenset[str] = frozenset(
    spec.key for spec in POLICY_FACTS if spec.supervisor_generated
)


def authority_of(key: str) -> Authority:
    """The declared authority for ``key`` (client-asserted when unknown)."""
    spec = AUTHORITY_MAP.get(key)
    return spec.authority if spec else Authority.CLIENT_ASSERTED


@dataclass(frozen=True)
class AuthoritativeFacts:
    """The facts the trusted supervisor produced for one request.

    Only facts the supervisor can genuinely establish are included. A field left
    as ``None`` means "not observed", never "false" and never "zero".
    """

    resource: "str | None" = None
    process_count: "int | None" = None
    runtime_seconds: "int | None" = None
    session_state: "str | None" = None

    def to_metadata(self) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if self.resource is not None:
            payload["resource"] = self.resource
        if self.process_count is not None:
            payload["process_count"] = int(self.process_count)
        if self.runtime_seconds is not None:
            payload["runtime_seconds"] = int(self.runtime_seconds)
        if self.session_state is not None:
            payload["session_state"] = self.session_state
        return payload

    @classmethod
    def from_metadata(cls, metadata: Mapping[str, Any]) -> "AuthoritativeFacts":
        """Extract the supervisor's facts, ignoring anything malformed."""
        raw = metadata.get(AUTHORITATIVE_NAMESPACE)
        if not isinstance(raw, Mapping):
            return cls()
        return cls(
            resource=raw.get("resource") if isinstance(raw.get("resource"), str) else None,
            process_count=_as_int(raw.get("process_count")),
            runtime_seconds=_as_int(raw.get("runtime_seconds")),
            session_state=(
                raw.get("session_state")
                if isinstance(raw.get("session_state"), str)
                else None
            ),
        )


def _as_int(value: Any) -> "int | None":
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def resolve_fact(metadata: Mapping[str, Any], key: str) -> tuple[Any, Authority]:
    """Return ``(value, authority)`` for one policy fact.

    A supervisor-generated fact is read from the reserved authoritative
    namespace first. Only when the supervisor did not observe it does the
    client-supplied key apply, and then it is returned as ``CLIENT_ASSERTED`` so
    the caller can record what it was actually trusting.
    """
    facts = AuthoritativeFacts.from_metadata(metadata)
    spec = AUTHORITY_MAP.get(key)

    if spec is not None and spec.supervisor_generated:
        if key == "process_count" and facts.process_count is not None:
            return facts.process_count, Authority.OBSERVED
        if key == "runtime_seconds" and facts.runtime_seconds is not None:
            return facts.runtime_seconds, Authority.OBSERVED
        if key == "resource" and facts.resource is not None:
            return facts.resource, Authority.AUTHORITATIVE

    # ``process_count`` has a legacy alias that predates the authority split.
    if key == "process_count" and "child_processes" in metadata:
        return metadata.get("child_processes"), Authority.CLIENT_ASSERTED

    if key not in metadata:
        return None, authority_of(key)
    return metadata.get(key), Authority.CLIENT_ASSERTED


def looks_like_path(value: Any) -> bool:
    """Whether a value is plausibly a filesystem path.

    Used to decide whether the recorded ``resource`` must be evaluated as a
    path candidate. A resource that *is* a path is always checked, so it can
    never be hidden behind a harmless ``metadata.path``. A resource that is a
    verb or a description (``"read"``, ``"tool_call"``) is not turned into a
    path, because doing so would invent denials against the workspace base that
    the caller never asked for.
    """
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text:
        return False
    if text.startswith(("/", "./", "../", "~")):
        return True
    # Windows drive-absolute form, e.g. C:\work\x or C:/work/x
    if len(text) > 2 and text[1] == ":" and text[0].isalpha() and text[2] in "\\/":
        return True
    return False


def looks_like_host(value: Any) -> bool:
    """Whether a value is plausibly a network target rather than a verb.

    Mirrors :func:`looks_like_path` for the network rule. ``connect`` is a verb
    and carries no host information, so treating it as a hostname would invent a
    fact the caller never supplied; ``evil.example`` and ``https://evil.example``
    are claims about a host and are always evaluated.
    """
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text:
        return False
    if "://" in text:
        return True
    head = text.split("/", 1)[0]
    if "@" in head:
        head = head.rsplit("@", 1)[-1]
    if head.startswith("["):
        return True
    if ":" in head:
        return True
    return "." in head


def candidate_values(
    metadata: Mapping[str, Any], resource: str, key: str
) -> list[tuple[str, Any, Authority]]:
    """Every candidate value for a fact, labelled with its provenance.

    For a fact that has both an authoritative and a client-asserted candidate
    this returns both, so the caller can evaluate the rule against each and keep
    the most severe outcome. That is what makes a forged metadata key unable to
    *weaken* a decision: the authoritative candidate is always evaluated too.

    Entries are de-duplicated by value, preserving the authoritative one first.
    """
    candidates: list[tuple[str, Any, Authority]] = []

    def add(source: str, value: Any) -> None:
        if value is None or value == "":
            return
        for _, existing, _ in candidates:
            if existing == value:
                return
        candidates.append((source, value, Authority.CLIENT_ASSERTED))

    if key == "path":
        # The recorded resource is always a candidate when it is path-shaped,
        # even without a supervisor to mark it authoritative. This is the
        # forgery this rule exists to stop: a client that records
        # ``resource="/etc/shadow"`` cannot redirect the check to a harmless
        # ``metadata.path``.
        add("resource", resource if looks_like_path(resource) else None)
        add("metadata.path", metadata.get("path"))
        if not candidates:
            add("resource", resource)
        return candidates

    if key == "domain":
        claimed = metadata.get("domain")
        if looks_like_host(resource) or not claimed:
            add("resource", resource)
        add("metadata.domain", claimed)
        if not candidates:
            add("resource", resource)
        return candidates

    if key == "tool":
        add("metadata.tool", metadata.get("tool"))
        add("resource", resource)
        return candidates

    value, authority = resolve_fact(metadata, key)
    if value is not None and value != "":
        candidates.append((key, value, authority))
    return candidates


def client_forged_reserved_namespace(metadata: Mapping[str, Any]) -> bool:
    """Whether a client supplied the reserved authoritative namespace itself.

    The supervisor overwrites it, so the forgery cannot take effect, but the
    attempt is worth recording: a client trying to write the supervisor's own
    facts is a signal, not an accident.
    """
    return AUTHORITATIVE_NAMESPACE in metadata


def describe_authority() -> dict[str, Any]:
    """Serialisable classification, for documentation and ``doctor``."""
    return {
        "namespace": AUTHORITATIVE_NAMESPACE,
        "facts": [spec.to_dict() for spec in POLICY_FACTS],
        "supervisor_generated": sorted(SUPERVISOR_FACT_KEYS),
        "rule": (
            "A client assertion may only ever add restriction. Every rule with "
            "both an authoritative and a client-asserted candidate is evaluated "
            "against both, and the most severe outcome is kept."
        ),
    }


def iter_facts(keys: "Iterable[str]") -> list[FactSpec]:
    """The specs for ``keys``, for tests and documentation."""
    return [AUTHORITY_MAP[key] for key in keys if key in AUTHORITY_MAP]
