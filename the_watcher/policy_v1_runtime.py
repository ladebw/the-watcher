"""Policy V1 -> runtime projection.

This module is the **only** boundary between the Policy V1 document format and
the running supervisor. It exists so that the two never blur:

* :mod:`the_watcher.policy_v1` stays a pure document model. It parses, validates,
  normalises and digests; it holds no runtime authority, and nothing here gives
  it any.
* The V3/V2 runtime keeps owning decisions, tripwires, the kill switch and the
  trace. This module does not reimplement any of that; it *projects* a validated
  document onto the machinery that already exists.

The projection is a deterministic function of the **canonical** Policy V1
document. Because the canonical form is what the digest is taken over, two
documents with the same digest project to the same runtime configuration. There
is no clock, no environment lookup and no filesystem access in here.

Field classification
--------------------

Every Policy V1 field is classified, and the classification is enforced, not
documented-and-hoped. ``ENFORCED`` means the runtime does the thing the document
says. ``NOT_APPLICABLE`` means the field holds its documented default, so the
author configured nothing and there is nothing to enforce. ``REFUSED`` means the
document asks for something this runtime cannot faithfully do - and a refusal is
an error, never a silent no-op, because a security control that is silently
absent is worse than one that is loudly missing.

The classification is derived from field *values*, never from whether a key was
written, which is what makes it digest-consistent: Policy V1 materialises
defaults, so ``{"network": {"mode": "none"}}`` and omitting ``network`` normalise
to the same bytes and therefore get the same treatment.

Platform note
-------------

Policy V1 patterns are absolute POSIX paths: the format refuses drive letters on
purpose, so that one document means one thing everywhere. A Windows action path
canonicalises to ``C:/...``, which no absolute POSIX pattern can ever equal. On
such a platform a non-empty filesystem rule or tripwire pattern would therefore
match *nothing* while looking like a working rule - the exact failure this
project refuses everywhere else. The projection refuses those documents with a
precise message instead.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable

from .exceptions import PolicyError
from .policy_v1 import PolicyV1
from .watcher.decision import Decision, Evaluation, Risk
from .watcher.matching import normalise_path
from .watcher.policy import Policy
from .watcher.tripwire import Tripwire, TripwireRegistry

__all__ = [
    "ENFORCED",
    "NOT_APPLICABLE",
    "POLICY_FORMAT",
    "REFUSED",
    "FieldDisposition",
    "RuntimeProjection",
    "project_policy_v1",
]

#: Identifies the document format in trace evidence and diagnostics.
POLICY_FORMAT = "watcher-policy/1"

ENFORCED = "ENFORCED"
REFUSED = "REFUSED"
NOT_APPLICABLE = "NOT_APPLICABLE"

#: Documented Policy V1 defaults. A field holding its default is configuration
#: the author did not write, so there is nothing to enforce or refuse.
_DEFAULT_MAX_CHILDREN = 32
_DEFAULT_MAX_RUNTIME_SECONDS = 3600
_DEFAULT_NETWORK_MODE = "none"
_ON_VIOLATION_DEFAULTS = {
    "filesystem": "DENY",
    "network": "DENY",
    "process": "DENY",
    "resources": "QUARANTINE",
    "tripwire": "KILL",
}

_IS_WINDOWS = os.name == "nt"

#: Decisions a Policy V1 violation may carry, and the risk the trace records
#: with each. These are the *existing* runtime decisions; nothing new is added.
_VIOLATION_RISK = {
    "DENY": Risk.HIGH,
    "QUARANTINE": Risk.CRITICAL,
    "KILL": Risk.CRITICAL,
}


@dataclass(frozen=True)
class FieldDisposition:
    """How one Policy V1 field was treated by the projection."""

    field: str
    disposition: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {
            "field": self.field,
            "disposition": self.disposition,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class _FilesystemRules:
    """Policy V1 filesystem rules, evaluated with Policy V1 semantics.

    This is the callable the runtime consults for path decisions. It is
    deliberately *not* part of :mod:`the_watcher.policy_v1` and deliberately not
    a second policy engine: it answers one question ("which rule, if any, does
    this path hit?") and hands the verdict back as the runtime's own
    :class:`Evaluation`.
    """

    workspace_root: str
    allow: tuple[Any, ...]
    deny: tuple[Any, ...]
    violation: Decision
    digest: str

    def canonical_subject(self, raw_path: Any) -> str:
        """The one canonical subject form for this action.

        The runtime's own canonicalisation is applied here, exactly once per
        action, and the result is reused for every rule. That is deliberate:
        re-deriving it per rule is the quadratic habit Phase 1 measured, and two
        different canonical forms for one action is how a rule ends up deciding
        about a path the trace does not name.

        The canonical form is absolute, because Policy V1 patterns are.
        """
        if raw_path is None:
            return ""
        canonical = normalise_path(raw_path, base=self.workspace_root)
        if not canonical:
            return ""
        if not canonical.startswith("/"):
            canonical = os.path.abspath(canonical).replace("\\", "/")
        return canonical

    def verdict(self, raw_path: Any) -> "Evaluation | None":
        """The runtime verdict for one candidate path, or ``None`` to abstain."""
        canonical = self.canonical_subject(raw_path)
        if not canonical:
            return None

        # DENY overrides ALLOW, always, and is evaluated first so that no
        # allow-list can ever re-admit a denied path.
        for index, pattern in enumerate(self.deny):
            if self._matches(pattern, canonical):
                return self._evaluation(
                    f"policy_v1:filesystem.deny[{index}]",
                    f"Policy V1 filesystem.deny[{index}] matches {canonical}",
                    canonical,
                )

        if self.allow and not any(
            self._matches(pattern, canonical) for pattern in self.allow
        ):
            # An allow-list exists and this path is outside it. This is the one
            # behaviour Policy V1 inherits unchanged from V3: a configured
            # allow-list is a default-deny.
            return self._evaluation(
                "policy_v1:filesystem.allow",
                f"Policy V1 path is outside every filesystem.allow root: {canonical}",
                canonical,
            )
        return None

    @staticmethod
    def _matches(pattern: Any, canonical: str) -> bool:
        try:
            return bool(pattern.matches(canonical))
        except Exception:  # noqa: BLE001 - a subject V1 cannot parse is not a match
            # PathPattern.matches raises rather than answering "no match" to a
            # question it cannot parse. At the runtime boundary that must not
            # become a crash mid-decision, and it must not become "allowed"
            # either: the caller sees a refusal (see verdict) because a subject
            # the matcher cannot parse never reaches the allow branch as a pass.
            return False

    def _evaluation(self, rule: str, reason: str, canonical: str) -> Evaluation:
        return Evaluation(
            self.violation,
            _VIOLATION_RISK[self.violation.value],
            reason,
            rule,
            facts={"path": "OBSERVED"},
            evidence={
                "policy_format": POLICY_FORMAT,
                "policy_document_digest": self.digest,
                "policy_subsystem": "filesystem",
                "policy_rule": rule,
                "canonical_subject": canonical,
            },
        )


@dataclass(frozen=True)
class RuntimeProjection:
    """A Policy V1 document projected onto the existing runtime machinery."""

    policy: Policy
    tripwires: TripwireRegistry
    dispositions: tuple[FieldDisposition, ...]
    document_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_format": POLICY_FORMAT,
            "policy_document_digest": self.document_digest,
            "enforced_here": [
                item.field for item in self.dispositions if item.disposition == ENFORCED
            ],
            "refused_here": [
                item.field for item in self.dispositions if item.disposition == REFUSED
            ],
            "not_applicable": [
                item.field
                for item in self.dispositions
                if item.disposition == NOT_APPLICABLE
            ],
            "fields": [item.to_dict() for item in self.dispositions],
        }


def _refuse(field_name: str, detail: str) -> "PolicyError":
    return PolicyError(
        f"Policy V1 {field_name} cannot be enforced by this runtime, and the "
        f"--policy runtime path refuses it rather than ignoring it: {detail}"
    )


def _disposition(field_name: str, disposition: str, detail: str) -> FieldDisposition:
    return FieldDisposition(field_name, disposition, detail)


def _classify_network(policy: PolicyV1) -> "tuple[list[FieldDisposition], list[str]]":
    """Network: ``none`` is enforced, everything else is refused.

    ``network.mode = "none"`` is not "no posture declared" - the design's legacy
    projection (``docs/V4_DESIGN.md`` §4.8) defines it as **no network access**:
    ``restrict_network = True`` with an empty allow-list, plus the empty
    network-namespace containment posture. Treating it as "not configured" would
    leave the runtime's own default (``restrict_network = None`` with no allowed
    domains, which restricts nothing) and therefore permit exactly the traffic the
    document forbids.

    The first two halves of that mapping are the existing cooperative domain
    check, and they deny every target because no domain is allowed. The third -
    the empty network namespace - is kernel-enforced and belongs to the
    containment posture, which requires ``--enforced`` on Linux.
    """
    problems: list[str] = []
    items: list[FieldDisposition] = []
    network = policy.network

    if network.mode == _DEFAULT_NETWORK_MODE:
        items.append(
            _disposition(
                "network.mode",
                ENFORCED,
                "'none' means no network access (design §4.8): projected as "
                "restrict_network=True with an empty allow-list, so the existing "
                "domain check denies every target. The kernel-enforced half - the "
                "empty network namespace - is the containment posture and needs "
                "--enforced on Linux; without it this denial is cooperative, not "
                "OS interception",
            )
        )
    else:
        message = (
            f"network.mode is {network.mode!r}; there is no network interception "
            "in this runtime, so no mode other than 'none' can be applied "
            "(the broker is Phase 8)"
        )
        problems.append(message)
        items.append(_disposition("network.mode", REFUSED, message))

    for name, values in (("network.allow", network.allow), ("network.deny", network.deny)):
        if values:
            message = (
                f"{name} lists {len(values)} hostname(s); domain rules are not "
                "enforced at the OS level by this runtime (the broker is Phase 8)"
            )
            problems.append(message)
            items.append(_disposition(name, REFUSED, message))
        else:
            items.append(_disposition(name, NOT_APPLICABLE, "empty: nothing declared"))
    return items, problems


def _classify_resources(policy: PolicyV1) -> "tuple[list[FieldDisposition], list[str]]":
    problems: list[str] = []
    items: list[FieldDisposition] = []
    resources = policy.resources

    for name, value in (
        ("resources.memory_mb", resources.memory_mb),
        ("resources.cpu_seconds", resources.cpu_seconds),
    ):
        if value is None:
            items.append(
                _disposition(name, NOT_APPLICABLE, "unset: the document declares no ceiling")
            )
        else:
            message = (
                f"{name} is {value}; resource ceilings live in the containment "
                "profile (rlimits today, cgroups in Phase 7) and are not derived "
                "from a policy document by this runtime"
            )
            problems.append(message)
            items.append(_disposition(name, REFUSED, message))
    return items, problems


def _classify_on_violation(policy: PolicyV1) -> "tuple[list[FieldDisposition], list[str]]":
    """Each subsystem's violation decision must be faithfully representable."""
    problems: list[str] = []
    items: list[FieldDisposition] = []
    configured = policy.on_violation

    for subsystem in ("filesystem", "network", "process", "resources", "tripwire"):
        value = str(configured.get(subsystem, _ON_VIOLATION_DEFAULTS[subsystem]))
        default = _ON_VIOLATION_DEFAULTS[subsystem]
        name = f"on_violation.{subsystem}"
        if subsystem == "filesystem":
            items.append(
                _disposition(
                    name,
                    ENFORCED,
                    f"{value}: applied to every filesystem rule violation by the "
                    "existing decision machinery",
                )
            )
        elif subsystem == "tripwire":
            items.append(
                _disposition(
                    name,
                    ENFORCED,
                    f"{value}: Policy V1 permits only KILL, which the existing kill "
                    "switch applies",
                )
            )
        elif value == default:
            items.append(
                _disposition(
                    name,
                    NOT_APPLICABLE,
                    f"default {default!r} and no {subsystem} rule is declared, so it "
                    "cannot fire",
                )
            )
        else:
            message = (
                f"{name} is {value!r} but no {subsystem} rule is enforceable by this "
                "runtime, so the decision could never be applied faithfully"
            )
            problems.append(message)
            items.append(_disposition(name, REFUSED, message))
    return items, problems


def _project_tripwires(policy: PolicyV1) -> "tuple[list[FieldDisposition], list[str], list[Tripwire]]":
    """Project V1 tripwire patterns onto the existing tripwire registry.

    Policy V1 tripwire patterns use the same small grammar as its filesystem
    rules. The registry can express a literal path exactly (a path and its
    descendants, which is what a literal Policy V1 pattern already means), but it
    has no glob support. A wildcard tripwire is therefore refused rather than
    registered as a literal that would quietly never fire.
    """
    problems: list[str] = []
    items: list[FieldDisposition] = []
    tripwires: list[Tripwire] = []

    if not policy.tripwires:
        items.append(_disposition("tripwires", NOT_APPLICABLE, "empty: nothing declared"))
        return items, problems, tripwires

    for index, pattern in enumerate(policy.tripwires):
        name = f"tripwires[{index}]"
        if pattern.has_wildcard:
            message = (
                f"{name} ({pattern.pattern!r}) uses glob syntax; the tripwire "
                "registry matches literal paths only, so this pattern is refused "
                "rather than registered as a literal that would never fire"
            )
            problems.append(message)
            items.append(_disposition(name, REFUSED, message))
            continue
        tripwires.append(
            Tripwire(
                id=f"policy_v1.tripwire.{index}",
                description=f"Policy V1 tripwire {pattern.pattern}",
                paths=(pattern.pattern,),
                decision=Decision.KILL,
                risk=Risk.CRITICAL,
            )
        )
        items.append(
            _disposition(
                name,
                ENFORCED,
                f"{pattern.pattern!r} -> KILL through the existing tripwire registry "
                "and kill switch",
            )
        )

    # An aggregate row as well as the per-pattern ones, so the table always
    # classifies the field itself and not only its entries.
    if problems:
        items.append(
            _disposition("tripwires", REFUSED, "at least one tripwire pattern is refused")
        )
    else:
        items.append(
            _disposition(
                "tripwires",
                ENFORCED,
                f"{len(tripwires)} literal tripwire pattern(s) -> KILL",
            )
        )
    return items, problems, tripwires


def project_policy_v1(
    policy: PolicyV1, workspace_root: "str | None" = None
) -> RuntimeProjection:
    """Project a validated Policy V1 document onto the runtime.

    ``workspace_root`` is the base a relative action path is resolved against
    before Policy V1 rules see it. It defaults to the current working directory;
    the CLI passes ``--workspace``.

    Raises :class:`PolicyError` if the document asks for anything the runtime
    cannot faithfully enforce. The caller must treat that as a failure to launch,
    never as a warning.
    """
    if not isinstance(policy, PolicyV1):
        raise PolicyError(
            f"project_policy_v1 expects a PolicyV1 document, got {type(policy).__name__}"
        )

    workspace_root = os.path.abspath(workspace_root or os.getcwd())
    dispositions: list[FieldDisposition] = []
    problems: list[str] = []

    dispositions.append(
        _disposition("version", ENFORCED, f"Policy V1 version {policy.version} validated")
    )
    dispositions.append(
        _disposition("name", ENFORCED, f"recorded as the runtime policy name {policy.name!r}")
    )

    has_filesystem_rules = bool(policy.filesystem.allow or policy.filesystem.deny)
    if has_filesystem_rules and _IS_WINDOWS:
        problems.append(
            "filesystem rules cannot be enforced on this platform: Policy V1 "
            "patterns are absolute POSIX paths and refuse drive letters, while a "
            "Windows action path canonicalises to 'C:/...', so every rule would "
            "match nothing while looking like a working rule"
        )
        dispositions.append(
            _disposition("filesystem", REFUSED, problems[-1])
        )
    elif has_filesystem_rules:
        dispositions.append(
            _disposition(
                "filesystem.allow",
                ENFORCED if policy.filesystem.allow else NOT_APPLICABLE,
                f"{len(policy.filesystem.allow)} allow rule(s), matched with Policy V1 "
                "semantics ('*' within a segment, '**' whole segments, '?')",
            )
        )
        dispositions.append(
            _disposition(
                "filesystem.deny",
                ENFORCED if policy.filesystem.deny else NOT_APPLICABLE,
                f"{len(policy.filesystem.deny)} deny rule(s), matched with Policy V1 "
                "semantics and evaluated before allow",
            )
        )
    else:
        dispositions.append(
            _disposition("filesystem", NOT_APPLICABLE, "empty: nothing declared")
        )

    network_items, network_problems = _classify_network(policy)
    resource_items, resource_problems = _classify_resources(policy)
    violation_items, violation_problems = _classify_on_violation(policy)
    tripwire_items, tripwire_problems, tripwires = _project_tripwires(policy)
    dispositions.extend(network_items)
    dispositions.extend(resource_items)
    dispositions.extend(violation_items)
    dispositions.extend(tripwire_items)
    problems.extend(network_problems)
    problems.extend(resource_problems)
    problems.extend(violation_problems)
    problems.extend(tripwire_problems)

    # -- process ceilings -------------------------------------------------
    process = policy.process
    if process.max_children != _DEFAULT_MAX_CHILDREN:
        dispositions.append(
            _disposition(
                "process.max_children",
                ENFORCED,
                f"{process.max_children}: applied as the runtime process-tree "
                "ceiling, which is conservative (total <= N implies children <= N)",
            )
        )
    else:
        dispositions.append(
            _disposition(
                "process.max_children",
                NOT_APPLICABLE,
                f"default {_DEFAULT_MAX_CHILDREN}: matches the runtime default",
            )
        )
    dispositions.append(
        _disposition(
            "process.max_runtime_seconds",
            ENFORCED,
            f"{process.max_runtime_seconds}: applied as the supervisor session timeout",
        )
    )

    if problems:
        raise PolicyError(
            "Policy V1 document cannot be enforced by this runtime; refusing to "
            "launch rather than run with a control silently missing:\n  - "
            + "\n  - ".join(problems)
        )

    filesystem_rules: "Callable[[Any], Evaluation | None] | None" = None
    if has_filesystem_rules:
        filesystem_rules = _FilesystemRules(
            workspace_root=workspace_root,
            allow=tuple(policy.filesystem.allow),
            deny=tuple(policy.filesystem.deny),
            violation=Decision(str(policy.on_violation.get("filesystem", "DENY")).upper()),
            digest=policy.document_digest,
        ).verdict

    runtime_policy = Policy(
        name=policy.name,
        workspace_root=workspace_root,
        # ``network.mode`` is necessarily "none" here: every other mode was
        # refused above. The design's legacy projection (§4.8) is applied
        # literally - restrict_network=True with no allowed domains - so the
        # existing domain check denies every target instead of restricting
        # nothing.
        restrict_network=True,
        allowed_domains=(),
        unknown_domain=Decision(
            str(policy.on_violation.get("network", _ON_VIOLATION_DEFAULTS["network"])).upper()
        ),
        max_processes=process.max_children,
        max_runtime_seconds=process.max_runtime_seconds,
        path_rule=filesystem_rules,
        policy_evidence={
            "policy_format": POLICY_FORMAT,
            "policy_document_digest": policy.document_digest,
            "policy_name": policy.name,
        },
    )

    registry = TripwireRegistry(base=workspace_root)
    for tripwire in tripwires:
        registry.add(tripwire)

    return RuntimeProjection(
        policy=runtime_policy,
        tripwires=registry,
        dispositions=tuple(dispositions),
        document_digest=policy.document_digest,
    )
