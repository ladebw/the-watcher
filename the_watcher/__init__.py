"""The Watcher.

Runtime observation, Proof of Execution and emergency control for autonomous
AI systems.

V1 (in-process)::

    from the_watcher import Watcher, Policy

    watcher = Watcher(policy=Policy(allowed_domains=["github.com"]))

    decision = watcher.evaluate("network_request", "connect", "example.com")
    assert decision.blocked

    with watcher.protect("python agent.py") as session:
        session.wait()

    print(session.status)
    print(session.trace.verify())

V2 (external supervisor) lives in two subpackages:

* :mod:`the_watcher.supervisor` — the trusted daemon that owns policy, the
  PoE trace, storage, tripwires, the kill switch and process control;
* :mod:`the_watcher.ipc` — the local, authenticated transport, including the
  thin :class:`~the_watcher.ipc.client.WatcherClient` that the protected
  process runs.

This project is independent of AAIP: it contains no agent identity, no
signatures, no validators, no blockchain and no economic layer.
"""

from __future__ import annotations

from .exceptions import (
    CanonicalizationError,
    KillSwitchError,
    PolicyError,
    SessionError,
    SessionKilledError,
    TraceError,
    TraceVerificationError,
    TripwireViolation,
    WatcherError,
)
from .poe import (
    DEFAULT_REDACTOR,
    EVENT_TYPES,
    GENESIS_HASH,
    REDACTED,
    SCHEMA_VERSION,
    TAMPER_SIGNALS,
    EventType,
    ExecutionTrace,
    PoEEvent,
    Recorder,
    Redactor,
    TamperSignal,
    TraceVerifier,
    VerificationResult,
    canonical_bytes,
    canonical_json,
    hash_value,
    is_hex_digest,
    normalise,
    redact,
    sha256_hex,
)
from .runtime import LocalProcess, TerminationReport, descendant_pids
from .watcher import (
    DEFAULT_PROTECTED_ENV_VARS,
    SIGNAL_RESPONSES,
    Decision,
    Evaluation,
    HostSignal,
    KillRecord,
    KillState,
    KillSwitch,
    PoEWatcher,
    Policy,
    Risk,
    Session,
    SessionStatus,
    Tripwire,
    TripwireRegistry,
    blocked,
    domain_matches,
    domain_matches_any,
    extract_domain,
    max_decision,
    max_risk,
    normalise_domain,
    normalise_path,
    normalise_tool,
    path_is_within,
    response_for,
)

#: Kept in step with ``pyproject.toml`` by ``tests/test_packaging.py``.
#: V1 = in-process, V2 = external supervisor, V3 = OS-enforced containment.
__version__ = "0.3.0"

#: ``Watcher`` is an alias for the main class, whose canonical name is
#: :class:`PoEWatcher` because its central job is the Proof of Execution.
Watcher = PoEWatcher

__all__ = [
    "__version__",
    # main class
    "PoEWatcher",
    "Watcher",
    "Session",
    "SessionStatus",
    "Policy",
    "Tripwire",
    "TripwireRegistry",
    "KillSwitch",
    "KillRecord",
    "KillState",
    "HostSignal",
    "SIGNAL_RESPONSES",
    "DEFAULT_PROTECTED_ENV_VARS",
    "response_for",
    # decisions
    "Decision",
    "Risk",
    "Evaluation",
    "blocked",
    "max_decision",
    "max_risk",
    # proof of execution
    "ExecutionTrace",
    "PoEEvent",
    "EventType",
    "EVENT_TYPES",
    "Recorder",
    "TraceVerifier",
    "VerificationResult",
    "TamperSignal",
    "TAMPER_SIGNALS",
    "SCHEMA_VERSION",
    "GENESIS_HASH",
    # canonicalisation and redaction
    "canonical_json",
    "canonical_bytes",
    "normalise",
    "sha256_hex",
    "hash_value",
    "is_hex_digest",
    "Redactor",
    "DEFAULT_REDACTOR",
    "redact",
    "REDACTED",
    # runtime
    "LocalProcess",
    "TerminationReport",
    "descendant_pids",
    # path/domain helpers
    "normalise_path",
    "path_is_within",
    "normalise_domain",
    "domain_matches",
    "domain_matches_any",
    "extract_domain",
    "normalise_tool",
    # errors
    "WatcherError",
    "CanonicalizationError",
    "TraceError",
    "TraceVerificationError",
    "PolicyError",
    "TripwireViolation",
    "SessionError",
    "SessionKilledError",
    "KillSwitchError",
]
