"""Host-level signal ingestion.

V1 cannot detect every sandbox escape, and it does not pretend to. What it can
do is define the *vocabulary* and the *response* for escape evidence, so that
richer sources can be plugged in later without redesigning the core:

    container runtime | namespaces | seccomp | eBPF | host monitor |
    VM supervisor | Kubernetes | cloud runtime
            |
            v
    watcher.report_signal(...)   <- a single, stable entry point

Signals are never trusted to arrive; any component that can observe the
sandbox may send them. The response mapping below is deterministic and lives
entirely on the Watcher side.
"""

from __future__ import annotations

import enum

from .decision import Decision, Risk

__all__ = ["HostSignal", "SIGNAL_RESPONSES", "response_for"]


class HostSignal(str, enum.Enum):
    """Signals an external monitor may report to the Watcher."""

    HOST_NAMESPACE_ACCESS = "HOST_NAMESPACE_ACCESS"
    FORBIDDEN_SYSCALL = "FORBIDDEN_SYSCALL"
    UNEXPECTED_PROCESS_TREE = "UNEXPECTED_PROCESS_TREE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    UNAUTHORIZED_NETWORK = "UNAUTHORIZED_NETWORK"
    PROTECTED_FILE_ACCESS = "PROTECTED_FILE_ACCESS"
    WATCHER_TAMPER_ATTEMPT = "WATCHER_TAMPER_ATTEMPT"
    MONITOR_DISABLE_ATTEMPT = "MONITOR_DISABLE_ATTEMPT"
    PERSISTENCE_ATTEMPT = "PERSISTENCE_ATTEMPT"


#: Deterministic response for each known signal.
SIGNAL_RESPONSES: dict[str, tuple[Decision, Risk]] = {
    HostSignal.HOST_NAMESPACE_ACCESS.value: (Decision.KILL, Risk.CRITICAL),
    HostSignal.FORBIDDEN_SYSCALL.value: (Decision.KILL, Risk.CRITICAL),
    HostSignal.UNEXPECTED_PROCESS_TREE.value: (Decision.DENY, Risk.HIGH),
    HostSignal.PRIVILEGE_ESCALATION.value: (Decision.KILL, Risk.CRITICAL),
    HostSignal.UNAUTHORIZED_NETWORK.value: (Decision.DENY, Risk.HIGH),
    HostSignal.PROTECTED_FILE_ACCESS.value: (Decision.KILL, Risk.CRITICAL),
    HostSignal.WATCHER_TAMPER_ATTEMPT.value: (Decision.KILL, Risk.CRITICAL),
    HostSignal.MONITOR_DISABLE_ATTEMPT.value: (Decision.KILL, Risk.CRITICAL),
    HostSignal.PERSISTENCE_ATTEMPT.value: (Decision.KILL, Risk.CRITICAL),
}

#: Unknown signals fail closed rather than being ignored.
DEFAULT_SIGNAL_RESPONSE: tuple[Decision, Risk] = (Decision.DENY, Risk.ELEVATED)


def response_for(signal: "HostSignal | str") -> tuple[Decision, Risk]:
    """Return the deterministic ``(decision, risk)`` for a host signal."""
    key = signal.value if isinstance(signal, enum.Enum) else str(signal)
    key = key.strip().upper()
    return SIGNAL_RESPONSES.get(key, DEFAULT_SIGNAL_RESPONSE)
