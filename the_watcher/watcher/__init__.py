"""Observation, policy and emergency control layer."""

from __future__ import annotations

from .decision import Evaluation, Decision, Risk, blocked, max_decision, max_risk
from .kill_switch import KillRecord, KillState, KillSwitch
from .matching import (
    domain_matches,
    domain_matches_any,
    extract_domain,
    normalise_domain,
    normalise_path,
    normalise_tool,
    path_is_within,
)
from .policy import DEFAULT_PROTECTED_ENV_VARS, Policy
from .signals import SIGNAL_RESPONSES, HostSignal, response_for
from .tripwire import Tripwire, TripwireRegistry
from .watcher import PoEWatcher, Session, SessionStatus

__all__ = [
    "PoEWatcher",
    "Session",
    "SessionStatus",
    "Policy",
    "DEFAULT_PROTECTED_ENV_VARS",
    "Decision",
    "Risk",
    "Evaluation",
    "blocked",
    "max_decision",
    "max_risk",
    "Tripwire",
    "TripwireRegistry",
    "KillSwitch",
    "KillRecord",
    "KillState",
    "HostSignal",
    "SIGNAL_RESPONSES",
    "response_for",
    "normalise_path",
    "path_is_within",
    "normalise_domain",
    "domain_matches",
    "domain_matches_any",
    "extract_domain",
    "normalise_tool",
]
