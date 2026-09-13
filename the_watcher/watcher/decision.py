"""Decision vocabulary shared by policies, tripwires and the kill switch."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any

__all__ = ["Decision", "Risk", "Evaluation", "max_decision", "blocked"]


class Decision(str, enum.Enum):
    """What the Watcher decided about an attempted action."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    QUARANTINE = "QUARANTINE"
    KILL = "KILL"


class Risk(str, enum.Enum):
    """How severe the Watcher considers the attempted action."""

    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


_SEVERITY = {
    Decision.ALLOW: 0,
    Decision.DENY: 1,
    Decision.QUARANTINE: 2,
    Decision.KILL: 3,
}

_RISK_SEVERITY = {
    Risk.NORMAL: 0,
    Risk.ELEVATED: 1,
    Risk.HIGH: 2,
    Risk.CRITICAL: 3,
}


def max_decision(first: Decision, second: Decision) -> Decision:
    """Return the more severe of two decisions."""
    return first if _SEVERITY[first] >= _SEVERITY[second] else second


def max_risk(first: Risk, second: Risk) -> Risk:
    """Return the more severe of two risk levels."""
    return first if _RISK_SEVERITY[first] >= _RISK_SEVERITY[second] else second


def blocked(decision: Decision) -> bool:
    """``True`` when the decision stops the action from proceeding."""
    return decision is not Decision.ALLOW


@dataclass(frozen=True)
class Evaluation:
    """The Watcher's verdict on one attempted action.

    Attributes
    ----------
    decision:
        The action this should take.
    risk:
        Severity attached to the decision.
    reason:
        Human-readable explanation, recorded verbatim in the trace.
    rule:
        Stable identifier of the rule that produced the decision, e.g.
        ``"forbidden_path"`` or ``"default"``.
    tripwire_id:
        Set when a tripwire, rather than a policy rule, produced the decision.
    """

    decision: Decision = Decision.ALLOW
    risk: Risk = Risk.NORMAL
    reason: str = "no policy rule matched"
    rule: str = "default"
    tripwire_id: "str | None" = None

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def blocked(self) -> bool:
        return blocked(self.decision)

    def escalate(self, decision: Decision, risk: Risk, reason: str, rule: str) -> "Evaluation":
        """Return a copy with a more severe decision, never a weaker one."""
        return Evaluation(
            decision=max_decision(self.decision, decision),
            risk=max_risk(self.risk, risk),
            reason=f"{self.reason}; {reason}" if self.reason else reason,
            rule=rule,
            tripwire_id=self.tripwire_id,
        )

    def to_metadata(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "rule": self.rule,
            "reason": self.reason,
        }
        if self.tripwire_id:
            payload["tripwire_id"] = self.tripwire_id
        return payload

    def __str__(self) -> str:
        return f"{self.decision.value}/{self.risk.value} ({self.rule}): {self.reason}"
