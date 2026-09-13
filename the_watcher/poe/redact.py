"""Redaction of secrets before anything is written to a trace.

A Proof of Execution trace is meant to be durably preserved, exported and
inspected, so raw credentials must never reach it. Two complementary
strategies are applied:

* **key-based** — values whose *field name* looks sensitive are dropped;
* **pattern-based** — values that *look like* well-known credential formats
  (provider API keys, JWTs, PEM blocks, URL userinfo) are masked in place.

Redaction is applied by the recorder, not by callers, so a forgotten
``redact()`` call cannot leak a secret.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

__all__ = ["Redactor", "DEFAULT_REDACTOR", "redact", "REDACTED"]

REDACTED = "[REDACTED]"

# Exact-normalised field names that always hold a secret.
_SENSITIVE_KEYS = {
    "auth",
    "authorization",
    "apikey",
    "secret",
    "secretkey",
    "clientsecret",
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "tokenvalue",
    "password",
    "passwd",
    "pwd",
    "credential",
    "credentials",
    "privatekey",
    "accesskey",
    "cookie",
    "setcookie",
    "sessionid",
    "bearer",
    "signature",
    "passphrase",
}

# Substrings that make a field name sensitive regardless of prefix/suffix.
_SENSITIVE_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "privatekey",
    "accesskey",
    "credential",
)

# Matches well-known credential shapes anywhere inside a string value.
_VALUE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
        ),
        REDACTED,
    ),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{8,}"), f"Bearer {REDACTED}"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"), REDACTED),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"), REDACTED),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), REDACTED),
    (re.compile(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"), REDACTED),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), REDACTED),
    (
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b"),
        REDACTED,
    ),
    # scheme://user:password@host -> scheme://user:[REDACTED]@host
    (re.compile(r"(?i)([a-z][a-z0-9+.\-]*://[^/\s:@]+:)([^/\s@]+)(@)"), rf"\1{REDACTED}\3"),
)

_MAX_DEPTH = 32


def _normalise_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def is_sensitive_key(key: Any) -> bool:
    """Return ``True`` when a field name indicates secret content."""
    if not isinstance(key, str) or not key:
        return False
    normalised = _normalise_key(key)
    if not normalised:
        return False
    if normalised in _SENSITIVE_KEYS:
        return True
    return any(fragment in normalised for fragment in _SENSITIVE_SUBSTRINGS)


class Redactor:
    """Deterministic redaction engine.

    Parameters
    ----------
    extra_keys:
        Additional field names treated as sensitive.
    extra_patterns:
        Additional ``(regex, replacement)`` pairs applied to string values.
    """

    def __init__(
        self,
        extra_keys: Sequence[str] = (),
        extra_patterns: Sequence[tuple[re.Pattern[str], str]] = (),
    ) -> None:
        self._extra_keys = {_normalise_key(k) for k in extra_keys}
        self._patterns = tuple(_VALUE_PATTERNS) + tuple(extra_patterns)

    def key_is_sensitive(self, key: Any) -> bool:
        if is_sensitive_key(key):
            return True
        if isinstance(key, str) and _normalise_key(key) in self._extra_keys:
            return True
        return False

    def redact_text(self, value: str) -> str:
        """Apply pattern-based masking to a single string."""
        for pattern, replacement in self._patterns:
            value = pattern.sub(replacement, value)
        return value

    def redact(self, value: Any, _depth: int = 0) -> Any:
        """Return a deep copy of ``value`` with secrets masked."""
        if _depth > _MAX_DEPTH:
            return REDACTED

        if isinstance(value, Mapping):
            out: dict[str, Any] = {}
            for key, item in value.items():
                name = key if isinstance(key, str) else str(key)
                out[name] = (
                    REDACTED
                    if self.key_is_sensitive(name)
                    else self.redact(item, _depth + 1)
                )
            return out

        if isinstance(value, tuple):
            return tuple(self.redact(item, _depth + 1) for item in value)

        if isinstance(value, (list, set, frozenset)):
            return [self.redact(item, _depth + 1) for item in value]

        if isinstance(value, str):
            return self.redact_text(value)

        return value

    def redact_env(
        self,
        env: Mapping[str, str],
        protected_names: Sequence[str] = (),
    ) -> dict[str, str]:
        """Redact environment values for sensitive or explicitly protected names."""
        protected = {name.lower() for name in protected_names}
        out: dict[str, str] = {}
        for key, value in env.items():
            if key.lower() in protected or self.key_is_sensitive(key):
                out[key] = REDACTED
            else:
                out[key] = self.redact_text(str(value))
        return out


DEFAULT_REDACTOR = Redactor()


def redact(value: Any) -> Any:
    """Redact ``value`` using the default :class:`Redactor`."""
    return DEFAULT_REDACTOR.redact(value)
