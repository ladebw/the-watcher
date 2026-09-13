"""Normalisation and matching helpers for paths, domains and tools.

Path and domain comparison is where most security policies quietly fail, so
the rules are explicit:

* paths are expanded (``~``, environment variables), made absolute against a
  base directory, normalised to forward slashes and lower-cased on
  case-insensitive filesystems;
* membership is decided on path *components*, never on raw string prefixes,
  so ``/etc/shadowed`` is not treated as being inside ``/etc/shadow``;
* domains are compared case-insensitively with optional ``*.`` globs.
"""

from __future__ import annotations

import os
import urllib.parse

__all__ = [
    "normalise_path",
    "path_is_within",
    "any_path_matches",
    "extract_domain",
    "normalise_domain",
    "domain_matches",
    "domain_matches_any",
    "normalise_tool",
]

_IS_WINDOWS = os.name == "nt"


def normalise_path(path: str, base: "str | None" = None) -> str:
    """Return a canonical, comparable form of ``path``.

    ``base`` is used to resolve relative paths (typically the workspace root).
    """
    if path is None:
        return ""
    text = str(path).strip()
    if not text:
        return ""

    # Expand ``~`` and ``$VAR`` / ``%VAR%`` without raising on unknown names.
    text = os.path.expanduser(text)
    text = os.path.expandvars(text)

    if base and not os.path.isabs(text):
        text = os.path.join(base, text)

    text = os.path.normpath(text).replace("\\", "/")
    if _IS_WINDOWS:
        text = text.lower()
    return text


def path_is_within(child: str, parent: str) -> bool:
    """Return ``True`` when ``child`` is ``parent`` or lives beneath it."""
    if not child or not parent:
        return False
    child_norm = child.rstrip("/") or "/"
    parent_norm = parent.rstrip("/") or "/"
    if child_norm == parent_norm:
        return True
    return child_norm.startswith(parent_norm + "/")


def any_path_matches(path: str, candidates: "list[str] | tuple[str, ...]") -> bool:
    """Return ``True`` when ``path`` matches any entry in ``candidates``.

    An entry matches the path itself or any descendant of the path.
    """
    return any(path_is_within(path, candidate) for candidate in candidates)


def extract_domain(resource: str) -> str:
    """Extract a lower-case hostname from a URL, host or ``host:port`` string.

    Returns ``""`` when the resource does not look like a network target.
    """
    if not resource:
        return ""
    text = str(resource).strip()
    if not text:
        return ""

    candidate = text
    if "://" not in candidate:
        if candidate.startswith(("/", "./", "../", "~")):
            return ""
        candidate = "//" + candidate

    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        # Malformed IPv6 literals and similar inputs.
        return ""

    host = parsed.hostname or parsed.netloc or ""
    host = host.split("@")[-1]
    if host.count(":") == 1 and not host.startswith("["):
        host = host.split(":")[0]
    return normalise_domain(host)


def normalise_domain(domain: str) -> str:
    """Lower-case a hostname and strip a trailing root dot."""
    if not domain:
        return ""
    return str(domain).strip().strip(".").lower()


def domain_matches(pattern: str, domain: str) -> bool:
    """Match ``domain`` against an exact host or a ``*.example.com`` glob."""
    target = normalise_domain(domain)
    rule = normalise_domain(pattern)
    if not rule or not target:
        return False
    if rule.startswith("*."):
        suffix = rule[2:]
        return target == suffix or target.endswith("." + suffix)
    if rule.startswith("."):
        suffix = rule[1:]
        return target == suffix or target.endswith("." + suffix)
    return target == rule


def domain_matches_any(domain: str, patterns: "list[str] | tuple[str, ...]") -> bool:
    """Return ``True`` when any pattern matches ``domain``."""
    return any(domain_matches(pattern, domain) for pattern in patterns)


def normalise_tool(tool: str) -> str:
    """Normalise a tool identifier for comparison."""
    if not tool:
        return ""
    return str(tool).strip().lower()
