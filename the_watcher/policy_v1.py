"""Policy V1 - the public user-policy document.

The mission of this module is narrow and deliberate: turn a JSON document into a
fully validated, immutable, canonically normalised policy object with a stable
digest. It **does not evaluate anything**, and it is not wired into
``watcher run``. What it produces is the deterministic input that later phases
will resolve and enforce.

Design rules, and where they come from
--------------------------------------

**JSON only.** Policy V1 is JSON, not YAML. A hand-written YAML parser would be
the single largest new attack surface this project could add, and the brief for
this phase rules it out. A later phase may add a strict YAML *subset* reader;
until then, one syntax means one meaning.

**No silent coercion, anywhere.** ``"32"`` is not ``32``, ``1`` is not ``true``,
``1.0`` is not ``1``, and ``null`` is not "unset". Every acceptance is an exact,
documented match or a hard error naming the field.

**Duplicate keys are a security problem.** ``json.loads`` keeps the *last* of
duplicate keys and says nothing, so ``{"filesystem": {...}, "filesystem":
{...}}`` silently discards a rule set. That is unacceptable in a policy
document: the author and the enforcement engine would disagree about what was
written. Duplicate keys are detected at every level and rejected.

**Patterns are matched, never resolved.** No regex, no shell expansion, no
filesystem access, and no ``..`` traversal resolution - the last one because
lexical ``..`` collapsing produces a *different rule* from the one written
(``/workspace/../etc`` becomes ``/etc``), which is a policy-smuggling vector.
Unsupported syntax is rejected rather than interpreted as a literal.

**One canonical form.** Two documents that mean the same thing must normalise to
the same bytes, because the digest is what gets recorded in the Proof of
Execution. Section defaults are materialised, rule lists are sorted and
de-duplicated because their order carries no meaning, and optional values are
omitted when unset.

What this module does **not** claim
-----------------------------------

Fields here are *document configuration*. Nothing in Phase 1 enforces them, and
:mod:`the_watcher.enforcement.declared` remains the authority on what a backend
actually enforces. ``docs/policy.md`` carries the enforced/not-enforced table;
the short version is that no Policy V1 field is enforced yet.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .exceptions import PolicyIssue, PolicyParseError, PolicyValidationError
from .poe.canonical import canonical_bytes, sha256_hex

__all__ = [
    "POLICY_VERSION",
    "DOCUMENT_DIGEST_DOMAIN",
    "RESOLVED_DIGEST_DOMAIN",
    "MAX_DOCUMENT_BYTES",
    "MAX_PATTERN_LENGTH",
    "MAX_RULE_COUNT",
    "MAX_SEGMENTS",
    "VIOLATION_CLASSES",
    "NETWORK_MODES",
    "ON_VIOLATION_DECISIONS",
    "ENFORCED_IN_PHASE_1",
    "PathPattern",
    "FilesystemSection",
    "NetworkSection",
    "ProcessSection",
    "ResourceSection",
    "PolicyV1",
    "load_policy",
    "loads_policy",
    "parse_policy",
]


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

#: The only document version this module understands.
POLICY_VERSION = 1

#: Domain separator for the *document* digest. Recorded in the Proof of
#: Execution so a policy digest can never be confused with an event hash.
DOCUMENT_DIGEST_DOMAIN = b"watcher-policy-document/1"

#: Reserved for Phase 2. Deliberately unused here: a resolved-policy digest must
#: describe the *merged* policy, and returning the document digest under this
#: name would be a lie about which policy was in force. Exported so a caller can
#: see the namespace is claimed and distinct, not so it can be used yet.
RESOLVED_DIGEST_DOMAIN = b"watcher-policy-resolved/1"

#: A policy document is configuration, not data. The cap keeps a malformed or
#: hostile file from turning startup into a memory event.
MAX_DOCUMENT_BYTES = 1 << 20  # 1 MiB

MAX_PATTERN_LENGTH = 4096
MAX_RULE_COUNT = 4096
MAX_SEGMENTS = 256
MAX_NAME_LENGTH = 64

#: Violation classes, and the decision each may carry. ``ALLOW`` is absent on
#: purpose: it would mean "this rule does not apply", which is what omitting the
#: class already means, and accepting it invites a document that quietly
#: disables a mandatory control.
VIOLATION_CLASSES: tuple[str, ...] = (
    "filesystem",
    "network",
    "process",
    "resources",
    "tripwire",
)
ON_VIOLATION_DECISIONS: tuple[str, ...] = ("DENY", "QUARANTINE", "KILL")
NETWORK_MODES: tuple[str, ...] = ("none", "restricted", "open")

#: Which phase is expected to make each section real. Phase 1 enforces nothing;
#: this table exists so the documentation can be generated from code rather
#: than drifting from it, and so a test can assert the claim is still honest.
ENFORCED_IN_PHASE_1: Mapping[str, str] = MappingProxyType(
    {
        "filesystem": "document only - no runtime enforcement in Phase 1",
        "network": "document only - no runtime enforcement in Phase 1",
        "process": "document only - no runtime enforcement in Phase 1",
        "resources": "document only - no runtime enforcement in Phase 1",
        "tripwires": "document only - no runtime enforcement in Phase 1",
        "on_violation": "document only - no runtime enforcement in Phase 1",
    }
)

_NAME = re.compile(r"^[A-Za-z0-9._-]{1,%d}$" % MAX_NAME_LENGTH)

#: Characters that look like pattern syntax but are not part of the grammar.
#: Rejecting them is the whole point: a rule the engine does not understand must
#: never be quietly reinterpreted as a literal, because a rule that matches
#: nothing looks exactly like a rule that works.
_UNSUPPORTED_PATTERN_CHARS = "[]{}!\\"

#: Placeholders the loader refuses to expand. Expanding ``~`` or ``$VAR`` makes
#: one document mean different things on different machines, which breaks the
#: determinism the digest depends on.
_EXPANSION_MARKERS = ("~", "$", "%")

#: Characters a path may never contain: C0 controls, and the surrogate range
#: U+D800-U+DFFF. A surrogate is not valid Unicode text, so no UTF-8 path can
#: contain one; a rule carrying one could only ever be a silent no-op. Matched
#: with a single compiled scan because this runs once per rule per subject, and
#: a per-character Python loop over a 4096-character subject is measurably more
#: expensive than the match itself.
_UNSAFE_PATH_CHARS = re.compile("[\x00-\x1f\ud800-\udfff]")


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class _StrictObjectMarker(Exception):
    """Internal: raised by the JSON object hook and converted by the loader."""


class _NonFiniteMarker(Exception):
    """Internal: raised for NaN/Infinity and converted by the loader."""


def _issue(path: str, message: str, code: str = "invalid") -> PolicyIssue:
    return PolicyIssue(path=path, message=message, code=code)


def _fail(path: str, message: str, code: str = "invalid") -> None:
    raise PolicyValidationError(issues=[_issue(path, message, code)])


# ---------------------------------------------------------------------------
# JSON loading: duplicate keys, non-finite numbers, encoding, size
# ---------------------------------------------------------------------------


def _object_pairs_hook(pairs: "list[tuple[str, Any]]") -> dict[str, Any]:
    """Build an object, refusing duplicate keys.

    ``json.loads`` silently keeps the last duplicate, which for a policy
    document means an author's rule set can be discarded without a word.
    """
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _StrictObjectMarker(key)
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    """Refuse ``NaN``, ``Infinity`` and ``-Infinity``.

    These are accepted by Python's decoder by default even though they are not
    JSON, and they have no deterministic representation in the canonical
    encoder - which would turn a policy digest into a coin flip.
    """
    raise _NonFiniteMarker(name)


def _decode_document(text: str, source: str) -> Mapping[str, Any]:
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_object_pairs_hook,
            parse_constant=_reject_constant,
        )
    except _StrictObjectMarker as marker:
        key = str(marker.args[0]) if marker.args else "?"
        raise PolicyValidationError(
            summary=f"{source} is not a valid Policy V1 document",
            issues=[
                _issue(
                    str(key),
                    "duplicate key; the later value would silently replace the "
                    "earlier one",
                    "duplicate_key",
                )
            ],
        ) from None
    except _NonFiniteMarker as marker:
        name = str(marker.args[0]) if marker.args else "?"
        raise PolicyValidationError(
            summary=f"{source} is not a valid Policy V1 document",
            issues=[
                _issue(
                    name,
                    "NaN and Infinity are not JSON and have no deterministic "
                    "representation; they are refused",
                    "non_finite_number",
                )
            ],
        ) from None
    except json.JSONDecodeError as exc:
        raise PolicyParseError(
            f"{source} is not valid JSON: {exc.msg} at line {exc.lineno} "
            f"column {exc.colno}"
        ) from exc

    if not isinstance(parsed, Mapping):
        raise PolicyValidationError(
            summary=f"{source} is not a valid Policy V1 document",
            issues=[
                _issue(
                    "",
                    f"the document root must be a JSON object, got "
                    f"{_type_name(parsed)}",
                    "wrong_type",
                )
            ],
        )
    return parsed


def _type_name(value: Any) -> str:
    """A JSON-facing type name, so errors do not leak Python class names."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, (list, tuple)):
        return "array"
    return type(value).__name__


# ---------------------------------------------------------------------------
# path patterns
# ---------------------------------------------------------------------------


def _normalise_segments(raw: str, path: str) -> "list[str]":
    """Split an absolute POSIX path into canonical segments.

    Canonicalisation is deliberately lexical and total:

    * duplicate and trailing separators collapse (``/a//b/`` -> ``a/b``);
    * ``.`` segments are dropped, which is what they mean lexically;
    * ``..`` segments are **rejected**, not resolved: collapsing them changes
      the rule (``/workspace/../etc`` would become ``/etc``), and resolving them
      correctly needs the filesystem, which the matcher must never consult;
    * a trailing ``/`` never changes meaning, so ``/a/`` and ``/a`` are the
      same rule.
    """
    if not isinstance(raw, str):
        _fail(path, f"expected a string path, got {_type_name(raw)}", "wrong_type")
    if raw == "":
        _fail(path, "path must not be empty", "empty")
    if len(raw) > MAX_PATTERN_LENGTH:
        _fail(
            path,
            f"path is longer than {MAX_PATTERN_LENGTH} characters",
            "too_long",
        )
    unsafe = _UNSAFE_PATH_CHARS.search(raw)
    if unsafe is not None:
        if 0xD800 <= ord(unsafe.group()) <= 0xDFFF:
            _fail(
                path,
                "path must not contain a lone surrogate (U+D800-U+DFFF). A "
                "surrogate is not valid Unicode text and cannot appear in a "
                "UTF-8 path, so a rule containing one could never match "
                "anything - the exact silent no-op this format refuses "
                "everywhere else. Only a JSON \\uD800-style escape can produce "
                "one; write the character itself instead",
                "lone_surrogate",
            )
        _fail(path, "path must not contain control characters", "control_character")
    if "\\" in raw:
        _fail(
            path,
            "path must use forward slashes; backslashes are refused so that a "
            "document has one meaning on every platform",
            "backslash",
        )
    for marker in _EXPANSION_MARKERS:
        if raw.startswith(marker):
            _fail(
                path,
                f"{marker!r} is refused: expanding it would make this document "
                "mean different things on different machines. Write the "
                "absolute path instead",
                "expansion_not_supported",
            )
    if re.match(r"^[A-Za-z]:", raw):
        _fail(
            path,
            "drive-letter paths are not supported; Policy V1 uses absolute "
            "POSIX paths",
            "platform_path",
        )
    if not raw.startswith("/"):
        _fail(
            path,
            "path must be absolute (start with '/')",
            "not_absolute",
        )

    segments: list[str] = []
    for segment in raw.split("/"):
        if segment == "" or segment == ".":
            continue
        if segment == "..":
            _fail(
                path,
                "'..' is refused rather than resolved: collapsing it would "
                "silently change this rule, and resolving it correctly needs "
                "the filesystem, which matching must never touch",
                "parent_traversal",
            )
        segments.append(segment)

    if len(segments) > MAX_SEGMENTS:
        _fail(path, f"path has more than {MAX_SEGMENTS} segments", "too_deep")
    return segments


def _anchored_match(block: str, chunk: str) -> bool:
    """Match a ``*``-free block against a chunk of exactly the same length."""
    if len(block) != len(chunk):
        return False
    if "?" not in block:
        # The common case: a literal block is one C-level string comparison.
        return block == chunk
    if block.count("?") == len(block):
        return True
    for pattern_char, text_char in zip(block, chunk):
        if pattern_char != "?" and pattern_char != text_char:
            return False
    return True


def _shift_and_find(block: str, text: str, start: int, end: int) -> int:
    """Leftmost index in ``[start, end)`` where ``block`` matches, or ``-1``.

    Bit-parallel Shift-And over a block that contains ``?``. Each subject
    character costs one shift, one or and one and on an ``len(block)``-bit
    integer, so the loop is linear in the scanned window and the per-character
    work happens in C rather than in the interpreter. Reaching bit ``n - 1``
    means a match ending at the current character; because the block has a fixed
    length, the earliest end is also the earliest start.
    """
    size = len(block)
    accept = 1 << (size - 1)
    literals: dict[str, int] = {}
    wildcards = 0
    for index, char in enumerate(block):
        if char == "?":
            wildcards |= 1 << index
        else:
            literals[char] = literals.get(char, 0) | (1 << index)
    state = 0
    for index in range(start, end):
        state = ((state << 1) | 1) & (literals.get(text[index], 0) | wildcards)
        if state & accept:
            return index - size + 1
    return -1


def _find_block(block: str, text: str, start: int, end: int) -> int:
    """Leftmost placement of ``block`` within ``text[start:end]``, or ``-1``."""
    size = len(block)
    if size == 0:
        return start if start <= end else -1
    last = end - size
    if last < start:
        return -1
    if "?" not in block:
        return text.find(block, start, last + size)
    if block.count("?") == size:
        # Every character is a wildcard, so the first window that fits is a
        # match. This is the shape a long ``?`` run produces, and it is worth
        # answering without entering the bit-parallel scan at all.
        return start
    return _shift_and_find(block, text, start, last + size)


def _segment_matches(pattern: str, text: str) -> bool:
    """Match one path segment against a pattern segment in linear time.

    A segment never contains ``/`` by construction, so ``*`` and ``?`` cannot
    cross a separator. No regex is involved, so nothing in a pattern can be
    interpreted as an expression.

    The pattern is split on ``*`` into ``*``-free blocks. The block before the
    first ``*`` is anchored to the start of the subject and the block after the
    last ``*`` to its end; the blocks in between are located left to right,
    earliest first. Greedy-earliest is optimal because every block has a fixed
    length, so a block placed earlier never removes room that a later block
    needs.

    This replaces a single-backtrack-point matcher whose worst case re-scanned
    the whole pattern tail once per subject character. That form is O(n*m) and
    the blow-up is reachable: ``'*' + '?' * 2040`` against a 4095-character
    subject measured ~1.7 seconds of CPU for one match attempt, which an agent
    that chooses its own paths could repeat at will.

    The cost here is one comparison per anchored block, one C-level ``find`` per
    literal block that must be located, and one bit-parallel scan per ``?``
    block that must be located. The scans are the only part that can overlap a
    subject more than once, and their per-character work is a fixed number of
    operations on ``len(block)``-bit integers, so it happens in C: the worst
    adversarial shape at the caps measures ~0.6 ms for a pattern carrying 1020
    stars, and the shape that used to take 1.7 s now takes ~50 us.
    """
    blocks = pattern.split("*")
    if len(blocks) == 1:
        return _anchored_match(pattern, text)

    head = blocks[0]
    tail = blocks[-1]
    if len(text) < len(head) + len(tail):
        return False
    if not _anchored_match(head, text[: len(head)]):
        return False
    if tail and not _anchored_match(tail, text[len(text) - len(tail):]):
        return False

    middle = blocks[1:-1]
    position = len(head)
    limit = len(text) - len(tail)
    still_needed = sum(len(block) for block in middle)
    for block in middle:
        still_needed -= len(block)
        found = _find_block(block, text, position, limit - still_needed)
        if found < 0:
            return False
        position = found + len(block)
    return True


def _segments_match(pattern: "Sequence[str]", text: "Sequence[str]") -> bool:
    """Match whole segment lists, with ``**`` spanning zero or more segments.

    Iterative, with a single backtrack point at the most recent ``**``. Both
    sides are bounded by :data:`MAX_SEGMENTS`.

    **How many states the loop can visit, and why that number is not ``P * T``.**
    Let ``P = len(pattern)`` and ``T = len(text)``. At the top of every iteration
    ``0 <= pi <= P`` and ``0 <= mark <= ti < T``, so the potential

        ``Phi = (T - mark) * (P + 1) + (P - pi)``

    is non-negative. Every branch lowers it by at least one:

    * the ``**`` branch increments ``pi`` and sets ``mark = ti``, which is at
      least the old ``mark``, so ``Phi - Phi' = (P + 1) * (ti - mark) + 1 >= 1``;
    * the match branch increments ``pi``, so ``Phi - Phi' = 1``;
    * the backtrack branch sets ``pi = star + 1`` and increments ``mark``, so
      ``Phi - Phi' = P + 2 - pi + star >= 2``, because ``pi <= P`` and
      ``star >= 0``.

    ``Phi`` starts at ``T * (P + 1) + P`` and cannot go below zero, so the loop
    runs at most ``(P + 1) * (T + 1)`` times. A test asserts that count.

    The bound is therefore ``(P + 1) * (T + 1)`` states - **not** ``P * T``, and
    the difference is not academic: with ``P = 1`` and ``T = 77`` (a lone ``**``
    against 77 segments) the loop runs 78 times, so ``P * T = 77`` is false as an
    absolute bound even though the cost is still ``O(P * T)``. At the caps that
    is at most 257 x 257 = 66,049 iterations.

    There is deliberately no memo of element comparisons. An earlier revision
    cached them on the theory that backtracking revisits a pair; an exhaustive
    sweep of small inputs and a randomised search at the caps both found **zero**
    revisits, so the cache could never hit and was pure overhead. Removing it also
    drops the only structure here whose size was proportional to pattern x
    subject, leaving the matcher's extra memory constant.
    """
    pi = ti = 0
    star = -1
    mark = 0
    while ti < len(text):
        if pi < len(pattern) and pattern[pi] == "**":
            star = pi
            mark = ti
            pi += 1
        elif pi < len(pattern) and _segment_matches(pattern[pi], text[ti]):
            pi += 1
            ti += 1
        elif star != -1:
            pi = star + 1
            mark += 1
            ti = mark
        else:
            return False
    while pi < len(pattern) and pattern[pi] == "**":
        pi += 1
    return pi == len(pattern)


@dataclass(frozen=True)
class PathPattern:
    """A compiled path pattern with documented matching semantics.

    Matching is total over *canonical* subjects: every subject that canonicalises
    to an absolute POSIX path gets a deterministic yes or no. A subject that
    cannot be canonicalised is refused rather than answered with a silent
    ``False`` (see :meth:`matches`), so "no match" always means "no match" and
    never "this question was not understood".

    Cost is bounded and small at the enforced caps. Patterns and subjects are
    both capped by :data:`MAX_PATTERN_LENGTH`, and segments by
    :data:`MAX_SEGMENTS`; anchored blocks cost one comparison each, literal
    blocks that must be located cost one C-level search, and ``?`` blocks that
    must be located cost one bit-parallel scan. At the segment level the ``**``
    matcher walks at most ``(P + 1) * (T + 1)`` states for ``P`` pattern segments
    and ``T`` subject segments — ``O(P * T)``, and at most 257 x 257 under the
    caps — with constant extra memory. The worst adversarial shape measured at
    the caps is under a millisecond, where the single-backtrack-point matcher this
    replaced spent 1.7 seconds on one match attempt.

    Grammar (this is the whole of it):

    ==================  =====================================================
    ``/a/b``            the literal path ``/a/b`` **and every descendant**
                        (the existing V3 implicit-subtree meaning, preserved)
    ``/a/**``           exactly the same set as ``/a``: the prefix and every
                        descendant, because ``**`` spans zero or more segments
    ``/a/*``            ``/a`` plus exactly one more segment, never deeper
    ``/a/*.conf``       one segment under ``/a`` ending in ``.conf``
    ``/a/?``            one segment under ``/a`` of exactly one character
    ==================  =====================================================

    Everything else is a literal character. ``**`` is only meaningful as a whole
    segment; ``[``, ``]``, ``{``, ``}``, ``!`` and ``\\`` are rejected outright
    rather than treated as literals, because a pattern that silently matches
    nothing is indistinguishable from one that works.
    """

    raw: str
    pattern: str
    segments: tuple[str, ...]
    has_wildcard: bool
    subtree: bool

    def __str__(self) -> str:
        return self.pattern

    def matches(self, path: str) -> bool:
        """Return whether ``path`` falls under this pattern.

        ``path`` must already be a canonical absolute POSIX path. A subject that
        is relative, contains a backslash, or contains ``..`` raises
        :class:`PolicyValidationError` rather than quietly returning ``False``:
        a matcher that answers "no match" to a question it cannot parse is the
        kind of silent wrong answer this project exists to avoid, and the caller
        must not be able to mistake it for a decision.
        """
        segments = _normalise_segments(path, "path")
        canonical = "/" + "/".join(segments)
        if self.subtree:
            if self.pattern == "/":
                return True
            return canonical == self.pattern or canonical.startswith(
                self.pattern + "/"
            )
        return _segments_match(self.segments, segments)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "segments": list(self.segments),
            "has_wildcard": self.has_wildcard,
            "subtree": self.subtree,
        }


def compile_pattern(raw: Any, path: str) -> PathPattern:
    """Validate and compile one pattern, or raise a located error."""
    segments = _normalise_segments(raw, path)
    for character in _UNSUPPORTED_PATTERN_CHARS:
        if character in raw:
            _fail(
                path,
                f"unsupported pattern syntax {character!r}; Policy V1 supports "
                "only '*' (within one segment), '**' (whole segments) and '?' "
                "(one character). Unsupported syntax is refused rather than "
                "treated as a literal, because a rule that matches nothing "
                "looks identical to a rule that works",
                "unsupported_pattern",
            )

    for index, segment in enumerate(segments):
        if segment == "**":
            continue
        if "**" in segment:
            _fail(
                path,
                f"'**' must be a whole path segment, not part of {segment!r}",
                "unsupported_pattern",
            )

    has_wildcard = any("*" in segment or "?" in segment for segment in segments)
    canonical = "/" + "/".join(segments) if segments else "/"
    return PathPattern(
        raw=raw,
        pattern=canonical,
        segments=tuple(segments),
        has_wildcard=has_wildcard,
        subtree=not has_wildcard,
    )


# ---------------------------------------------------------------------------
# strict scalar helpers
# ---------------------------------------------------------------------------


def _require_object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(path, f"expected an object, got {_type_name(value)}", "wrong_type")
    return value


def _require_array(value: Any, path: str) -> "list[Any]":
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        _fail(path, f"expected an array, got {_type_name(value)}", "wrong_type")
    return list(value)


def _require_int(
    value: Any,
    path: str,
    *,
    minimum: "int | None" = None,
    maximum: "int | None" = None,
    maximum_exclusive: "int | None" = None,
) -> int:
    """Strict integer: booleans and floats are refused, never coerced."""
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(
            path,
            f"expected an integer, got {_type_name(value)}; Policy V1 never "
            "coerces a value into the expected type",
            "wrong_type",
        )
    if minimum is not None and value < minimum:
        _fail(path, f"must be >= {minimum}, got {value}", "out_of_range")
    if maximum is not None and value > maximum:
        _fail(path, f"must be <= {maximum}, got {value}", "out_of_range")
    if maximum_exclusive is not None and value >= maximum_exclusive:
        _fail(path, f"must be < {maximum_exclusive}, got {value}", "out_of_range")
    return int(value)


def _require_string(value: Any, path: str) -> str:
    if not isinstance(value, str):
        _fail(path, f"expected a string, got {_type_name(value)}", "wrong_type")
    return value


def _reject_null(value: Any, path: str) -> None:
    if value is None:
        _fail(
            path,
            "null is not accepted here; omit the field to leave it unset",
            "unexpected_null",
        )


def _check_keys(
    data: Mapping[str, Any],
    path: str,
    allowed: "Sequence[str]",
    hints: "Mapping[str, str] | None" = None,
) -> None:
    """Refuse unknown keys, with a pointer at the likely intent."""
    unknown = sorted(set(data) - set(allowed))
    if not unknown:
        return
    issues: list[PolicyIssue] = []
    for key in unknown:
        location = f"{path}.{key}" if path else key
        hint = (hints or {}).get(key)
        if hint is None:
            near = _nearest(key, allowed)
            hint = f"did you mean {near!r}?" if near else None
        message = "unknown field"
        if hint:
            message = f"unknown field; {hint}"
        issues.append(_issue(location, message, "unknown_field"))
    raise PolicyValidationError(
        summary=f"{path or 'document'} has unknown fields", issues=issues
    )


def _nearest(key: str, candidates: "Sequence[str]") -> "str | None":
    """A deterministic near-miss suggestion (no locale, no randomness)."""
    best = None
    best_score = None
    for candidate in sorted(candidates):
        score = _edit_distance(key.lower(), candidate.lower())
        if best_score is None or score < best_score:
            best, best_score = candidate, score
    if best is None or best_score is None:
        return None
    # Only suggest when it is plausibly a typo rather than a different word.
    return best if best_score <= max(1, len(best) // 3) else None


def _edit_distance(first: str, second: str) -> int:
    if first == second:
        return 0
    previous = list(range(len(second) + 1))
    for i, a in enumerate(first, 1):
        current = [i]
        for j, b in enumerate(second, 1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (a != b),
                )
            )
        previous = current
    return previous[-1]


# ---------------------------------------------------------------------------
# sections
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FilesystemSection:
    """Declared filesystem rules. Order carries no meaning; deny wins."""

    allow: tuple[PathPattern, ...] = ()
    deny: tuple[PathPattern, ...] = ()


@dataclass(frozen=True)
class NetworkSection:
    """Declared network rules.

    ``allow``/``deny`` are **hostnames**, not addresses. That is deliberately a
    different thing from ``ContainmentProfile.allowed_networks``, which holds
    CIDRs for the OS-level backend; conflating the two would give one field two
    meanings. An address or CIDR here is refused with a pointer at the profile.
    """

    mode: str = "none"
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProcessSection:
    """Declared process-tree ceilings."""

    max_children: int = 32
    max_runtime_seconds: int = 3600


@dataclass(frozen=True)
class ResourceSection:
    """Declared resource ceilings. ``None`` means "not configured"."""

    memory_mb: "int | None" = None
    cpu_seconds: "int | None" = None


# ---------------------------------------------------------------------------
# the document
# ---------------------------------------------------------------------------

_SECTION_KEYS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "filesystem": ("allow", "deny"),
        "network": ("mode", "allow", "deny"),
        "process": ("max_children", "max_runtime_seconds"),
        "resources": ("memory_mb", "cpu_seconds"),
    }
)

_ROOT_KEYS: tuple[str, ...] = (
    "version",
    "name",
    "filesystem",
    "network",
    "process",
    "resources",
    "tripwires",
    "on_violation",
)

#: Pointers for fields that exist elsewhere in the project under another name.
#: Naming the other place is the difference between a usable error and a puzzle.
_ROOT_HINTS: Mapping[str, str] = MappingProxyType({})

_SECTION_HINTS: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {
        "resources": {
            "pids": (
                "the process ceiling is 'process.max_children'; a separate "
                "'resources.pids' would give one ceiling two names"
            ),
            "cpus": (
                "CPU rate limits are not part of Policy V1; the containment "
                "profile carries 'resources.cpus' for backends that implement it"
            ),
            "max_runtime_seconds": (
                "the runtime ceiling is 'process.max_runtime_seconds'"
            ),
        },
        "network": {
            "allowed_networks": (
                "Policy V1 uses 'network.allow' with hostnames; "
                "ContainmentProfile.allowed_networks holds CIDRs for the OS "
                "backend"
            ),
            "restrict_network": "use 'network.mode' instead",
            "unknown_domain": "use 'on_violation.network' instead",
            "allowed_domains": "use 'network.allow' instead",
            "forbidden_domains": "use 'network.deny' instead",
        },
        "filesystem": {
            "allowed_paths": "use 'filesystem.allow' instead",
            "forbidden_paths": "use 'filesystem.deny' instead",
            "allow_read": (
                "read/write ceilings are containment-profile settings "
                "(filesystem.allow_read); Policy V1 declares 'filesystem.allow' "
                "and 'filesystem.deny'"
            ),
            "allow_write": (
                "read/write ceilings are containment-profile settings "
                "(filesystem.allow_write)"
            ),
        },
        "process": {
            "max_processes": "use 'process.max_children' instead",
            "pids": "use 'process.max_children' instead",
        },
    }
)


@dataclass(frozen=True)
class PolicyV1:
    """A validated, immutable Policy V1 document.

    Immutability is part of the contract: the digest is computed once at
    construction, and every field is a tuple or a read-only mapping so a caller
    cannot mutate the policy after it has been validated and change what the
    digest attests to.
    """

    version: int
    name: str
    filesystem: FilesystemSection
    network: NetworkSection
    process: ProcessSection
    resources: ResourceSection
    tripwires: tuple[PathPattern, ...]
    on_violation: Mapping[str, str]
    _digest: str = field(default="", init=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "on_violation", MappingProxyType(dict(self.on_violation))
        )
        object.__setattr__(
            self,
            "_digest",
            sha256_hex(
                DOCUMENT_DIGEST_DOMAIN + b"\x00" + canonical_bytes(self.normalized())
            ),
        )

    # -- identity --------------------------------------------------------

    @property
    def document_digest(self) -> str:
        """SHA-256 over the canonical normalised document.

        Domain-separated with :data:`DOCUMENT_DIGEST_DOMAIN`, built on the same
        canonical encoder the Proof of Execution uses, so the two can never
        collide. Two documents that mean the same thing share this digest; any
        change that could change behaviour does not.
        """
        return self._digest

    def normalized(self) -> Mapping[str, Any]:
        """The canonical form the digest is taken over.

        Rules for producing it, all of which exist so that "same meaning =>
        same digest" is true:

        * every section key is always present;
        * fields with a declared default are always materialised, so omitting a
          section and writing its defaults out are the same document;
        * ``resources`` keys are omitted when not configured rather than set to
          ``null``, so there is never a null in the canonical form;
        * rule lists are de-duplicated and sorted by Unicode code point, because
          their order carries no meaning - Policy V1 has no first-match-wins
          rule, so nothing depends on the order they were written in;
        * domain names are lower-cased, because DNS is case-insensitive;
        * nothing else is reordered, re-cased or reformatted.
        """
        resources: dict[str, Any] = {}
        if self.resources.memory_mb is not None:
            resources["memory_mb"] = self.resources.memory_mb
        if self.resources.cpu_seconds is not None:
            resources["cpu_seconds"] = self.resources.cpu_seconds

        return MappingProxyType(
            {
                "version": self.version,
                "name": self.name,
                "filesystem": MappingProxyType(
                    {
                        "allow": [p.pattern for p in self.filesystem.allow],
                        "deny": [p.pattern for p in self.filesystem.deny],
                    }
                ),
                "network": MappingProxyType(
                    {
                        "mode": self.network.mode,
                        "allow": list(self.network.allow),
                        "deny": list(self.network.deny),
                    }
                ),
                "process": MappingProxyType(
                    {
                        "max_children": self.process.max_children,
                        "max_runtime_seconds": self.process.max_runtime_seconds,
                    }
                ),
                "resources": MappingProxyType(resources),
                "tripwires": [p.pattern for p in self.tripwires],
                "on_violation": MappingProxyType(
                    {key: self.on_violation[key] for key in sorted(self.on_violation)}
                ),
            }
        )

    def to_dict(self) -> dict[str, Any]:
        """A plain, JSON-serialisable copy of the canonical form."""
        return json.loads(canonical_bytes(self.normalized()).decode("utf-8"))

    def __repr__(self) -> str:
        return (
            f"<PolicyV1 v{self.version} name={self.name!r} "
            f"digest={self._digest[:12]}>"
        )


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def _section(
    data: Mapping[str, Any], key: str
) -> Mapping[str, Any]:
    """Return a section object, distinguishing absent from explicit null.

    ``data.get(key)`` cannot tell those apart, and treating an explicit ``null``
    as "absent" would silently turn ``"filesystem": null`` into the default
    filesystem policy - a coercion, and exactly the kind this format refuses.
    """
    if key not in data:
        return {}
    value = data[key]
    if value is None:
        _fail(
            key,
            "null is not accepted; omit the section to use its defaults "
            "explicitly",
            "unexpected_null",
        )
    return _require_object(value, key)


def _patterns(
    values: Any, path: str, seen: "set[str]"
) -> tuple[PathPattern, ...]:
    array = _require_array(values, path)
    if len(array) > MAX_RULE_COUNT:
        _fail(path, f"more than {MAX_RULE_COUNT} rules", "too_many_rules")
    compiled: list[PathPattern] = []
    for index, entry in enumerate(array):
        pattern = compile_pattern(entry, f"{path}[{index}]")
        # A repeated rule is harmless but it is not the document the author
        # wrote; refuse it rather than let the canonical form hide it.
        if pattern.pattern in seen:
            _fail(
                f"{path}[{index}]",
                f"duplicate rule {pattern.pattern!r}",
                "duplicate_rule",
            )
        seen.add(pattern.pattern)
        compiled.append(pattern)
    return tuple(sorted(compiled, key=lambda item: item.pattern))


def _hostnames(values: Any, path: str) -> tuple[str, ...]:
    array = _require_array(values, path)
    if len(array) > MAX_RULE_COUNT:
        _fail(path, f"more than {MAX_RULE_COUNT} entries", "too_many_rules")
    seen: set[str] = set()
    result: list[str] = []
    for index, entry in enumerate(array):
        location = f"{path}[{index}]"
        name = _require_string(entry, location)
        if name == "":
            _fail(location, "hostname must not be empty", "empty")
        if len(name) > 253:
            _fail(location, "hostname is longer than 253 characters", "too_long")
        if any(ord(char) > 127 for char in name):
            _fail(
                location,
                "non-ASCII hostnames are not supported in Policy V1; write the "
                "A-label (punycode) form",
                "idna_not_supported",
            )
        lowered = name.strip(".").lower()
        if lowered.startswith("*."):
            body = lowered[2:]
            if not body:
                _fail(location, "'*.' must be followed by a domain", "invalid_hostname")
        else:
            body = lowered

        # Addresses, CIDRs and host:port pairs are a *different* concept from a
        # hostname allow-list, and they belong to the containment profile. Say
        # so, rather than reporting them as malformed hostnames.
        if "/" in body or ":" in body or re.match(r"^[0-9]+(\.[0-9]+){3}$", body):
            _fail(
                location,
                f"{name!r} looks like an address, CIDR or host:port. Policy V1 "
                "'network.allow' takes hostnames; address-level rules belong to "
                "the containment profile (allowed_networks)",
                "address_not_supported",
            )

        if body and not re.match(
            r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$",
            body,
        ):
            _fail(location, f"{name!r} is not a valid hostname", "invalid_hostname")
        if lowered in seen:
            _fail(location, f"duplicate entry {lowered!r}", "duplicate_entry")
        seen.add(lowered)
        result.append(lowered)
    return tuple(sorted(result))


def parse_policy(data: Mapping[str, Any]) -> PolicyV1:
    """Validate an already-decoded mapping as a Policy V1 document.

    Use this when the document came from somewhere other than a file. The rules
    are identical to :func:`load_policy`; only the encoding and size checks are
    skipped, because there is no byte stream to check.
    """
    document = _require_object(data, "")

    _check_keys(document, "", _ROOT_KEYS, _ROOT_HINTS)

    if "version" not in document:
        _fail("version", "missing required field", "missing_field")
    version = document["version"]
    _reject_null(version, "version")
    if isinstance(version, bool) or not isinstance(version, int):
        _fail(
            "version",
            f"expected the integer {POLICY_VERSION}, got {_type_name(version)}",
            "wrong_type",
        )
    if version != POLICY_VERSION:
        _fail(
            "version",
            f"unsupported policy version {version}; this build understands "
            f"version {POLICY_VERSION}",
            "unsupported_version",
        )

    name = "default"
    if "name" in document:
        _reject_null(document["name"], "name")
        name = _require_string(document["name"], "name")
        if not _NAME.match(name):
            _fail(
                "name",
                "must be 1-%d characters of letters, digits, dot, underscore or "
                "hyphen" % MAX_NAME_LENGTH,
                "invalid_name",
            )

    issues: list[PolicyIssue] = []

    # -- filesystem ------------------------------------------------------
    filesystem_data = _section(document, "filesystem")
    _check_keys(filesystem_data, "filesystem", _SECTION_KEYS["filesystem"],
                _SECTION_HINTS.get("filesystem"))
    try:
        allow = _patterns(filesystem_data.get("allow", []), "filesystem.allow", set())
        deny = _patterns(filesystem_data.get("deny", []), "filesystem.deny", set())
    except PolicyValidationError as exc:
        issues.extend(exc.issues)

    overlap = {p.pattern for p in allow} & {p.pattern for p in deny} \
        if not issues else set()
    if overlap:
        issues.append(
            _issue(
                "filesystem",
                "the same pattern appears in both 'allow' and 'deny' "
                f"({', '.join(sorted(overlap))}); deny wins, so the allow entry "
                "has no effect - remove one of them",
                "contradictory_rule",
            )
        )

    # -- network ---------------------------------------------------------
    network_data = _section(document, "network")
    _check_keys(network_data, "network", _SECTION_KEYS["network"],
                _SECTION_HINTS.get("network"))
    mode = "none"
    if "mode" in network_data:
        _reject_null(network_data["mode"], "network.mode")
        mode = _require_string(network_data["mode"], "network.mode")
    if mode not in NETWORK_MODES:
        issues.append(
            _issue(
                "network.mode",
                f"must be one of {', '.join(NETWORK_MODES)}, got {mode!r}",
                "invalid_enum",
            )
        )
    try:
        network_allow = _hostnames(network_data.get("allow", []), "network.allow")
        network_deny = _hostnames(network_data.get("deny", []), "network.deny")
    except PolicyValidationError as exc:
        issues.extend(exc.issues)
        network_allow = network_deny = ()

    if network_allow and mode != "restricted":
        issues.append(
            _issue(
                "network.allow",
                "an allow-list is only meaningful with mode 'restricted'; with "
                f"mode {mode!r} the list would be silently ignored",
                "contradictory_setting",
            )
        )
    both = set(network_allow) & set(network_deny)
    if both:
        issues.append(
            _issue(
                "network",
                "the same host appears in both 'allow' and 'deny' "
                f"({', '.join(sorted(both))}); deny wins",
                "contradictory_rule",
            )
        )

    # -- process ---------------------------------------------------------
    process_data = _section(document, "process")
    _check_keys(process_data, "process", _SECTION_KEYS["process"],
                _SECTION_HINTS.get("process"))
    max_children = 32
    max_runtime = 3600
    for key, target in (("max_children", "children"), ("max_runtime_seconds", "runtime")):
        if key not in process_data:
            continue
        location = f"process.{key}"
        _reject_null(process_data[key], location)
        # max_children may be 0 (no children at all); a runtime of 0 would mean
        # "expire immediately", which is never what an operator means.
        minimum = 0 if target == "children" else 1
        try:
            value = _require_int(process_data[key], location, minimum=minimum)
        except PolicyValidationError as exc:
            issues.extend(exc.issues)
            continue
        if target == "children":
            max_children = value
        else:
            max_runtime = value

    # -- resources -------------------------------------------------------
    resource_data = _section(document, "resources")
    _check_keys(resource_data, "resources", _SECTION_KEYS["resources"],
                _SECTION_HINTS.get("resources"))
    memory_mb: "int | None" = None
    cpu_seconds: "int | None" = None
    if "memory_mb" in resource_data:
        _reject_null(resource_data["memory_mb"], "resources.memory_mb")
        try:
            memory_mb = _require_int(
                resource_data["memory_mb"], "resources.memory_mb", minimum=16
            )
        except PolicyValidationError as exc:
            issues.extend(exc.issues)
    if "cpu_seconds" in resource_data:
        _reject_null(resource_data["cpu_seconds"], "resources.cpu_seconds")
        try:
            cpu_seconds = _require_int(
                resource_data["cpu_seconds"], "resources.cpu_seconds", minimum=1
            )
        except PolicyValidationError as exc:
            issues.extend(exc.issues)

    # -- tripwires -------------------------------------------------------
    tripwires: tuple[PathPattern, ...] = ()
    if "tripwires" in document:
        _reject_null(document["tripwires"], "tripwires")
        entries = _require_array(document["tripwires"], "tripwires")
        compiled: list[PathPattern] = []
        seen: set[str] = set()
        for index, entry in enumerate(entries):
            location = f"tripwires[{index}]"
            if isinstance(entry, Mapping):
                issues.append(
                    _issue(
                        location,
                        "Policy V1 tripwires are path patterns; the object form "
                        "belongs to the tripwire registry, not the document",
                        "wrong_type",
                    )
                )
                continue
            try:
                pattern = compile_pattern(entry, location)
            except PolicyValidationError as exc:
                issues.extend(exc.issues)
                continue
            if pattern.pattern in seen:
                issues.append(
                    _issue(location, f"duplicate tripwire {pattern.pattern!r}",
                           "duplicate_rule")
                )
                continue
            seen.add(pattern.pattern)
            compiled.append(pattern)
        tripwires = tuple(sorted(compiled, key=lambda item: item.pattern))

    # -- on_violation ----------------------------------------------------
    on_violation: dict[str, str] = {
        "filesystem": "DENY",
        "network": "DENY",
        "process": "DENY",
        "resources": "QUARANTINE",
        "tripwire": "KILL",
    }
    if "on_violation" in document:
        _reject_null(document["on_violation"], "on_violation")
        violation_data = _require_object(document["on_violation"], "on_violation")
        _check_keys(violation_data, "on_violation", VIOLATION_CLASSES)
        for key in sorted(violation_data):
            location = f"on_violation.{key}"
            raw = violation_data[key]
            _reject_null(raw, location)
            decision = _require_string(raw, location).upper()
            if decision not in ON_VIOLATION_DECISIONS:
                if decision == "ALLOW":
                    issues.append(
                        _issue(
                            location,
                            "'ALLOW' is not permitted: a violation class that "
                            "decides nothing is the same as omitting it, and "
                            "this spelling invites a document that quietly "
                            "disables a control",
                            "allow_not_permitted",
                        )
                    )
                else:
                    issues.append(
                        _issue(
                            location,
                            f"must be one of "
                            f"{', '.join(ON_VIOLATION_DECISIONS)}, got {raw!r}",
                            "invalid_enum",
                        )
                    )
                continue
            if key == "tripwire" and decision != "KILL":
                issues.append(
                    _issue(
                        location,
                        f"a tripwire can only be KILL; {decision!r} is refused "
                        "rather than recorded, because the enforcement engine "
                        "cannot honour a downgraded tripwire",
                        "unsupported_decision",
                    )
                )
                continue
            on_violation[key] = decision

    if issues:
        raise PolicyValidationError(
            summary="policy document is not valid", issues=issues
        )

    return PolicyV1(
        version=version,
        name=name,
        filesystem=FilesystemSection(allow=allow, deny=deny),
        network=NetworkSection(
            mode=mode, allow=network_allow, deny=network_deny
        ),
        process=ProcessSection(
            max_children=max_children, max_runtime_seconds=max_runtime
        ),
        resources=ResourceSection(memory_mb=memory_mb, cpu_seconds=cpu_seconds),
        tripwires=tripwires,
        on_violation=on_violation,
    )


def loads_policy(text: str, source: str = "<string>") -> PolicyV1:
    """Parse a Policy V1 document from text."""
    if not isinstance(text, str):
        _fail("", f"expected a string document, got {_type_name(text)}", "wrong_type")
    if text.startswith("\ufeff"):
        raise PolicyParseError(
            f"{source} starts with a UTF-8 byte-order mark; Policy V1 documents "
            "must be UTF-8 without a BOM (save the file as 'UTF-8', not "
            "'UTF-8 with BOM')"
        )
    return parse_policy(_decode_document(text, source))


def load_policy(path: str) -> PolicyV1:
    """Load and validate a Policy V1 document from a file.

    Encoding and size are checked before parsing: the file must be UTF-8 without
    a BOM and no larger than :data:`MAX_DOCUMENT_BYTES`. A malformed byte
    sequence is reported as a parse error naming the offset, never decoded
    leniently - a policy that decodes "as best it can" is a policy nobody can
    predict.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_DOCUMENT_BYTES + 1)
    except OSError as exc:
        raise PolicyParseError(f"cannot read policy file {path}: {exc}") from exc

    if len(raw) > MAX_DOCUMENT_BYTES:
        raise PolicyParseError(
            f"{path} is larger than {MAX_DOCUMENT_BYTES} bytes; a policy "
            "document is configuration, not data"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyParseError(
            f"{path} is not valid UTF-8: byte 0x{raw[exc.start]:02x} at offset "
            f"{exc.start} is not a valid sequence"
        ) from exc

    return loads_policy(text, source=path)
