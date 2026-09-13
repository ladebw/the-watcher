"""Deterministic canonical serialisation.

Adapted from AAIP's deterministic Proof-of-Execution idea
(``json.dumps(payload, sort_keys=True, separators=(",", ":"))``) and hardened:

* every value is normalised to a small, stable set of JSON types first;
* unsupported or ambiguous values raise instead of silently degrading;
* the same logical value always produces the same bytes across platforms,
  Python versions and dict insertion orders.

The output is used as the pre-image of every SHA-256 digest in the trace, so
determinism here is what makes tamper detection meaningful.
"""

from __future__ import annotations

import dataclasses
import datetime as _datetime
import decimal
import enum
import hashlib
import json
import math
import pathlib
import uuid
from collections.abc import Mapping, Sequence, Set
from typing import Any

from ..exceptions import CanonicalizationError

__all__ = [
    "normalise",
    "canonical_json",
    "canonical_bytes",
    "sha256_hex",
    "hash_value",
    "is_hex_digest",
    "GENESIS_HASH",
]

# The chain anchor. ``previous_hash`` of the first event is always this value.
GENESIS_HASH = "0" * 64

_MAX_DEPTH = 64
_HEX_DIGEST_LEN = 64


def _normalise(obj: Any, depth: int = 0) -> Any:
    """Recursively coerce ``obj`` into a deterministic, JSON-safe structure."""
    if depth > _MAX_DEPTH:
        raise CanonicalizationError(
            f"value nested deeper than {_MAX_DEPTH} levels cannot be canonicalised"
        )

    if obj is None or isinstance(obj, (bool, str)):
        return obj

    # bool is a subclass of int, so it must be handled above this branch.
    if isinstance(obj, int):
        return obj

    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise CanonicalizationError(
                f"non-finite float {obj!r} has no deterministic JSON representation"
            )
        # Collapse the negative zero representation.
        return 0.0 if obj == 0.0 else obj

    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj).hex()

    if isinstance(obj, decimal.Decimal):
        return str(obj)

    if isinstance(obj, _datetime.datetime):
        if obj.tzinfo is not None:
            obj = obj.astimezone(_datetime.timezone.utc)
        return obj.isoformat()

    if isinstance(obj, _datetime.date):
        return obj.isoformat()

    if isinstance(obj, enum.Enum):
        return _normalise(obj.value, depth + 1)

    if isinstance(obj, pathlib.PurePath):
        return str(obj)

    if isinstance(obj, uuid.UUID):
        return str(obj)

    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return _normalise(dataclasses.asdict(obj), depth + 1)

    if isinstance(obj, Mapping):
        normalised: dict[str, Any] = {}
        for key, value in obj.items():
            name = key if isinstance(key, str) else str(key)
            if name in normalised:
                raise CanonicalizationError(
                    f"mapping keys collide after string coercion: {name!r}"
                )
            normalised[name] = _normalise(value, depth + 1)
        return normalised

    # Sets have no inherent order, so order them by their canonical encoding.
    if isinstance(obj, (Set, frozenset)):
        items = [_normalise(value, depth + 1) for value in obj]
        return sorted(items, key=canonical_json)

    if isinstance(obj, Sequence):
        return [_normalise(value, depth + 1) for value in obj]

    raise CanonicalizationError(
        f"unsupported type for canonicalisation: {type(obj).__name__}"
    )


def normalise(obj: Any) -> Any:
    """Return a canonical, JSON-safe copy of ``obj``."""
    return _normalise(obj)


def canonical_json(obj: Any) -> str:
    """Return the canonical JSON encoding of ``obj`` as an ASCII string."""
    return json.dumps(
        _normalise(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_bytes(obj: Any) -> bytes:
    """Return the canonical JSON encoding of ``obj`` as UTF-8 bytes."""
    return canonical_json(obj).encode("utf-8")


def sha256_hex(data: "bytes | bytearray | memoryview | str") -> str:
    """Return the lowercase hex SHA-256 digest of ``data``."""
    if isinstance(data, str):
        raw = data.encode("utf-8")
    elif isinstance(data, (bytearray, memoryview)):
        raw = bytes(data)
    elif isinstance(data, bytes):
        raw = data
    else:
        raise CanonicalizationError(
            f"sha256_hex expects bytes or str, got {type(data).__name__}"
        )
    return hashlib.sha256(raw).hexdigest()


def hash_value(value: Any) -> str:
    """Return a privacy-preserving digest for an arbitrary value.

    Strings are hashed as their raw UTF-8 bytes (matching AAIP's
    ``sha256(raw.encode())`` convention for outputs); every other type is
    hashed through its canonical JSON encoding.
    """
    if isinstance(value, str):
        return sha256_hex(value.encode("utf-8"))
    return sha256_hex(canonical_bytes(value))


def is_hex_digest(value: Any) -> bool:
    """Return ``True`` when ``value`` looks like a 64-character hex digest."""
    if not isinstance(value, str) or len(value) != _HEX_DIGEST_LEN:
        return False
    return all(char in "0123456789abcdef" for char in value.lower())
