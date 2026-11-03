"""AWS action/resource pattern matching (case-insensitive, '*' and '?' globs)."""

from __future__ import annotations

import re
from functools import lru_cache


@lru_cache(maxsize=8192)
def _compile(pattern: str) -> re.Pattern:
    """Translate an AWS glob pattern into a compiled, case-insensitive regex."""
    parts = []
    for ch in pattern:
        if ch == "*":
            parts.append(".*")
        elif ch == "?":
            parts.append(".")
        else:
            parts.append(re.escape(ch))
    return re.compile("^" + "".join(parts) + "$", re.IGNORECASE | re.DOTALL)


def matches(pattern: str, value: str) -> bool:
    """True when `value` is selected by the AWS wildcard pattern `pattern`."""
    if pattern == "*" or pattern == value:
        return True
    return bool(_compile(pattern).match(value))


def service_of(action: str) -> str:
    """Service prefix of an action: 's3:GetObject' -> 's3'."""
    return action.split(":", 1)[0].lower() if ":" in action else action.lower()


def as_list(value) -> list[str]:
    """Normalize an AWS statement field that may be a string, list or None."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]
