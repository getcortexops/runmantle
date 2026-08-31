"""Internal validation helpers shared by the framework's value objects.

This module is private. It exists only to keep the identical
"must not be empty" and "must be unique" guards in one place; every helper
raises exactly the messages the individual value objects raised before.
"""

from __future__ import annotations

from collections.abc import Iterable


def require_non_empty(value: object, label: str) -> None:
    """Reject a missing, non-string, or whitespace-only declared value."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must not be empty")


def require_non_empty_attributes(
    instance: object,
    attributes: Iterable[str],
    *,
    prefix: str = "",
) -> None:
    """Apply :func:`require_non_empty` to each named attribute of ``instance``."""

    for attribute in attributes:
        label = f"{prefix} {attribute}" if prefix else attribute
        require_non_empty(getattr(instance, attribute), label)


def require_unique(values: Iterable[str], message: str) -> None:
    """Reject duplicate identifiers within one declared collection."""

    items = list(values)
    if len(items) != len(set(items)):
        raise ValueError(message)


def require_aware(moment: object, label: str) -> None:
    """Reject a naive timestamp on a value object that requires UTC offsets."""

    utcoffset = getattr(moment, "utcoffset", None)
    if utcoffset is None or utcoffset() is None:
        raise ValueError(label)
