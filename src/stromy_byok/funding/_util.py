"""Small parsing helpers shared by the funding modules. Never raise."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any


def num(value: Any) -> float | None:
    """A finite, non-negative, non-boolean number, else None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        return None
    return float(value)


def positive(value: Any) -> float | None:
    """A finite, strictly positive, non-boolean number, else None."""
    n = num(value)
    return n if n is not None and n > 0 else None


def aware(value: Any) -> datetime | None:
    """A timezone-aware ISO-8601 timestamp, else None (``Z`` accepted)."""
    if not isinstance(value, str):
        return None
    try:
        at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return at if at.tzinfo is not None else None


def iso_z(at: datetime) -> str:
    """``YYYY-MM-DDTHH:MM:SSZ`` in UTC."""
    return at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def mapping(value: Any) -> dict[str, Any]:
    """``value`` when it is a dict, else an empty dict."""
    return value if isinstance(value, dict) else {}  # pyright: ignore[reportUnknownVariableType]
