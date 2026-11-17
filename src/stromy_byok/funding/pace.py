"""Expiry pacing: will a free credit grant expire unused?

Free credit is a sunk cost that expires; a cheap paid provider is cash. So a
consumer asks not only "may I spend this grant?" (:func:`~stromy_byok.funding.guard.decide`)
but "is it on track to be wasted?". :func:`pace` answers from fields a capture
row already holds (``credits_left``, ``used_usd``, ``window_start``,
``grant_expires_at``, ``per_cycle``)::

    burn             = used_usd / max(elapsed_days, 1)
    projected_unused = credits_left - burn * days_left

    surplus   projected_unused >= max(20, 10% of per_cycle)
    short     projected_unused <  0
    on-pace   otherwise
    unknown   any input missing/invalid, or no time left

Pacing never widens admission: the guard still decides every call.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from stromy_byok.funding._util import aware, mapping, num

__all__ = ["ON_PACE", "SHORT", "SURPLUS", "SURPLUS_FLOOR_USD", "SURPLUS_FRACTION", "UNKNOWN", "pace",
           "surplus_threshold"]

SURPLUS, ON_PACE, SHORT, UNKNOWN = "surplus", "on-pace", "short", "unknown"
SURPLUS_FLOOR_USD = 20.0
SURPLUS_FRACTION = 0.10


def surplus_threshold(per_cycle: float | None) -> float:
    return max(SURPLUS_FLOOR_USD, SURPLUS_FRACTION * (per_cycle or 0.0))


def pace(row: Any, now: datetime) -> dict[str, Any]:
    """The pace of one capture row. Never raises; bad input is ``unknown``.

    Returns ``state``, ``projected_unused_usd``, ``burn_usd_per_day`` and
    ``days_left`` (the numbers are None when the state is ``unknown``).
    """
    out: dict[str, Any] = {"state": UNKNOWN, "projected_unused_usd": None, "burn_usd_per_day": None,
                           "days_left": None}
    if not isinstance(row, dict) or now.tzinfo is None:
        return out
    r = mapping(row)
    left, used, per_cycle = num(r.get("credits_left")), num(r.get("used_usd")), num(r.get("per_cycle"))
    start, expires = aware(r.get("window_start")), aware(r.get("grant_expires_at"))
    if left is None or used is None or start is None or expires is None:
        return out
    days_left = (expires - now).total_seconds() / 86400
    if days_left <= 0 or now < start:
        return out
    burn = used / max((now - start).total_seconds() / 86400, 1.0)
    projected = left - burn * days_left
    state = SURPLUS if projected >= surplus_threshold(per_cycle) else SHORT if projected < 0 else ON_PACE
    return {"state": state, "projected_unused_usd": round(projected, 2), "burn_usd_per_day": round(burn, 4),
            "days_left": round(days_left, 3)}
