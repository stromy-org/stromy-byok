"""Conservative admission against an estimated credit allowance.

One question, offline, with no key and no network: may work that expects to
spend ``need_usd`` start on ``allowance``, keeping ``reserve_usd`` back? The
inputs are the CURRENT register, its digest, and a capture envelope written by
a cost probe. OK only when every check passes and ``credits_left - need >=
reserve``. Anything missing, malformed, stale, expired, disabled, forecast or
changed since the capture HOLDs, and a HOLD is never an error: the caller falls
back.

What this is not: a reservation. Two callers that read the same capture both
see the same ``left``; the capture is a delayed estimate from a lagging cost
report, and unguarded jobs share the same balance. Provider spend limits stay
the aggregate backstop.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from stromy_byok.funding._util import aware, mapping, num
from stromy_byok.funding.model import current_grant, observed_grants, parse_recurrence

__all__ = ["CAPTURE_SCHEMA", "DEFAULT_MAX_AGE_HOURS", "HOLD", "OK", "REGISTER_SCHEMA", "decide"]

CAPTURE_SCHEMA = "subscriptions-usage-v1"
REGISTER_SCHEMA = "subscriptions-v1"
DEFAULT_MAX_AGE_HOURS = 36.0

OK, HOLD = "OK", "HOLD"


def _result(decision: str, code: str, reason: str, row: dict[str, Any] | None = None,
            capture: dict[str, Any] | None = None) -> dict[str, Any]:
    row = row or {}
    return {"decision": decision, "code": code, "reason": reason,
            "left": num(row.get("credits_left")), "captured_at": (capture or {}).get("captured_at"),
            "grant_id": row.get("grant_id"), "balance_basis": row.get("balance_basis")}


def _hold(code: str, reason: str, row: dict[str, Any] | None = None,
          capture: dict[str, Any] | None = None) -> dict[str, Any]:
    return _result(HOLD, code, reason, row, capture)


def _forecast_hold(allow: dict[str, Any], allowance: str, per_cycle: float, now: datetime) -> dict[str, Any] | None:
    observed, previous = observed_grants(allow)
    forecast = current_grant(observed=None, previous=tuple(g for g in (observed, *previous) if g is not None),
                             recurrence=parse_recurrence(allow.get("recurrence")), per_cycle=per_cycle,
                             source_id=allowance, now=now)
    if forecast is not None and forecast.basis == "recurring":
        return _hold("recurring-unconfirmed",
                     f"the next grant is forecast ({forecast.starts_at.date()} to {forecast.expires_at.date()}) "
                     "but not yet observed; a forecast never funds work")
    return None


def decide(*, capture: Any, register: Any, register_sha: str | None, allowance: str,
           need_usd: float, reserve_usd: float, now: datetime,
           max_age_hours: float = DEFAULT_MAX_AGE_HOURS, key_present: bool | None = None) -> dict[str, Any]:
    """OK only when every check passes and left - need >= reserve; HOLD otherwise.

    Checks, in order: the request; the current register and its entry; the
    entry's allowance and observed grant (enabled, active now; a forecast
    successor HOLDs ``recurring-unconfirmed``); the paying key when
    ``key_present`` is given; the capture's schema, status, timestamp (aware,
    not future, young enough); that the capture was taken against THIS register;
    exactly one matching row that is a live estimate of THIS grant; no uncosted
    usage; and finally the reserve.
    """
    need, reserve, ceiling = num(need_usd), num(reserve_usd), num(max_age_hours)
    if need is None or reserve is None or ceiling is None or ceiling <= 0:
        return _hold("invalid-request", "need, reserve and max age must be finite, non-negative numbers "
                     "(max age positive)")
    if now.tzinfo is None:
        return _hold("invalid-request", "the clock must be timezone-aware")

    # --- the current register: the only source of what is funded
    if not isinstance(register, dict) or not isinstance(register.get("subscriptions"), list):  # pyright: ignore[reportUnknownMemberType]
        return _hold("register-missing", "the current subscriptions register is missing or unreadable")
    reg = mapping(register)
    if reg.get("schema") != REGISTER_SCHEMA:
        return _hold("register-schema", f"register schema is {reg.get('schema')!r}, expected {REGISTER_SCHEMA!r}")
    entries = [mapping(e) for e in reg["subscriptions"] if isinstance(e, dict) and mapping(e).get("id") == allowance]
    if len(entries) != 1:
        return _hold("register-entry", f"the register has {len(entries)} entries named {allowance!r}, need exactly one")
    allow = mapping(entries[0].get("allowance"))
    per_cycle_raw = allow.get("per_cycle")
    per_cycle = num(per_cycle_raw)
    if per_cycle is None:
        return _hold("register-invalid", "allowance.per_cycle is not a finite, non-negative number")
    if per_cycle == 0:
        return _hold("disabled", "allowance.per_cycle is 0: the allowance is shut down for new work")
    grant_raw = allow.get("grant")
    grant = mapping(grant_raw) if isinstance(grant_raw, dict) else None
    if grant is None:
        return _forecast_hold(allow, allowance, per_cycle, now) or _hold(
            "no-grant", "no observed grant is recorded in the register")
    starts, expires = aware(grant.get("starts_at")), aware(grant.get("expires_at"))
    amount = num(grant.get("amount_usd"))
    if starts is None or expires is None or amount is None or not isinstance(grant.get("id"), str) or expires <= starts:
        return _hold("register-invalid", "the recorded grant has an invalid id, amount or window")
    if now < starts:
        return _hold("grant-not-started", f"the grant starts at {grant['starts_at']}")
    if now >= expires:
        return _forecast_hold(allow, allowance, per_cycle, now) or _hold(
            "grant-expired", f"the grant expired at {grant['expires_at']}; no new grant is recorded")
    if key_present is False:
        return _hold("key-missing", "the key this grant pays through is not available")

    # --- the capture
    if not isinstance(capture, dict):
        return _hold("capture-missing", "no subscriptions capture (run subscriptions.py probe --write-cache)")
    cap_doc = mapping(capture)
    if cap_doc.get("schema") != CAPTURE_SCHEMA:
        return _hold("capture-schema", f"capture schema is {cap_doc.get('schema')!r}, expected {CAPTURE_SCHEMA!r}",
                     capture=cap_doc)
    if cap_doc.get("status") != "OK":
        return _hold("capture-status", f"capture status is {cap_doc.get('status')!r}", capture=cap_doc)
    captured = aware(cap_doc.get("captured_at"))
    if captured is None:
        return _hold("capture-time", "capture captured_at is not a timezone-aware timestamp", capture=cap_doc)
    if captured > now:
        return _hold("capture-future", "capture captured_at is in the future", capture=cap_doc)
    if (now - captured).total_seconds() / 3600 > ceiling:
        return _hold("capture-stale", f"capture is older than {ceiling:g} hours", capture=cap_doc)
    if not register_sha or cap_doc.get("register_sha") != register_sha:
        return _hold("register-changed", "the register changed since the capture was taken; re-run the probe",
                     capture=cap_doc)
    providers: Any = cap_doc.get("providers") or []
    rows = [mapping(p) for p in providers if isinstance(p, dict) and mapping(p).get("id") == allowance]
    if len(rows) != 1:
        return _hold("capture-row", f"the capture has {len(rows)} rows named {allowance!r}, need exactly one",
                     capture=cap_doc)
    row = rows[0]
    if row.get("read") != "live":
        return _hold("not-live", f"the capture row reads {row.get('read')!r}, not live", row, cap_doc)
    if row.get("balance_basis") != "estimated":
        return _hold("not-estimated", "the capture row is not an estimated allowance", row, cap_doc)
    if (row.get("grant_id") != grant["id"] or aware(row.get("grant_expires_at")) != expires
            or aware(row.get("window_start")) != starts):
        return _hold("grant-mismatch", "the capture row describes a different grant than the register", row, cap_doc)
    cap = min(per_cycle, amount)
    if num(row.get("per_cycle")) != cap:
        return _hold("grant-mismatch", "the capture row's allowance differs from the register's", row, cap_doc)
    left = num(row.get("credits_left"))
    if left is None:
        return _hold("capture-invalid", "credits_left is not a finite, non-negative number", row, cap_doc)
    if row.get("uncosted_priority_tier") is not False:
        return _hold("uncosted-usage", "Priority Tier usage may be uncosted, or coverage is unknown", row, cap_doc)
    if left - need < reserve:
        return _hold("reserve", f"{left:g} left minus {need:g} needed is below the {reserve:g} reserve", row, cap_doc)
    return _result(OK, "ok", f"{left:g} left covers {need:g} plus the {reserve:g} reserve", row, cap_doc)
