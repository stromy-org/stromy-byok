"""Funding sources: which free credit grant may pay, and through which key.

A *funding source* is one ``credit-allowance`` entry of a caller-supplied
register (the shape of a subscriptions register: ``{"schema": ...,
"subscriptions": [...]}``). This module parses those entries into
:class:`FundingSource` values and orders them soonest expiry first. It holds
logic only: the register, the clock and the credential store are inputs, so a
local operator run and a hosted run differ only in who supplies them.

Grant windows (ORG-PLAN-589 D4):

- An **observed** grant (``allowance.grant``) that is active, or not yet
  started, is the current grant.
- Otherwise, when the entry declares ``allowance.recurrence``, the immediate
  successor of the latest observed expiry is *forecast*: it starts at that
  expiry and ends ``min_period_days`` later. A forecast is reporting only — the
  guard HOLDs it (``recurring-unconfirmed``) until an authorized source records
  it as observed. An expired forecast never generates another one.
- No observed grant at all derives nothing.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from stromy_byok.funding._util import aware, mapping, num, positive
from stromy_byok.models import CredentialId, Subject
from stromy_byok.store import CredentialReader

__all__ = [
    "MAX_PERIOD_DAYS",
    "MIN_PERIOD_DAYS",
    "FundingSource",
    "Grant",
    "KeyRef",
    "Recurrence",
    "current_grant",
    "key_available",
    "observed_grants",
    "parse_recurrence",
    "parse_source",
    "recurrence_problems",
    "sources",
]

Basis = Literal["observed", "recurring"]

#: Bounds on ``recurrence.min_period_days``: a monthly credit is never shorter
#: than a day nor, for the providers this models, longer than 40 days.
MIN_PERIOD_DAYS = 1
MAX_PERIOD_DAYS = 40

#: The default inference key env per vendor, when the entry names none.
DEFAULT_KEY_ENV: dict[str, str] = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}


@dataclass(frozen=True, slots=True)
class Grant:
    """One credit grant's window and amount. ``basis`` says whether it was seen."""

    id: str
    amount_usd: float
    starts_at: datetime
    expires_at: datetime
    basis: Basis = "observed"

    def active(self, now: datetime) -> bool:
        return self.starts_at <= now < self.expires_at


@dataclass(frozen=True, slots=True)
class Recurrence:
    """A declared monthly renewal: the amount and the shortest possible cycle."""

    per_cycle_usd: float
    min_period_days: int


@dataclass(frozen=True, slots=True)
class KeyRef:
    """Where a key lives: an env name (local) or a closed-catalogue credential id (hosted).

    Exactly one is set. A reference never carries a value.
    """

    env: str | None = None
    credential_id: str | None = None

    def __post_init__(self) -> None:
        if (self.env is None) == (self.credential_id is None):
            raise ValueError("KeyRef needs exactly one of env or credential_id")
        if self.credential_id is not None:
            CredentialId(self.credential_id)  # validates the grammar

    @property
    def label(self) -> str:
        """A loggable name for the reference (never a value)."""
        return f"env:{self.env}" if self.env is not None else f"credential:{self.credential_id}"


@dataclass(frozen=True, slots=True)
class FundingSource:
    """One funding source of one tenant, with its current grant resolved for ``now``."""

    id: str
    vendor: str
    tenant: str
    key_ref: KeyRef | None
    admin_ref: KeyRef | None
    per_cycle: float
    grant: Grant | None
    previous_grants: tuple[Grant, ...] = ()
    recurrence: Recurrence | None = None
    holder: str | None = None
    console_org: str | None = None
    extra: Mapping[str, Any] = field(default_factory=lambda: {}, compare=False, repr=False)

    @property
    def basis(self) -> Basis | None:
        return self.grant.basis if self.grant is not None else None

    @property
    def expires_at(self) -> datetime | None:
        return self.grant.expires_at if self.grant is not None else None


def _grant(raw: Any, *, basis: Basis = "observed") -> Grant | None:
    g = mapping(raw)
    starts, expires, amount = aware(g.get("starts_at")), aware(g.get("expires_at")), num(g.get("amount_usd"))
    gid = g.get("id")
    if starts is None or expires is None or amount is None or not isinstance(gid, str) or not gid or expires <= starts:
        return None
    return Grant(id=gid, amount_usd=amount, starts_at=starts, expires_at=expires, basis=basis)


def parse_recurrence(raw: Any) -> Recurrence | None:
    r = mapping(raw)
    per_cycle, period = positive(r.get("per_cycle_usd")), r.get("min_period_days")
    if per_cycle is None or isinstance(period, bool) or not isinstance(period, int):
        return None
    if not MIN_PERIOD_DAYS <= period <= MAX_PERIOD_DAYS:
        return None
    return Recurrence(per_cycle_usd=per_cycle, min_period_days=period)


def observed_grants(allowance: Mapping[str, Any]) -> tuple[Grant | None, tuple[Grant, ...]]:
    """(the recorded current grant, the valid previous grants) of one allowance block."""
    previous_raw: Any = allowance.get("previous_grants")
    previous: list[Grant] = []
    if isinstance(previous_raw, list):
        for item in previous_raw:  # pyright: ignore[reportUnknownVariableType]
            g = _grant(item)
            if g is not None:
                previous.append(g)
    return _grant(allowance.get("grant")), tuple(previous)


def current_grant(*, observed: Grant | None, previous: tuple[Grant, ...], recurrence: Recurrence | None,
                  per_cycle: float, source_id: str, now: datetime) -> Grant | None:
    """The grant that applies at ``now`` under D4, or None.

    An observed grant that has not expired wins (a not-yet-started one too, so
    the guard can say ``grant-not-started``). Otherwise the one forecast
    successor of the latest observed expiry, while it lasts. A disabled source
    (``per_cycle`` 0) or one with no observation derives nothing.
    """
    if observed is not None and now < observed.expires_at:
        return observed
    if recurrence is None or per_cycle <= 0:
        return None
    seen = [g for g in (observed, *previous) if g is not None]
    if not seen:
        return None
    latest = max(seen, key=lambda g: g.expires_at)
    starts = latest.expires_at
    expires = starts + timedelta(days=recurrence.min_period_days)
    if now >= expires:
        return None  # one forecast only: an expired forecast is not renewed again
    return Grant(id=f"{source_id}-forecast-{starts.date().isoformat()}",
                 amount_usd=min(recurrence.per_cycle_usd, per_cycle),
                 starts_at=starts, expires_at=expires, basis="recurring")


def _key_ref(block: Mapping[str, Any], env_field: str, credential_field: str, default_env: str | None) -> KeyRef | None:
    cred, env = block.get(credential_field), block.get(env_field)
    if isinstance(cred, str) and cred:
        return KeyRef(credential_id=cred)
    if isinstance(env, str) and env:
        return KeyRef(env=env)
    return KeyRef(env=default_env) if default_env else None


def parse_source(entry: Mapping[str, Any], *, now: datetime, legacy_tenant: str | None = None) -> FundingSource:
    """Parse one ``credit-allowance`` entry. Raises ValueError on an unusable entry.

    Inference key: ``allowance.api_key_credential`` (hosted) or
    ``allowance.api_key_env`` (local; default per vendor). Admin key:
    ``probe.credential`` or ``probe.env``. A source with no inference key
    reference is still returned (reports list it) but can never pay. An entry with no ``account.tenant``
    belongs to ``legacy_tenant`` when one is given, else it is rejected.
    """
    if entry.get("kind") != "credit-allowance":
        raise ValueError("not a credit-allowance entry")
    sid = entry.get("id")
    if not isinstance(sid, str) or not sid:
        raise ValueError("entry id is missing")
    vendor = str(entry.get("vendor") or "").strip().lower()
    if not vendor:
        raise ValueError(f"{sid}: vendor is missing")
    account = mapping(entry.get("account"))
    tenant = account.get("tenant") or legacy_tenant
    if not isinstance(tenant, str) or not tenant:
        raise ValueError(f"{sid}: account.tenant is missing")
    allowance = mapping(entry.get("allowance"))
    per_cycle = num(allowance.get("per_cycle"))
    if per_cycle is None:
        raise ValueError(f"{sid}: allowance.per_cycle is not a finite, non-negative number")
    key_ref = _key_ref(allowance, "api_key_env", "api_key_credential", DEFAULT_KEY_ENV.get(vendor))
    probe = mapping(entry.get("probe"))
    admin_ref = _key_ref(probe, "env", "credential", None)
    observed, previous = observed_grants(allowance)
    recurrence = parse_recurrence(allowance.get("recurrence"))
    holder, org = account.get("holder"), account.get("console_org")
    return FundingSource(
        id=sid, vendor=vendor, tenant=tenant, key_ref=key_ref, admin_ref=admin_ref, per_cycle=per_cycle,
        grant=current_grant(observed=observed, previous=previous, recurrence=recurrence, per_cycle=per_cycle,
                            source_id=sid, now=now),
        previous_grants=previous, recurrence=recurrence,
        holder=holder if isinstance(holder, str) else None,
        console_org=org if isinstance(org, str) else None,
        extra=entry,
    )


def _entries(register: Any) -> list[Mapping[str, Any]]:
    reg = mapping(register)
    subs: Any = reg.get("subscriptions")
    if not isinstance(subs, list):
        return []
    return [e for e in subs if isinstance(e, dict)]  # pyright: ignore[reportUnknownVariableType]


def sources(register: Any, *, tenant: str, now: datetime, vendor: str | None = None,
            legacy_tenant: str | None = None, include_disabled: bool = False) -> list[FundingSource]:
    """Every funding source of ``tenant`` (optionally one vendor), soonest expiry first.

    Sources with no current grant sort last; ties break on id. Another tenant's
    source is never returned, nor a disabled one (``per_cycle`` 0) unless
    ``include_disabled``. Unparseable entries are skipped: they cannot fund.
    """
    want_vendor = vendor.strip().lower() if vendor is not None else None
    found: list[FundingSource] = []
    for entry in _entries(register):
        if entry.get("kind") != "credit-allowance":
            continue
        try:
            src = parse_source(entry, now=now, legacy_tenant=legacy_tenant)
        except ValueError:
            continue
        if src.tenant != tenant or (want_vendor is not None and src.vendor != want_vendor):
            continue
        if src.per_cycle <= 0 and not include_disabled:
            continue
        found.append(src)
    return sorted(found, key=_order_key)


def _order_key(src: FundingSource) -> tuple[int, str, str]:
    exp = src.expires_at
    return (0 if exp is not None else 1, exp.isoformat() if exp is not None else "", src.id)


def recurrence_problems(eid: str, allowance: Mapping[str, Any]) -> list[str]:
    """Validation of ``allowance.recurrence`` for a register checker.

    ``per_cycle_usd`` positive and within a positive ``per_cycle``;
    ``min_period_days`` an integer in bounds and no longer than the current
    observed grant's window (a renewal cannot be expected sooner than a cycle
    we have seen). Previous grants do not bound it: their recorded windows may
    be truncated for accounting.
    """
    raw: Any = allowance.get("recurrence")
    if raw is None:
        return []
    if not isinstance(raw, dict):
        return [f"{eid}: allowance.recurrence must be an object"]
    rec = mapping(raw)
    problems: list[str] = []
    unknown = sorted(set(rec) - {"per_cycle_usd", "min_period_days", "source"})
    if unknown:
        problems.append(f"{eid}: allowance.recurrence has unknown field(s) {', '.join(unknown)}")
    per_cycle_usd = positive(rec.get("per_cycle_usd"))
    if per_cycle_usd is None:
        problems.append(f"{eid}: allowance.recurrence.per_cycle_usd must be a positive number")
    else:
        cap = num(allowance.get("per_cycle"))
        if cap is not None and cap > 0 and per_cycle_usd > cap:
            problems.append(f"{eid}: allowance.recurrence.per_cycle_usd exceeds per_cycle")
    period = rec.get("min_period_days")
    if isinstance(period, bool) or not isinstance(period, int) or not MIN_PERIOD_DAYS <= period <= MAX_PERIOD_DAYS:
        problems.append(f"{eid}: allowance.recurrence.min_period_days must be an integer "
                        f"{MIN_PERIOD_DAYS}–{MAX_PERIOD_DAYS}")
    else:
        observed, _ = observed_grants(allowance)
        if observed is not None:
            cycle = (observed.expires_at - observed.starts_at).total_seconds() / 86400
            if period > cycle:
                problems.append(f"{eid}: allowance.recurrence.min_period_days {period} exceeds the observed "
                                f"grant's {cycle:g}-day window")
    return problems


def key_available(ref: KeyRef | None, *, environ: Mapping[str, str] | None = None,
                  reader: CredentialReader | None = None, subject: Subject | None = None) -> bool:
    """Whether the referenced key is present, without returning it.

    An env reference reads only ``environ``; a credential reference asks only the
    ``reader`` for ``subject`` (``exists``). A credential id is never looked up
    in the environment, and an env name never in the store. No reference: False.
    """
    if ref is None:
        return False
    if ref.credential_id is not None:
        if reader is None or subject is None:
            return False
        return bool(reader.exists(CredentialId(ref.credential_id), subject))
    if environ is None or ref.env is None:
        return False
    return bool(environ.get(ref.env))
