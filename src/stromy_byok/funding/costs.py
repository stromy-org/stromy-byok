"""Bounded vendor cost readers and the pure capture builder.

Two readers, one per vendor, each returning a normalized :class:`CostReport`
(total USD over a frozen window, plus usage-coverage evidence). Readers never
see a grant amount or a register digest: :func:`allowance_row` and
:func:`capture_envelope` combine a resolved grant with a report into the capture
row the guard reads.

Hardening shared by both readers:

- host, path and query-key allowlists per endpoint; HTTPS only, no port;
- a transport that refuses redirects (an admin header must never follow one);
- every page read or nothing: a broken page, a missing or repeated cursor, a
  malformed envelope or a transport error invalidates the whole read;
- fixed, redacted error reasons — never a response body, never a key.

Units: Anthropic's ``cost_report`` returns US **cents** (``amount`` with
``currency == "USD"``); OpenAI's ``/v1/organization/costs`` returns **USD** in
``amount.value`` with lowercase ``amount.currency == "usd"``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from stromy_byok.funding._util import iso_z, mapping
from stromy_byok.funding.guard import CAPTURE_SCHEMA
from stromy_byok.funding.model import Grant

__all__ = [
    "ANTHROPIC_COST_REPORT_PATH",
    "ANTHROPIC_HOST",
    "ANTHROPIC_USAGE_REPORT_PATH",
    "OPENAI_COSTS_PATH",
    "OPENAI_HOST",
    "CostReadError",
    "CostReport",
    "Transport",
    "admin_report",
    "allowance_row",
    "anthropic_cost_report",
    "capture_envelope",
    "cost_cents",
    "default_transport",
    "openai_admin_read",
    "openai_costs",
    "priority_tier_seen",
]

#: (method, url, headers) -> (status, body). Tests pass a recorded transport.
Transport = Callable[[str, str, dict[str, str]], tuple[int, bytes]]

TIMEOUT_S = 20
MAX_PAGES = 20

ANTHROPIC_HOST = "api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"
ANTHROPIC_COST_REPORT_PATH = "/v1/organizations/cost_report"
ANTHROPIC_USAGE_REPORT_PATH = "/v1/organizations/usage_report/messages"
#: cost_report costs these service tiers only; anything else is uncosted usage.
COSTED_SERVICE_TIERS = ("standard", "batch")

OPENAI_HOST = "api.openai.com"
OPENAI_COSTS_PATH = "/v1/organization/costs"

ALLOWED: dict[str, dict[str, frozenset[str]]] = {
    ANTHROPIC_HOST: {
        ANTHROPIC_COST_REPORT_PATH: frozenset({"starting_at", "ending_at", "page", "limit", "group_by[]"}),
        ANTHROPIC_USAGE_REPORT_PATH: frozenset({"starting_at", "ending_at", "page", "limit", "group_by[]",
                                                "bucket_width"}),
        "/v1/organizations/me": frozenset(),
    },
    OPENAI_HOST: {
        OPENAI_COSTS_PATH: frozenset({"start_time", "end_time", "bucket_width", "limit", "page", "group_by"}),
        "/v1/organization/projects": frozenset({"limit", "after"}),
        "/v1/organization/admin_api_keys": frozenset({"limit", "after", "order"}),
    },
}


class CostReadError(Exception):
    """The whole read is unusable. ``read`` is ``rejected`` (HTTP 4xx) or ``error``."""

    def __init__(self, read: str, reason: str, http: int | None = None) -> None:
        super().__init__(reason)
        self.read, self.reason, self.http = read, reason, http


@dataclass(frozen=True, slots=True)
class CostReport:
    """Normalized cost over one frozen half-open window ``[start, end)``.

    ``uncosted_usage`` is True when usage was seen that the report does not
    cost (Anthropic Priority Tier), False when coverage is complete, None when
    the reader could not tell.
    """

    vendor: str
    total_usd: Decimal
    start: datetime
    end: datetime
    uncosted_usage: bool | None
    buckets: tuple[dict[str, Any], ...] = field(default=(), repr=False)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: urllib would otherwise forward the admin header."""

    def redirect_request(self, req: Any, fp: Any, code: Any, msg: Any, headers: Any, newurl: Any) -> None:  # noqa: ARG002
        return None  # urllib then raises HTTPError carrying the 3xx code


def default_transport(method: str, url: str, headers: dict[str, str]) -> tuple[int, bytes]:
    """urllib GET with no redirects and a timeout. A non-2xx returns an empty body."""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers=headers, method=method)  # noqa: S310 (allowlisted https)
    try:
        with opener.open(req, timeout=TIMEOUT_S) as resp:  # noqa: S310
            return int(resp.status), bytes(resp.read())
    except urllib.error.HTTPError as exc:
        return int(exc.code), b""


def _allowed(url: str) -> bool:
    parts = urllib.parse.urlsplit(url)
    paths = ALLOWED.get(parts.hostname or "")
    if parts.scheme != "https" or parts.port is not None or paths is None:
        return False
    keys = paths.get(parts.path)
    present = {k for k, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)}
    return keys is not None and present <= keys


def _get_json(url: str, headers: dict[str, str], transport: Transport) -> dict[str, Any]:
    if not _allowed(url):
        raise CostReadError("error", "not-allowlisted")
    try:
        status, body = transport("GET", url, headers)
    except (OSError, ValueError) as exc:
        raise CostReadError("error", type(exc).__name__) from None
    if 400 <= status < 500:
        raise CostReadError("rejected", f"HTTP {status}", status)
    if status != 200:
        raise CostReadError("error", f"HTTP {status}", status)
    try:
        doc: Any = json.loads(body)
    except ValueError:
        raise CostReadError("error", "non-JSON reply") from None
    if not isinstance(doc, dict):
        raise CostReadError("error", "malformed report envelope")
    return mapping(doc)


def _pages(host: str, path: str, query: list[tuple[str, str]], headers: dict[str, str], transport: Transport,
           max_pages: int) -> list[dict[str, Any]]:
    buckets: list[dict[str, Any]] = []
    cursor: str | None = None
    seen: set[str] = set()
    for _ in range(max_pages):
        q = list(query) + ([("page", cursor)] if cursor else [])
        doc = _get_json(f"https://{host}{path}?{urllib.parse.urlencode(q)}", headers, transport)
        data: Any = doc.get("data")
        if not isinstance(data, list) or not isinstance(doc.get("has_more"), bool):
            raise CostReadError("error", "malformed report envelope")
        for bucket in data:  # pyright: ignore[reportUnknownVariableType]
            if not isinstance(bucket, dict) or not isinstance(mapping(bucket).get("results"), list):
                raise CostReadError("error", "malformed report bucket")
            buckets.append(mapping(bucket))
        if not doc["has_more"]:
            return buckets
        nxt = doc.get("next_page")
        if not isinstance(nxt, str) or not nxt:
            raise CostReadError("error", "has_more without a next_page cursor")
        if nxt in seen:
            raise CostReadError("error", "repeated next_page cursor")
        seen.add(nxt)
        cursor = nxt
    raise CostReadError("error", f"more than {max_pages} pages")


# --- Anthropic ---------------------------------------------------------------------------------------------

def _anthropic_headers(key: str) -> dict[str, str]:
    return {"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION, "Accept": "application/json"}


def admin_report(path: str, query: list[tuple[str, str]], key: str, *, transport: Transport = default_transport,
                 max_pages: int = MAX_PAGES) -> list[dict[str, Any]]:
    """Every bucket of one Anthropic admin report across all its pages, or CostReadError."""
    return _pages(ANTHROPIC_HOST, path, query, _anthropic_headers(key), transport, max_pages)


def cost_cents(buckets: Iterable[dict[str, Any]]) -> Decimal:
    """Exact total in US cents across every workspace and cost type of an Anthropic cost report."""
    total = Decimal(0)
    for bucket in buckets:
        for result in bucket["results"]:
            res = mapping(result)
            if not isinstance(result, dict) or res.get("currency") != "USD":
                raise CostReadError("error", "cost result is not USD")
            amount = res.get("amount")
            if isinstance(amount, bool) or not isinstance(amount, (str, int, float)):
                raise CostReadError("error", "cost amount is not a number")
            try:
                cents = Decimal(str(amount))
            except InvalidOperation:
                raise CostReadError("error", "cost amount is not a number") from None
            if not cents.is_finite() or cents < 0:
                raise CostReadError("error", "cost amount is not finite and non-negative")
            total += cents
    return total


def priority_tier_seen(buckets: Iterable[dict[str, Any]]) -> bool:
    """True when any usage row ran on a tier cost_report does not cost."""
    return any(isinstance(r, dict) and mapping(r).get("service_tier") not in (None, *COSTED_SERVICE_TIERS)
               for b in buckets for r in b["results"])


def anthropic_cost_report(key: str, *, start: datetime, end: datetime, transport: Transport = default_transport,
                          max_pages: int = MAX_PAGES) -> CostReport:
    """The organisation's reported cost over ``[start, end)`` plus Priority Tier coverage.

    Two reads over the same frozen window: ``cost_report`` (grouped by
    workspace and description) and the messages usage report by service tier.
    """
    window = [("starting_at", iso_z(start)), ("ending_at", iso_z(end))]
    cost = admin_report(ANTHROPIC_COST_REPORT_PATH, [
        *window, ("group_by[]", "workspace_id"), ("group_by[]", "description"), ("limit", "31")], key,
        transport=transport, max_pages=max_pages)
    cents = cost_cents(cost)
    usage = admin_report(ANTHROPIC_USAGE_REPORT_PATH, [
        *window, ("group_by[]", "service_tier"), ("bucket_width", "1d"), ("limit", "31")], key,
        transport=transport, max_pages=max_pages)
    return CostReport(vendor="anthropic", total_usd=cents / 100, start=start, end=end,
                      uncosted_usage=priority_tier_seen(usage), buckets=tuple(cost))


# --- OpenAI ------------------------------------------------------------------------------------------------

def _openai_headers(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}", "Accept": "application/json"}


def _utc_midnight(at: datetime) -> datetime:
    at = at.astimezone(UTC)
    return datetime(at.year, at.month, at.day, tzinfo=UTC)


def _usd(value: Any) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise CostReadError("error", "cost amount is not a number")
    try:
        usd = Decimal(str(value))
    except InvalidOperation:
        raise CostReadError("error", "cost amount is not a number") from None
    if not usd.is_finite() or usd < 0:
        raise CostReadError("error", "cost amount is not finite and non-negative")
    return usd


def openai_costs(key: str, *, start: datetime, end: datetime, transport: Transport = default_transport,
                 max_pages: int = MAX_PAGES) -> CostReport:
    """The organisation's cost from the UTC midnight of ``start`` to ``end``, in USD.

    Buckets are UTC days. The query starts at the start day's midnight, so the
    intersecting first day counts in full (over-counts, erring toward HOLD); a
    bucket wholly outside the window is excluded. The end is frozen by the
    caller (``min(now, expiry)``). OpenAI cost covers every line item, so
    ``uncosted_usage`` is False.
    """
    if end <= start:
        raise CostReadError("error", "empty window")
    q_start = _utc_midnight(start)
    q_end_epoch = int(end.timestamp())
    q_start_epoch = int(q_start.timestamp())
    query = [("start_time", str(q_start_epoch)), ("end_time", str(q_end_epoch)), ("bucket_width", "1d"),
             ("limit", "31")]
    buckets = _pages(OPENAI_HOST, OPENAI_COSTS_PATH, query, _openai_headers(key), transport, max_pages)
    total = Decimal(0)
    for bucket in buckets:
        b_start, b_end = bucket.get("start_time"), bucket.get("end_time")
        if (isinstance(b_start, bool) or isinstance(b_end, bool) or not isinstance(b_start, int)
                or not isinstance(b_end, int) or b_end <= b_start):
            raise CostReadError("error", "malformed bucket window")
        if b_end <= q_start_epoch or b_start >= q_end_epoch:
            continue  # wholly outside the window
        for result in bucket["results"]:
            amount = mapping(mapping(result).get("amount"))
            if not isinstance(result, dict) or amount.get("currency") != "usd":
                raise CostReadError("error", "cost result is not usd")
            total += _usd(amount.get("value"))
    return CostReport(vendor="openai", total_usd=total, start=q_start, end=end, uncosted_usage=False,
                      buckets=tuple(buckets))


def openai_admin_read(path: str, query: list[tuple[str, str]], key: str, *,
                      transport: Transport = default_transport) -> dict[str, Any]:
    """One allowlisted OpenAI Admin API GET (organisation identity probes), or CostReadError."""
    return _get_json(f"https://{OPENAI_HOST}{path}?{urllib.parse.urlencode(query)}", _openai_headers(key),
                     transport)


# --- capture builder (pure) --------------------------------------------------------------------------------

def allowance_row(*, grant: Grant, per_cycle: float, report: CostReport, now: datetime) -> dict[str, Any]:
    """The estimated-allowance fields of one capture row: the grant minus the reported cost.

    ``report`` must cover ``[grant.starts_at or its UTC midnight, min(now, expiry))``.
    Reported cost lags, so the estimate can only overstate what is left; the
    guard's reserve absorbs that. An expired grant leaves nothing available.
    """
    cap = Decimal(str(min(per_cycle, grant.amount_usd)))
    available = cap if now < grant.expires_at else Decimal(0)
    used = report.total_usd
    left = max(Decimal(0), available - used)
    uncosted = report.uncosted_usage
    return {
        "read": "live", "verified_on": now.date().isoformat(), "balance_basis": "estimated",
        "used_usd": float(used.quantize(Decimal("0.0001"))),
        "credits_left": float(left.quantize(Decimal("0.01"))),
        "per_cycle": float(cap),
        "lapses_on": (grant.expires_at - timedelta(microseconds=1)).date().isoformat(),
        "grant_id": grant.id, "grant_expires_at": iso_z(grant.expires_at),
        "window_start": iso_z(grant.starts_at), "window_end": iso_z(report.end),
        "uncosted_priority_tier": uncosted,
        "reason": "priority-tier usage is not costed by cost_report" if uncosted else "",
    }


def capture_envelope(providers: list[dict[str, Any]], *, register_sha: str, now: datetime) -> dict[str, Any]:
    """The capture document the guard reads: schema, status, time, register digest and rows."""
    return {"schema": CAPTURE_SCHEMA, "status": "OK", "reason": "", "captured_at": iso_z(now),
            "register_sha": register_sha, "providers": providers}
