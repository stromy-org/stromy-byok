"""stromy_byok.funding.costs — recorded-response readers and the capture round trip. No network."""

from __future__ import annotations

import json
import urllib.parse
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest

from stromy_byok.funding import (
    CostReadError,
    Grant,
    allowance_row,
    anthropic_cost_report,
    capture_envelope,
    decide,
    openai_costs,
)
from stromy_byok.funding.costs import admin_report, openai_admin_read

DAY = 86400


class Recorded:
    """A transport replaying responses in order and recording what was asked."""

    def __init__(self, *responses: tuple[int, Any]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, str]]] = []

    def __call__(self, method: str, url: str, headers: dict[str, str]) -> tuple[int, bytes]:
        assert method == "GET"
        self.calls.append((url, headers))
        status, body = self.responses.pop(0)
        return status, body if isinstance(body, bytes) else json.dumps(body).encode()


def _q(url: str) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)


# --- OpenAI ------------------------------------------------------------------------------------------------

START = datetime(2026, 11, 13, tzinfo=UTC)
END = datetime(2026, 11, 17, 6, tzinfo=UTC)
E0 = int(START.timestamp())


def _bucket(day: int, *values: Any, currency: str = "usd") -> dict[str, Any]:
    return {"object": "bucket", "start_time": E0 + day * DAY, "end_time": E0 + (day + 1) * DAY,
            "results": [{"object": "organization.costs.result", "amount": {"value": v, "currency": currency},
                         "line_item": None, "project_id": None} for v in values]}


def _page(*buckets: dict[str, Any], next_page: str | None = None) -> dict[str, Any]:
    return {"object": "page", "data": list(buckets), "has_more": next_page is not None, "next_page": next_page}


@pytest.mark.unit
def test_openai_sums_usd_from_the_grant_start() -> None:
    t = Recorded((200, _page(_bucket(0, 1.25, 0.5), _bucket(1, "2.00"), _bucket(4, 0))))
    report = openai_costs("sk-admin-x", start=START, end=END, transport=t)
    assert report.total_usd == Decimal("3.75")
    assert report.uncosted_usage is False
    (url, headers), = t.calls
    assert url.startswith("https://api.openai.com/v1/organization/costs?")
    q = _q(url)
    assert q["start_time"] == [str(E0)] and q["end_time"] == [str(int(END.timestamp()))]
    assert q["bucket_width"] == ["1d"]
    assert headers["Authorization"] == "Bearer sk-admin-x"


@pytest.mark.unit
def test_openai_bucket_wholly_before_the_window_is_excluded() -> None:
    """Negative control: counting the day-before bucket would make used 104.0."""
    t = Recorded((200, _page(_bucket(-1, 100), _bucket(0, 4.0))))
    assert openai_costs("k", start=START, end=END, transport=t).total_usd == Decimal("4.0")


@pytest.mark.unit
def test_openai_intraday_start_queries_from_midnight_and_counts_the_first_day_in_full() -> None:
    intraday = datetime(2026, 11, 13, 15, tzinfo=UTC)
    t = Recorded((200, _page(_bucket(0, 7.0))))
    report = openai_costs("k", start=intraday, end=END, transport=t)
    assert report.total_usd == Decimal("7.0")
    assert _q(t.calls[0][0])["start_time"] == [str(E0)]


@pytest.mark.unit
def test_openai_bucket_at_or_after_the_frozen_end_is_excluded() -> None:
    end = datetime(2026, 11, 15, tzinfo=UTC)
    t = Recorded((200, _page(_bucket(0, 1), _bucket(1, 1), _bucket(2, 50))))
    assert openai_costs("k", start=START, end=end, transport=t).total_usd == Decimal(2)


@pytest.mark.unit
def test_openai_paginates_over_two_pages() -> None:
    t = Recorded((200, _page(_bucket(0, 1), next_page="p2")), (200, _page(_bucket(1, 2))))
    assert openai_costs("k", start=START, end=END, transport=t).total_usd == Decimal(3)
    assert _q(t.calls[1][0])["page"] == ["p2"]


@pytest.mark.unit
@pytest.mark.parametrize(("responses", "read", "reason"), [
    ([(200, _page(_bucket(0, 1), next_page="p2")), (500, b"")], "error", "HTTP 500"),
    ([(403, b"")], "rejected", "HTTP 403"),
    ([(200, _page(_bucket(0, 1, currency="eur")))], "error", "cost result is not usd"),
    ([(200, _page(_bucket(0, 1, currency="USD")))], "error", "cost result is not usd"),
    ([(200, _page(_bucket(0, -1)))], "error", "cost amount is not finite and non-negative"),
    ([(200, _page(_bucket(0, "NaN")))], "error", "cost amount is not finite and non-negative"),
    ([(200, _page(_bucket(0, True)))], "error", "cost amount is not a number"),
    ([(200, _page(_bucket(0, 1), next_page="p2")), (200, _page(_bucket(1, 1), next_page="p2"))], "error",
     "repeated next_page cursor"),
    ([(200, {"data": [], "has_more": True})], "error", "has_more without a next_page cursor"),
    ([(200, b"not json")], "error", "non-JSON reply"),
    ([(200, {"data": [{"start_time": 1, "end_time": 0, "results": []}], "has_more": False})], "error",
     "malformed bucket window"),
])
def test_openai_read_fails_whole_never_partial(responses: list[tuple[int, Any]], read: str, reason: str) -> None:
    with pytest.raises(CostReadError) as exc:
        openai_costs("k", start=START, end=END, transport=Recorded(*responses))
    assert (exc.value.read, exc.value.reason) == (read, reason)


@pytest.mark.unit
def test_openai_error_never_carries_the_body() -> None:
    with pytest.raises(CostReadError) as exc:
        openai_costs("k", start=START, end=END, transport=Recorded((401, b'{"error": "sk-secret"}')))
    assert "sk-secret" not in str(exc.value) and exc.value.http == 401


@pytest.mark.unit
def test_openai_empty_window_is_refused() -> None:
    with pytest.raises(CostReadError):
        openai_costs("k", start=END, end=START, transport=Recorded())


@pytest.mark.unit
def test_openai_admin_read_is_allowlisted() -> None:
    t = Recorded((200, {"data": [], "has_more": False}))
    assert openai_admin_read("/v1/organization/projects", [("limit", "1")], "k", transport=t)["data"] == []
    with pytest.raises(CostReadError, match="not-allowlisted"):
        openai_admin_read("/v1/organization/users", [], "k", transport=Recorded())
    with pytest.raises(CostReadError, match="not-allowlisted"):
        openai_admin_read("/v1/organization/projects", [("evil", "1")], "k", transport=Recorded())


# --- Anthropic ---------------------------------------------------------------------------------------------

def _a_page(*results: dict[str, Any], next_page: str | None = None) -> dict[str, Any]:
    return {"data": [{"starting_at": "2026-11-14T00:00:00Z", "results": list(results)}],
            "has_more": next_page is not None, "next_page": next_page}


@pytest.mark.unit
def test_anthropic_cents_to_usd_and_priority_coverage() -> None:
    t = Recorded((200, _a_page({"currency": "USD", "amount": "643.2"}, {"currency": "USD", "amount": 59})),
                 (200, _a_page({"service_tier": "standard"}, {"service_tier": "batch"})))
    report = anthropic_cost_report("ak", start=datetime(2026, 11, 14, tzinfo=UTC),
                                   end=datetime(2026, 11, 16, tzinfo=UTC), transport=t)
    assert report.total_usd == Decimal("7.022")
    assert report.uncosted_usage is False
    cost_url, usage_url = (c[0] for c in t.calls)
    assert "/v1/organizations/cost_report?" in cost_url and _q(cost_url)["group_by[]"] == ["workspace_id",
                                                                                          "description"]
    assert "/v1/organizations/usage_report/messages?" in usage_url and _q(usage_url)["group_by[]"] == ["service_tier"]
    assert t.calls[0][1]["x-api-key"] == "ak"


@pytest.mark.unit
def test_anthropic_priority_tier_is_uncosted_usage() -> None:
    t = Recorded((200, _a_page({"currency": "USD", "amount": 0})), (200, _a_page({"service_tier": "priority"})))
    report = anthropic_cost_report("ak", start=datetime(2026, 11, 14, tzinfo=UTC),
                                   end=datetime(2026, 11, 16, tzinfo=UTC), transport=t)
    assert report.uncosted_usage is True


@pytest.mark.unit
def test_anthropic_non_usd_and_page_failure() -> None:
    with pytest.raises(CostReadError, match="not USD"):
        anthropic_cost_report("k", start=START, end=END, transport=Recorded((200, _a_page({"currency": "usd",
                                                                                           "amount": 1}))))
    with pytest.raises(CostReadError):
        admin_report("/v1/organizations/cost_report", [], "k",
                     transport=Recorded((200, _a_page(next_page="p")), (502, b"")))
    with pytest.raises(CostReadError, match="more than 1 pages"):
        admin_report("/v1/organizations/cost_report", [], "k", max_pages=1,
                     transport=Recorded((200, _a_page(next_page="p"))))


@pytest.mark.unit
def test_transport_exception_is_a_fixed_reason() -> None:
    def boom(method: str, url: str, headers: dict[str, str]) -> tuple[int, bytes]:
        raise OSError("connection reset by sk-secret")

    with pytest.raises(CostReadError) as exc:
        openai_costs("k", start=START, end=END, transport=boom)
    assert exc.value.reason == "OSError"


# --- capture builder + guard round trip --------------------------------------------------------------------

GRANT = Grant(id="g-2026-11-13", amount_usd=100, starts_at=START, expires_at=datetime(2026, 12, 13, tzinfo=UTC))
REGISTER = {"schema": "subscriptions-v1", "subscriptions": [{
    "id": "vendor-b-credits", "vendor": "VendorB", "kind": "credit-allowance",
    "allowance": {"per_cycle": 100, "grant": {"id": GRANT.id, "amount_usd": 100, "observed_on": "2026-11-14",
                                              "starts_at": "2026-11-13T00:00:00Z",
                                              "expires_at": "2026-12-13T00:00:00Z"}}}]}


@pytest.mark.unit
def test_capture_built_from_an_openai_report_admits_through_the_guard() -> None:
    now = END
    report = openai_costs("k", start=GRANT.starts_at, end=min(now, GRANT.expires_at),
                          transport=Recorded((200, _page(_bucket(0, 12.5), _bucket(1, 2.5)))))
    row = {"id": "vendor-b-credits", **allowance_row(grant=GRANT, per_cycle=100, report=report, now=now)}
    assert row["used_usd"] == 15.0 and row["credits_left"] == 85.0 and row["read"] == "live"
    assert row["balance_basis"] == "estimated" and row["window_start"] == "2026-11-13T00:00:00Z"
    env = capture_envelope([row], register_sha="sha256:" + "c" * 64, now=now)
    got = decide(capture=env, register=REGISTER, register_sha="sha256:" + "c" * 64, allowance="vendor-b-credits",
                 need_usd=2, reserve_usd=10, now=now)
    assert got["decision"] == "OK", got
    held = decide(capture=env, register=REGISTER, register_sha="sha256:" + "c" * 64, allowance="vendor-b-credits",
                  need_usd=2, reserve_usd=84, now=now)
    assert held["code"] == "reserve"


@pytest.mark.unit
def test_expired_grant_leaves_nothing_available() -> None:
    now = datetime(2026, 12, 14, tzinfo=UTC)
    report = openai_costs("k", start=GRANT.starts_at, end=GRANT.expires_at,
                          transport=Recorded((200, _page(_bucket(0, 1)))))
    assert allowance_row(grant=GRANT, per_cycle=100, report=report, now=now)["credits_left"] == 0.0
