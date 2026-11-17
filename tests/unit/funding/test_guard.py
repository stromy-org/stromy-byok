"""stromy_byok.funding.decide — the shared admission vectors plus D4 and key presence."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from stromy_byok.funding import decide

VECTORS = json.loads((Path(__file__).parent / "guard_vectors.json").read_text())["vectors"]
BY_NAME = {v["name"]: v for v in VECTORS}


def _run(inp: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return decide(capture=inp.get("capture"), register=inp.get("register"), register_sha=inp.get("register_sha"),
                  allowance=inp["allowance"], need_usd=inp["need_usd"], reserve_usd=inp["reserve_usd"],
                  now=datetime.fromisoformat(inp["now"].replace("Z", "+00:00")),
                  max_age_hours=inp.get("max_age_hours", 36), **extra)


@pytest.mark.unit
@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector(vector: dict[str, Any]) -> None:
    got = _run(vector["input"])
    assert (got["decision"], got["code"]) == (vector["expect"]["decision"], vector["expect"]["code"])


@pytest.mark.unit
def test_vectors_cover_every_hold_code() -> None:
    """Removing any check (the reserve included) leaves at least one vector failing."""
    codes = {v["expect"]["code"] for v in VECTORS}
    assert {"reserve", "capture-stale", "register-changed", "grant-mismatch", "uncosted-usage", "disabled",
            "no-grant", "grant-expired", "grant-not-started", "not-live", "not-estimated", "capture-row",
            "capture-invalid", "invalid-request", "register-entry", "register-schema", "register-missing",
            "capture-missing", "capture-schema", "capture-status", "capture-time", "capture-future",
            "register-invalid"} <= codes


def _ok() -> dict[str, Any]:
    return copy.deepcopy(BY_NAME["ok"]["input"])


def _allowance(inp: dict[str, Any]) -> dict[str, Any]:
    return inp["register"]["subscriptions"][0]["allowance"]


@pytest.mark.unit
def test_ok_baseline() -> None:
    assert _run(_ok())["decision"] == "OK"


@pytest.mark.unit
@pytest.mark.parametrize("mutate", [
    lambda i: i["capture"].update(status="ERROR"),
    lambda i: i["capture"].update(schema="other"),
    lambda i: i["capture"].update(register_sha="sha256:" + "b" * 64),
    lambda i: i["capture"]["providers"][0].update(per_cycle=1),
    lambda i: i["capture"]["providers"][0].update(window_start="2026-10-27T00:00:00Z"),
    lambda i: i["capture"]["providers"][0].update(credits_left=float("nan")),
    lambda i: i["capture"]["providers"][0].update(uncosted_priority_tier=None),
    lambda i: i["capture"]["providers"].append(copy.deepcopy(i["capture"]["providers"][0])),
    lambda i: i.update(register_sha=None),
    lambda i: _allowance(i)["grant"].update(amount_usd=-1),
], ids=["status", "schema", "digest", "cap", "window", "nan-left", "coverage-unknown", "two-rows", "no-sha",
        "bad-amount"])
def test_each_envelope_input_holds_independently(mutate: Any) -> None:
    inp = _ok()
    mutate(inp)
    assert _run(inp)["decision"] == "HOLD"


@pytest.mark.unit
def test_key_missing_holds_and_absent_evidence_is_not_checked() -> None:
    assert _run(_ok(), key_present=False)["code"] == "key-missing"
    assert _run(_ok(), key_present=True)["decision"] == "OK"
    assert _run(_ok())["decision"] == "OK"


@pytest.mark.unit
def test_forecast_after_expiry_holds_recurring_unconfirmed_even_with_a_fresh_capture() -> None:
    """D4/Q6: an expired observed grant + recurrence forecasts a successor that never funds."""
    inp = copy.deepcopy(BY_NAME["hold-grant-expired-at-the-instant"]["input"])
    _allowance(inp)["recurrence"] = {"per_cycle_usd": 200, "min_period_days": 20}
    got = _run(inp)
    assert (got["decision"], got["code"]) == ("HOLD", "recurring-unconfirmed")


@pytest.mark.unit
def test_forecast_from_previous_grants_when_no_current_grant() -> None:
    inp = copy.deepcopy(BY_NAME["hold-no-grant"]["input"])
    allow = _allowance(inp)
    allow["previous_grants"] = [{"id": "g1", "amount_usd": 200, "observed_on": "2026-10-01",
                                 "starts_at": "2026-10-01T00:00:00Z", "expires_at": "2026-10-28T00:00:00Z"}]
    allow["recurrence"] = {"per_cycle_usd": 200, "min_period_days": 26}
    assert _run(inp)["code"] == "recurring-unconfirmed"


@pytest.mark.unit
def test_expired_forecast_is_not_renewed_again() -> None:
    inp = copy.deepcopy(BY_NAME["hold-grant-expired-at-the-instant"]["input"])
    _allowance(inp)["recurrence"] = {"per_cycle_usd": 200, "min_period_days": 1}
    inp["now"] = "2026-12-30T00:00:00Z"  # far past expiry + 1 day
    assert _run(inp)["code"] == "grant-expired"


@pytest.mark.unit
def test_active_observed_grant_admits_with_recurrence_declared() -> None:
    inp = _ok()
    _allowance(inp)["recurrence"] = {"per_cycle_usd": 200, "min_period_days": 15}
    assert _run(inp)["decision"] == "OK"


@pytest.mark.unit
def test_naive_clock_is_invalid() -> None:
    inp = _ok()
    got = decide(capture=inp["capture"], register=inp["register"], register_sha=inp["register_sha"],
                 allowance=inp["allowance"], need_usd=5, reserve_usd=25, now=datetime(2026, 10, 29, 12))
    assert got["code"] == "invalid-request"
    assert datetime(2026, 10, 29, 12, tzinfo=UTC)  # aware clocks are the contract
