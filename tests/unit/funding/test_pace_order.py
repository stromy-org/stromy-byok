"""stromy_byok.funding.pace (shared vectors) and order (D1/D2)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from stromy_byok.funding import Candidate, FundingSource, Grant, KeyRef, order, pace

PACE = json.loads((Path(__file__).parent / "pace_vectors.json").read_text())


@pytest.mark.unit
@pytest.mark.parametrize("vector", PACE["vectors"], ids=[v["name"] for v in PACE["vectors"]])
def test_pace_vector(vector: dict[str, Any]) -> None:
    row = {**PACE["base_row"], **vector["row"]}
    got = pace(row, datetime.fromisoformat(vector["now"].replace("Z", "+00:00")))
    assert got["state"] == vector["state"]
    if got["state"] == "unknown":
        assert got["projected_unused_usd"] is None and got["days_left"] is None


@pytest.mark.unit
def test_pace_never_raises_on_junk() -> None:
    assert pace(None, datetime(2026, 1, 1, tzinfo=UTC))["state"] == "unknown"
    assert pace({}, datetime(2026, 1, 1))["state"] == "unknown"


NOW = datetime(2026, 11, 20, tzinfo=UTC)
ALL = frozenset({"medium", "smart", "frontier"})


def _cand(sid: str, vendor: str, expires: str, *, pace_state: str = "surplus", ok: bool = True,
          tiers: frozenset[str] = ALL, basis: str = "observed") -> Candidate:
    grant = Grant(id=f"{sid}-g", amount_usd=100, starts_at=datetime(2026, 11, 1, tzinfo=UTC),
                  expires_at=datetime.fromisoformat(expires).replace(tzinfo=UTC), basis=basis)  # type: ignore[arg-type]
    src = FundingSource(id=sid, vendor=vendor, tenant="t", key_ref=KeyRef(env=f"{sid.upper()}_KEY"), admin_ref=None,
                        per_cycle=100, grant=grant)
    return Candidate(source=src, decision={"decision": "OK" if ok else "HOLD"}, pace=pace_state, tiers=tiers,
                     provider=vendor)


def _ids(result: dict[str, Candidate | None]) -> dict[str, str | None]:
    return {t: (c.source.id if c else None) for t, c in result.items()}


@pytest.mark.unit
def test_two_vendors_the_sooner_serves() -> None:
    got = order([_cand("a", "vendora", "2026-12-17"), _cand("b", "vendorb", "2026-12-12")], now=NOW)
    assert _ids(got) == {"cheap": None, "medium": "b", "smart": "b", "frontier": "b"}


@pytest.mark.unit
def test_sooner_short_keeps_strong_tiers_later_surplus_serves_medium() -> None:
    got = order([_cand("soon", "vendora", "2026-12-12", pace_state="short"),
                 _cand("later", "vendorb", "2026-12-17", pace_state="surplus")], now=NOW)
    assert _ids(got) == {"cheap": None, "medium": "later", "smart": "soon", "frontier": "soon"}


@pytest.mark.unit
@pytest.mark.parametrize("state", ["on-pace", "unknown", "short"])
def test_non_surplus_serves_strong_tiers_only(state: str) -> None:
    got = order([_cand("a", "vendora", "2026-12-12", pace_state=state)], now=NOW)
    assert _ids(got) == {"cheap": None, "medium": None, "smart": "a", "frontier": "a"}


@pytest.mark.unit
def test_cheap_is_never_credit_funded_when_the_route_excludes_it() -> None:
    got = order([_cand("a", "vendora", "2026-12-12")], now=NOW)
    assert got["cheap"] is None


@pytest.mark.unit
def test_held_and_forecast_and_expired_candidates_never_serve() -> None:
    got = order([_cand("held", "vendora", "2026-12-01", ok=False),
                 _cand("forecast", "vendora", "2026-12-02", basis="recurring"),
                 _cand("expired", "vendora", "2026-11-19"),
                 _cand("good", "vendorb", "2026-12-20")], now=NOW)
    assert set(_ids(got).values()) == {None, "good"}


@pytest.mark.unit
def test_ties_break_on_source_id() -> None:
    got = order([_cand("z", "vendora", "2026-12-12"), _cand("m", "vendorb", "2026-12-12")], now=NOW)
    assert got["smart"] is not None and got["smart"].source.id == "m"


@pytest.mark.unit
def test_nothing_admitted_means_every_tier_falls_to_the_chain() -> None:
    assert set(_ids(order([], now=NOW)).values()) == {None}
