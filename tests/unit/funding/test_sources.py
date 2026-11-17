"""stromy_byok.funding.sources — tenancy, vendor filtering, key references and D4 recurrence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from stromy_byok.funding import KeyRef, key_available, recurrence_problems, sources
from stromy_byok.models import CredentialId, Subject, SubjectKind

NOW = datetime(2026, 11, 20, tzinfo=UTC)


def _entry(sid: str, vendor: str, tenant: str | None, *, expires: str | None, starts: str = "2026-11-01T00:00:00Z",
           key_env: str | None = None, key_cred: str | None = None, per_cycle: float = 100,
           recurrence: dict[str, Any] | None = None, previous: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    allowance: dict[str, Any] = {"per_cycle": per_cycle}
    if expires is not None:
        allowance["grant"] = {"id": f"{sid}-g", "amount_usd": per_cycle or 100, "observed_on": starts[:10],
                              "starts_at": starts, "expires_at": expires}
    if key_env:
        allowance["api_key_env"] = key_env
    if key_cred:
        allowance["api_key_credential"] = key_cred
    if recurrence:
        allowance["recurrence"] = recurrence
    if previous:
        allowance["previous_grants"] = previous
    entry: dict[str, Any] = {"id": sid, "vendor": vendor, "kind": "credit-allowance", "allowance": allowance}
    if tenant is not None:
        entry["account"] = {"holder": "operator", "tenant": tenant}
    return entry


def _register(*entries: dict[str, Any]) -> dict[str, Any]:
    return {"schema": "subscriptions-v1", "subscriptions": list(entries)}


REG = _register(
    _entry("a-late", "VendorA", "tenant-one", expires="2026-12-17T00:00:00Z", key_env="VENDOR_A_KEY"),
    _entry("b-soon", "VendorB", "tenant-one", expires="2026-12-12T00:00:00Z", key_env="VENDOR_B_KEY"),
    _entry("a-mid", "VendorA", "tenant-one", expires="2026-12-13T00:00:00Z", key_env="VENDOR_A_KEY_2"),
    _entry("client-a", "VendorA", "client-x", expires="2026-12-01T00:00:00Z", key_env="CLIENT_KEY"),
    _entry("unobserved", "VendorB", "tenant-one", expires=None),
    _entry("off", "VendorA", "tenant-one", expires="2026-12-01T00:00:00Z", per_cycle=0),
    {"id": "membership", "kind": "membership", "vendor": "VendorA"},
)


@pytest.mark.unit
def test_tenant_sources_soonest_expiry_first_each_with_its_own_key() -> None:
    got = sources(REG, tenant="tenant-one", now=NOW)
    assert [s.id for s in got] == ["b-soon", "a-mid", "a-late", "unobserved"]
    assert [s.key_ref.env for s in got[:3]] == ["VENDOR_B_KEY", "VENDOR_A_KEY_2", "VENDOR_A_KEY"]


@pytest.mark.unit
def test_another_tenants_source_is_never_returned() -> None:
    """Negative control: remove the tenant filter and client-a (the soonest) leaks in."""
    got = sources(REG, tenant="tenant-one", now=NOW)
    assert "client-a" not in {s.id for s in got}
    assert [s.id for s in sources(REG, tenant="client-x", now=NOW)] == ["client-a"]


@pytest.mark.unit
def test_vendor_filter_is_exact() -> None:
    assert {s.vendor for s in sources(REG, tenant="tenant-one", vendor="vendorb", now=NOW)} == {"vendorb"}
    assert all(s.vendor == "vendora" for s in sources(REG, tenant="tenant-one", vendor="VendorA", now=NOW))


@pytest.mark.unit
def test_disabled_excluded_unless_asked() -> None:
    assert "off" not in {s.id for s in sources(REG, tenant="tenant-one", now=NOW)}
    assert "off" in {s.id for s in sources(REG, tenant="tenant-one", now=NOW, include_disabled=True)}


@pytest.mark.unit
def test_untenanted_entry_needs_an_explicit_legacy_tenant() -> None:
    reg = _register(_entry("legacy", "VendorA", None, expires="2026-12-01T00:00:00Z"))
    assert sources(reg, tenant="tenant-one", now=NOW) == []
    assert [s.id for s in sources(reg, tenant="tenant-one", now=NOW, legacy_tenant="tenant-one")] == ["legacy"]


@pytest.mark.unit
def test_unreadable_register_yields_nothing() -> None:
    assert sources(None, tenant="t", now=NOW) == []
    assert sources({"subscriptions": "x"}, tenant="t", now=NOW) == []


class FakeReader:
    def __init__(self, present: set[tuple[str, str]]) -> None:
        self.present = present
        self.asked: list[tuple[str, str]] = []

    @property
    def writable(self) -> bool:
        return False

    def get_enabled(self, credential_id: CredentialId, subject: Subject) -> str | None:
        raise AssertionError("key_available must never read a value")

    def exists(self, credential_id: CredentialId, subject: Subject) -> bool:
        self.asked.append((str(credential_id), subject.value))
        return (str(credential_id), subject.value) in self.present


@pytest.mark.unit
def test_credential_key_ref_resolves_through_the_reader_never_the_environment() -> None:
    reg = _register(_entry("hosted", "VendorA", "tenant-one", expires="2026-12-01T00:00:00Z",
                           key_cred="vendor-a-inference"))
    (src,) = sources(reg, tenant="tenant-one", now=NOW)
    assert src.key_ref == KeyRef(credential_id="vendor-a-inference")
    subject = Subject(SubjectKind.ENTRA_OID, "00000000-0000-0000-0000-000000000001")
    reader = FakeReader({("vendor-a-inference", subject.value)})
    env = {"vendor-a-inference": "set-in-env-but-ignored"}
    assert key_available(src.key_ref, environ=env, reader=reader, subject=subject) is True
    assert key_available(src.key_ref, environ=env) is False  # no reader: never falls back to env
    other = Subject(SubjectKind.CLIENT_SLUG, "client-x")
    assert key_available(src.key_ref, environ=env, reader=reader, subject=other) is False


@pytest.mark.unit
def test_env_key_ref_reads_only_the_environment() -> None:
    ref = KeyRef(env="VENDOR_A_KEY")
    assert key_available(ref, environ={"VENDOR_A_KEY": "x"}) is True
    assert key_available(ref, environ={"VENDOR_A_KEY": ""}) is False
    assert key_available(ref, environ={}, reader=FakeReader(set()), subject=Subject(SubjectKind.CLIENT_SLUG, "c")) \
        is False


@pytest.mark.unit
def test_keyref_needs_exactly_one_target() -> None:
    with pytest.raises(ValueError):
        KeyRef()
    with pytest.raises(ValueError):
        KeyRef(env="A", credential_id="b")
    with pytest.raises(ValueError):
        KeyRef(credential_id="bad name")


# --- D4: no manual reads -------------------------------------------------------------------------------------

REC = {"per_cycle_usd": 100, "min_period_days": 26}


@pytest.mark.unit
def test_active_observed_grant_beats_the_recurrence() -> None:
    reg = _register(_entry("s", "VendorA", "t", expires="2026-12-12T00:00:00Z", recurrence=REC))
    (src,) = sources(reg, tenant="t", now=NOW)
    assert src.basis == "observed" and src.grant is not None and src.grant.id == "s-g"


@pytest.mark.unit
def test_recurrence_derives_the_immediate_successor() -> None:
    reg = _register(_entry("s", "VendorA", "t", expires="2026-11-16T00:00:00Z", recurrence=REC))
    (src,) = sources(reg, tenant="t", now=NOW)
    assert src.basis == "recurring" and src.grant is not None
    assert src.grant.starts_at == datetime(2026, 11, 16, tzinfo=UTC)
    assert src.grant.expires_at == datetime(2026, 11, 16, tzinfo=UTC) + timedelta(days=26)
    assert src.grant.amount_usd == 100


@pytest.mark.unit
def test_recurrence_without_any_prior_grant_derives_nothing() -> None:
    reg = _register(_entry("s", "VendorA", "t", expires=None, recurrence=REC))
    (src,) = sources(reg, tenant="t", now=NOW)
    assert src.grant is None


@pytest.mark.unit
def test_expired_forecast_never_generates_another_renewal() -> None:
    reg = _register(_entry("s", "VendorA", "t", expires="2026-10-01T00:00:00Z", starts="2026-09-05T00:00:00Z",
                           recurrence=REC))
    (src,) = sources(reg, tenant="t", now=NOW)  # forecast 10-01..10-27 already over
    assert src.grant is None


@pytest.mark.unit
def test_forecast_uses_the_latest_observed_expiry_across_history() -> None:
    previous = [{"id": "old", "amount_usd": 100, "observed_on": "2026-10-01", "starts_at": "2026-10-01T00:00:00Z",
                 "expires_at": "2026-11-10T00:00:00Z"}]
    reg = _register(_entry("s", "VendorA", "t", expires=None, recurrence=REC, previous=previous))
    (src,) = sources(reg, tenant="t", now=NOW)
    assert src.grant is not None and src.grant.starts_at == datetime(2026, 11, 10, tzinfo=UTC)


@pytest.mark.unit
def test_disabled_source_derives_nothing() -> None:
    reg = _register(_entry("s", "VendorA", "t", expires="2026-11-16T00:00:00Z", per_cycle=0, recurrence=REC))
    (src,) = sources(reg, tenant="t", now=NOW, include_disabled=True)
    assert src.grant is None


@pytest.mark.unit
def test_not_started_observed_grant_is_kept_for_grant_not_started() -> None:
    reg = _register(_entry("s", "VendorA", "t", starts="2026-11-25T00:00:00Z", expires="2026-12-25T00:00:00Z",
                           recurrence=REC))
    (src,) = sources(reg, tenant="t", now=NOW)
    assert src.basis == "observed" and src.grant is not None and not src.grant.active(NOW)


@pytest.mark.unit
@pytest.mark.parametrize(("recurrence", "fragment"), [
    ({"per_cycle_usd": 100, "min_period_days": 0}, "min_period_days"),
    ({"per_cycle_usd": 100, "min_period_days": 41}, "min_period_days"),
    ({"per_cycle_usd": 100, "min_period_days": True}, "min_period_days"),
    ({"per_cycle_usd": 0, "min_period_days": 26}, "per_cycle_usd"),
    ({"per_cycle_usd": 500, "min_period_days": 26}, "exceeds per_cycle"),
    ({"per_cycle_usd": 100, "min_period_days": 26, "extra": 1}, "unknown field"),
    ({"per_cycle_usd": 100, "min_period_days": 27}, "exceeds the observed grant"),
])
def test_recurrence_problems(recurrence: dict[str, Any], fragment: str) -> None:
    allowance = _entry("s", "VendorA", "t", starts="2026-11-16T00:00:00Z", expires="2026-12-12T00:00:00Z",
                       recurrence=recurrence)["allowance"]
    problems = recurrence_problems("s", allowance)
    assert any(fragment in p for p in problems), problems


@pytest.mark.unit
def test_recurrence_within_the_observed_cycle_is_valid() -> None:
    allowance = _entry("s", "VendorA", "t", starts="2026-11-16T00:00:00Z", expires="2026-12-12T00:00:00Z",
                       recurrence=REC)["allowance"]
    assert recurrence_problems("s", allowance) == []
    assert recurrence_problems("s", {"per_cycle": 1}) == []
