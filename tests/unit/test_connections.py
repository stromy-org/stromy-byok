"""Connection isolation, fencing and single-use grant adversarial contracts."""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from stromy_byok import (
    ConnectionError,
    ConnectionGrantAction,
    ConnectionGrantBinding,
    ConnectionRecord,
    ConnectionSpec,
    ConnectionState,
    InMemoryConnectionGrantStore,
    InMemoryConnectionStore,
    Subject,
    SubjectKind,
    assert_connection_grants_durable,
    mint_connection_grant,
)

NOW = datetime(2026, 10, 4, tzinfo=UTC)
A = Subject(SubjectKind.CLIENT_SLUG, "a")
B = Subject(SubjectKind.CLIENT_SLUG, "b")
SPEC = ConnectionSpec(
    "test_connection",
    json.dumps(
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["resource_id"],
            "properties": {"resource_id": {"type": "string"}},
        }
    ),
)


def record() -> ConnectionRecord:
    return ConnectionRecord(
        "id-1", A, SPEC.kind, 1, ConnectionState.PENDING, SPEC.encode_metadata({"resource_id": "private-resource"}), NOW
    )


def binding() -> ConnectionGrantBinding:
    return ConnectionGrantBinding(
        A,
        "test_service",
        SPEC.kind,
        "app-a",
        ConnectionGrantAction.REGISTER,
        "https://example.test/connect/callback",
        "session-a",
        "verified-issuer",
        connection_id="id-1",
        expected_version=1,
    )


def test_version_cas_and_subject_cannot_be_retargeted() -> None:
    store = InMemoryConnectionStore()
    row = record()
    assert store.put_version(row, expected_version=0)
    assert not store.put_version(row, expected_version=0)
    assert not store.put_version(replace(row, subject=B, version=2), expected_version=1)
    assert not store.put_version(replace(row, kind="other", version=2), expected_version=1)
    assert store.get(row.connection_id, B) is None
    assert not store.put_version(replace(row, version=3), expected_version=1)


def test_revoke_fences_queued_versions_without_erasing_history() -> None:
    store = InMemoryConnectionStore()
    row = record()
    assert store.put_version(row, expected_version=0)
    assert store.revoke(row.connection_id, B, expected_version=1, at=NOW) is None
    revoked = store.revoke(row.connection_id, A, expected_version=1, at=NOW)
    assert revoked and revoked.version == 2 and revoked.state == ConnectionState.REVOKED
    assert store.get(row.connection_id, A) == revoked
    assert store.get(row.connection_id, A, version=1) == row
    assert store.revoke(row.connection_id, A, expected_version=1, at=NOW) is None
    assert not store.put_version(replace(row, version=2, state=ConnectionState.ACTIVE), expected_version=1)


def test_connection_metadata_is_a_snapshot_and_status_is_redacted() -> None:
    row = record()
    metadata = row.metadata
    metadata["resource_id"] = "mutated"
    assert row.metadata["resource_id"] == "private-resource"
    assert "private-resource" not in repr(row)
    assert "private-resource" not in json.dumps(row.status())
    assert "client-slug:a" not in repr(row)


@pytest.mark.parametrize("payload", [{}, {"resource_id": 3}, {"resource_id": "x", "token": "sensitive"}])
def test_closed_schema_rejects_missing_wrong_or_credential_fields(payload: dict) -> None:
    with pytest.raises(ConnectionError) as caught:
        SPEC.encode_metadata(payload)
    assert "sensitive" not in str(caught.value)


def test_metadata_is_bounded_finite_json() -> None:
    with pytest.raises(ConnectionError, match="byte limit"):
        SPEC.encode_metadata({"resource_id": "x" * 16_384})
    with pytest.raises(ConnectionError, match="finite JSON"):
        SPEC.encode_metadata({"resource_id": float("nan")})
    with pytest.raises(ConnectionError):
        ConnectionSpec("test", '{"type":"object"}')


@pytest.mark.parametrize(
    "changes",
    [
        {"subject": B},
        {"service": "other"},
        {"kind": "other"},
        {"app_id": "app-b"},
        {"action": ConnectionGrantAction.DISCONNECT},
        {"callback_uri": "https://evil.test/callback"},
        {"session_id": "session-b"},
        {"issuer": "other-issuer"},
        {"workflow": "other"},
        {"connection_id": "id-2"},
        {"expected_version": 2},
    ],
)
def test_every_grant_binding_is_checked_without_spending(changes: dict) -> None:
    store = InMemoryConnectionGrantStore()
    bound = binding()
    grant = mint_connection_grant(store, bound, now=NOW)
    forged = replace(bound, **changes)
    assert store.peek(grant.token, forged, now=NOW) is None
    assert store.consume(grant.token, forged, now=NOW) is None
    assert store.consume(grant.token, bound, now=NOW) == grant
    assert store.consume(grant.token, bound, now=NOW) is None


def test_one_concurrent_submit_and_get_does_not_spend() -> None:
    store = InMemoryConnectionGrantStore()
    grant = mint_connection_grant(store, binding(), now=NOW)
    assert store.peek(grant.token, grant.binding, now=NOW) == grant
    with ThreadPoolExecutor(max_workers=8) as pool:
        consumed = list(pool.map(lambda _: store.consume(grant.token, grant.binding, now=NOW), range(32)))
    assert sum(row is not None for row in consumed) == 1
    assert grant.token not in repr(grant)
    assert grant.nonce not in repr(grant)
    assert grant.binding.session_id not in repr(grant)


def test_cross_process_timestamps_expiry_and_replica_guard() -> None:
    store = InMemoryConnectionGrantStore()
    grant = mint_connection_grant(store, binding(), now=NOW, ttl_seconds=60)
    assert store.consume(grant.token, grant.binding, now=NOW - timedelta(seconds=1)) is None
    assert store.peek(grant.token, grant.binding, now=NOW + timedelta(seconds=59)) == grant
    assert store.consume(grant.token, grant.binding, now=NOW + timedelta(seconds=60)) is None
    with pytest.raises(ConnectionError, match="durable"):
        assert_connection_grants_durable(store, 2)
    assert_connection_grants_durable(store, 1)


@pytest.mark.parametrize("ttl", [0, -1, 901, True])
def test_link_lifetime_is_bounded(ttl: int) -> None:
    with pytest.raises(ConnectionError):
        mint_connection_grant(InMemoryConnectionGrantStore(), binding(), now=NOW, ttl_seconds=ttl)


def test_two_writers_cannot_create_the_same_connection_version() -> None:
    store = InMemoryConnectionStore()
    row = record()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: store.put_version(row, expected_version=0), range(32)))
    assert sum(results) == 1


def test_invalid_clock_and_protocol_are_rejected() -> None:
    with pytest.raises(ConnectionError):
        replace(record(), updated_at=datetime(2026, 10, 4))
    with pytest.raises(ConnectionError):
        replace(record(), protocol_version=2)


def test_schema_cannot_fetch_an_external_reference() -> None:
    with pytest.raises(ConnectionError, match="remote"):
        ConnectionSpec(
            "test",
            json.dumps(
                {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"x": {"$ref": "https://example.test/metadata.json"}},
                }
            ),
        )


def test_datetime_formats_are_checked_with_required_format_dependencies() -> None:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"verified_at": {"type": "string", "format": "date-time"}},
    }
    spec = ConnectionSpec("test", json.dumps(schema))
    assert spec.encode_metadata({"verified_at": NOW.isoformat()})
    for value in ("not-a-date", "2026-99-99T00:00:00Z", "2026-10-04T00:00:00"):
        with pytest.raises(ConnectionError):
            spec.encode_metadata({"verified_at": value})
    schema["properties"]["verified_at"]["format"] = "unknown-format"
    with pytest.raises(ConnectionError, match="unsupported formats"):
        ConnectionSpec("test", json.dumps(schema))


def verify_binding(**changes) -> ConnectionGrantBinding:
    fields = {"action": ConnectionGrantAction.VERIFY, "parameters_digest": "a" * 64}
    return replace(binding(), **(fields | changes))


def test_verify_binds_its_parameters_digest_and_never_spends_on_a_swap() -> None:
    store = InMemoryConnectionGrantStore()
    bound = verify_binding()
    grant = mint_connection_grant(store, bound, now=NOW)
    for forged in (replace(bound, parameters_digest="b" * 64), replace(bound, expected_version=2)):
        assert store.consume(grant.token, forged, now=NOW) is None
    assert store.consume(grant.token, bound, now=NOW) == grant


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"connection_id": None, "expected_version": None}, "Verify requires a bound connection"),
        ({"parameters_digest": None}, "parameters digest"),
        ({"parameters_digest": "A" * 64}, "parameters digest"),
        ({"parameters_digest": "a" * 63}, "parameters digest"),
    ],
)
def test_verify_requires_a_version_fence_and_a_digest(changes: dict, message: str) -> None:
    with pytest.raises(ConnectionError, match=message):
        verify_binding(**changes)


@pytest.mark.parametrize("action", [ConnectionGrantAction.REGISTER, ConnectionGrantAction.DISCONNECT])
def test_only_verify_carries_a_parameters_digest(action: ConnectionGrantAction) -> None:
    with pytest.raises(ConnectionError, match="Only verify"):
        replace(binding(), action=action, parameters_digest="a" * 64)
