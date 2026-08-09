"""The registration route end-to-end: headers, binding, redaction, lifecycle."""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from stromy_byok import (
    AuditEvent,
    CredentialCatalogue,
    GrantAction,
    InMemoryCredentialStore,
    InMemoryGrantStore,
    NullCredentialStore,
    Subject,
    build_keys_routes,
    mint_grant,
)
from tests.conftest import APIFY, OPENAI


@pytest.fixture
def audit_log() -> list[AuditEvent]:
    return []


@pytest.fixture
def client(
    catalogue: CredentialCatalogue,
    grants: InMemoryGrantStore,
    store: InMemoryCredentialStore,
    audit_log: list[AuditEvent],
) -> TestClient:
    routes = build_keys_routes(
        catalogue=catalogue,
        grant_store=grants,
        store_factory=lambda: store,
        service="test-service",
        audit_sink=audit_log.append,
        validate=False,  # provider probes are covered by the validator tests
    )
    app = Starlette(
        routes=[
            Route("/keys", routes.get, methods=["GET"]),
            Route("/keys", routes.post, methods=["POST"]),
        ]
    )
    return TestClient(app)


def _grant(grants: InMemoryGrantStore, subject: Subject, **kw):
    params = {
        "subject": subject,
        "service": "test-service",
        "credential_id": OPENAI,
        "action": GrantAction.REGISTER_OR_ROTATE,
        "issuer": "test",
    }
    params.update(kw)
    return mint_grant(grants, **params)  # type: ignore[arg-type]


@pytest.mark.integration
def test_security_headers_on_every_response(
    client: TestClient, grants: InMemoryGrantStore, alice: Subject
) -> None:
    grant = _grant(grants, alice)
    for response in (
        client.get("/keys", params={"token": grant.token}),
        client.get("/keys", params={"token": "bogus"}),
    ):
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["x-content-type-options"] == "nosniff"
        csp = response.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in csp
        assert "default-src 'none'" in csp


@pytest.mark.integration
def test_page_loads_no_third_party_assets(
    client: TestClient, grants: InMemoryGrantStore, alice: Subject
) -> None:
    grant = _grant(grants, alice)
    body = client.get("/keys", params={"token": grant.token}).text
    assert "<script" not in body.lower()
    # The only external link is the provider signup URL, which is a plain
    # anchor, never a fetched subresource.
    assert "src=" not in body.lower()


@pytest.mark.integration
def test_get_with_a_bad_token_reveals_nothing(client: TestClient) -> None:
    response = client.get("/keys", params={"token": "nope"})
    assert response.status_code == 404
    assert "invalid" in response.text.lower()


@pytest.mark.integration
def test_get_does_not_spend_the_grant(
    client: TestClient, grants: InMemoryGrantStore, alice: Subject
) -> None:
    grant = _grant(grants, alice)
    client.get("/keys", params={"token": grant.token})
    client.get("/keys", params={"token": grant.token})
    response = client.post("/keys", data={"token": grant.token, "provider_key": "sk-1"})
    assert response.status_code == 200


@pytest.mark.integration
def test_register_then_replay_is_rejected(
    client: TestClient, grants: InMemoryGrantStore, store: InMemoryCredentialStore, alice: Subject
) -> None:
    grant = _grant(grants, alice)
    assert client.post("/keys", data={"token": grant.token, "provider_key": "sk-1"}).status_code == 200
    assert store.get_enabled(OPENAI, alice) == "sk-1"

    replay = client.post("/keys", data={"token": grant.token, "provider_key": "sk-EVIL"})
    assert replay.status_code == 404
    assert store.get_enabled(OPENAI, alice) == "sk-1"  # unchanged


@pytest.mark.integration
def test_the_form_cannot_choose_the_credential_or_the_subject(
    client: TestClient,
    grants: InMemoryGrantStore,
    store: InMemoryCredentialStore,
    alice: Subject,
    bob: Subject,
) -> None:
    """Extra form fields are inert — every scoping field comes from the grant."""
    grant = _grant(grants, alice, credential_id=OPENAI)
    client.post(
        "/keys",
        data={
            "token": grant.token,
            "provider_key": "sk-1",
            # All of these are attacker-supplied and must be ignored.
            "credential_id": "apify-api",
            "subject": bob.value,
            "subject_kind": "client-slug",
            "action": "disconnect",
        },
    )
    assert store.get_enabled(OPENAI, alice) == "sk-1"
    assert store.get_enabled(APIFY, alice) is None  # not redirected
    assert store.get_enabled(OPENAI, bob) is None  # not written to another subject


@pytest.mark.integration
def test_the_key_is_never_echoed_back(
    client: TestClient, grants: InMemoryGrantStore, alice: Subject
) -> None:
    grant = _grant(grants, alice)
    response = client.post("/keys", data={"token": grant.token, "provider_key": "sk-SUPERSECRET"})
    assert "sk-SUPERSECRET" not in response.text


@pytest.mark.integration
def test_empty_key_is_correctable_without_burning_the_grant(
    client: TestClient, grants: InMemoryGrantStore, store: InMemoryCredentialStore, alice: Subject
) -> None:
    grant = _grant(grants, alice)
    first = client.post("/keys", data={"token": grant.token, "provider_key": "  "})
    assert first.status_code == 400
    second = client.post("/keys", data={"token": grant.token, "provider_key": "sk-ok"})
    assert second.status_code == 200
    assert store.get_enabled(OPENAI, alice) == "sk-ok"


@pytest.mark.integration
def test_disconnect_grant_disables_and_allows_reregistration(
    client: TestClient, grants: InMemoryGrantStore, store: InMemoryCredentialStore, alice: Subject
) -> None:
    store.put_version(OPENAI, alice, "sk-existing")

    disconnect = _grant(grants, alice, action=GrantAction.DISCONNECT)
    response = client.post("/keys", data={"token": disconnect.token})
    assert response.status_code == 200
    assert "disconnected" in response.text.lower()
    assert store.get_enabled(OPENAI, alice) is None

    fresh = _grant(grants, alice)
    client.post("/keys", data={"token": fresh.token, "provider_key": "sk-new"})
    assert store.get_enabled(OPENAI, alice) == "sk-new"


@pytest.mark.integration
def test_disconnect_page_offers_only_disconnect(
    client: TestClient, grants: InMemoryGrantStore, alice: Subject
) -> None:
    grant = _grant(grants, alice, action=GrantAction.DISCONNECT)
    body = client.get("/keys", params={"token": grant.token}).text
    assert "provider_key" not in body
    assert "disconnect" in body.lower()


@pytest.mark.integration
def test_a_register_grant_cannot_be_posted_as_a_disconnect(
    catalogue: CredentialCatalogue,
    grants: InMemoryGrantStore,
    store: InMemoryCredentialStore,
    alice: Subject,
) -> None:
    """The action is bound; a disconnect-shaped POST cannot disable a key."""
    store.put_version(OPENAI, alice, "sk-live")
    routes = build_keys_routes(
        catalogue=catalogue,
        grant_store=grants,
        store_factory=lambda: store,
        service="test-service",
        validate=False,
    )
    app = Starlette(routes=[Route("/keys", routes.post, methods=["POST"])])
    grant = _grant(grants, alice, action=GrantAction.REGISTER_OR_ROTATE)
    with TestClient(app) as client:
        # Posting with no key against a REGISTER grant is a validation error,
        # never a silent disconnect.
        response = client.post("/keys", data={"token": grant.token})
    assert response.status_code == 400
    assert store.get_enabled(OPENAI, alice) == "sk-live"


@pytest.mark.integration
def test_unprovisioned_store_refuses_rather_than_dropping_the_key(
    catalogue: CredentialCatalogue, grants: InMemoryGrantStore, alice: Subject
) -> None:
    """A read-only store must fail loudly, not accept a key into the void."""
    routes = build_keys_routes(
        catalogue=catalogue,
        grant_store=grants,
        store_factory=NullCredentialStore,
        service="test-service",
        validate=False,
    )
    app = Starlette(routes=[Route("/keys", routes.post, methods=["POST"])])
    grant = _grant(grants, alice)
    with TestClient(app) as client:
        response = client.post("/keys", data={"token": grant.token, "provider_key": "sk-1"})
    assert response.status_code == 503
    assert "provisioned" in response.text.lower()


@pytest.mark.integration
def test_audit_events_carry_no_secret_and_no_raw_subject(
    client: TestClient,
    grants: InMemoryGrantStore,
    alice: Subject,
    audit_log: list[AuditEvent],
) -> None:
    grant = _grant(grants, alice, workflow="stakeholder-analysis")
    client.post("/keys", data={"token": grant.token, "provider_key": "sk-SUPERSECRET"})

    assert audit_log, "registration must emit audit events"
    flat = repr([event.to_dict() for event in audit_log])
    assert "sk-SUPERSECRET" not in flat
    assert alice.value not in flat
    assert alice.hashed in flat

    actions = {event.action.value for event in audit_log}
    assert "grant.exchanged" in actions
    assert "credential.registered" in actions


@pytest.mark.integration
def test_a_raising_audit_sink_never_breaks_registration(
    catalogue: CredentialCatalogue,
    grants: InMemoryGrantStore,
    store: InMemoryCredentialStore,
    alice: Subject,
) -> None:
    def explode(event: AuditEvent) -> None:
        raise RuntimeError("sink down")

    routes = build_keys_routes(
        catalogue=catalogue,
        grant_store=grants,
        store_factory=lambda: store,
        service="test-service",
        audit_sink=explode,
        validate=False,
    )
    app = Starlette(routes=[Route("/keys", routes.post, methods=["POST"])])
    grant = _grant(grants, alice)
    with TestClient(app) as client:
        response = client.post("/keys", data={"token": grant.token, "provider_key": "sk-1"})
    assert response.status_code == 200
    assert store.get_enabled(OPENAI, alice) == "sk-1"
