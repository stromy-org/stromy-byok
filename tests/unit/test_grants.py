"""Grants: binding, replay, expiry, action-scoping and the replica invariant."""

from __future__ import annotations

import pytest

from stromy_byok import (
    GrantAction,
    GrantError,
    InMemoryGrantStore,
    Subject,
    assert_single_replica_or_durable,
    consume_for,
    mint_grant,
)
from tests.conftest import APIFY, OPENAI


def _mint(grants: InMemoryGrantStore, subject: Subject, **kw):
    params = {
        "subject": subject,
        "service": "stromy-workflows-mcp",
        "credential_id": OPENAI,
        "action": GrantAction.REGISTER_OR_ROTATE,
        "issuer": "test",
    }
    params.update(kw)
    return mint_grant(grants, **params)  # type: ignore[arg-type]


@pytest.mark.unit
def test_grant_binds_every_scoping_field(grants: InMemoryGrantStore, alice: Subject) -> None:
    grant = _mint(grants, alice, workflow="stakeholder-analysis")
    assert grant.subject == alice
    assert grant.service == "stromy-workflows-mcp"
    assert grant.credential_id == OPENAI
    assert grant.action is GrantAction.REGISTER_OR_ROTATE
    assert grant.workflow == "stakeholder-analysis"
    assert grant.nonce and grant.token


@pytest.mark.unit
def test_grant_repr_does_not_leak_the_token(grants: InMemoryGrantStore, alice: Subject) -> None:
    grant = _mint(grants, alice)
    assert grant.token not in repr(grant)
    assert "<redacted>" in repr(grant)


@pytest.mark.unit
def test_peek_does_not_spend(grants: InMemoryGrantStore, alice: Subject) -> None:
    """A reload or a mistyped key must not burn the link."""
    grant = _mint(grants, alice)
    assert grants.peek(grant.token) is not None
    assert grants.peek(grant.token) is not None
    assert consume_for(grants, grant.token, GrantAction.REGISTER_OR_ROTATE) is not None


@pytest.mark.unit
def test_consume_is_single_use(grants: InMemoryGrantStore, alice: Subject) -> None:
    grant = _mint(grants, alice)
    consume_for(grants, grant.token, GrantAction.REGISTER_OR_ROTATE)
    with pytest.raises(GrantError):
        consume_for(grants, grant.token, GrantAction.REGISTER_OR_ROTATE)


@pytest.mark.unit
def test_wrong_action_is_rejected_and_does_not_spend_the_grant(
    grants: InMemoryGrantStore, alice: Subject
) -> None:
    """A mis-posted disconnect must not destroy the user's only valid grant."""
    grant = _mint(grants, alice, action=GrantAction.REGISTER_OR_ROTATE)
    with pytest.raises(GrantError, match="does not permit"):
        consume_for(grants, grant.token, GrantAction.DISCONNECT)
    # Still usable for what it WAS issued for.
    assert consume_for(grants, grant.token, GrantAction.REGISTER_OR_ROTATE) is not None


@pytest.mark.unit
def test_a_grant_expires_on_its_own_clock(grants: InMemoryGrantStore, alice: Subject) -> None:
    """Expiry rides on the grant, not the store, so it survives a store swap."""
    grant = _mint(grants, alice, ttl_seconds=900)
    assert grant.is_expired(now=grant.expires_at - 1) is False
    assert grant.is_expired(now=grant.expires_at) is True


@pytest.mark.unit
def test_expired_grant_is_pruned_and_unusable(
    grants: InMemoryGrantStore, alice: Subject, monkeypatch: pytest.MonkeyPatch
) -> None:
    grant = _mint(grants, alice, ttl_seconds=900)
    assert grants.peek(grant.token) is not None

    # Advance the clock past the grant's expiry rather than sleeping 900s.
    monkeypatch.setattr(
        "stromy_byok.grants.time.monotonic", lambda: grant.expires_at + 1
    )
    assert grants.peek(grant.token) is None
    with pytest.raises(GrantError, match="expired"):
        consume_for(grants, grant.token, GrantAction.REGISTER_OR_ROTATE)


@pytest.mark.unit
def test_unknown_and_empty_tokens_are_rejected(grants: InMemoryGrantStore) -> None:
    assert grants.peek("") is None
    assert grants.peek("not-a-real-token") is None
    with pytest.raises(GrantError):
        consume_for(grants, "not-a-real-token", GrantAction.REGISTER_OR_ROTATE)


@pytest.mark.unit
def test_two_grants_for_different_credentials_do_not_cross(
    grants: InMemoryGrantStore, alice: Subject
) -> None:
    openai_grant = _mint(grants, alice, credential_id=OPENAI)
    apify_grant = _mint(grants, alice, credential_id=APIFY)
    assert openai_grant.token != apify_grant.token
    spent = consume_for(grants, openai_grant.token, GrantAction.REGISTER_OR_ROTATE)
    assert spent.credential_id == OPENAI
    assert grants.peek(apify_grant.token) is not None


@pytest.mark.unit
def test_single_replica_invariant_rejects_in_memory_store_on_scale_out(
    grants: InMemoryGrantStore,
) -> None:
    assert_single_replica_or_durable(grants, max_replicas=1)  # fine
    with pytest.raises(GrantError, match="maxReplicas"):
        assert_single_replica_or_durable(grants, max_replicas=2)


@pytest.mark.unit
def test_durable_store_lifts_the_replica_restriction(alice: Subject) -> None:
    class DurableStore:
        def __init__(self) -> None:
            self._g: dict[str, object] = {}

        def mint(self, grant) -> None:  # noqa: ANN001
            self._g[grant.token] = grant

        def peek(self, token: str):  # noqa: ANN201
            return self._g.get(token)

        def consume(self, token: str):  # noqa: ANN201
            return self._g.pop(token, None)

    assert_single_replica_or_durable(DurableStore(), max_replicas=5)


@pytest.mark.unit
def test_mint_requires_a_service(grants: InMemoryGrantStore, alice: Subject) -> None:
    with pytest.raises(ValueError, match="service"):
        _mint(grants, alice, service="")
