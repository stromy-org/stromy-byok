"""The catalogue is closed: unknown ids never reach a vault or a network call."""

from __future__ import annotations

import pytest

from stromy_byok import (
    CredentialCatalogue,
    CredentialId,
    CredentialOwner,
    CredentialSpec,
    ProviderProbe,
    UnknownCredentialError,
)
from tests.conftest import OPENAI


@pytest.mark.unit
def test_unknown_credential_id_is_rejected(catalogue: CredentialCatalogue) -> None:
    with pytest.raises(UnknownCredentialError) as exc:
        catalogue.get("totally-made-up")
    # The error names what IS declared, so a typo is self-correcting.
    assert "openai-api" in str(exc.value)


@pytest.mark.unit
def test_a_caller_cannot_smuggle_an_endpoint_through_the_id(
    catalogue: CredentialCatalogue,
) -> None:
    """The id is looked up, never interpreted — no path or host can ride in."""
    for hostile in ("../../etc/passwd", "https://evil.test", "openai-api;drop"):
        with pytest.raises((UnknownCredentialError, ValueError)):
            catalogue.get(hostile)


@pytest.mark.unit
def test_credential_id_grammar_matches_key_vault() -> None:
    CredentialId("openai-api")
    for bad in ("", "-leading", "trailing-", "under_score", "has space", "sláinte"):
        with pytest.raises(ValueError):
            CredentialId(bad)


@pytest.mark.unit
def test_duplicate_credential_ids_are_rejected() -> None:
    spec = CredentialSpec(
        credential_id=OPENAI,
        provider="OpenAI",
        owner=CredentialOwner.CALLER_BYOK,
        env_aliases=("OPENAI_API_KEY",),
    )
    with pytest.raises(ValueError, match="Duplicate credential id"):
        CredentialCatalogue([spec, spec])


@pytest.mark.unit
def test_two_credentials_may_not_claim_the_same_env_alias() -> None:
    """Otherwise scrubbing one would silently disarm the other."""
    a = CredentialSpec(
        credential_id=CredentialId("a-api"),
        provider="A",
        owner=CredentialOwner.CALLER_BYOK,
        env_aliases=("SHARED_KEY",),
    )
    b = CredentialSpec(
        credential_id=CredentialId("b-api"),
        provider="B",
        owner=CredentialOwner.OPERATOR,
        env_aliases=("SHARED_KEY",),
    )
    with pytest.raises(ValueError, match="claimed by both"):
        CredentialCatalogue([a, b])


@pytest.mark.unit
def test_a_spec_must_declare_at_least_one_alias() -> None:
    with pytest.raises(ValueError, match="no env_aliases"):
        CredentialSpec(
            credential_id=CredentialId("x-api"),
            provider="X",
            owner=CredentialOwner.CALLER_BYOK,
            env_aliases=(),
        )


@pytest.mark.unit
def test_probe_must_be_https() -> None:
    with pytest.raises(ValueError, match="must be https"):
        ProviderProbe(url="http://api.openai.com/v1/models", header="Authorization")


@pytest.mark.unit
def test_probe_template_must_carry_the_key() -> None:
    with pytest.raises(ValueError, match=r"\{key\}"):
        ProviderProbe(
            url="https://api.openai.com/v1/models",
            header="Authorization",
            header_template="Bearer nothing",
        )


@pytest.mark.unit
def test_probe_status_sets_may_not_overlap() -> None:
    with pytest.raises(ValueError, match="overlap"):
        ProviderProbe(
            url="https://api.openai.com/v1/models",
            header="Authorization",
            valid_statuses=frozenset({200, 401}),
            invalid_statuses=frozenset({401}),
        )


@pytest.mark.unit
def test_probe_puts_the_key_in_a_header_not_a_query_string(
    catalogue: CredentialCatalogue,
) -> None:
    spec = catalogue.get("openai-api")
    assert spec.probe is not None
    headers = spec.probe.build_header("sk-test")
    assert headers == {"Authorization": "Bearer sk-test"}
    assert "sk-test" not in spec.probe.url


@pytest.mark.unit
def test_owner_split_drives_the_scrub_set(catalogue: CredentialCatalogue) -> None:
    caller_funded = {s.credential_id for s in catalogue.caller_funded()}
    assert "openai-api" in caller_funded
    assert "internal-metrics" not in caller_funded
