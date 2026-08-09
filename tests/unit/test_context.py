"""The credential scope — the mechanism that stops silent operator spend.

These are the highest-value tests in the package. The failure they guard is
not a crash: it is a client-mode run quietly succeeding on Stromy's key and
sending Stromy the bill.
"""

from __future__ import annotations

import pytest

from stromy_byok import (
    CredentialCatalogue,
    CredentialSource,
    ResolvedCredential,
    credential_scope,
    safe_sources,
    scrub_aliases,
)
from tests.conftest import APIFY, DEEPSEEK, OPENAI


@pytest.mark.unit
def test_client_mode_scrubs_every_caller_funded_alias(catalogue: CredentialCatalogue) -> None:
    """The operator's ambient keys must be gone BEFORE client keys go in."""
    env = {
        "OPENAI_API_KEY": "sk-STROMY-OPERATOR",
        "DEEPSEEK_API_KEY": "ds-STROMY-OPERATOR",
        "APIFY_API_TOKEN": "apify-STROMY",
        "APIFY_TOKEN": "apify-STROMY-ALT",
        "HUNTER_API_KEY": "hunter-STROMY",
        "INTERNAL_METRICS_KEY": "operator-owned",
    }
    resolved = [ResolvedCredential(OPENAI, CredentialSource.CALLER_BYOK, "sk-CLIENT")]

    with credential_scope(catalogue, resolved, scrub=True, env=env):
        assert env["OPENAI_API_KEY"] == "sk-CLIENT"
        # Every other caller-funded alias is GONE, not merely overwritten.
        assert "DEEPSEEK_API_KEY" not in env
        assert "APIFY_API_TOKEN" not in env
        assert "APIFY_TOKEN" not in env
        assert "HUNTER_API_KEY" not in env
        # An operator-owned credential is NOT caller-funded and stays put.
        assert env["INTERNAL_METRICS_KEY"] == "operator-owned"


@pytest.mark.unit
def test_the_second_apify_alias_is_not_forgotten(catalogue: CredentialCatalogue) -> None:
    """APIFY_TOKEN is as real as APIFY_API_TOKEN.

    A hand-written scrub list is exactly where the second alias gets dropped,
    leaving a live caller-funded credential in a client-mode environment. The
    scrub list is derived from the catalogue so this cannot drift.
    """
    aliases = catalogue.caller_funded_env_aliases()
    assert "APIFY_API_TOKEN" in aliases
    assert "APIFY_TOKEN" in aliases
    assert "INTERNAL_METRICS_KEY" not in aliases


@pytest.mark.unit
def test_operator_mode_leaves_ambient_keys_intact(catalogue: CredentialCatalogue) -> None:
    env = {"OPENAI_API_KEY": "sk-STROMY-OPERATOR"}
    with credential_scope(catalogue, [], scrub=False, env=env):
        assert env["OPENAI_API_KEY"] == "sk-STROMY-OPERATOR"


@pytest.mark.unit
def test_environment_is_restored_exactly_on_success(catalogue: CredentialCatalogue) -> None:
    env = {"OPENAI_API_KEY": "sk-ORIGINAL", "DEEPSEEK_API_KEY": "ds-ORIGINAL"}
    before = dict(env)
    resolved = [ResolvedCredential(OPENAI, CredentialSource.CALLER_BYOK, "sk-CLIENT")]
    with credential_scope(catalogue, resolved, scrub=True, env=env):
        pass
    assert env == before


@pytest.mark.unit
def test_environment_is_restored_when_the_graph_raises(catalogue: CredentialCatalogue) -> None:
    """Restoration is in `finally` — an exploding graph must not leak state."""
    env = {"OPENAI_API_KEY": "sk-ORIGINAL", "APIFY_TOKEN": "apify-ORIGINAL"}
    before = dict(env)
    resolved = [ResolvedCredential(OPENAI, CredentialSource.CALLER_BYOK, "sk-CLIENT")]

    with pytest.raises(RuntimeError, match="graph exploded"):
        with credential_scope(catalogue, resolved, scrub=True, env=env):
            assert env["OPENAI_API_KEY"] == "sk-CLIENT"
            raise RuntimeError("graph exploded")

    assert env == before


@pytest.mark.unit
def test_absent_variable_is_restored_as_absent_not_empty(catalogue: CredentialCatalogue) -> None:
    """`VAR in env` must answer the same before and after the scope."""
    env: dict[str, str] = {}
    resolved = [ResolvedCredential(OPENAI, CredentialSource.CALLER_BYOK, "sk-CLIENT")]
    with credential_scope(catalogue, resolved, scrub=True, env=env):
        assert env["OPENAI_API_KEY"] == "sk-CLIENT"
    assert "OPENAI_API_KEY" not in env


@pytest.mark.unit
def test_a_credential_with_no_value_injects_nothing(catalogue: CredentialCatalogue) -> None:
    env = {"OPENAI_API_KEY": "sk-OPERATOR"}
    resolved = [ResolvedCredential(OPENAI, CredentialSource.DENIED_UNREGISTERED, None)]
    with credential_scope(catalogue, resolved, scrub=True, env=env):
        # Scrubbed, and NOT refilled from the operator's value.
        assert "OPENAI_API_KEY" not in env


@pytest.mark.unit
def test_multi_alias_credential_fills_every_alias(catalogue: CredentialCatalogue) -> None:
    env: dict[str, str] = {}
    resolved = [ResolvedCredential(APIFY, CredentialSource.CALLER_BYOK, "apify-CLIENT")]
    with credential_scope(catalogue, resolved, scrub=True, env=env):
        assert env["APIFY_API_TOKEN"] == "apify-CLIENT"
        assert env["APIFY_TOKEN"] == "apify-CLIENT"


@pytest.mark.unit
def test_scrub_aliases_reports_prior_values(catalogue: CredentialCatalogue) -> None:
    env = {"OPENAI_API_KEY": "sk-1"}
    prior = scrub_aliases(["OPENAI_API_KEY", "MISSING_VAR"], env)
    assert prior == {"OPENAI_API_KEY": "sk-1", "MISSING_VAR": None}
    assert env == {}


@pytest.mark.unit
def test_safe_sources_never_carries_a_value() -> None:
    resolved = [
        ResolvedCredential(OPENAI, CredentialSource.CALLER_BYOK, "sk-SECRET"),
        ResolvedCredential(DEEPSEEK, CredentialSource.CALLER_BYOK, "ds-SECRET"),
    ]
    sources = safe_sources(resolved)
    flat = repr(sources)
    assert "sk-SECRET" not in flat
    assert "ds-SECRET" not in flat
    assert sources[0] == {"credential_id": "openai-api", "source": "caller-byok"}


@pytest.mark.unit
def test_resolved_credential_repr_is_redacted() -> None:
    credential = ResolvedCredential(OPENAI, CredentialSource.CALLER_BYOK, "sk-SECRET")
    assert "sk-SECRET" not in repr(credential)
    assert "<redacted>" in repr(credential)
