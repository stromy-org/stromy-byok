"""Shared fixtures.

The catalogue here mirrors the real initial declaration set (OpenAI, DeepSeek,
Google, Apify, Hunter) closely enough that the alias-scrubbing tests are
meaningful — including the two-alias Apify case, which is exactly the shape a
naive scrub list gets wrong.
"""

from __future__ import annotations

import pytest

from stromy_byok import (
    CredentialCatalogue,
    CredentialId,
    CredentialOwner,
    CredentialSpec,
    InMemoryCredentialStore,
    InMemoryGrantStore,
    ProviderProbe,
    Subject,
    SubjectKind,
)

OPENAI = CredentialId("openai-api")
DEEPSEEK = CredentialId("deepseek-api")
APIFY = CredentialId("apify-api")
HUNTER = CredentialId("hunter-api")
GOOGLE = CredentialId("google-genai")
OPERATOR_ONLY = CredentialId("internal-metrics")


@pytest.fixture
def catalogue() -> CredentialCatalogue:
    return CredentialCatalogue(
        [
            CredentialSpec(
                credential_id=OPENAI,
                provider="OpenAI",
                owner=CredentialOwner.CALLER_BYOK,
                env_aliases=("OPENAI_API_KEY",),
                display_name="OpenAI API key",
                signup_url="https://platform.openai.com/api-keys",
                probe=ProviderProbe(
                    url="https://api.openai.com/v1/models",
                    header="Authorization",
                    header_template="Bearer {key}",
                ),
            ),
            CredentialSpec(
                credential_id=DEEPSEEK,
                provider="DeepSeek",
                owner=CredentialOwner.CALLER_BYOK,
                env_aliases=("DEEPSEEK_API_KEY",),
                display_name="DeepSeek API key",
            ),
            CredentialSpec(
                credential_id=APIFY,
                provider="Apify",
                owner=CredentialOwner.CALLER_BYOK,
                # Two real aliases. A scrub list that knows only the first
                # leaves a live caller-funded credential in the environment.
                env_aliases=("APIFY_API_TOKEN", "APIFY_TOKEN"),
                display_name="Apify API token",
                probe=ProviderProbe(
                    url="https://api.apify.com/v2/users/me",
                    header="Authorization",
                    header_template="Bearer {key}",
                ),
            ),
            CredentialSpec(
                credential_id=HUNTER,
                provider="Hunter",
                owner=CredentialOwner.CALLER_BYOK,
                env_aliases=("HUNTER_API_KEY",),
            ),
            CredentialSpec(
                credential_id=GOOGLE,
                provider="Google",
                owner=CredentialOwner.CALLER_BYOK,
                env_aliases=("GOOGLE_API_KEY", "GEMINI_API_KEY"),
                # Gemini answers 400 — not 401 — to an invalid key, so its
                # probe must NOT declare 400 as definitive.
                probe=ProviderProbe(
                    url="https://generativelanguage.googleapis.com/v1beta/models",
                    header="x-goog-api-key",
                    invalid_statuses=frozenset({401, 403}),
                ),
            ),
            CredentialSpec(
                credential_id=OPERATOR_ONLY,
                provider="Internal",
                owner=CredentialOwner.OPERATOR,
                env_aliases=("INTERNAL_METRICS_KEY",),
            ),
        ]
    )


@pytest.fixture
def store() -> InMemoryCredentialStore:
    return InMemoryCredentialStore()


@pytest.fixture
def grants() -> InMemoryGrantStore:
    return InMemoryGrantStore()


@pytest.fixture
def alice() -> Subject:
    return Subject(SubjectKind.ENTRA_OID, "11111111-2222-3333-4444-555555555555")


@pytest.fixture
def bob() -> Subject:
    return Subject(SubjectKind.ENTRA_OID, "99999999-8888-7777-6666-555555555555")


@pytest.fixture
def duke() -> Subject:
    return Subject(SubjectKind.CLIENT_SLUG, "dukestrategies")
