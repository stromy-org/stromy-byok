"""Validator classification — provider-specific, tri-state, never body-leaking.

No live network call happens here. The status codes asserted are the ones real
read-only probes with invalid keys actually returned, recorded so a future
change to the classification has to argue with the evidence.
"""

from __future__ import annotations

import pytest

from stromy_byok import CredentialCatalogue, ValidationStatus, classify_status, validate_key
from stromy_byok.validators import _MAX_BODY_BYTES


@pytest.mark.unit
def test_openai_401_is_definitive(catalogue: CredentialCatalogue) -> None:
    """Observed: OpenAI /v1/models returns 401 for an invalid key."""
    probe = catalogue.get("openai-api").probe
    assert probe is not None
    assert classify_status(probe, 401).status is ValidationStatus.INVALID


@pytest.mark.unit
def test_apify_401_is_definitive(catalogue: CredentialCatalogue) -> None:
    """Observed: Apify /v2/users/me returns 401 for an invalid token."""
    probe = catalogue.get("apify-api").probe
    assert probe is not None
    assert classify_status(probe, 401).status is ValidationStatus.INVALID


@pytest.mark.unit
def test_gemini_400_is_NOT_treated_as_definitive(catalogue: CredentialCatalogue) -> None:
    """Observed: Gemini /v1beta/models returns 400 — not 401 — for a bad key.

    This is the single most important classification case. A global
    "not 200 means invalid" rule would reject working keys for every provider
    that answers 400, and a global "only 401 is invalid" rule would accept
    broken Gemini keys. Hence per-credential status sets.
    """
    probe = catalogue.get("google-genai").probe
    assert probe is not None
    outcome = classify_status(probe, 400)
    assert outcome.status is ValidationStatus.UNVERIFIED_TRANSIENT
    assert outcome.rejects_storage is False


@pytest.mark.unit
def test_200_is_valid(catalogue: CredentialCatalogue) -> None:
    probe = catalogue.get("openai-api").probe
    assert probe is not None
    assert classify_status(probe, 200).status is ValidationStatus.VALID


@pytest.mark.parametrize("status", [500, 502, 503, 504])
@pytest.mark.unit
def test_5xx_never_rejects_a_key(catalogue: CredentialCatalogue, status: int) -> None:
    probe = catalogue.get("openai-api").probe
    assert probe is not None
    outcome = classify_status(probe, status)
    assert outcome.status is ValidationStatus.UNVERIFIED_TRANSIENT
    assert outcome.rejects_storage is False


@pytest.mark.unit
def test_rate_limit_never_rejects_a_key(catalogue: CredentialCatalogue) -> None:
    probe = catalogue.get("openai-api").probe
    assert probe is not None
    assert classify_status(probe, 429).rejects_storage is False


@pytest.mark.unit
def test_only_invalid_rejects_storage(catalogue: CredentialCatalogue) -> None:
    probe = catalogue.get("openai-api").probe
    assert probe is not None
    rejecting = [s for s in (200, 400, 401, 403, 429, 500) if classify_status(probe, s).rejects_storage]
    assert rejecting == [401, 403]


@pytest.mark.unit
def test_a_spec_without_a_probe_is_unverified_not_valid(
    catalogue: CredentialCatalogue,
) -> None:
    """An undeclared validator must never read as a VERIFIED key."""
    outcome = validate_key(catalogue.get("deepseek-api"), "ds-anything")
    assert outcome.status is ValidationStatus.UNVERIFIED_TRANSIENT


@pytest.mark.unit
def test_transport_failure_is_unverified_and_leaks_nothing(
    catalogue: CredentialCatalogue, monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    """A network error must not put the key (or a URL carrying it) in a log."""
    import httpx

    class Boom:
        def __init__(self, *a, **kw) -> None:  # noqa: ANN002, ANN003
            pass

        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, *a) -> None:  # noqa: ANN002
            return None

        def get(self, *a, **kw):  # noqa: ANN002, ANN003, ANN201
            raise httpx.ConnectError("failed to connect to sk-LEAKY.example")

    monkeypatch.setattr(httpx, "Client", Boom)
    with caplog.at_level("WARNING"):
        outcome = validate_key(catalogue.get("openai-api"), "sk-LEAKY")

    assert outcome.status is ValidationStatus.UNVERIFIED_TRANSIENT
    assert "sk-LEAKY" not in caplog.text
    assert "sk-LEAKY" not in outcome.detail


@pytest.mark.unit
def test_response_body_is_bounded() -> None:
    assert _MAX_BODY_BYTES <= 4096
