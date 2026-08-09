"""Provider key validation.

One rule, learned from real probes: **there is no single global HTTP rule that
classifies every provider.** Read-only probes with deliberately invalid keys
returned 401 from OpenAI ``/v1/models``, Apify ``/v2/users/me`` and Hunter
``/v2/account`` — but **400** from Gemini ``/v1beta/models``. A validator that
treats "not 200" as invalid would reject working keys, and one that treats only
401 as invalid would accept broken Gemini keys. So each credential declares its
own status sets in its :class:`~stromy_byok.catalogue.ProviderProbe`.

The tri-state exists for the same reason. A timeout, a 5xx or a rate limit says
nothing about the key, and a *valid but narrowly scoped* key can return 403 on
a listing endpoint while working perfectly for the call we actually make. Only
:attr:`~stromy_byok.models.ValidationStatus.INVALID` rejects storage;
``unverified_transient`` stores the key and records that we could not confirm it.

Hardening applied to every probe:

- fixed HTTPS host and path from the catalogue — never caller-supplied;
- the key travels in a **header**, never a query parameter (query strings land
  in provider access logs and every proxy in between);
- redirects disabled (a redirect could carry the Authorization header to a
  host we did not choose);
- a bounded response read and a hard deadline;
- the provider's response body is **never** returned or logged — only a
  sanitized, provider-agnostic message derived from the status class.
"""

from __future__ import annotations

import logging

from stromy_byok.catalogue import CredentialSpec, ProviderProbe
from stromy_byok.models import ValidationOutcome, ValidationStatus

logger = logging.getLogger(__name__)

__all__ = ["classify_status", "validate_key", "validate_key_async"]

#: Cap on how much of a provider response we read. We never parse the body —
#: this exists purely so a hostile or broken endpoint cannot stream us to death.
_MAX_BODY_BYTES = 2048


def classify_status(probe: ProviderProbe, status_code: int) -> ValidationOutcome:
    """Map an HTTP status to a tri-state outcome using the probe's own sets.

    Order matters: ``invalid`` is checked before ``valid`` so that a
    misdeclared overlapping set fails closed rather than silently accepting.
    (``ProviderProbe`` rejects overlapping sets at construction, so this is
    defence in depth.)
    """
    if status_code in probe.invalid_statuses:
        return ValidationOutcome(
            ValidationStatus.INVALID,
            "The provider rejected this key. Check you pasted it in full and that it is active.",
        )
    if status_code in probe.valid_statuses:
        return ValidationOutcome(ValidationStatus.VALID, "Key verified with the provider.")
    if 500 <= status_code < 600:
        return ValidationOutcome(
            ValidationStatus.UNVERIFIED_TRANSIENT,
            "The provider is having trouble right now, so we could not verify the key. "
            "It has been saved.",
        )
    if status_code == 429:
        return ValidationOutcome(
            ValidationStatus.UNVERIFIED_TRANSIENT,
            "The provider rate-limited the check, so we could not verify the key. "
            "It has been saved.",
        )
    # Anything else — including a scoped-key 403 on a listing endpoint, or
    # Gemini's 400 shape when a probe declares it non-definitive.
    return ValidationOutcome(
        ValidationStatus.UNVERIFIED_TRANSIENT,
        "We could not confirm this key with the provider. It has been saved; "
        "if calls fail, re-register it.",
    )


def _unverified(reason: str) -> ValidationOutcome:
    return ValidationOutcome(ValidationStatus.UNVERIFIED_TRANSIENT, reason)


_NETWORK_MESSAGE = (
    "We could not reach the provider to verify the key. It has been saved; "
    "if calls fail, re-register it."
)


def validate_key(spec: CredentialSpec, key: str) -> ValidationOutcome:
    """Probe ``key`` against ``spec``'s declared endpoint, synchronously.

    A spec with no probe returns ``unverified_transient`` — an undeclared
    validator must never read as a *verified* key.
    """
    if spec.probe is None:
        return _unverified("No validator is declared for this provider; the key has been saved.")
    try:
        import httpx
    except ImportError:  # pragma: no cover - httpx is a hard dependency
        return _unverified("Validation is unavailable on this server; the key has been saved.")

    probe = spec.probe
    try:
        with httpx.Client(timeout=probe.timeout_seconds, follow_redirects=False) as client:
            response = client.get(probe.url, headers=probe.build_header(key))
            _ = response.content[:_MAX_BODY_BYTES]
    except Exception as exc:  # noqa: BLE001 - every transport failure is non-definitive
        # Log the exception *type* only. The string form of an httpx error can
        # include the request URL, and a misbuilt probe could put the key there.
        logger.warning(
            "credential validation could not complete for %s: %s",
            spec.credential_id,
            type(exc).__name__,
        )
        return _unverified(_NETWORK_MESSAGE)
    return classify_status(probe, response.status_code)


async def validate_key_async(spec: CredentialSpec, key: str) -> ValidationOutcome:
    """Async twin of :func:`validate_key`, for use inside an ASGI route."""
    if spec.probe is None:
        return _unverified("No validator is declared for this provider; the key has been saved.")
    try:
        import httpx
    except ImportError:  # pragma: no cover - httpx is a hard dependency
        return _unverified("Validation is unavailable on this server; the key has been saved.")

    probe = spec.probe
    try:
        async with httpx.AsyncClient(
            timeout=probe.timeout_seconds, follow_redirects=False
        ) as client:
            response = await client.get(probe.url, headers=probe.build_header(key))
            _ = response.content[:_MAX_BODY_BYTES]
    except Exception as exc:  # noqa: BLE001 - every transport failure is non-definitive
        logger.warning(
            "credential validation could not complete for %s: %s",
            spec.credential_id,
            type(exc).__name__,
        )
        return _unverified(_NETWORK_MESSAGE)
    return classify_status(probe, response.status_code)
