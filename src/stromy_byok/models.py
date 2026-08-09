"""Core value types for the BYOK credential plane.

Everything here is deliberately *client-neutral*: no client slug, provider
endpoint, vault URI or service name is hardcoded. Adopting applications supply
those through :mod:`stromy_byok.catalogue` and their own configuration.

The types in this module are the vocabulary the rest of the package speaks:

- :class:`Subject` — *who* a credential belongs to, and by what kind of identity.
- :class:`CredentialId` — *which* declared credential, from a closed catalogue.
- :class:`ResolvedCredential` — a resolution decision, carrying a **source label
  and never the value**.
- :class:`ValidationOutcome` — the tri-state result of probing a provider.
- :class:`AuditEvent` — a structured, pre-redacted record of a lifecycle action.

Invariant that binds the whole module: **no type here ever carries secret
material in a field that gets logged, serialized or returned to a caller.**
:class:`ResolvedCredential` is the one type that holds a value, and it is
explicitly non-reprable (see its docstring).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self

__all__ = [
    "AuditAction",
    "AuditEvent",
    "CredentialId",
    "CredentialSource",
    "ResolvedCredential",
    "Subject",
    "SubjectKind",
    "ValidationOutcome",
    "ValidationStatus",
    "utcnow",
]


def utcnow() -> datetime:
    """Timezone-aware UTC now, in one place so tests can monkeypatch it."""
    return datetime.now(UTC)


class SubjectKind(StrEnum):
    """How the subject of a credential was identified.

    The kind is part of the opaque secret name, so two subjects that happen to
    share a string value under different identity schemes can never collide.
    """

    #: A verified Entra object id (``oid``) — a personal interactive caller.
    ENTRA_OID = "entra-oid"
    #: A client slug resolved from a verified ``client.<slug>`` role claim.
    CLIENT_SLUG = "client-slug"


@dataclass(frozen=True, slots=True)
class Subject:
    """The verified principal a credential belongs to.

    ``value`` is **never** logged, echoed in a response, or written into a Key
    Vault tag. Use :attr:`hashed` wherever an identifier must be recorded.
    """

    kind: SubjectKind
    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("Subject.value must be a non-empty string")

    @property
    def qualified(self) -> str:
        """``<kind>:<value>`` — the string that gets hashed. Never log this."""
        return f"{self.kind.value}:{self.value}"

    @property
    def hashed(self) -> str:
        """A stable 32-hex digest of the qualified subject, safe to record.

        32 hex chars = 128 bits of the SHA-256 digest: collision-free at any
        realistic subject count while keeping the derived secret name well
        inside Key Vault's 127-character limit.
        """
        return hashlib.sha256(self.qualified.encode("utf-8")).hexdigest()[:32]

    def __repr__(self) -> str:
        # Defensive: a stray repr in a traceback or log must not leak the oid.
        return f"Subject(kind={self.kind.value!r}, hashed={self.hashed!r})"


class CredentialId(str):
    """A stable identifier for one declared credential, e.g. ``openai-api``.

    A ``str`` subclass so it slots into dict keys, sets and formatting without
    ceremony, while still being a distinct type in signatures. Construction
    validates the grammar, because the value becomes part of a Key Vault secret
    name and Key Vault permits only ``[0-9a-zA-Z-]``.
    """

    __slots__ = ()

    def __new__(cls, value: str) -> Self:
        if not value:
            raise ValueError("CredentialId must be non-empty")
        if not all(c.isalnum() and c.isascii() or c == "-" for c in value):
            raise ValueError(
                f"CredentialId {value!r} may contain only ASCII letters, digits and hyphens "
                "(it becomes part of a Key Vault secret name)"
            )
        if value.startswith("-") or value.endswith("-"):
            raise ValueError(f"CredentialId {value!r} must not start or end with a hyphen")
        return super().__new__(cls, value)


class CredentialSource(StrEnum):
    """Where the credential used for a call actually came from.

    This is a **recorded fact, not an inference**. The absence of a denial is
    not evidence of a billing path — every resolution stamps one of these.
    """

    #: The caller's own registered key. Spend lands on the caller.
    CALLER_BYOK = "caller-byok"
    #: An operator identity falling back to the service's ambient key.
    OPERATOR_FALLBACK = "operator-fallback"
    #: Operator/ambient process environment (hosted operator-funded run).
    OPERATOR_ENV = "operator-env"
    #: No verified identity at all (local, dev, CI) — ambient env.
    LOCAL = "local"
    #: A non-operator caller with nothing registered: denied, no spend.
    DENIED_UNREGISTERED = "denied-unregistered"


@dataclass(frozen=True, slots=True)
class ResolvedCredential:
    """One resolved credential: its declared id, its source, and its value.

    **This is the only type in the package that holds secret material.** It
    deliberately overrides ``__repr__`` so that a debugger, a traceback frame,
    a ``print()`` or a structured-logging call that naively reprs its arguments
    cannot leak the value. Use :meth:`safe_dict` for anything recorded.
    """

    credential_id: CredentialId
    source: CredentialSource
    value: str | None = None

    def safe_dict(self) -> dict[str, str]:
        """The recordable projection: id and source, never the value."""
        return {"credential_id": str(self.credential_id), "source": self.source.value}

    def __repr__(self) -> str:
        held = "<redacted>" if self.value else "None"
        return (
            f"ResolvedCredential(credential_id={str(self.credential_id)!r}, "
            f"source={self.source.value!r}, value={held})"
        )


class ValidationStatus(StrEnum):
    """Tri-state outcome of probing a provider with a candidate key.

    Deliberately three states, not two. A binary valid/invalid forces a
    timeout, a 5xx or a *valid-but-narrowly-scoped* key into one of the two
    buckets — and whichever way you choose, you either reject working keys or
    accept broken ones. Only :attr:`INVALID` may reject storage.
    """

    #: The probe succeeded — the key authenticates.
    VALID = "valid"
    #: A definitive authentication rejection from the provider.
    INVALID = "invalid"
    #: Timeout, 5xx, rate limit, or a valid-but-insufficiently-scoped response.
    UNVERIFIED_TRANSIENT = "unverified_transient"


@dataclass(frozen=True, slots=True)
class ValidationOutcome:
    """The persisted result of a validation probe.

    ``detail`` is a **sanitized** message safe to show a user and write to a
    Key Vault tag. Raw provider response bodies never reach this field — see
    :mod:`stromy_byok.validators`.
    """

    status: ValidationStatus
    detail: str = ""

    @property
    def rejects_storage(self) -> bool:
        """Only a definitive ``invalid`` may block a write."""
        return self.status is ValidationStatus.INVALID


class AuditAction(StrEnum):
    """The lifecycle actions that emit a structured audit event."""

    GRANT_MINTED = "grant.minted"
    GRANT_EXCHANGED = "grant.exchanged"
    GRANT_DENIED = "grant.denied"
    CREDENTIAL_REGISTERED = "credential.registered"
    CREDENTIAL_ROTATED = "credential.rotated"
    CREDENTIAL_DISCONNECTED = "credential.disconnected"
    RESOLUTION_ALLOWED = "resolution.allowed"
    RESOLUTION_DENIED = "resolution.denied"
    OPERATOR_ACTING_FOR = "operator.acting_for"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """A structured, already-redacted record of one lifecycle action.

    Carries the *hashed* subject, never the raw one, and never a credential
    value. Emitting this type is what makes spend attribution and credential
    lifecycle observable without turning the log into a secret store.
    """

    action: AuditAction
    service: str
    outcome: str
    subject_hash: str | None = None
    subject_kind: SubjectKind | None = None
    credential_id: CredentialId | None = None
    workflow: str | None = None
    run_id: str | None = None
    reason: str | None = None
    at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Flat, JSON-safe projection for a structured log sink."""
        payload: dict[str, Any] = {
            "action": self.action.value,
            "service": self.service,
            "outcome": self.outcome,
            "at": self.at.isoformat(),
        }
        if self.subject_hash:
            payload["subject_hash"] = self.subject_hash
        if self.subject_kind:
            payload["subject_kind"] = self.subject_kind.value
        if self.credential_id:
            payload["credential_id"] = str(self.credential_id)
        if self.workflow:
            payload["workflow"] = self.workflow
        if self.run_id:
            payload["run_id"] = self.run_id
        if self.reason:
            payload["reason"] = self.reason
        return payload
