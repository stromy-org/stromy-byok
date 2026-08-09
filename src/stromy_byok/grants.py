"""Bound, single-use registration grants.

A grant is a *capability*: whoever holds the opaque token may bind or disable
one credential for one subject. Everything that scopes that capability is baked
into the grant at mint time and **never** read from the request:

    subject + subject_kind + service + workflow + credential_id + action
    + issuer + issued_at + expires_at + nonce

The ``/keys`` route therefore accepts a token and a key, and nothing else. If
the route took ``credential_id`` from the form, a holder of a grant for
``apify-api`` could register a value as ``openai-api``; if it took the subject,
they could register against someone else's identity. The whole point of the
binding is that those fields have exactly one source.

**Peek does not spend.** ``GET`` peeks so a reload or a mistyped key does not
burn the link; only a successful ``POST`` consumes, exactly once.

**Single-replica invariant.** The in-memory store is correct only while the
registration app runs one replica — otherwise the browser can land on a
process that never minted the token. That is not left to documentation:
:func:`assert_single_replica_or_durable` is called at startup/readiness and
refuses ``maxReplicas > 1`` unless a durable :class:`RegistrationGrantStore` is
supplied.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from stromy_byok.exceptions import StromyByokError
from stromy_byok.models import CredentialId, Subject

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_TTL_SECONDS",
    "Grant",
    "GrantAction",
    "GrantError",
    "InMemoryGrantStore",
    "RegistrationGrantStore",
    "assert_single_replica_or_durable",
]

#: Grant lifetime. Short on purpose: the holder opens the link seconds after
#: their agent mints it, and the grant is a credential-binding capability.
#: Must stay below the container's scale-to-zero cooldown so the TTL — not the
#: process lifecycle — is what expires a grant.
DEFAULT_TTL_SECONDS = 900


class GrantError(StromyByokError):
    """A grant was missing, expired, already spent, or used for the wrong action."""


class GrantAction(StrEnum):
    """What a grant permits. A grant permits exactly one of these."""

    #: Write a new enabled version (first registration or rotation).
    REGISTER_OR_ROTATE = "register_or_rotate"
    #: Disable the current version.
    DISCONNECT = "disconnect"


@dataclass(frozen=True, slots=True)
class Grant:
    """An issued capability. Every field is authoritative; none is re-read."""

    token: str
    subject: Subject
    service: str
    credential_id: CredentialId
    action: GrantAction
    issuer: str
    issued_at: float
    expires_at: float
    nonce: str
    workflow: str | None = None

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.monotonic()) >= self.expires_at

    def permits(self, action: GrantAction) -> bool:
        return self.action is action

    def __repr__(self) -> str:
        # The token is a bearer capability — keep it out of tracebacks.
        return (
            f"Grant(service={self.service!r}, credential_id={str(self.credential_id)!r}, "
            f"action={self.action.value!r}, subject={self.subject!r}, "
            f"workflow={self.workflow!r}, token=<redacted>)"
        )


@runtime_checkable
class RegistrationGrantStore(Protocol):
    """Mint / peek / consume. Implement this to survive multiple replicas."""

    def mint(self, grant: Grant) -> None: ...

    def peek(self, token: str) -> Grant | None:
        """Return the grant without spending it, or ``None`` if invalid/expired."""
        ...

    def consume(self, token: str) -> Grant | None:
        """Atomically spend the grant, or ``None`` if invalid/expired/spent."""
        ...


class InMemoryGrantStore:
    """Thread-safe, TTL-pruned grant store for a single-replica process.

    Deliberately in-memory: a restart drops pending grants, which is the
    correct behaviour (mint a fresh one) and keeps a credential-granting
    capability out of any durable store.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants: dict[str, Grant] = {}

    def mint(self, grant: Grant) -> None:
        with self._lock:
            self._prune_locked()
            self._grants[grant.token] = grant

    def peek(self, token: str) -> Grant | None:
        if not token:
            return None
        with self._lock:
            self._prune_locked()
            return self._grants.get(token)

    def consume(self, token: str) -> Grant | None:
        if not token:
            return None
        with self._lock:
            self._prune_locked()
            return self._grants.pop(token, None)

    def _prune_locked(self) -> None:
        now = time.monotonic()
        self._grants = {t: g for t, g in self._grants.items() if not g.is_expired(now)}


def mint_grant(
    store: RegistrationGrantStore,
    *,
    subject: Subject,
    service: str,
    credential_id: CredentialId,
    action: GrantAction,
    issuer: str,
    workflow: str | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> Grant:
    """Mint and persist a bound grant, returning it (the caller sends the token).

    ``credential_id`` must already have been checked against the catalogue and
    the caller's entitlement *by the caller* — this function binds, it does not
    authorize.
    """
    if not service:
        raise ValueError("mint_grant requires a service name")
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    now = time.monotonic()
    grant = Grant(
        token=secrets.token_urlsafe(32),
        subject=subject,
        service=service,
        credential_id=credential_id,
        action=action,
        issuer=issuer,
        issued_at=now,
        expires_at=now + ttl_seconds,
        nonce=secrets.token_urlsafe(16),
        workflow=workflow,
    )
    store.mint(grant)
    return grant


def consume_for(
    store: RegistrationGrantStore, token: str, action: GrantAction
) -> Grant:
    """Spend ``token``, asserting it permits ``action``.

    A grant used for the wrong action is **not** consumed — it is rejected and
    left intact, so a disconnect link mis-posted as a registration does not
    silently destroy the user's only valid grant.
    """
    grant = store.peek(token)
    if grant is None:
        raise GrantError("This link is invalid or has expired.")
    if not grant.permits(action):
        raise GrantError("This link does not permit that action.")
    spent = store.consume(token)
    if spent is None:  # lost a race with a concurrent submit
        raise GrantError("This link has already been used.")
    return spent


def assert_single_replica_or_durable(
    store: RegistrationGrantStore, max_replicas: int
) -> None:
    """Refuse an in-memory grant store on a multi-replica deployment.

    Called from startup and from the readiness report. Without this, scaling
    the registration app to two replicas turns "mint a link, open it" into a
    coin flip — a failure that looks like flaky links rather than a
    misconfiguration, which is why it is asserted rather than documented.
    """
    if max_replicas > 1 and isinstance(store, InMemoryGrantStore):
        raise GrantError(
            f"maxReplicas={max_replicas} with an in-memory grant store: a registration "
            "link minted on one replica is unresolvable on another. Supply a durable "
            "RegistrationGrantStore, or pin the registration app to a single replica."
        )
