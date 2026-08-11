"""Credential storage, split by privilege.

Three protocols, deliberately separate:

- :class:`CredentialReader` — ``get_enabled`` / ``exists``. What a *workload*
  identity needs.
- :class:`CredentialWriter` — ``put_version`` / ``disable`` / ``metadata``. What
  a *registration* identity needs, and nothing a workload should hold.
- :class:`RegistrationGrantStore` lives in :mod:`stromy_byok.grants`.

Splitting them is not decoration: the Terraform module grants the runner
identity Key Vault *Secrets User* and the registration app *Secrets Officer*,
and these protocols are the code-side mirror of that RBAC split. A single
combined protocol would make it natural to hand a workload a writer.

**Capability is declared, not sniffed.** :attr:`CredentialReader.writable` tells
a caller whether a writer is available. Route construction requires an actual
:class:`CredentialWriter`. This replaces the ``isinstance(store, AzureKeyVault…)``
capability test in the original media-gen implementation, which silently
couples every call site to one concrete class and breaks the moment a second
backend (or a fake, in tests) appears.

**Disable, do not delete.** Azure Key Vault soft delete means a *deleted*
secret name cannot be recreated until it is recovered or purged — so a
delete-based "disconnect" bricks re-registration for the retention window.
:meth:`CredentialWriter.disable` disables the current version instead, leaving
the name free to take a new enabled version immediately. Purge stays an
operator retention action, never a client-facing one.
"""

from __future__ import annotations

import contextlib
import logging
import threading
from typing import Any, Protocol, runtime_checkable

from stromy_byok.catalogue import CATALOGUE_VERSION, CredentialCatalogue
from stromy_byok.exceptions import DependencyError, StromyByokError
from stromy_byok.models import (
    CredentialId,
    Subject,
    SubjectKind,
    ValidationOutcome,
    utcnow,
)

logger = logging.getLogger(__name__)

__all__ = [
    "CredentialReader",
    "CredentialWriter",
    "InMemoryCredentialStore",
    "NullCredentialStore",
    "SecretNaming",
    "StoreUnavailableError",
    "secret_name",
]

#: Key Vault secret names are limited to 127 characters and ``[0-9a-zA-Z-]``.
_MAX_SECRET_NAME = 127


class StoreUnavailableError(StromyByokError):
    """The backing store is not provisioned, so a write cannot be attempted."""


def secret_name(credential_id: CredentialId, subject: Subject) -> str:
    """Build the opaque secret name for ``(credential_id, subject)``.

    ``byok-<credential-id>-<sha256(kind + ":" + subject)[:32]>``

    The subject is hashed, never embedded: a Key Vault secret name is visible
    to anyone with list permission and shows up in diagnostics, so a raw Entra
    oid or client slug in the name would leak the tenancy map to every reader.
    The vault is already application-scoped, so no service prefix is needed.
    """
    name = f"byok-{credential_id}-{subject.hashed}"
    if len(name) > _MAX_SECRET_NAME:  # pragma: no cover - CredentialId grammar prevents this
        raise ValueError(f"Derived secret name exceeds {_MAX_SECRET_NAME} chars: {name!r}")
    return name


class SecretNaming(Protocol):
    """Pluggable naming so an adopter can keep a legacy scheme alive.

    media-gen has live secrets under ``mediagen-byok-<oid>``. A rename orphans
    every registered key, so C3 supplies a compatibility strategy that reads
    the legacy name and writes the new one.
    """

    def primary(self, credential_id: CredentialId, subject: Subject) -> str:
        """The name a *new* version is written under."""
        ...

    def read_order(self, credential_id: CredentialId, subject: Subject) -> tuple[str, ...]:
        """Names to try on read, most-preferred first."""
        ...


class _DefaultNaming:
    """The opaque hashed scheme — the default for every new adopter."""

    def primary(self, credential_id: CredentialId, subject: Subject) -> str:
        return secret_name(credential_id, subject)

    def read_order(self, credential_id: CredentialId, subject: Subject) -> tuple[str, ...]:
        return (secret_name(credential_id, subject),)


DEFAULT_NAMING: SecretNaming = _DefaultNaming()


@runtime_checkable
class CredentialReader(Protocol):
    """Read-side of a credential store — what a workload identity needs."""

    @property
    def writable(self) -> bool:
        """Whether a :class:`CredentialWriter` is available for this backend.

        A declared capability, so callers never need ``isinstance``.
        """
        ...

    def get_enabled(self, credential_id: CredentialId, subject: Subject) -> str | None:
        """Return the enabled secret value, or ``None`` if absent/disabled.

        A *disabled* secret must read as ``None``, not raise — disconnect is a
        normal state, and the caller's job is to fail the run cleanly, not to
        distinguish "never registered" from "turned off".
        """
        ...

    def exists(self, credential_id: CredentialId, subject: Subject) -> bool:
        """Whether an enabled secret exists, without reading its value.

        This is what powers "is this registered?" in a UI. It must never
        return, log or otherwise expose the value.
        """
        ...


@runtime_checkable
class CredentialWriter(Protocol):
    """Write-side of a credential store — what a registration identity needs."""

    def put_version(
        self,
        credential_id: CredentialId,
        subject: Subject,
        value: str,
        *,
        outcome: ValidationOutcome | None = None,
    ) -> None:
        """Write a new **enabled** version under the naming strategy's primary.

        Rotation and first registration are the same operation: a new enabled
        version. That is what makes rotate-after-disconnect work without a
        purge.

        **Superseding is part of the write.** Under a compatibility
        :class:`SecretNaming` the primary is not the only place a value can
        live, so writing it also disables every *other* name in
        ``read_order`` — those are superseded locations by definition, and
        :meth:`get_enabled` short-circuits on the primary anyway, so nothing is
        lost. Skipping it would leave the caller's previous key enabled in the
        vault after a rotation: unreachable, but live, and still there to be
        read by anything holding vault access. It also keeps
        :meth:`disable` provably complete after a rotate.
        """
        ...

    def disable(self, credential_id: CredentialId, subject: Subject) -> bool:
        """Disable the current version. Returns whether anything was disabled.

        Deliberately **not** a delete — see the module docstring.
        """
        ...

    def metadata(self, credential_id: CredentialId, subject: Subject) -> dict[str, str] | None:
        """Non-secret tags for the current version, or ``None`` if absent."""
        ...


def _tags(
    credential_id: CredentialId,
    subject: Subject,
    outcome: ValidationOutcome | None,
    catalogue_version: int,
) -> dict[str, str]:
    """Non-secret tags recorded beside a stored credential.

    Note what is *absent*: the raw subject. Only the hash is stored, matching
    the secret name, so a vault listing never reconstructs the tenancy map.
    """
    tags = {
        "credential_id": str(credential_id),
        "subject_kind": subject.kind.value,
        "subject_hash": subject.hashed,
        "catalogue_version": str(catalogue_version),
        "rotated_at": utcnow().isoformat(),
        "schema_version": "1",
    }
    if outcome is not None:
        tags["validation"] = outcome.status.value
    return tags


class NullCredentialStore:
    """Reader used before a vault is provisioned. Never writable.

    Every subject resolves as unregistered, so the operator/deny split in a
    resolver still behaves correctly — the invariants hold even before the
    Key Vault exists. Crucially it reports ``writable = False`` rather than
    pretending, so route construction fails loudly instead of accepting a key
    and dropping it.
    """

    @property
    def writable(self) -> bool:
        return False

    def get_enabled(self, credential_id: CredentialId, subject: Subject) -> str | None:
        return None

    def exists(self, credential_id: CredentialId, subject: Subject) -> bool:
        return False


class InMemoryCredentialStore:
    """A complete reader+writer for tests and local development.

    Models the parts of Key Vault semantics that the design depends on —
    versions, the enabled flag, and disable-not-delete — so a test can prove
    ``register -> rotate -> disable -> re-register`` without Azure.

    It takes the same ``naming`` strategy as
    :class:`AzureKeyVaultCredentialStore` and resolves through ``read_order``
    identically. An earlier cut hardcoded :func:`secret_name`, which made the
    one seam the library exposes for adopters — compatibility naming — the one
    behavior no test could reach: media-gen's legacy ``mediagen-byok-<oid>``
    fallback could only have been exercised against a live vault.
    """

    def __init__(
        self,
        catalogue: CredentialCatalogue | None = None,
        *,
        naming: SecretNaming | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._versions: dict[str, list[str]] = {}
        self._enabled: dict[str, bool] = {}
        self._tags: dict[str, dict[str, str]] = {}
        self._naming = naming or DEFAULT_NAMING
        self._catalogue_version = catalogue.version if catalogue else CATALOGUE_VERSION

    @property
    def writable(self) -> bool:
        return True

    def _present_locked(self, name: str) -> bool:
        """Whether ``name`` exists at all — enabled or not."""
        return bool(self._versions.get(name))

    def get_enabled(self, credential_id: CredentialId, subject: Subject) -> str | None:
        with self._lock:
            for name in self._naming.read_order(credential_id, subject):
                if not self._present_locked(name):
                    continue
                # The first name that EXISTS decides; a disabled one resolves
                # to None rather than falling through, so a disconnect can
                # never be defeated by a stale fallback name.
                if not self._enabled.get(name):
                    return None
                return self._versions[name][-1]
        return None

    def exists(self, credential_id: CredentialId, subject: Subject) -> bool:
        with self._lock:
            for name in self._naming.read_order(credential_id, subject):
                if not self._present_locked(name):
                    continue
                return bool(self._enabled.get(name))
        return False

    def put_version(
        self,
        credential_id: CredentialId,
        subject: Subject,
        value: str,
        *,
        outcome: ValidationOutcome | None = None,
    ) -> None:
        if not value:
            raise ValueError("put_version requires a non-empty value")
        primary = self._naming.primary(credential_id, subject)
        with self._lock:
            self._versions.setdefault(primary, []).append(value)
            self._enabled[primary] = True
            self._tags[primary] = _tags(credential_id, subject, outcome, self._catalogue_version)
            for name in self._naming.read_order(credential_id, subject):
                if name != primary and self._present_locked(name):
                    self._enabled[name] = False

    def disable(self, credential_id: CredentialId, subject: Subject) -> bool:
        disabled_any = False
        with self._lock:
            for name in self._naming.read_order(credential_id, subject):
                if self._present_locked(name) and self._enabled.get(name):
                    self._enabled[name] = False
                    disabled_any = True
        return disabled_any

    def metadata(self, credential_id: CredentialId, subject: Subject) -> dict[str, str] | None:
        with self._lock:
            for name in self._naming.read_order(credential_id, subject):
                tags = self._tags.get(name)
                if tags is None:
                    continue
                return dict(tags) | {"enabled": str(bool(self._enabled.get(name))).lower()}
        return None

    def version_count(self, credential_id: CredentialId, subject: Subject) -> int:
        """Test affordance: how many versions the PRIMARY name has accumulated."""
        with self._lock:
            return len(self._versions.get(self._naming.primary(credential_id, subject), []))

    def seed_legacy(self, name: str, value: str) -> None:
        """Test affordance: plant a pre-existing secret under a raw ``name``.

        Models the state C3 inherits — secrets written by the *previous*
        implementation, under a name the current primary strategy would never
        produce.
        """
        with self._lock:
            self._versions.setdefault(name, []).append(value)
            self._enabled[name] = True


class AzureKeyVaultCredentialStore:
    """Production reader+writer over one application-scoped Key Vault.

    Auth is the ACA managed identity (``DefaultAzureCredential``); no client
    secret is ever configured for this store.

    **No value cache.** Every read is a live ``get_secret`` round-trip. That is
    a decision, not an omission: a TTL cache reopens a window in which a
    revoked or rotated key keeps spending, which is exactly the silent-spend
    class this design exists to kill. At these volumes the round-trip is
    invisible against provider calls that take seconds. The sanctioned
    exception, when fan-out makes it matter, is a short TTL scoped to a *single
    run* with refetch on provider auth failure — never a cross-run cache, and
    never ACA's ``keyvaultref:`` injection, whose platform cache refreshes
    ~30-minutely and silently reopens the same window.
    """

    def __init__(
        self,
        vault_url: str,
        *,
        catalogue: CredentialCatalogue | None = None,
        naming: SecretNaming | None = None,
        client: Any | None = None,
    ) -> None:
        """:param client: injected ``SecretClient``-shaped object, for tests.

        Without this seam the Azure branch is only reachable against a live
        vault, so the lifecycle the design turns on — disable-not-delete,
        rotate, re-register, and the read_order fall-through — would ship
        unverified. Production always leaves it ``None``.
        """
        if client is not None:
            self._client = client
            self._naming = naming or DEFAULT_NAMING
            self._catalogue_version = catalogue.version if catalogue else CATALOGUE_VERSION
            return

        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except ImportError as exc:  # pragma: no cover - exercised by extras-less installs
            raise DependencyError("azure", "azure-keyvault-secrets") from exc

        self._client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
        self._naming = naming or DEFAULT_NAMING
        self._catalogue_version = catalogue.version if catalogue else CATALOGUE_VERSION

    @property
    def writable(self) -> bool:
        return True

    def get_enabled(self, credential_id: CredentialId, subject: Subject) -> str | None:
        from azure.core.exceptions import ResourceNotFoundError

        for name in self._naming.read_order(credential_id, subject):
            try:
                secret = self._client.get_secret(name)
            except ResourceNotFoundError:
                continue
            # A disabled secret still resolves by name; enabled is the gate.
            if secret.properties.enabled is False:
                return None
            if secret.value:
                return secret.value
        return None

    def exists(self, credential_id: CredentialId, subject: Subject) -> bool:
        from azure.core.exceptions import ResourceNotFoundError

        for name in self._naming.read_order(credential_id, subject):
            try:
                props = self._client.get_secret(name).properties
            except ResourceNotFoundError:
                continue
            # The first name that EXISTS decides, matching get_enabled. An
            # earlier cut continued past a disabled name to the next one, so
            # under a compatibility read_order a disconnected primary plus a
            # stale enabled legacy name reported "registered" while
            # get_enabled resolved None — a UI saying connected over a
            # credential the resolver refuses to use.
            return props.enabled is not False
        return False

    def put_version(
        self,
        credential_id: CredentialId,
        subject: Subject,
        value: str,
        *,
        outcome: ValidationOutcome | None = None,
    ) -> None:
        from azure.core.exceptions import ResourceNotFoundError

        if not value:
            raise ValueError("put_version requires a non-empty value")
        primary = self._naming.primary(credential_id, subject)
        self._client.set_secret(
            primary,
            value,
            tags=_tags(credential_id, subject, outcome, self._catalogue_version),
            enabled=True,
        )
        # Supersede every other name this subject could resolve through, so a
        # rotation does not leave the previous key enabled under a legacy name.
        for name in self._naming.read_order(credential_id, subject):
            if name == primary:
                continue
            with contextlib.suppress(ResourceNotFoundError):
                if self._client.get_secret(name).properties.enabled is not False:
                    self._client.update_secret_properties(name, enabled=False)

    def disable(self, credential_id: CredentialId, subject: Subject) -> bool:
        from azure.core.exceptions import ResourceNotFoundError

        disabled_any = False
        for name in self._naming.read_order(credential_id, subject):
            with contextlib.suppress(ResourceNotFoundError):
                props = self._client.get_secret(name).properties
                if props.enabled is not False:
                    self._client.update_secret_properties(name, enabled=False)
                    disabled_any = True
        return disabled_any

    def metadata(self, credential_id: CredentialId, subject: Subject) -> dict[str, str] | None:
        from azure.core.exceptions import ResourceNotFoundError

        for name in self._naming.read_order(credential_id, subject):
            try:
                props = self._client.get_secret(name).properties
            except ResourceNotFoundError:
                continue
            tags: dict[str, Any] = dict(props.tags or {})
            tags["enabled"] = str(props.enabled is not False).lower()
            return {str(k): str(v) for k, v in tags.items()}
        return None


def require_writer(store: object) -> CredentialWriter:
    """Assert that ``store`` can write, or raise :class:`StoreUnavailableError`.

    The declared-capability replacement for ``isinstance(store, AzureKeyVault…)``.
    Checks the ``writable`` flag *and* the structural protocol, so a reader that
    merely claims to be writable still fails here rather than at write time.
    """
    if not getattr(store, "writable", False):
        raise StoreUnavailableError(
            "The credential store is not provisioned for writes on this server yet."
        )
    if not isinstance(store, CredentialWriter):
        raise StoreUnavailableError(
            f"{type(store).__name__} reports writable=True but does not implement CredentialWriter"
        )
    return store


def legacy_naming(prefix: str, kind: SubjectKind = SubjectKind.ENTRA_OID) -> SecretNaming:
    """A compatibility strategy that reads a legacy ``<prefix><raw-subject>`` name.

    Writes go to the new opaque name; reads try the opaque name first and fall
    back to the legacy one, so already-registered callers keep working and
    naturally migrate on their next rotation. ``kind`` narrows the fallback to
    the identity scheme the legacy names were minted under, so a client-slug
    subject can never accidentally read an oid-shaped legacy secret.
    """

    class _LegacyNaming:
        def primary(self, credential_id: CredentialId, subject: Subject) -> str:
            return secret_name(credential_id, subject)

        def read_order(self, credential_id: CredentialId, subject: Subject) -> tuple[str, ...]:
            names = [secret_name(credential_id, subject)]
            if subject.kind is kind:
                names.append(f"{prefix}{subject.value}")
            return tuple(names)

    return _LegacyNaming()
