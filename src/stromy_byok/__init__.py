"""Client-neutral BYOK credential plane.

One reusable *pattern*, not one shared secret boundary. Adopting applications
get the same storage protocols, registration flow, credential catalogue,
validators, attribution types and audit events — while each keeps its **own**
application-scoped Key Vault. A compromised service identity therefore cannot
read another service's client credentials.

Nothing in this package hardcodes a client, a service, a provider endpoint or a
vault URI: those arrive through a :class:`~stromy_byok.catalogue.CredentialCatalogue`
and the adopter's own configuration.

Start at :mod:`stromy_byok.catalogue` to declare credentials, :mod:`stromy_byok.store`
to persist them, :mod:`stromy_byok.grants` + :mod:`stromy_byok.routes` for the
registration flow, and :mod:`stromy_byok.context` for the runtime scope that
scrubs ambient authority before injecting a caller's own.
"""

from importlib.metadata import version as _metadata_version

from stromy_byok.catalogue import (
    CATALOGUE_VERSION,
    CredentialCatalogue,
    CredentialOwner,
    CredentialSpec,
    ProviderProbe,
    UnknownCredentialError,
)
from stromy_byok.context import (
    credential_scope,
    last_credential_source,
    record_credential_source,
    reset_credential_source,
    safe_sources,
    scrub_aliases,
)
from stromy_byok.exceptions import DependencyError, StromyByokError
from stromy_byok.grants import (
    DEFAULT_TTL_SECONDS,
    Grant,
    GrantAction,
    GrantError,
    InMemoryGrantStore,
    RegistrationGrantStore,
    assert_single_replica_or_durable,
    consume_for,
    mint_grant,
)
from stromy_byok.models import (
    AuditAction,
    AuditEvent,
    CredentialId,
    CredentialSource,
    ResolvedCredential,
    Subject,
    SubjectKind,
    ValidationOutcome,
    ValidationStatus,
)
from stromy_byok.routes import SECURITY_HEADERS, KeysRoutes, build_keys_routes
from stromy_byok.store import (
    AzureKeyVaultCredentialStore,
    CredentialReader,
    CredentialWriter,
    InMemoryCredentialStore,
    NullCredentialStore,
    SecretNaming,
    StoreUnavailableError,
    legacy_naming,
    require_writer,
    secret_name,
)
from stromy_byok.validators import classify_status, validate_key, validate_key_async

#: Read from installed package metadata rather than hand-maintained here.
#: A literal silently desyncs from pyproject.toml on the first version bump
#: that forgets it — and it desynced immediately, on v0.2.0: the consumer
#: pinned the right tag, uv resolved the right commit, and the package still
#: reported 0.1.0, so the one signal an operator would use to confirm a
#: rollout lied while everything underneath was correct.
__version__ = _metadata_version("stromy-byok")

__all__ = [
    "CATALOGUE_VERSION",
    "DEFAULT_TTL_SECONDS",
    "SECURITY_HEADERS",
    "AuditAction",
    "AuditEvent",
    "AzureKeyVaultCredentialStore",
    "CredentialCatalogue",
    "CredentialId",
    "CredentialOwner",
    "CredentialReader",
    "CredentialSource",
    "CredentialSpec",
    "CredentialWriter",
    "DependencyError",
    "Grant",
    "GrantAction",
    "GrantError",
    "InMemoryCredentialStore",
    "InMemoryGrantStore",
    "KeysRoutes",
    "NullCredentialStore",
    "ProviderProbe",
    "RegistrationGrantStore",
    "ResolvedCredential",
    "SecretNaming",
    "StoreUnavailableError",
    "StromyByokError",
    "Subject",
    "SubjectKind",
    "UnknownCredentialError",
    "ValidationOutcome",
    "ValidationStatus",
    "assert_single_replica_or_durable",
    "build_keys_routes",
    "classify_status",
    "consume_for",
    "credential_scope",
    "last_credential_source",
    "legacy_naming",
    "mint_grant",
    "record_credential_source",
    "require_writer",
    "reset_credential_source",
    "safe_sources",
    "scrub_aliases",
    "secret_name",
    "validate_key",
    "validate_key_async",
]
