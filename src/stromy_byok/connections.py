"""Provider-neutral, versioned non-secret connections and bound grants.

Adopters own provider schemas, verification and authorization. This module never
accepts pasted credentials, aliases, tokens or refresh-token storage. Metadata is
validated against an adopter's closed JSON schema, not CredentialSpec.
Historical records are evidence, not authority: every effect must also check the
current version/state. Production adapters enforce these CAS rules durably.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

from stromy_byok.exceptions import StromyByokError
from stromy_byok.models import Subject

CONNECTION_PROTOCOL_VERSION = 1
MAX_METADATA_BYTES = 16_384
_KIND = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


class _MetadataValidator(Protocol):
    # jsonschema's deprecated two-argument overload has incomplete typing.
    def is_valid(self, instance: object) -> bool: ...


class ConnectionError(StromyByokError):
    """A connection or grant violates its schema, binding or version fence."""


class ConnectionState(StrEnum):
    PENDING = "pending"
    PROPAGATING = "propagating"
    ACTIVE = "active"
    VERIFICATION_FAILED = "verification_failed"
    VERIFICATION_EXPIRED = "verification_expired"
    REVOKED = "revoked"


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ConnectionError("Connection timestamps must be timezone-aware")


def _metadata_json(metadata: dict[str, Any]) -> str:
    try:
        result = json.dumps(metadata, allow_nan=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ConnectionError("Connection metadata must be finite JSON") from exc
    if len(result.encode("utf-8")) > MAX_METADATA_BYTES:
        raise ConnectionError("Connection metadata exceeds its byte limit")
    return result


@dataclass(frozen=True, slots=True)
class ConnectionSpec:
    """An adopter-owned kind and immutable closed metadata schema.

    Schemas are trusted deployment inputs. They declare non-secret metadata only;
    schema/version changes require adopter migrations and explicit consumer pins.
    """

    kind: str
    metadata_schema_json: str = field(repr=False)
    schema_version: int = 1
    protocol_version: int = CONNECTION_PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if not _KIND.fullmatch(self.kind) or self.schema_version < 1:
            raise ConnectionError("Invalid connection kind or schema version")
        if self.protocol_version != CONNECTION_PROTOCOL_VERSION:
            raise ConnectionError("Unsupported connection protocol version")
        parsed: object = json.loads(self.metadata_schema_json)
        if not isinstance(parsed, dict):
            raise ConnectionError("Connection metadata requires a closed object schema")
        schema = cast(dict[str, Any], parsed)
        Draft202012Validator.check_schema(schema)
        if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
            raise ConnectionError("Connection metadata requires a closed object schema")
        # Provider schemas are local contracts. Never fetch an external $ref.
        pending: list[Any] = [schema]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                entry = cast(dict[str, Any], item)
                for key, value in entry.items():
                    if key == "format" and value not in FormatChecker.checkers:
                        raise ConnectionError("Connection schemas cannot declare unsupported formats")
                    if key in {"$ref", "$dynamicRef"} and isinstance(value, str) and not value.startswith("#"):
                        raise ConnectionError("Connection schemas cannot reference remote resources")
                    pending.append(value)
            elif isinstance(item, list):
                pending.extend(cast(list[Any], item))

    def encode_metadata(self, metadata: dict[str, Any]) -> str:
        """Validate and snapshot metadata; errors never echo input values."""
        encoded = _metadata_json(metadata)
        validator = cast(
            _MetadataValidator,
            Draft202012Validator(json.loads(self.metadata_schema_json), format_checker=FormatChecker()),
        )
        if not validator.is_valid(json.loads(encoded)):
            raise ConnectionError("Connection metadata does not match its declared schema")
        return encoded


@dataclass(frozen=True, slots=True)
class ConnectionRecord:
    connection_id: str
    subject: Subject
    kind: str
    version: int
    state: ConnectionState
    metadata_json: str = field(repr=False)
    updated_at: datetime
    schema_version: int = 1
    protocol_version: int = CONNECTION_PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if not self.connection_id or not _KIND.fullmatch(self.kind) or self.version < 1 or self.schema_version < 1:
            raise ConnectionError("Invalid connection identity/version")
        if self.protocol_version != CONNECTION_PROTOCOL_VERSION or not isinstance(
            cast(object, self.state), ConnectionState
        ):
            raise ConnectionError("Unsupported connection protocol/state")
        _aware(self.updated_at)
        metadata: object = json.loads(self.metadata_json)
        if not isinstance(metadata, dict):
            raise ConnectionError("Connection metadata must be an object")
        object.__setattr__(self, "metadata_json", _metadata_json(cast(dict[str, Any], metadata)))

    @property
    def metadata(self) -> dict[str, Any]:
        """A fresh copy: callers cannot mutate a stored version."""
        return json.loads(self.metadata_json)

    def status(self) -> dict[str, str | int]:
        """Public status excludes subject, metadata and any provider authority."""
        return {
            "connection_id": self.connection_id,
            "kind": self.kind,
            "version": self.version,
            "state": self.state.value,
            "schema_version": self.schema_version,
            "protocol_version": self.protocol_version,
        }


@runtime_checkable
class ConnectionReader(Protocol):
    def get(self, connection_id: str, subject: Subject, *, version: int | None = None) -> ConnectionRecord | None:
        """Read an owned version, latest by default; historical state grants nothing."""
        ...


@runtime_checkable
class ConnectionWriter(Protocol):
    def put_version(self, record: ConnectionRecord, *, expected_version: int) -> bool:
        """Atomically append expected_version+1; 0 creates; identity/kind immutable."""
        ...

    def revoke(
        self, connection_id: str, subject: Subject, *, expected_version: int, at: datetime
    ) -> ConnectionRecord | None:
        """Atomically append a revoked fencing version; never imply remote revocation."""
        ...


class InMemoryConnectionStore:
    """Fixture/single-process implementation; not a production metadata store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._versions: dict[str, list[ConnectionRecord]] = {}

    def get(self, connection_id: str, subject: Subject, *, version: int | None = None) -> ConnectionRecord | None:
        with self._lock:
            rows = self._versions.get(connection_id, [])
            if not rows or rows[-1].subject != subject:
                return None
            if version is None:
                return rows[-1]
            return next((row for row in rows if row.version == version), None)

    def put_version(self, record: ConnectionRecord, *, expected_version: int) -> bool:
        with self._lock:
            rows = self._versions.get(record.connection_id, [])
            if expected_version < 0 or record.version != expected_version + 1 or len(rows) != expected_version:
                return False
            if rows and (rows[-1].subject != record.subject or rows[-1].kind != record.kind):
                return False
            self._versions.setdefault(record.connection_id, []).append(record)
            return True

    def revoke(
        self, connection_id: str, subject: Subject, *, expected_version: int, at: datetime
    ) -> ConnectionRecord | None:
        with self._lock:
            rows = self._versions.get(connection_id, [])
            if not rows or rows[-1].subject != subject or rows[-1].version != expected_version:
                return None
            revoked = replace(rows[-1], version=expected_version + 1, state=ConnectionState.REVOKED, updated_at=at)
            rows.append(revoked)
            return revoked


class ConnectionGrantAction(StrEnum):
    REGISTER = "register"
    DISCONNECT = "disconnect"


@dataclass(frozen=True, slots=True)
class ConnectionGrantBinding:
    """Only verified/server-owned fields; never rebuild this from browser inputs."""

    subject: Subject
    service: str
    kind: str
    app_id: str
    action: ConnectionGrantAction
    callback_uri: str
    session_id: str = field(repr=False)
    issuer: str
    workflow: str | None = None
    connection_id: str | None = None
    expected_version: int | None = None

    def __post_init__(self) -> None:
        if not all((self.service, self.app_id, self.session_id, self.issuer)) or not _KIND.fullmatch(self.kind):
            raise ConnectionError("Incomplete connection grant binding")
        if not isinstance(cast(object, self.action), ConnectionGrantAction):
            raise ConnectionError("Unsupported connection grant action")
        if (self.connection_id is None) != (self.expected_version is None):
            raise ConnectionError("Connection identity and expected version must be bound together")
        if self.expected_version is not None and (not self.connection_id or self.expected_version < 1):
            raise ConnectionError("Invalid connection grant version fence")
        if self.action == ConnectionGrantAction.DISCONNECT and self.connection_id is None:
            raise ConnectionError("Disconnect requires a bound connection and version")
        callback = urlsplit(self.callback_uri)
        if (
            callback.scheme != "https"
            or not callback.hostname
            or callback.username
            or callback.password
            or callback.fragment
        ):
            raise ConnectionError("Connection callback must be a trusted HTTPS URL")


@dataclass(frozen=True, slots=True)
class ConnectionGrant:
    token: str = field(repr=False)
    binding: ConnectionGrantBinding
    issued_at: datetime
    expires_at: datetime
    nonce: str = field(repr=False)
    protocol_version: int = CONNECTION_PROTOCOL_VERSION

    def __post_init__(self) -> None:
        _aware(self.issued_at)
        _aware(self.expires_at)
        if self.expires_at <= self.issued_at or not self.token or not self.nonce:
            raise ConnectionError("Invalid connection grant lifetime/capability")
        if self.protocol_version != CONNECTION_PROTOCOL_VERSION:
            raise ConnectionError("Unsupported connection grant protocol")


@runtime_checkable
class ConnectionGrantStore(Protocol):
    @property
    def durable(self) -> bool: ...

    def mint(self, grant: ConnectionGrant) -> None: ...

    def peek(self, token: str, binding: ConnectionGrantBinding, *, now: datetime) -> ConnectionGrant | None:
        """Bound read only; GET cannot consume or alter connection authority."""
        ...

    def consume(self, token: str, binding: ConnectionGrantBinding, *, now: datetime) -> ConnectionGrant | None:
        """Atomic compare-all-bindings, expiry check and single spend."""
        ...


class InMemoryConnectionGrantStore:
    """Hash-indexed, bound, single-use grants for a single replica only."""

    durable = False

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants: dict[str, ConnectionGrant] = {}

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def mint(self, grant: ConnectionGrant) -> None:
        with self._lock:
            key = self._hash(grant.token)
            if key in self._grants:
                raise ConnectionError("Connection grant already exists")
            self._grants[key] = grant

    def _valid(self, token: str, binding: ConnectionGrantBinding, now: datetime) -> ConnectionGrant | None:
        _aware(now)
        # Pruning and comparison occur inside the same lock as consumption.
        self._grants = {key: grant for key, grant in self._grants.items() if now < grant.expires_at}
        grant = self._grants.get(self._hash(token))
        return grant if grant and grant.binding == binding and grant.issued_at <= now else None

    def peek(self, token: str, binding: ConnectionGrantBinding, *, now: datetime) -> ConnectionGrant | None:
        with self._lock:
            return self._valid(token, binding, now)

    def consume(self, token: str, binding: ConnectionGrantBinding, *, now: datetime) -> ConnectionGrant | None:
        with self._lock:
            grant = self._valid(token, binding, now)
            if grant:
                del self._grants[self._hash(token)]
            return grant


def mint_connection_grant(
    store: ConnectionGrantStore, binding: ConnectionGrantBinding, *, now: datetime | None = None, ttl_seconds: int = 900
) -> ConnectionGrant:
    """Bind, not authorize; durable adapters store only the capability hash."""
    if isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= 900:
        raise ConnectionError("Connection grant lifetime must be 1..900 seconds")
    issued_at = now if now is not None else datetime.now(UTC)
    grant = ConnectionGrant(
        secrets.token_urlsafe(32),
        binding,
        issued_at,
        issued_at + timedelta(seconds=ttl_seconds),
        secrets.token_urlsafe(16),
    )
    store.mint(grant)
    return grant


def assert_connection_grants_durable(store: ConnectionGrantStore, max_replicas: int) -> None:
    if max_replicas > 1 and not store.durable:
        raise ConnectionError("Multiple replicas require a durable connection grant store")
