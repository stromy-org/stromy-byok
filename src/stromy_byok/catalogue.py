"""The closed credential catalogue.

A catalogue maps a stable :class:`~stromy_byok.models.CredentialId` to the facts
the plane needs about it: which provider it belongs to, which environment
aliases carry it, who pays for it, and how to probe it.

**Closed by construction.** Callers cannot invent a provider, an endpoint or an
environment alias — a credential either was declared by the adopting
application at import time, or it does not exist. This is what stops a caller
string from ever selecting a vault URI or an outbound host.

Two things live here that look incidental and are load-bearing:

- :attr:`CredentialSpec.owner` is the *key-ownership routing* decision from the
  org standard — ``OPERATOR`` (Stromy's spend, one shared key) versus
  ``CALLER_BYOK`` (the client's spend, one key per subject). Client mode scrubs
  exactly the ``CALLER_BYOK`` aliases and no others, so a mis-declared owner is
  the difference between "client pays" and "we silently pay".
- :attr:`CredentialSpec.env_aliases` is the *complete* set of environment
  variables a provider SDK might read for this credential. It has to be
  complete: scrubbing is only as good as this list. ``APIFY_API_TOKEN`` and
  ``APIFY_TOKEN`` are both real, and missing the second one would leave a live
  caller-funded credential in the environment of a client-mode run.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from stromy_byok.exceptions import StromyByokError
from stromy_byok.models import CredentialId

__all__ = [
    "CATALOGUE_VERSION",
    "CredentialCatalogue",
    "CredentialOwner",
    "CredentialSpec",
    "ProviderProbe",
    "UnknownCredentialError",
]

#: Bumped when the *shape* of a spec changes. Recorded in secret tags so a
#: stored credential can be reasoned about against the catalogue that wrote it.
CATALOGUE_VERSION = 1


class UnknownCredentialError(StromyByokError):
    """A credential id was requested that the catalogue does not declare.

    Raised *before* any vault or network call. This is the check that makes
    "the caller cannot invent a provider" true rather than aspirational.
    """

    def __init__(self, credential_id: str, known: Iterable[str]) -> None:
        known_list = ", ".join(sorted(known)) or "<none>"
        super().__init__(
            f"Unknown credential id {credential_id!r}. Declared credentials: {known_list}"
        )
        self.credential_id = credential_id


class CredentialOwner(StrEnum):
    """Who pays for the provider account behind a credential.

    The two classes look like one problem and have opposite fixes: an absent
    ``OPERATOR`` key is Stromy's provisioning bug, while an absent
    ``CALLER_BYOK`` key is the correct and expected server state.
    """

    #: Stromy's spend. One shared key, provisioned as an app secret.
    OPERATOR = "operator"
    #: The client's spend. One key per subject, registered through ``/keys``.
    CALLER_BYOK = "caller-byok"


@dataclass(frozen=True, slots=True)
class ProviderProbe:
    """How to verify a candidate key for this credential.

    Fixed at declaration time. The host and path are **never** taken from a
    caller, and the key always travels in a header — never a query parameter,
    which would land it in the provider's access logs and any proxy in between.
    """

    #: Full HTTPS URL. Scheme is asserted at construction.
    url: str
    #: Header name carrying the credential, e.g. ``Authorization``.
    header: str
    #: ``{key}`` is substituted with the candidate, e.g. ``"Bearer {key}"``.
    header_template: str = "{key}"
    #: HTTP statuses that mean "this key definitively does not authenticate".
    invalid_statuses: frozenset[int] = frozenset({401, 403})
    #: Statuses that mean "the key authenticated".
    valid_statuses: frozenset[int] = frozenset({200})
    #: Hard deadline for the probe, in seconds.
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        if not self.url.startswith("https://"):
            raise ValueError(f"ProviderProbe.url must be https, got {self.url!r}")
        if "{key}" not in self.header_template:
            raise ValueError("ProviderProbe.header_template must contain '{key}'")
        overlap = self.valid_statuses & self.invalid_statuses
        if overlap:
            raise ValueError(f"ProviderProbe status sets overlap on {sorted(overlap)}")

    def build_header(self, key: str) -> dict[str, str]:
        return {self.header: self.header_template.format(key=key)}


@dataclass(frozen=True, slots=True)
class CredentialSpec:
    """One declared credential.

    ``env_aliases`` must list *every* environment variable a provider SDK reads
    for this credential — the scrub step is only as complete as this tuple.
    """

    credential_id: CredentialId
    provider: str
    owner: CredentialOwner
    env_aliases: tuple[str, ...]
    #: Human-facing label used on the registration page.
    display_name: str = ""
    #: Where a user goes to create this key. Shown on the registration page.
    signup_url: str | None = None
    probe: ProviderProbe | None = None

    def __post_init__(self) -> None:
        if not self.env_aliases:
            raise ValueError(
                f"CredentialSpec {self.credential_id!r} declares no env_aliases; "
                "scrubbing cannot protect a credential it does not know the name of"
            )
        if len(set(self.env_aliases)) != len(self.env_aliases):
            raise ValueError(f"CredentialSpec {self.credential_id!r} has duplicate env_aliases")

    @property
    def is_caller_funded(self) -> bool:
        return self.owner is CredentialOwner.CALLER_BYOK


@dataclass(frozen=True)
class CredentialCatalogue:
    """An immutable, closed set of credential declarations.

    Built once by the adopting application and passed to stores, routes and
    resolvers. Lookup raises :class:`UnknownCredentialError` rather than
    returning ``None``, so an unknown id can never fall through into a vault
    call as a silently-absent secret.
    """

    _specs: Mapping[CredentialId, CredentialSpec] = field(repr=False)
    version: int = CATALOGUE_VERSION

    def __init__(self, specs: Iterable[CredentialSpec], version: int = CATALOGUE_VERSION) -> None:
        table: dict[CredentialId, CredentialSpec] = {}
        for spec in specs:
            if spec.credential_id in table:
                raise ValueError(f"Duplicate credential id {spec.credential_id!r} in catalogue")
            table[spec.credential_id] = spec
        self._assert_alias_uniqueness(table.values())
        object.__setattr__(self, "_specs", MappingProxyType(table))
        object.__setattr__(self, "version", version)

    @staticmethod
    def _assert_alias_uniqueness(specs: Iterable[CredentialSpec]) -> None:
        """Two credentials must never claim the same environment alias.

        If they did, scrubbing one would silently disarm the other, and the
        resolver could not tell which credential an ambient value belonged to.
        """
        seen: dict[str, CredentialId] = {}
        for spec in specs:
            for alias in spec.env_aliases:
                if alias in seen:
                    raise ValueError(
                        f"Environment alias {alias!r} is claimed by both "
                        f"{seen[alias]!r} and {spec.credential_id!r}"
                    )
                seen[alias] = spec.credential_id

    def __contains__(self, credential_id: object) -> bool:
        return credential_id in self._specs

    def __iter__(self) -> Iterator[CredentialSpec]:
        return iter(self._specs.values())

    def __len__(self) -> int:
        return len(self._specs)

    def ids(self) -> frozenset[CredentialId]:
        return frozenset(self._specs)

    def get(self, credential_id: str) -> CredentialSpec:
        """Return the spec for ``credential_id`` or raise ``UnknownCredentialError``."""
        try:
            return self._specs[CredentialId(credential_id)]
        except (KeyError, ValueError):
            raise UnknownCredentialError(credential_id, self._specs) from None

    def caller_funded(self) -> tuple[CredentialSpec, ...]:
        """Every ``caller-byok`` spec — the exact set client mode scrubs."""
        return tuple(s for s in self._specs.values() if s.is_caller_funded)

    def caller_funded_env_aliases(self) -> tuple[str, ...]:
        """Every environment alias that could carry someone else's funded key.

        This is the scrub list. It is deliberately derived from the catalogue
        rather than written out at the call site, so declaring a new
        caller-funded credential automatically widens the scrub.
        """
        aliases: list[str] = []
        for spec in self.caller_funded():
            aliases.extend(spec.env_aliases)
        return tuple(dict.fromkeys(aliases))
