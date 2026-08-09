"""Attribution context and the scoped credential environment.

Two things live here.

**Attribution.** :func:`last_credential_source` records where the credential
for the current call came from, per-task via a :class:`~contextvars.ContextVar`
so concurrent callers never see each other's label. Spend attribution has to be
a *recorded fact*: inferring "the caller must have paid" from the absence of a
denial is exactly the reasoning that hides a silent fallback.

**The scoped environment.** :func:`credential_scope` is the mechanism that makes
client mode safe, and the order of its three steps is the whole design:

1. **Scrub every caller-funded alias first.** The runner job carries Stromy's
   own keys. If we injected client keys without removing ours, a credential the
   client did not register would silently fall through to operator spend — the
   precise failure this plane exists to prevent. Scrubbing first means a
   missing declaration or key produces an *authentication failure*, never a
   surprise invoice.
2. **Inject only what was resolved.** Nothing else enters the environment.
3. **Restore in ``finally``.** Injection is an execution *scope*, not a
   permanent mutation. Job-per-run is still the production isolation boundary,
   but restoring makes tests, retries and any future multiplexed runner safe,
   and it holds even when the graph raises.

Operator mode leaves the ambient environment untouched and simply labels the
source ``operator-env`` — the difference between the two modes is authority
removal, not a different code path bolted on later.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Generator, Iterable, Sequence
from contextlib import contextmanager
from contextvars import ContextVar

from stromy_byok.catalogue import CredentialCatalogue
from stromy_byok.models import CredentialSource, ResolvedCredential

logger = logging.getLogger(__name__)

__all__ = [
    "credential_scope",
    "last_credential_source",
    "record_credential_source",
    "reset_credential_source",
    "scrub_aliases",
]

_source: ContextVar[CredentialSource | None] = ContextVar("stromy_byok_source", default=None)


def reset_credential_source() -> None:
    """Clear the attribution record at the start of a call."""
    _source.set(None)


def record_credential_source(source: CredentialSource) -> None:
    """Stamp the attribution record for this call context."""
    _source.set(source)


def last_credential_source() -> CredentialSource | None:
    """The source label of the last resolution, or ``None`` if none ran."""
    return _source.get()


def scrub_aliases(aliases: Iterable[str], env: dict[str, str] | None = None) -> dict[str, str | None]:
    """Remove ``aliases`` from the environment, returning their prior values.

    The returned mapping distinguishes "was absent" (``None``) from "was empty
    string", so restoration is exact — re-setting an absent variable to ``""``
    would make a later ``"VAR" in os.environ`` check answer differently than
    before the scope.
    """
    target = os.environ if env is None else env
    prior: dict[str, str | None] = {}
    for alias in aliases:
        prior[alias] = target.get(alias)
        target.pop(alias, None)
    return prior


def _restore(prior: dict[str, str | None], env: dict[str, str] | None = None) -> None:
    target = os.environ if env is None else env
    for alias, value in prior.items():
        if value is None:
            target.pop(alias, None)
        else:
            target[alias] = value


@contextmanager
def credential_scope(
    catalogue: CredentialCatalogue,
    resolved: Sequence[ResolvedCredential],
    *,
    scrub: bool = True,
    env: dict[str, str] | None = None,
) -> Generator[None]:
    """Enter an execution scope carrying exactly ``resolved`` credentials.

    :param scrub: ``True`` for client mode — remove **every** caller-funded
        alias in the catalogue before injecting. ``False`` for operator mode,
        which keeps the ambient operator keys.
    :param env: injectable environment mapping, for tests.

    On exit — including on an exception — the environment is restored to
    exactly its prior state.
    """
    target = os.environ if env is None else env
    prior: dict[str, str | None] = {}

    try:
        if scrub:
            # Scrub the full caller-funded surface, not just the aliases we are
            # about to fill. An alias we hold no resolution for is precisely
            # the one that would otherwise fall through to operator spend.
            prior.update(scrub_aliases(catalogue.caller_funded_env_aliases(), env))

        for credential in resolved:
            if credential.value is None:
                continue
            spec = catalogue.get(credential.credential_id)
            for alias in spec.env_aliases:
                if alias not in prior:
                    prior[alias] = target.get(alias)
                target[alias] = credential.value

        yield
    finally:
        _restore(prior, env)


def safe_sources(resolved: Sequence[ResolvedCredential]) -> list[dict[str, str]]:
    """The recordable projection of a resolution set — ids and sources only.

    This is what gets persisted into run metadata. It deliberately cannot carry
    a value: :meth:`ResolvedCredential.safe_dict` does not expose one.
    """
    return [credential.safe_dict() for credential in resolved]
