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

   ``scrub_except`` narrows that surface for **mixed funding**, where one run
   spends the caller's key for some credentials and the operator's for others.
   The exemption is a list of ids the caller passes from a recorded funding
   decision — it is never derived here, because a hole computed from "we could
   not resolve this one" is exactly the fallback the totality exists to close.
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
    scrub_except: Iterable[str] = (),
    env: dict[str, str] | None = None,
) -> Generator[None]:
    """Enter an execution scope carrying exactly ``resolved`` credentials.

    :param scrub: ``True`` for client mode — remove **every** caller-funded
        alias in the catalogue before injecting. ``False`` for operator mode,
        which keeps the ambient operator keys.
    :param scrub_except: credential ids whose aliases are LEFT IN PLACE under
        ``scrub``, because the caller holds a recorded decision that the
        operator funds them. Mixed funding — the client pays for the model
        tokens their own work consumes while the platform absorbs a flat-rate
        subscription — is the case this exists for.

        **The exemption must come from a decision, never from a failure.** The
        totality of the scrub is what makes "a missing registration produces an
        authentication error, not a surprise invoice" true; every hole punched
        in it is a place where an unresolved credential could fall back to
        operator spend instead. So this function will not infer one: it accepts
        only ids the caller names, and refuses the two shapes that would let an
        accident look like a decision — an id that is also being injected
        (funded twice) and an id the catalogue does not know (whose aliases
        cannot be identified, so "exempt" would silently scrub them anyway).
    :param env: injectable environment mapping, for tests.

    On exit — including on an exception — the environment is restored to
    exactly its prior state.
    """
    target = os.environ if env is None else env
    prior: dict[str, str | None] = {}

    exempt_ids = tuple(dict.fromkeys(str(cid) for cid in scrub_except))
    injected_ids = {str(credential.credential_id) for credential in resolved}
    both = sorted(injected_ids.intersection(exempt_ids))
    if both:
        raise ValueError(
            f"credential(s) {', '.join(both)} are both injected and exempted from "
            "the scrub. One credential has exactly one funder; a caller asking for "
            "both is carrying two funding decisions for it."
        )
    # `get` raises UnknownCredentialError, which is the right answer: an id whose
    # spec we cannot read has aliases we cannot name, so it would be scrubbed
    # despite the exemption — a silent no-op on a safety-relevant request.
    exempt_aliases = {
        alias for cid in exempt_ids for alias in catalogue.get(cid).env_aliases
    }

    try:
        if scrub:
            # Scrub the full caller-funded surface, not just the aliases we are
            # about to fill. An alias we hold no resolution for is precisely
            # the one that would otherwise fall through to operator spend.
            prior.update(
                scrub_aliases(
                    tuple(
                        alias
                        for alias in catalogue.caller_funded_env_aliases()
                        if alias not in exempt_aliases
                    ),
                    env,
                )
            )

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
