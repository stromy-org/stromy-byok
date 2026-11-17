"""Which admitted grant serves each model tier (ORG-PLAN-589 D1/D2).

Among admitted candidates, the grant that expires soonest serves the tiers its
route allows: a ``surplus`` grant every tier of its route, any other pace
(``on-pace``, ``short``, ``unknown``) only the strong tiers (``smart``,
``frontier``). Ties break on source id. A tier no candidate may serve maps to
None: the caller's chain (included quota, then cash) serves it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from stromy_byok.funding.model import FundingSource
from stromy_byok.funding.pace import SURPLUS

__all__ = ["STRONG_TIERS", "TIERS", "Candidate", "allowed_tiers", "order"]

TIERS: tuple[str, ...] = ("cheap", "medium", "smart", "frontier")
STRONG_TIERS: frozenset[str] = frozenset({"smart", "frontier"})


@dataclass(frozen=True, slots=True)
class Candidate:
    """One funding source considered for an invocation.

    ``decision`` is the guard's result, ``pace`` its pace state, ``tiers`` the
    tiers its route permits, ``provider`` the provider that route serves.
    """

    source: FundingSource
    decision: Mapping[str, Any]
    pace: str
    tiers: frozenset[str]
    provider: str | None = None

    @property
    def admitted(self) -> bool:
        return self.decision.get("decision") == "OK"


def allowed_tiers(candidate: Candidate) -> frozenset[str]:
    """The tiers this candidate may serve under D1 (empty when not admitted)."""
    if not candidate.admitted:
        return frozenset()
    return candidate.tiers if candidate.pace == SURPLUS else candidate.tiers & STRONG_TIERS


def _key(c: Candidate) -> tuple[int, str, str]:
    exp = c.source.expires_at
    return (0 if exp is not None else 1, exp.isoformat() if exp is not None else "", c.source.id)


def order(candidates: Iterable[Candidate], *, now: datetime, tiers: Iterable[str] = TIERS
          ) -> dict[str, Candidate | None]:
    """Per tier, the soonest-expiring admitted candidate allowed to serve it, else None.

    A candidate whose grant is not active at ``now`` never serves, whatever its
    decision says.
    """
    ranked = sorted(candidates, key=_key)
    out: dict[str, Candidate | None] = {}
    for tier in tiers:
        out[tier] = next((c for c in ranked
                          if tier in allowed_tiers(c) and c.source.grant is not None
                          and c.source.grant.basis == "observed" and c.source.grant.active(now)), None)
    return out
