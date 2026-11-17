"""Funding contract: which free API credit grant pays, how fast it burns, which serves first.

One implementation for every consumer (operator scripts, local and hosted
application runs). Everything except :mod:`~stromy_byok.funding.costs`' readers
is pure: the register, capture rows, the clock and key presence are inputs.
The package carries logic only — no register data, account name or secret.

- :func:`sources` — a tenant's funding sources, current grant resolved (observed
  first, one forecast successor otherwise), soonest expiry first.
- :func:`decide` — the conservative admission guard over a full capture envelope.
- :func:`pace` — surplus / on-pace / short / unknown for one capture row.
- :func:`order` — per model tier, the soonest-expiring admitted grant allowed to serve it.
- :mod:`~stromy_byok.funding.costs` — bounded Anthropic and OpenAI cost readers and
  the pure capture builder.
"""

from stromy_byok.funding.costs import (
    CostReadError,
    CostReport,
    Transport,
    allowance_row,
    anthropic_cost_report,
    capture_envelope,
    openai_costs,
)
from stromy_byok.funding.guard import CAPTURE_SCHEMA, DEFAULT_MAX_AGE_HOURS, HOLD, OK, REGISTER_SCHEMA, decide
from stromy_byok.funding.model import (
    FundingSource,
    Grant,
    KeyRef,
    Recurrence,
    current_grant,
    key_available,
    parse_source,
    recurrence_problems,
    sources,
)
from stromy_byok.funding.order import STRONG_TIERS, TIERS, Candidate, allowed_tiers, order
from stromy_byok.funding.pace import ON_PACE, SHORT, SURPLUS, UNKNOWN, pace, surplus_threshold

__all__ = [
    "CAPTURE_SCHEMA",
    "DEFAULT_MAX_AGE_HOURS",
    "HOLD",
    "OK",
    "ON_PACE",
    "REGISTER_SCHEMA",
    "SHORT",
    "STRONG_TIERS",
    "SURPLUS",
    "TIERS",
    "UNKNOWN",
    "Candidate",
    "CostReadError",
    "CostReport",
    "FundingSource",
    "Grant",
    "KeyRef",
    "Recurrence",
    "Transport",
    "allowance_row",
    "allowed_tiers",
    "anthropic_cost_report",
    "capture_envelope",
    "current_grant",
    "decide",
    "key_available",
    "openai_costs",
    "order",
    "pace",
    "parse_source",
    "recurrence_problems",
    "sources",
    "surplus_threshold",
]
