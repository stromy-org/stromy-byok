# Stromy BYOK

Client-neutral BYOK credential plane: split reader/writer stores, bound single-use registration grants, hardened registration routes and provider validators.

## Install

```bash
uv sync                          # Core deps
uv sync --extra all              # All optional extras
uv sync --extra dev              # Dev tools
```


## What this is

One reusable BYOK **pattern**, not one shared secret boundary.

Every adopting application gets the same storage protocols, registration flow,
credential catalogue, validators, attribution types and audit events — while
each keeps its **own application-scoped Key Vault**. That split is the point: a
compromised service identity cannot read another service's client credentials.
Nothing here hardcodes a client, service, provider endpoint or vault URI.

## The five load-bearing ideas

1. **A closed catalogue.** A caller cannot invent a provider, an endpoint or an
   environment alias. An unknown credential id raises before any vault or
   network call.
2. **Split privileges.** `CredentialReader` (workloads) and `CredentialWriter`
   (registration) are separate protocols, mirroring the Key Vault RBAC split.
   Capability is *declared* (`store.writable`), never sniffed with `isinstance`.
3. **Bound single-use grants.** Subject, service, workflow, credential and
   action are baked into the grant at mint time. The `/keys` form carries a
   token and a key — nothing else can scope the write.
4. **Scrub before inject.** Client mode removes *every* caller-funded env alias
   in the catalogue before injecting the client's keys, then restores in
   `finally`. A missing credential therefore fails authentication rather than
   silently spending the operator's budget.
5. **Disable, don't delete.** Azure soft delete makes a deleted secret *name*
   unrecreatable until recovery or purge, which would brick re-registration.
   Disconnect disables the current version; the name stays free.

## Public API

```python
from stromy_byok import (
    CredentialCatalogue, CredentialSpec, CredentialOwner, ProviderProbe,
    Subject, SubjectKind, CredentialId, ResolvedCredential, CredentialSource,
    AzureKeyVaultCredentialStore, InMemoryCredentialStore, NullCredentialStore,
    InMemoryGrantStore, mint_grant, consume_for, GrantAction,
    build_keys_routes, credential_scope, validate_key_async,
)
```

### Declaring credentials

```python
catalogue = CredentialCatalogue([
    CredentialSpec(
        credential_id=CredentialId("openai-api"),
        provider="OpenAI",
        owner=CredentialOwner.CALLER_BYOK,   # the client's spend
        env_aliases=("OPENAI_API_KEY",),     # MUST be complete — this is the scrub list
        probe=ProviderProbe(
            url="https://api.openai.com/v1/models",
            header="Authorization",
            header_template="Bearer {key}",
        ),
    ),
])
```

`env_aliases` has to list *every* variable a provider SDK reads. Apify honours
both `APIFY_API_TOKEN` and `APIFY_TOKEN`; missing the second would leave a live
caller-funded credential in a client-mode environment.

### Running inside a client's credentials

```python
with credential_scope(catalogue, resolved, scrub=True):
    await run_graph()      # only the client's keys are visible in here
# ambient environment restored exactly, including on exception
```

## Validation is tri-state, per provider

There is no single global HTTP rule. Real read-only probes with invalid keys
returned **401** from OpenAI, Apify and Hunter — but **400** from Gemini. So
each credential declares its own status sets, and outcomes are
`valid` / `invalid` / `unverified_transient`. Only a definitive `invalid`
rejects storage; a timeout, a 5xx, a rate limit or a narrowly-scoped key stores
the credential and records that it could not be confirmed.

## Tests

```bash
uv run pytest tests/unit
uv run pytest tests/contract
```

## Releases

This library is consumed by downstream repos via `[tool.uv.sources]` git+URL pins. To cut a release:

1. Bump `[project].version` in `pyproject.toml` on `main`.
2. `git tag vX.Y.Z && git push --tags`
3. CI builds + publishes a GitHub Release; `notify-parent.yml` fires a `submodule-bumped` event into stromy-org.

See `stromy-org/infra-docs/ai/internal-libs.md` for the full release pattern.

## Agent instructions

See `AGENTS.md` (canonical, cross-vendor). `CLAUDE.md` and `.github/copilot-instructions.md` are regenerated from it by `scripts/render-agent-md.py`.
