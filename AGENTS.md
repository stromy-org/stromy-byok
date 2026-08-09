# AGENTS.md

Self-contained instructions for Codex and other AI agents working on stromy-byok.

> **AGENTS.md is the canonical instruction file** for this repo (cross-vendor standard).
> `CLAUDE.md` and `.github/copilot-instructions.md` are generated from this file by
> `scripts/render-agent-md.py`. Gemini CLI reads this file directly via
> `context.fileName: ["AGENTS.md"]` in `.gemini/settings.json`. **Do not hand-edit
> the generated files.**

## Project Overview

Client-neutral BYOK credential plane: split reader/writer stores, bound single-use registration grants, hardened registration routes and provider validators.

## Commands

```bash
uv sync
uv sync --extra all              # All optional extras
uv run pytest -v
uv run ruff check src/
uv run pyright src/stromy_byok/
```


## Notes

This is a minimal-surface utility lib. See README.md for module structure and usage.


## Agent-md rendering

`AGENTS.md` is the only authored agent-instruction file. Regenerate the rest:

```bash
python3 scripts/render-agent-md.py            # CLAUDE.md + .github/copilot-instructions.md
python3 scripts/render-agent-md.py --check    # exit 1 if stale
```

**Never hand-edit** `CLAUDE.md` or `.github/copilot-instructions.md` — they carry a "GENERATED FILE" banner; edits are wiped on next render.

## Commit Standards

- Conventional Commits with gitmoji
- Every commit via the `conventional-commit` skill (machine-wide)
- Co-Authored-By trailer on AI-assisted commits

## Skill Workflow

- **Commits**: `/conventional-commit`
- **Library maintenance**: `/python-library-maintain` (in-satellite — bump version, tag release, refresh AGENTS, sync optional extras)
- **New skills (rare for libs)**: `/skill-creator`
