# Mordred Documentation Index (Hermes-base)

> Documentation set for **Mordred** — a privacy-hardening plugin layer for [Hermes](https://github.com/NousResearch/hermes-agent).
> Current version: **`0.1.0a0`** (see [`dev/VERSION`](./dev/VERSION)).
>
> **Version naming**: `0.1.0a0` is the current PEP 440 distribution version (the string in `mordred-hermes/pyproject.toml` and `dev/VERSION`). `v0.1.0-mvp.0` — used in prose across `dev/setup.md`, `dev/CI.md`, and this index — is the named GA milestone these docs target; it is not a separate release. The two strings describe the same release lane: `0.1.0a0` is the in-progress alpha that will graduate to the `v0.1.0-mvp.0` GA.

Docs are split by audience: **[`user/`](./user/)** for operators running Mordred, **[`dev/`](./dev/)** for contributors building it (with Hermes upstream reference under [`dev/hermes/`](./dev/hermes/)).

## Reading order

**Operators** start here:

1. [`user/QUICKSTART.md`](./user/QUICKSTART.md) — the short path to a running, protected install.
2. [`user/USAGE.md`](./user/USAGE.md) — full command reference and interactive-command walkthroughs.

**Contributors** then follow this flow:

1. [`dev/MIGRATION.md`](./dev/MIGRATION.md) — why Mordred targets Hermes (OpenClaw → Hermes), strategy and decisions.
2. [`dev/SPEC.md`](./dev/SPEC.md) — what is built: the 5 plugins, the keyvault wire formats, the threat model.
3. [`dev/PLAN.md`](./dev/PLAN.md) — how it is built: phases, module layout, implementation plan.
4. [`dev/TODO.md`](./dev/TODO.md) — task ordering and per-phase checklists (`PLAN` + `TODO` are canonical for ordering).
5. [`dev/setup.md`](./dev/setup.md) — local development environment setup for plugin developers.

## Documents

### `user/` — Operator docs

| Document | Purpose |
|---|---|
| [`QUICKSTART.md`](./user/QUICKSTART.md) | Quick setup guide — the short path to a running install, each step as purpose / do / result; network-path settings marked explicitly |
| [`USAGE.md`](./user/USAGE.md) | Operator usage guide — how to invoke `hermes-mordred`, quickstart, full command reference, interactive-command walkthroughs (keyvault ceremony / `network init` dialog / `configure` questions) |

### `dev/` — Developer & project docs

| Document | Purpose |
|---|---|
| [`SPEC.md`](./dev/SPEC.md) | Feature specification — 5 plugins, keyvault wire formats, threat model |
| [`KEYVAULT_BACKENDS.md`](./dev/KEYVAULT_BACKENDS.md) | Keyvault key-protection backend design + macOS Secure Enclave code-signing constraints (empirical findings, layered-backend proposal) |
| [`SECRETS_ENV_ENCRYPTION.md`](./dev/SECRETS_ENV_ENCRYPTION.md) | `.env` / secrets at-rest encryption design (vault wrap, reseal, write-guard) |
| [`PLAN.md`](./dev/PLAN.md) | Implementation plan — phases and module layout |
| [`TODO.md`](./dev/TODO.md) | Task ordering and per-phase checklists |
| [`PATHS.md`](./dev/PATHS.md) | Filesystem paths Mordred owns under `~/.hermes/mordred/` |
| [`POLICY.md`](./dev/POLICY.md) | Policy schema reference — audit `reason` enum, config schema, decision matrices |
| [`HARNESS_PRIVACY.md`](./dev/HARNESS_PRIVACY.md) | Threat note — why driving Mordred from a recording harness (Claude Code) can't be made private by workspace encryption; dev/operation boundary |
| [`HOOK_PAYLOADS.md`](./dev/HOOK_PAYLOADS.md) | Hermes hook payload verification reference (anchored to `hermes-agent` v0.11.0) |
| [`MIGRATION.md`](./dev/MIGRATION.md) | OpenClaw → Hermes migration strategy, term mapping, decisions |
| [`UPSTREAM.md`](./dev/UPSTREAM.md) | Relationship to Hermes upstream — zero-PR commitment, drift watch |
| [`CI.md`](./dev/CI.md) | CI workflow details |
| [`ROADMAP.md`](./dev/ROADMAP.md) | Post-v1 roadmap |
| [`setup.md`](./dev/setup.md) | Local development setup for plugin developers |
| [`VERSION`](./dev/VERSION) | Mordred-as-distribution version string (canonical mirror) |

### `dev/hermes/` — Hermes upstream reference

| Document | Purpose |
|---|---|
| [`DESIGN.md`](./dev/hermes/DESIGN.md) | Hermes design overview — context for plugin development |
| [`STRUCTURE.md`](./dev/hermes/STRUCTURE.md) | Hermes repository structure |

## Conventions

- **Audience split**: operator-facing docs live in [`user/`](./user/); developer & project docs live in [`dev/`](./dev/), with Hermes upstream reference under [`dev/hermes/`](./dev/hermes/). This layout supersedes the earlier pre-GA flat convention (see [`dev/ROADMAP.md`](./dev/ROADMAP.md) v2-X3).
- **Language**: English `.md` is the single source of truth. The Japanese `.ja.md` companion track was retired on 2026-06-25 (see [`dev/TODO.md`](./dev/TODO.md) §L1).
- The OpenClaw-era predecessor docs live at `../../mordred/mordred-mvp-docs/` and are **deprecated** — kept for searchability only.
