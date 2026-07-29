# Mordred — OpenClaw → Hermes Migration Guide (Draft)

> This file is the **foundational policy document** for rewriting `mordred-mvp-docs` from an `OpenClaw`-based standard to a `Hermes` (NousResearch/hermes-agent)-based standard.
> It catalogs terminology mappings, strategy, decided items, and open items, and serves as the reference for rewriting the main documents such as SPEC/PLAN/PATHS/TODO.
> **Status: DECIDED — the recommended approach has been finalized (see §10). The v1 strategy is `Option C + Vendored-fork escape hatch` (zero upstream PR); details in §5. Revised from the B+C hybrid on 2026-05-07.**

---

## 0. Background and Motivation

The old SPEC used a `Fork OpenClaw + 5 plugins + 3 core seams (S1–S3)` structure. The foundation was `OpenClaw` (TypeScript / Node.js).

The current working repository is `Mordred-Hermes/`, based on **Hermes (Python / NousResearch)**. Hermes supports migration from OpenClaw as a first-class citizen (`hermes claw migrate` already exists), and has the advantage in ecosystem maturity, model-selection flexibility, and breadth of distribution channels.

**Goal**: Rebuild Mordred's privacy-hardening layer on top of Hermes, and align the documentation set with it.

---

## 1. Architecture Difference Matrix (Verified)

| Area | OpenClaw | Hermes |
|------|----------|--------|
| Language/Runtime | TypeScript / Node.js (pnpm) | Python (pyproject.toml, pytest) |
| Plugin location | `extensions/<name>/` | `plugins/<name>/` (bundled) or `~/.hermes/plugins/<name>/` (user) or `./.hermes/plugins/<name>/` (project) or `pip` entry-point `hermes_agent.plugins` |
| Plugin manifest | `openclaw.plugin.json` (JSON) | `plugin.yaml` (YAML) + `register(ctx)` in `__init__.py` |
| Registration API | `api.on`, `api.registerCli`, `api.registerProvider`, `api.registerGatewayMethod` | `ctx.register_hook`, `ctx.register_cli_command`, `ctx.register_command` (slash), `ctx.register_tool`, `ctx.register_platform`, `ctx.register_context_engine`, `ctx.register_image_gen_provider`, `ctx.register_skill`, `ctx.dispatch_tool`, `ctx.inject_message` |
| Lifecycle hooks | `before_install`, `before_tool_call`, `before_model_resolve`, `gateway_start`, `gateway_stop` | `pre_tool_call`, `post_tool_call`, `pre_llm_call`, `post_llm_call`, `pre_api_request`, `post_api_request`, `on_session_start`, `on_session_end`, `on_session_finalize`, `on_session_reset`, `pre_gateway_dispatch`, `pre_approval_request`, `post_approval_response`, `subagent_stop`, `transform_terminal_output`, `transform_tool_result` |
| User path | `~/.openclaw/mordred/` | `~/.hermes/mordred/` |
| Config file | `~/.openclaw/openclaw.json` (JSON5) | `~/.hermes/config.yaml` (YAML) + `~/.hermes/.env` (API keys only) |
| CLI | `openclaw mordred ...` | `hermes mordred ...` |
| Provider reference implementation | `extensions/lmstudio/` | `agent/*_adapter.py` (anthropic, bedrock, gemini_native, codex_responses, lmstudio_reasoning, etc.) |
| Subagent | `agent` concept | `subagent_stop` hook + delegate_task tool |
| Secure Enclave binding | node-addon-api / node-gyp | pyobjc or cffi+Swift bridge or PyO3 |
| Tests | Vitest (`*.test.ts`) | pytest (`tests/test_*.py`) — `scripts/run_tests.sh` |
| Formatter | oxfmt | ruff (presumed) |
| Type checking | tsgo | mypy (presumed) |
| Upstream | `github.com/openclaw/openclaw` (MIT) | `github.com/NousResearch/hermes-agent` (MIT) |
| Skill registry | `clawhub.ai` | Skills Hub (built-in) + `agentskills.io` spec, `hermes_cli/skills_hub.py` |
| Existing OpenClaw migration tool | n/a | `hermes claw migrate` already exists |

---

## 2. Precise Mapping of Hooks and Signals

Mapping the 3 hooks that the old SPEC depended on to their Hermes equivalents yields the following:

| Old hook (OpenClaw) | New hook (Hermes) | Payload equivalence | Notes |
|---------------------|---------------------|-----------------|------|
| `before_install` | **Does not exist** | × | Hermes performs skill installation via `hermes_cli/skills_hub.py`, so a corresponding hook point needs to be **newly added** ⇒ candidate for **new Core Seam H1** |
| `before_tool_call` | `pre_tool_call` | ◯ (needs investigation) | Whether the payload includes an `originSkill` equivalent needs to be verified |
| `before_model_resolve` | `pre_llm_call` (or `pre_api_request`) | ◯ (needs investigation) | provider/model information is visible at an earlier stage in `pre_llm_call` |
| `gateway_start` / `gateway_stop` | `on_session_start` / `on_session_end` (individual session) | ✗ (different granularity) | In Hermes, "gateway" refers to the messaging gateway (Telegram/Discord/...), so a separate hook corresponding to **whole-process startup/shutdown** is needed ⇒ candidate for **new Core Seam H2** (e.g., `on_agent_init` / `on_agent_shutdown`) |
| `before_install` (skill metadata extraction) | n/a | × | Either add a skill installer guard mechanism to Hermes, or realize it via a CLI wrapper |

### Mapping the Old S1–S3 to Hermes

| Old Seam | Overview | Hermes equivalent |
|--------|------|--------------|
| S1: `pluginManifest.privacyLock?: boolean` | Protects against plugin disable | The v1 default is **plugin-side only** (the `hermes mordred plugins disable` wrapper CLI requires `--unlock` + a `mordred.degraded.disable_unprotected` audit log). If hard-enforce is needed, in v2 a **vendored fork extra** (`pip install mordred-hermes[hard-lock]` redistributes a patched version of `hermes_cli/plugins_cmd.py`). **No PR will be submitted upstream to Hermes** |
| S2: Add `originSkill?` to `before_tool_call` | Per-tool policy at the skill level | Include the origin skill in the `pre_tool_call` payload. Needs verification of whether there's a path where tools are invoked via Hermes's skill subsystem. If not, **new Seam H3** |
| S3: Add `resolvedProvider?` to `before_model_resolve` | Allow a cloud allow-list even under strict mode | The `pre_llm_call` payload likely includes provider/model (needs verification). If it does, S3 can be considered **already present upstream**, and the Mordred side simply consumes it |

→ S1–S3 need to be redesigned for Hermes as **"H1–H4" (tentative)**. Details will be worked out in the SPEC rewrite.

---

## 3. Hermes Mapping for the 5 Plugins

> **Note (L3, updated 2026-05-07)**: The distribution layout has been unified to **`src/mordred_hermes/<name>/`** (pip distribution layout, loaded via the `hermes_agent.plugins` entry-point) by the F4 fix. `plugins/mordred_*/` (bundled-style, the old OpenClaw-lineage notation) is not used. The wording still varied during the discussion phase of §0–§2, which is why references to it remained, but §10 (DECIDED) and SPEC/PLAN/PATHS are finalized on `src/mordred_hermes/<name>/`.

| Old plugin | Hermes implementation path (src layout) | Primary register API | Notes |
|-------------|--------------------|----------------------|------|
| `mordred-network` | `src/mordred_hermes/network/__init__.py` | `register_hook("on_session_start")`, `register_hook("pre_tool_call")`, `register_cli_command("mordred")` | Subprocess management (`tor`/`arti`/Mullvad WireGuard) uses the Python `subprocess` module. Proxy environment variable injection needs care at child-process launch points. Mid-session path switching has a transitive gap (see PLAN §3.1 M3) |
| `mordred-privacy-check` | `src/mordred_hermes/privacy_check/__init__.py` | `register_hook("pre_tool_call")`, `register_hook("on_session_start")`, skill install hook (new) | The challenge is that **there is no way to hook into the existing skill install path**. Either provide a CLI wrapper `hermes mordred install <skill>`, or add a new hook to Hermes core |
| `mordred-llm-guard` | `src/mordred_hermes/llm_guard/__init__.py` + `local_adapter.py` in the same dir | `register_hook("pre_llm_call")`, the provider adapter is bundled with the plugin (depending on the Phase 0.8 verify results, moving it to the `plugins/model-providers/<name>/` lineage is also under consideration) | Follows the Hermes provider adapter pattern. The override semantics of `pre_llm_call` need to be verified against actual code in Phase 0.8 (Story 4 caveat) |
| `mordred-keyvault` | `src/mordred_hermes/keyvault/__init__.py` (bundles `pyobjc-framework-Security` via the `[macos]` extra) | Register the `keyvault` subtree via `register_cli_command("mordred")` | **pyobjc** (direct Security.framework binding) is the leading candidate for the native binding. It's installable via `pip install mordred-hermes[macos]`, making it simpler than node-gyp |
| `mordred-wizard` | `src/mordred_hermes/wizard/__init__.py` | `register_cli_command("mordred", help, setup_fn, handler_fn)` | Build the `argparse` subparser hierarchy (`hermes mordred configure`, `hermes mordred network use ...`, `hermes mordred policy show`, etc.) inside `setup_fn(subparser)` |

---

## 4. Mapping of Mordred-Owned Paths

| Old path | New path | Owner (Hermes) |
|--------|--------|--------------------|
| `~/.openclaw/mordred/audit.log` | `~/.hermes/mordred/audit.log` | `mordred_privacy_check` |
| `~/.openclaw/mordred/policy.json` | `~/.hermes/mordred/policy.json` | `mordred_privacy_check` (writer is `mordred_wizard`) |
| `~/.openclaw/mordred/keyvault/` | `~/.hermes/mordred/keyvault/` | `mordred_keyvault` (Phase 4) |
| `~/.openclaw/credentials/mordred-network.json` | `~/.hermes/mordred/credentials/network.json` or a Mordred-specific key in `~/.hermes/.env` (e.g., `MORDRED_MULLVAD_ACCOUNT=...`) | `mordred_network` |
| `plugins.entries.mordred-*.config` in `~/.openclaw/openclaw.json` | the `plugins.mordred-*` section in `~/.hermes/config.yaml` | wizard goes from JSON5 round-trip → YAML round-trip (pyyaml's round-trip support is weak, so adoption of **`ruamel.yaml`** is under consideration) |

> Hermes's `get_hermes_home()` is profile-aware (default `~/.hermes/`). Mordred reuses the same profile resolution.

---

## 5. Candidate Strategies (3 options → Decision)

### Option A: Hard fork

Fork `NousResearch/hermes-agent` and develop on a Mordred-dedicated long-lived branch. Core modifications are unrestricted.

- ◯ Pros: No constraints; independent UX branding is also possible
- × Cons: Highest upstream sync cost, dependent on maintainer headcount, hard to keep up with Hermes's rapid evolution

### Option B: Soft fork + Hermes Core Seams (same philosophy as the old SPEC)

Keep `Mordred-Hermes/` as a fork, while limiting core modifications to **minimal, additive, general-purpose (H1–H4, tentative)**. Absorb upstream via weekly rebase.

- ◯ Pros: Consistent with the old SPEC, easy to absorb Hermes's evolution
- × Cons: Requires submitting PRs to Hermes (if not accepted, the fork must be maintained forever); review delays can become a phase blocker

### Option C: Pure plugin bundle + patch only when necessary

Distribute the 5 plugins via **`pip install mordred-hermes`**. Don't touch the Hermes core itself. Auto-loaded via the `hermes_agent.plugins` entry-point.

- ◯ Pros: The Mordred-Hermes repository needs no upstream rebase, distribution is extremely simple, users only need `pip install mordred-hermes`
- × Cons: Core-side guards don't work (if a user manually disables a plugin, the security layer disappears). There's no escape hatch if a scenario requiring core modification arises in the future

### Decision: Option C + Vendored-fork escape hatch [DECIDED, revised 2026-05-07]

**Based on Option C (pure plugin bundle), handle only the items where core modification truly becomes necessary via a vendored fork**. **No PR will be submitted upstream to Hermes (zero-PR commitment)**.

Rationale:

1. Submitting PRs upstream to Hermes carries review-time and acceptance-risk that can become a phase blocker. Mordred should be able to release independently, without depending on upstream's pace
2. The MVP (Phase 1–3) is achievable with plugin-only distribution. "Core seam" equivalents such as privacy-lock achieve defense-in-depth via a plugin-side wrapper + audit log
3. Even so, for items where core modification truly becomes necessary (future seams), we will not submit a PR upstream to Hermes; instead we absorb them via a **vendored fork** (keeping a copy of the Hermes core module under Mordred-Hermes, patching only the necessary spots, and redistributing that version as part of the `mordred-hermes` distribution)
4. The `Mordred-Hermes/` repository is positioned as "**a plugin development repository + (when necessary) a repository holding vendored patches to some Hermes modules**"

**Implementation implications**:

- `Mordred-Hermes/` requires no rebase of the upstream `NousResearch/hermes-agent` (a plugin development repo + some vendored modules)
- The 5 plugins are developed under `src/mordred_hermes/<name>/` (pip distribution layout) and distributed via `pip install mordred-hermes` (entry-point `hermes_agent.plugins`)
- "Core seam" equivalents from the old SPEC (old S1–S3) are handled **without submitting an upstream PR**, via the following two-tier approach:
  - **Tier A (v1 default, plugin-only)**: defense-in-depth via a plugin-side audit log (the `mordred.degraded.*` family) and the `hermes mordred ...` wrapper CLI
  - **Tier B (deferred, vendored fork extra)**: Only when hard-enforce is truly necessary, keep a patched version of the relevant Hermes module in `vendor/hermes/<version>/` and redistribute it via a packaging extra (e.g., `pip install mordred-hermes[hard-lock]`). Pinned to a specific Hermes version. Out of scope for the v1 release
- Upstream hook signature drift is detected via CI (`upstream-check.yml`) (informational; does not block releases)
- "Holding a vendored module" and "submitting a PR upstream" are separate things. The latter will **not** be done

---

## 6. Naming Conventions

| Item | Old (OpenClaw) | New (Hermes) | Notes |
|------|---------------|-----------------|------|
| Product name | Mordred | **Mordred** (unchanged) | Decided |
| CLI | `openclaw mordred ...` | **`hermes mordred ...`** (decided) | User-approved |
| Plugin ID | `mordred-network`, etc. (kebab-case) | `mordred_network`, etc. (snake_case) ⇒ Python module name | Hermes plugins must follow Python package naming |
| pip package name | n/a | `mordred-hermes` (kebab) or `mordred-network`, `mordred-privacy-check` individually | Depends on the bundling strategy |
| Config namespace | `plugins.entries.mordred-*.config` | `plugins.mordred_*` or a `mordred:` top-level key | Naming is up to the plugin, but following existing Hermes plugins is preferable |
| Skill frontmatter | `metadata.mordred.*` | **Same** `metadata.mordred.*` (compatibility maintained) | Need to confirm whether it conflicts with the agentskills.io spec |
| Mordred-as-distribution version | `mordred-mvp-docs/VERSION` | **Same** `docs/VERSION` | Unchanged |

---

## 7. Platform Support [DECIDED]

The old SPEC was **macOS Apple Silicon only** (reason: Secure Enclave native
addon), but moving to Hermes made Phase 1-3 OS-independent. A later backend
follow-up completed the Linux TPM 2.0 MVP on 2026-06-09.

| Phase | Platform |
|-------|-------------------|
| Phase 1–3 | **macOS / Linux / WSL2** (all environments where Hermes runs) |
| Phase 4 (keyvault, macOS) | Secure Enclave on supported Macs, with a login-Keychain software P-256 fallback |
| Phase 4 (keyvault, Linux) | **TPM 2.0 MVP complete**; packaged helper, machine-bound, no software fallback |
| Phase 4 (keyvault, Windows native) | DPAPI / TPM deferred to ROADMAP `v2-OS2` |

**Rationale**:
- Phase 1–3 (network/privacy-check/llm-guard/wizard) is pure Python. The Tor/Mullvad CLI is, if anything, easier to run on Linux
- Opening this up to the whole Hermes community has significant value (Hermes supports as far as Linux/Termux/WSL2)
- Phase 4 began with the macOS Secure Enclave implementation. Linux later
  gained the TPM 2.0 helper; transparent startup injection and the direct
  blackout fallback remain separate macOS-only integrations

---

## 8. Documentation Rewrite Phase Plan

| Phase | Duration | Deliverable |
|-------|------|---------|
| **A: Terminology mapping & decision-making** | 0.5 day | This `MIGRATION.md` (this file) — locked after decisions are made |
| **B: SPEC.md rewrite** | 1–2 days | Fully revise `SPEC.md` to the Hermes standard, finalize the 5 plugins / H1–H4 seams |
| **C: PLAN/PATHS/TODO rewrite** | 1–2 days | Enumerate file paths, Python tools, pytest fixtures, `hermes mordred ...` CLI |
| **D: UPSTREAM/ROADMAP/CI rewrite** | 0.5 day | `git remote add upstream https://github.com/NousResearch/hermes-agent.git`, replace with Python CI, make `upstream-sync.yml` Python-based |
| **(Later) F: Begin 5-plugin scaffolding** | Separate plan | Code implementation is handled in a separate PR/separate plan |

Total: **4–6 days** (documentation only; does not include code implementation)

---

## 9. Risks and Open Items

### High

1. **Hermes has no `before_install` equivalent hook** — policy enforcement at skill install time may not be possible. Workarounds:
   - (a) PR a Mordred hook point into `hermes_cli/skills_hub.py` on the Hermes side
   - (b) Provide a `hermes mordred install <skill>` wrapper CLI via the Mordred wizard (this is the more realistic option)

2. **Verify the contents of the `pre_llm_call` payload against actual code** — whether a `resolvedProvider` equivalent is visible affects how easy S3 (cloud allow-list) is to implement

3. **There is no official API for dynamically registering an LLM provider from a Hermes plugin** — the `agent/*_adapter.py` pattern needs to live on the core side. Design work is needed for how to integrate `mordred-llm-guard`'s `mordred-local` synthetic provider

### Medium

4. **[RESOLVED 2026-05-07]** ~~**Two-stage migration UX of `hermes claw migrate` and `hermes mordred upgrade`** — existing users coming from OpenClaw will need to run 2 commands. Story 1 needs to be rewritten~~ → **Resolved (L4)**: Finalized in §10 row 5 as "keep independent commands + spell out the 2-step flow in the docs". SPEC.md Story 1.5 spells out the 3 steps (`hermes claw migrate` → `pip install mordred-hermes` → `hermes mordred upgrade`). The unified wrapper will be reevaluated in v2

5. **Choice of YAML round-trip writer** — if adopting `ruamel.yaml` is finalized, it affects the Phase 1.3 wizard design

6. **Hermes upstream updates frequently** (rapid development) — since Mordred is plugin-only distribution, **no rebase is needed**. Hook signature drift is detected informationally by CI. If the vendored fork extra (Tier B) is introduced in a future v2, there will be a cost to keep up with the pinned Hermes version

### Low

7. **Terminology inconsistency in the Japanese version** — since this file includes a terminology mapping table (§1), use it as the reference point when translating English → Japanese

---

## 10. Decision Checklist [All items DECIDED]

| # | Item | Decision | Notes |
|---|------|------------|------|
| 1 | Strategy | **Option C + Vendored-fork escape hatch** (zero upstream PR) | See §5. Distributed via `pip install mordred-hermes`, no upstream PR submitted, only items where core modification truly becomes necessary are handled via a vendored fork extra (out of scope for v1) |
| 2 | Platform | **Phase 1-3 = macOS/Linux/WSL2; Phase 4 key custody = macOS + Linux TPM 2.0** | See §7. Windows-native key custody remains v2-OS2 |
| 3 | YAML writer | **`ruamel.yaml`** | Preserves user comments and key order via round-trip (an equivalent guarantee to the old SPEC's JSON5 round-trip) |
| 4 | Hermes upstream PR | **Not submitted (zero-PR commitment)** | Old S1 (privacy_lock) achieves defense-in-depth via a plugin-side wrapper + audit log. `H1` (before_install equivalent) and `H2` (agent init/shutdown) are also handled with a plugin-side fallback (CLI wrapper, existing hooks). If hard-enforce becomes necessary in v2, we proceed to the vendored fork extra |
| 5 | Relationship with `hermes claw migrate` | **Keep it as an independent command** (`hermes mordred upgrade`), but spell out the 2-step flow in the docs | Users coming from OpenClaw + Mordred go through 3 steps: `hermes claw migrate` → `pip install mordred-hermes` → `hermes mordred upgrade` |
| 6 | Distribution form | **Single package `mordred-hermes`** (bundles 6 plugins) | The plugins are tightly coupled (e.g., keyvault → network blackout assert). Distributed together to avoid version skew. Each plugin's enabled/disabled state can be controlled individually via config |
| 7 | Treatment of the old `mordred-mvp-docs/` | **Left in place with a deprecation marker added** | Create `../../mordred/mordred-mvp-docs/README.md` and note the migration destination. Not deleted, for discoverability |

---

## 11. Reference: Minimal Example of a Hermes Plugin Implementation

```python
# plugins/mordred_privacy_check/__init__.py
"""Mordred Privacy Check plugin — enforces network/cloud policy."""

from hermes_cli.plugins import PluginContext


def register(ctx: PluginContext) -> None:
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("on_session_start", _on_session_start)


def _on_pre_tool_call(tool_name: str, params: dict, **kwargs):
    # Policy decision. If blocking, control via exception or return value (needs verify)
    ...


def _on_session_start(**kwargs):
    # Load policy snapshot into memory
    ...
```

```yaml
# plugins/mordred_privacy_check/plugin.yaml
name: mordred_privacy_check
version: 0.1.0
description: Privacy policy enforcement for Mordred
author: InternetMaximalism
privacy_lock: true   # ← Field equivalent to old S1. In v1 it's a hint referenced on the plugin side (actual enforcement is via the `hermes mordred plugins disable` wrapper + audit log). No PR submitted upstream to Hermes. Hard-enforce will be handled by a vendored fork in a future `[hard-lock]` extra
config_schema:
  type: object
  properties:
    policy:
      enum: [strict, lenient, off]
      default: lenient
    allow_cloud_llm:
      type: boolean
      default: false
    cloud_provider_allowlist:
      type: array
      items: { type: string }
      default: []
```

---

## Appendix: Verified Hermes API Reference

Confirmed in `hermes_cli/plugins.py` (lines 78–114, 233–600+):

- **Plugin discovery**: 4 sources (bundled / user / project / pip entry-point `hermes_agent.plugins`)
- **Manifest**: `plugin.yaml` (YAML), the `register(ctx)` function in `__init__.py`
- **`PluginContext` API**:
  - `register_tool(name, toolset, schema, handler, check_fn=None, requires_env=None, is_async=False, description="", emoji="")`
  - `register_hook(hook_name, callback)` — one of `VALID_HOOKS`
  - `register_cli_command(name, help, setup_fn, handler_fn=None, description="")` — creates `hermes <name> ...`
  - `register_command(name, handler, description="", args_hint="")` — slash command `/<name>`
  - `register_context_engine(engine)` — only a single plugin may do this
  - `register_image_gen_provider(provider)`
  - `register_platform(name, label, adapter_factory, check_fn, ...)` — gateway platform adapter
  - `register_skill(name, path, description="")`
  - `dispatch_tool(tool_name, args, **kwargs)`
  - `inject_message(content, role="user")`
- **`VALID_HOOKS`** (16 types):
  - tool: `pre_tool_call`, `post_tool_call`, `transform_tool_result`, `transform_terminal_output`
  - llm: `pre_llm_call`, `post_llm_call`, `pre_api_request`, `post_api_request`
  - session: `on_session_start`, `on_session_end`, `on_session_finalize`, `on_session_reset`
  - subagent: `subagent_stop`
  - gateway: `pre_gateway_dispatch` (return `{action: skip|rewrite|allow}`)
  - approval: `pre_approval_request`, `post_approval_response` (observers only)
