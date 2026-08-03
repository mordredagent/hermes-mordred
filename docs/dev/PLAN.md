# Mordred — Implementation Plan (Hermes-base)

> **Note**: This PLAN is the Mordred implementation plan on the `Hermes (NousResearch/hermes-agent)` foundation. The old version based on OpenClaw remains at `../../mordred/mordred-mvp-docs/PLAN.md` (deprecated).

Companion to `SPEC.md`. Defines the concrete file paths, milestones, test approach, and acceptance criteria for each phase. The plugin implementation lands in `src/mordred_hermes/<name>/` (pip distribution layout) and is loaded into Hermes via `pyproject.toml`'s `[project.entry-points."hermes_agent.plugins"]`. v1 is a **zero-PR commitment** (`MIGRATION.md` §5, 2026-05-07): Hermes core modifications are completed entirely within **plugin-only Tier A** (wrapper CLI + audit log + strict-mode startup refusal), and only items where hard-enforce truly becomes necessary escalate to the v2 vendored fork extra (`mordred-hermes[hard-lock]`, Tier B). See SPEC §Plugin-Only Architecture for details.

The `Mordred-Hermes/` repository does not need to rebase onto upstream `NousResearch/hermes-agent` (it's a pure plugin development repo). Distribution is a single `pip install mordred-hermes` install.

## Phase 0 — Operational Setup (one-time, blocking everything else)

### 0.1 Repo & venv Check

- Confirm Hermes is available from `Mordred-Hermes/` (an environment with `pip install hermes-agent` already done, or the developer may instead have a Hermes development clone alongside): sanity-check with `python -m hermes_cli --version` etc.
- Activate the venv: `source .venv/bin/activate` (the order Hermes's `scripts/run_tests.sh` probes: `.venv` → `venv` → `~/.hermes/hermes-agent/venv`)
- Prepare a local development install of the `mordred-hermes` package via pyproject.toml (implemented in Phase 0.5)

### 0.2 Hermes Upstream Tracking Strategy (optional)

- The recommendation is **no rebase needed** (since distribution is plugin-only)
- Only if you want to track the latest Hermes upstream during development: `git remote add hermes-upstream https://github.com/NousResearch/hermes-agent.git`
- `.github/workflows/upstream-check.yml` weekly detects **name** drift in the latest Hermes hooks (`hermes_cli.plugins.VALID_HOOKS` membership) and compares it against the hook names Mordred plugins register via `register_hook("...")`. An issue is auto-filed when a difference is found (a deep diff of the hook **payload field shape** is v2 deferred — this workflow only covers name drift)
- decision: whether to introduce the above workflow in v1 or defer it to v2 will be decided in Phase 0.5

### 0.3 Mordred-owned paths (kept in sync with PATHS.md)

Reserved paths:
- `~/.hermes/mordred/audit.log` (Phase 1)
- `~/.hermes/mordred/policy.json` (Phase 1)
- `~/.hermes/mordred/credentials/` (Phase 3)
- `~/.hermes/mordred/keyvault/` (Phase 4)

Each plugin's `README.md` documents the paths it owns / its internal Python API.

### 0.4 Plugin scaffolding pattern

Each Mordred plugin has the following under `src/mordred_hermes/<name>/` (pip distribution layout):

- `plugin.yaml` — Hermes plugin manifest:
  ```yaml
  name: mordred_<name>
  version: 0.1.0
  description: <one-line>
  author: InternetMaximalism
  privacy_lock: true   # Mordred-internal hint (zero-PR commitment; since we don't submit a PR to Hermes upstream, Hermes core ignores this field). Used for Tier A sibling-disable detection. hard-enforce is handled by the v2 `[hard-lock]` extra (vendored fork)
  config_schema:
    type: object
    properties:
      ...
  ```
- `__init__.py` — entry, defines `def register(ctx: PluginContext) -> None`
- `*.py` — runtime modules
  - native / heavy deps are lazily loaded via `_lazy_import()` (e.g., `mordred_keyvault.native` doesn't raise an import error on non-macOS)
- `tests/test_*.py` — pytest, colocated
- `README.md` — Mordred-owned paths, config keys, internal Python API surface
- `AGENTS.md` (optional) — guide for AI agents during development

### 0.5 `mordred-hermes` Package Scaffold

- Example root `pyproject.toml`:
  ```toml
  [build-system]
  requires = ["hatchling"]
  build-backend = "hatchling.build"

  [project]
  name = "mordred-hermes"
  dynamic = ["version"]                        # read from docs/VERSION (single source of truth, M6)
  description = "Privacy-enhancement layer for Hermes"
  readme = "README.md"
  license = { file = "LICENSE" }
  requires-python = ">=3.10"
  dependencies = [
    "hermes-agent>=1.0",                       # H1: peer Hermes runtime. Required at install time (without it, the entry-point can't resolve)
    "ruamel.yaml>=0.18",
  ]

  [project.optional-dependencies]
  macos = ["pyobjc-framework-Security>=10.0"]   # Phase 4 keyvault

  [project.entry-points."hermes_agent.plugins"]
  mordred_network = "mordred_hermes.network"
  mordred_privacy_check = "mordred_hermes.privacy_check"
  mordred_llm_guard = "mordred_hermes.llm_guard"
  mordred_keyvault = "mordred_hermes.keyvault"
  mordred_wizard = "mordred_hermes.wizard"

  [project.metadata]
  mordred-min-hermes-version = "1.0.0"   # each plugin re-verifies the runtime version in on_session_start

  [tool.hatch.version]
  source = "regex"                       # the default `path` source expects a `__version__ = "..."` pattern, so we explicitly specify the regex source for a plain-text VERSION file
  path = "docs/VERSION"          # M6: the VERSION file is the single source of truth; don't hardcode it in pyproject
  pattern = "^v?(?P<version>.+?)\\s*$"   # allows a leading `v` prefix, chomps trailing whitespace. The extracted value must be PEP 440 compliant (Hatch validates it)
  ```

  > **PEP 440 compliance (Codex review 2026-05-09)**: The contents of `docs/VERSION` must be a **PEP 440-compliant version string** (e.g., `0.1.0a0` = alpha 0, `0.1.0` = release, `0.1.0.dev0` = dev release). The v1 baseline is `0.1.0a0` (since Hatch rejects `0.1.0-mvp.0`). The human-readable spec label `v0.1.0-mvp.0` is used only as branding in ROADMAP / SPEC / release notes; for packaging purposes `0.1.0a0` is the first PyPI upload version.

- The package layout is `src/mordred_hermes/{network,privacy_check,llm_guard,keyvault,wizard}/`
- During development, use `pip install -e ./mordred-hermes` for an editable install; Hermes loads it via the entry-point
- **Making hermes-agent mandatory at install time** (H1): `dependencies = ["hermes-agent>=1.0", ...]` makes a standalone `pip install mordred-hermes` fail-fast in an environment without Hermes. `[project.metadata].mordred-min-hermes-version` remains as a secondary runtime-side verification (for detecting cases where an older version got installed in an environment with a loosely pinned `hermes-agent`)
- **package-name reservation** (M7): claim the `mordred-hermes` name on TestPyPI / PyPI via a stub upload before the v1 docs are published (see TODO §0.5). This prevents supply-chain attacks via name squatting

### 0.6 CI workflow

- `.github/workflows/ci.yml`:
  - `pytest` (with `pytest-cov` for coverage)
  - `ruff check src tests`
  - `ruff format --check src tests`
  - `mypy src` (strict mode)
- `.github/workflows/upstream-check.yml` (the optional workflow from 0.2 above)
- Labeler: `.github/labeler.yml` applies labels to `mordred-*` paths (following the convention from the old OpenClaw repo)

### 0.7 ~~HSeam-1 PR~~ → Zero-PR commitment (deferred to v2 vendored fork)

> **2026-05-07 revise**: MIGRATION.md §10 row 4 / §5 confirmed **zero upstream PR**. The HSeam-1 PR to Hermes upstream will **not be submitted** in v1. Disable protection is fully handled by plugin-side strict-mode startup refusal (SPEC.md §Plugin-disable protection Tier A, TODO.md §1.1 H3 task).

In v1, the Phase 0.7 tasks are only the following:

- [x] Declare `privacy_lock: true` as a declarative marker in the five manifest-backed plugins (`keyvault` / `network` / `wizard` / `privacy_check` / `llm_guard`) — **Done**. Hermes ignores the field; runtime enforcement uses the explicit six-entry `SIBLING_PLUGINS` canonical list, including the manifest-less `mordred_e2e` entry point. The marker does not auto-expand that list
- [x] The implementation of H3 plugin-side strict-mode startup refusal happens in Phase 1.1 (`mordred_privacy_check.on_session_start`) — **Done**: `privacy_check/hooks.on_session_start` detects sibling-disable via `_runtime.find_disabled_siblings`, and in strict mode performs audit + poison + `MordredIntegrityRefused(BaseException)` (H3 Path B, SPEC.md §Plugin-disable protection Tier A). The hook is registered in `privacy_check/__init__.py` and covered by `tests/test_hooks.py`

Only if hard-enforce becomes necessary in the future (v2), introduce the vendored fork extra:

- Place a patched version of Hermes's corresponding version at `vendor/hermes/<version>/hermes_cli/plugins_cmd.py`
- Define the `hard-lock` extra via `[project.optional-dependencies]` in `pyproject.toml`
- Users obtain the hard-enforce version with `pip install mordred-hermes[hard-lock]`
- See UPSTREAM.md §Tier B for detailed steps; out of scope for v1

**Phase 0 acceptance**:

- `pip install -e ./mordred-hermes` succeeds, and `PluginManager.discover_and_load()` detects the 6 mordred_* entries via the entry-point
- ~~`hermes plugins list` shows the mordred_* entries~~ → Phase 1.3 wizard provides the `hermes mordred plugins list` wrapper CLI (a known gap where Hermes 0.11.0's `_discover_all_plugins()` doesn't display entry-point plugins; see TODO.md §Acceptance gate L126)
- pytest is green even with no tests, ruff/mypy are also green (enforced in CI, landed in PR #8. See `docs/dev/CI.md` §`ci.yml` details for specifics)
- ~~HSeam-1 PR draft~~ → not needed (zero-PR commitment)

---

## Phase 1 — Privacy Primitives (`mordred_privacy_check` + metadata + wizard)

Minimal end-to-end slice. Partially achieves Story 2 and Story 3. No network code / native modules whatsoever.

**Privacy-lock guard (Tier A, zero-PR commitment)**: `privacy_lock: true`
is a declarative marker on the five manifest-backed plugins; Hermes ignores
it. The five runtime plugins (`privacy_check`, `network`, `llm_guard`,
`keyvault`, and `e2e`) register the shared integrity callback, which checks
the fixed canonical list of all six Mordred entry points (including
`wizard`). Under strict policy it records
`mordred.degraded.disable_unprotected` and raises
`MordredIntegrityRefused(BaseException)`. If hard-enforce becomes necessary
in v2, escalate to the `[hard-lock]` extra (vendored fork).

### 1.1 Plugin: `mordred_privacy_check`

**Files**

- `src/mordred_hermes/privacy_check/plugin.yaml`
  ```yaml
  name: mordred_privacy_check
  version: 0.1.0
  description: Privacy policy enforcement for Mordred
  author: InternetMaximalism
  privacy_lock: true
  config_schema:
    type: object
    additionalProperties: false
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
      audit_log_path:
        type: string
  ```
- `src/mordred_hermes/privacy_check/__init__.py` — `register(ctx)` function
- `src/mordred_hermes/privacy_check/policy.py` — pure policy evaluator (no I/O)
- `src/mordred_hermes/privacy_check/skill_frontmatter.py` — SKILL.md frontmatter parser, extracts `metadata.mordred.*`
- `src/mordred_hermes/privacy_check/audit.py` — single-writer append-only audit logger with rotation
  - Phase 1–3: plaintext NDJSON, file mode `0600`
  - Writer interface: `class Writer(Protocol)`, factory-swapped to `EncryptedWriter` in Phase 4
- `src/mordred_hermes/privacy_check/install_wrapper.py` — implements `hermes mordred install <skill>` (called from the wizard)
- `tests/test_policy.py` — policy evaluation matrix (strict/lenient/off × clearnet/tor/vpn/local-only)
- `tests/test_audit.py` — rotation, file mode, single-writer concurrency
- `tests/test_install_wrapper.py` — installs fixture skills (clearnet/tor/missing) and asserts the expected outcome

**Hooks to register**

Hermes hook payload shapes are fixed in `hermes_cli/plugins.py:VALID_HOOKS`:

- **Skill install guard** (via a wrapper, since there's no Hermes core hook):
  - `hermes mordred install <skill>` → `install_wrapper.run(skill_path)`
  - Read SKILL.md from `skill_path`, `yaml.safe_load` the frontmatter
  - Extract `metadata.mordred.network_requirements`
  - Strict + `clearnet` → `RuntimeError` raise + audit log `policy.strict.clearnet`
  - Strict + missing → `RuntimeError` raise + audit log `policy.strict.unknown_metadata`
  - Lenient + missing → allow + audit log `policy.lenient.unknown_metadata_warning`
  - Allow → spawn Hermes's standard skill install as a child process (`hermes skills install <skill>`)
- `pre_tool_call` (`ctx.register_hook("pre_tool_call", _on_pre_tool_call)`)
  - payload (**Phase 0.8 verify complete**, [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4): `{tool_name, args, task_id, session_id, tool_call_id}`. **`origin_skill` is not included** — the only path for per-skill policy is determination by the install-time `hermes mordred install` wrapper
  - Generic per-tool allowlist (configurable). Default strict-mode blocklist: builtin `web_fetch`, `web_search` when active network path is Clearnet
  - The block format returns `{"action": "block", "message": str}` (**Phase 0.8 verify complete**, not an exception raise, [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4)
  - **v1 always uses the generic allowlist path** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4 confirmed the absence of the `origin_skill` payload). Records the audit `mordred.degraded.no_origin_skill` once at startup (a declaration that the per-skill path is unavailable in v1; this log is suppressed once the `origin_skill` payload extension lands in v2-H2)
- `on_session_start` (`ctx.register_hook("on_session_start", _on_session_start)`)
  - Load the policy snapshot from `plugins.mordred_privacy_check` in `~/.hermes/config.yaml`
  - Cache it in memory
  - If a sibling Mordred plugin is disabled, warning + `mordred.degraded.disable_unprotected`
  - If the v2 `[hard-lock]` extra (vendored fork) is installed, the core-side guard prevents it one step earlier, so the plugin-side startup refusal remains as redundant defense-in-depth (harmless)

**Audit log format** (newline-delimited JSON, `~/.hermes/mordred/audit.log`, 0600, daily rotation, 10 MB cap, 30-day retention, gzip after rotation, single-writer queue):

```json
{
  "ts": "2026-04-29T12:34:56.000Z",
  "event": "pre_install",
  "skill_id": "example",
  "decision": "block",
  "reason": "policy.strict.clearnet"
}
```

Fields: `ts` (ISO-8601 UTC), `event` (hook name or `pre_install`), `skill_id` / `tool_name` / `provider_id` (one of, depending on event), `decision` (`allow` | `block` | `override` | `warn`), `reason` (fixed enum, frozen in SPEC.md §Audit log policy). Raw `params`, prompt content, and skill body are never logged.

### 1.2 Skill metadata namespace

- Documented in `src/mordred_hermes/privacy_check/README.md`:
  - `metadata.mordred.network_requirements`: enum `tor` | `vpn` | `clearnet` | `local-only`
  - `metadata.mordred.requires_keyvault`: boolean (Phase 4)
  - `metadata.mordred.outbound_endpoints`: optional `string[]` — explicit endpoint allow-list
- Hermes's standard skill loader does not interpret `metadata.mordred.*` (no conflict with the agentskills.io spec, confirmed in Phase 1.5)
- Acceptance: fixture skill at `tests/fixtures/clearnet_skill/SKILL.md` is rejected at `hermes mordred install` under strict policy

### 1.3 Plugin: `mordred_wizard`

**Files**

- `src/mordred_hermes/wizard/plugin.yaml` — config under `plugins.mordred_wizard`
- `src/mordred_hermes/wizard/__init__.py` — in `register(ctx)`, calls `ctx.register_cli_command("mordred", help="Mordred privacy layer", setup_fn=_setup_subparser, ...)`
- `src/mordred_hermes/wizard/cli.py` — builds the argparse subparser tree in `_setup_subparser(subparser)` (configure / upgrade / install / network / policy / audit / keyvault)
- `src/mordred_hermes/wizard/configure.py` — spawns `hermes setup` as a child process via `subprocess.run`, then asks Mordred-specific questions via `prompt_toolkit` (an existing Hermes dependency)
- `src/mordred_hermes/wizard/upgrade.py` — Story 1 / 1.5 single-command migration
  - Round-trips `~/.hermes/config.yaml` through `ruamel.yaml` (preserving comments and key order)
  - idempotent
  - On conflict with existing `plugins.mordred_*`, diff + prompt
  - For existing skills lacking `metadata.mordred.*`, audit-warn under lenient, block under strict
  - **Story 1.5 (OpenClaw migration)**: when `~/.openclaw/mordred/` is detected, migrate according to the "Migration from legacy OpenClaw paths" table in PATHS.md
- `src/mordred_hermes/wizard/policy_writer.py` — writes out the `plugins.mordred_*` section of `~/.hermes/config.yaml` (`ruamel.yaml`)
- `src/mordred_hermes/wizard/policy_explainer.py` — implements `policy explain` / `policy dry-run`
- `tests/test_upgrade.py` — migrates a fixture config and verifies the expected output
- `tests/test_policy_writer.py` — asserts comment preservation across a JSON5/YAML round-trip

**CLI surface (Phase 1)**

- `hermes mordred configure` — child-spawns `hermes setup`, then Mordred prompts (policy, allow_cloud_llm, cloud_provider_allowlist, local LLM endpoint, local model id (Phase 2 fields are collected in Phase 1 but unused until then))
- `hermes mordred upgrade` — Story 1 / 1.5 migration; idempotent; preserves YAML comments (`ruamel.yaml`)
- `hermes mordred install <skill>` — the key entry point for Phase 1. Skill install via privacy-check
- `hermes mordred policy show` — print effective policy (merged from all `plugins.mordred_*`)
- `hermes mordred policy explain <skill-id>` — explain why a skill is allowed/blocked
- `hermes mordred policy dry-run <skill-path>` — predict install-time decision
- `hermes mordred policy reload` — invalidate in-memory policy cache (in-process call)
- `hermes mordred audit tail [-n N]` — print last N audit entries
- `hermes mordred audit grep <pattern>` — search audit log

### 1.4 Tests

- Unit: `test_policy.py` covers strict/lenient/off × clearnet/tor/vpn/local-only matrix
- Integration: install fixture skill via `hermes mordred install`, assert outcome
- Wizard: snapshot-test the prompt sequence (`pytest-snapshot`)
- E2E: the whole `pytest tests/` suite

**Phase 1 acceptance**:

- `hermes mordred configure` writes policy to `~/.hermes/config.yaml` and `policy.json`
- `hermes mordred upgrade` migrates an existing Hermes install without data loss; OpenClaw migration also follows Story 1.5
- `hermes mordred install <fixture-clearnet-skill>` is blocked under strict policy
- All tests pass on `pytest -q`, ruff / mypy green
- Even under the zero-PR commitment, defense-in-depth is established via the plugin-side Tier A guard (strict-mode startup refusal + audit log). Adding the `[hard-lock]` extra (vendored fork) in v2 can also support core-side hard-enforce

---

## Phase 2 — LLM Enforcement (`mordred_llm_guard` + `mordred-local` provider)

> **2026-05-13: Phase 2 PR1 + PR2 complete** (merged into `main`, PR #14 / #15). This section describes the **landed design** reflecting the PR1 prep findings (Codex review B1/B2/H1/H2, TODO.md §2 L227-234). The historical "dynamic provider override via pre_llm_call" plan was rejected upon Phase 0.8 verify completion ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5); §2.1 below is unified with the landed semantics.

session-scoped LLM enforcement and harness-startup refuse. Achieves Story 4.

**Hermes feature dependency** (Phase 0.8 verify complete, [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5):

- In v0.11.0, the `pre_llm_call` payload contains only `model`, not `provider`, and its return value is context-injection only (no provider override possible). `pre_api_request` carries provider/model/base_url but is observer-only. v1 uses **two-stage session-scoped enforcement via `on_session_start` + `pre_api_request`**:
  - strict + current provider matches `cloud_provider_allowlist` + `allow_cloud_llm: true` → session continues (passthrough, audit `policy.strict.cloud_allowlisted`)
  - strict + no match, or `allow_cloud_llm: false` → **refuse** (raises `MordredSessionRefused(BaseException)`, audit `policy.strict.session_refused` + classification `policy.strict.cloud_not_allowlisted`). **Auto-swap (config patch + `register_provider`) is not possible in v1 due to B2** — because Hermes has already resolved the provider **before** session start. Planned to be revived in the v2 vendored fork (`[hard-lock]` extra, Tier B) (the `policy.strict.provider_override_at_session_start` enum is already frozen as a forward-compat reservation; see POLICY.md row 11)
- Per-turn dynamic override is out of scope for v1 (structurally impossible)

### 2.1 Plugin: `mordred_llm_guard` (landed)

**Files** (landed in `src/mordred_hermes/llm_guard/`):

- `plugin.yaml` — config under `plugins.mordred_llm_guard`, `privacy_lock: true`
- `__init__.py` — in `register(ctx)`, **explicitly registers** the provider adapter (`register_mordred_local`) + 3 hooks (`on_session_start` × 2 + `pre_api_request`) (Codex B1: since `providers._discover_providers()` doesn't scan entry-point plugins, a module-import side effect isn't possible)
- `local_adapter.py` — **declarative `ProviderProfile` subclass only** (Codex H1: the SPI list the old PLAN version enumerated — `auth/discovery/resolve_synthetic_auth/normalize_config/prepare_dynamic_model/resolve_dynamic_model/augment_model_catalog/wrap_stream_fn/wizard` — doesn't exist in Hermes v0.11.0 and is stale). `name="mordred-local"` / `api_mode="chat_completions"` / `base_url` are dynamically read from `policy.json`. Streaming is owned by Hermes core (`agent/error_classifier.py`)
- ~~`transport.py`~~ → **removed from v1** (Codex H1). It will be recreated once a streaming hook lands upstream in v2
- `health.py` — endpoint health probe (`/models` GET, default timeout 2.0s); raises `MordredLocalUnreachable` on failure
- `enforce.py` (PR2) — `on_session_start` + `pre_api_request` handler, **v1 = refuse-only** (Codex B2):
  - lenient/off → no-op (audit silent — per-session allow audit will be reconsidered in v2)
  - strict + active provider matches `cloud_provider_allowlist` + `allow_cloud_llm: true` → passthrough, audit `policy.strict.cloud_allowlisted`
  - strict + no match, or `allow_cloud_llm: false` → raises `MordredSessionRefused(BaseException)`, **emits `policy.strict.session_refused` + classification `policy.strict.cloud_not_allowlisted` simultaneously as 2 entries** (Codex N1)
  - strict + no provider info (degraded) → refuse + audit `mordred.degraded.no_resolved_provider` (one-shot) + `policy.strict.unconditional_override`
  - strict + `mordred-local` active → allow if the health probe succeeds, else `MordredSessionRefused` (chains `MordredLocalUnreachable` as `__cause__`; Codex round-2 P2: wrapped as a `BaseException`-derived refusal because a bare `Exception` would be swallowed by Hermes's `invoke_hook`)
  - **runtime override support** (Codex round-3 P1): since `on_session_start` only resolves from disk and misses CLI `--provider` / `HERMES_INFERENCE_PROVIDER` / oneshot, an additional `check_runtime_provider(provider=kwargs.provider)` call runs in `pre_api_request` (consuming the resolved runtime provider from `run_agent.py:11320-11338`)
- ~~`override.py`~~ → **removed** (Codex B2 / HOOK_PAYLOADS §5: provider override via `pre_llm_call` is not possible; will be recreated when re-evaluated in the v2 vendored fork)
- `harness_detect.py` — `on_session_start` handler (called earlier than enforce.py):
  - Reads the configured harness primary from `~/.hermes/config.yaml plugins.mordred_llm_guard.harness_primary`
  - prefix-regex allowlist: `^codex(-\d+(\.\d+)*)?$` / `^claude-cli(-\d+(\.\d+)*)?$` / `^cursor(-\d+(\.\d+)*)?$` / `^acp-[a-z][a-z0-9-]*$`
  - strict → `MordredHarnessRefused(BaseException)` raise + audit `mordred.degraded.disable_unprotected` (decision=`block`)
  - lenient → audit (decision=`warn`) + log warning + continue (Codex M2)
  - off → no-op
- `_exceptions.py` — `MordredLocalUnreachable(Exception)` + `MordredHarnessRefused(BaseException)` + `MordredSessionRefused(BaseException)`. The latter two derive directly from `BaseException` so they escape Hermes `invoke_hook`'s `except Exception:` wrapper without being misdetected as CLI exits. `privacy_check` now follows the same regime with `MordredIntegrityRefused(BaseException)`.
- `_typing.py` — `PluginContext` Protocol narrow surface (`register_hook` only)
- `tests/test_enforce.py`, `tests/test_enforce_audit.py`, `tests/test_harness_detect.py`, `tests/test_health.py`, `tests/test_local_adapter.py`, `tests/test_exceptions.py`, `tests/test_llm_guard_register.py`, `tests/test_llm_guard_typing.py`, `tests/integration/test_llm_local.py` (`MORDRED_LIVE_LLM_TEST=1` gated)

**Provider behavior (`mordred-local`)**:

- Provider id: `mordred-local`, declarative `ProviderProfile` (OpenAI chat-completions wire format)
- Pre-request: `health.probe(endpoint=...)` does a `{endpoint}/models` GET, failure → `MordredLocalUnreachable`
- Cloud allow-list determination is `enforce.py`'s responsibility (the provider itself doesn't know about cloud)

**Mid-stream local-endpoint death (M2, v2 deferred)**:

Codex H1 confirmed that "Hermes core (`agent/error_classifier.py`) owns the streaming pipeline, and the plugin side cannot reliably capture `httpx.RemoteProtocolError` / `httpx.ReadError`." As a result:

- The former `transport.py` placeholder was removed; stream interrupt detection is not implemented on the plugin side
- The `MordredLocalStreamInterrupted` exception class is **intentionally left undefined** (see `_exceptions.py` docstring)
- The `policy.strict.local_stream_interrupted` audit reason is already frozen into the 12-code enum (forward-compat reservation, POLICY.md row 12); there's no emit site in v1
- Once a streaming hook lands upstream in v2, revive the class + implement the emit site + reintroduce `tests/test_enforce.py::test_mid_stream_disconnect` (currently deleted)

### 2.2 Wizard additions (landed)

- Added to `hermes mordred configure` (collected in Phase 1.3, wired into `PolicySnapshot` in Phase 2 PR1; the old separate `phase2_fields` dict has been removed):
  - local LLM endpoint URL (default `http://localhost:1234/v1`)
  - local model id
  - cloud attempt action (`always-block` / `prompt-once`)
  - harness primary declaration (PR2, default `none`, choices: `none` / `codex` / `claude-cli` / `cursor` / `acp-claude` / `acp-cline`)
- `PolicyWriter.write` upserts `~/.hermes/mordred/policy.json` + `~/.hermes/config.yaml plugins.mordred_privacy_check` (Phase 1 fields) + `plugins.mordred_llm_guard.harness_primary` (PR2)

### 2.3 Tests (landed)

- Unit: `tests/test_enforce.py` covers every case of the decision matrix (25 tests); `tests/test_enforce_audit.py` covers simultaneous reason-code emit + frozen-enum membership (7 tests)
- Harness: `tests/test_harness_detect.py` covers the prefix-regex matrix (24 tests)
- Adapter: `tests/test_local_adapter.py` covers B1 explicit-register + no module-import side effect + policy.json fallback (8 tests)
- Health: `tests/test_health.py` covers the success / timeout / connect-refused / 500 matrix (9 tests)
- Propagation: `tests/test_exceptions.py` covers the `BaseException` propagation contract (7 tests)
- Registration: `tests/test_llm_guard_register.py` covers provider registration + hook callback registration order (7 tests)
- Typing: `tests/test_llm_guard_typing.py` covers the `PluginContext` Protocol narrow surface (4 tests)
- Live: `tests/integration/test_llm_local.py` (`MORDRED_LIVE_LLM_TEST=1` gated): real LM Studio roundtrip + failure mode (run hermetically on port 1)

**Phase 2 acceptance** (all PASS in Phase 2 PR2, 2026-05-13):

- strict + `mordred-local` active → passthrough on health probe success, audit `policy.strict.cloud_allowlisted` (`test_enforce.py::TestStrictLocal`)
- strict + cloud upstream in `cloud_provider_allowlist` + `allow_cloud_llm: true` → no refuse, audit `policy.strict.cloud_allowlisted` (`test_enforce.py::TestStrictCloudAllowlisted`)
- strict + no provider info (degraded) → refuse + audit `mordred.degraded.no_resolved_provider` + `policy.strict.unconditional_override` (`test_enforce.py::TestStrictDegraded`). ~~`mordred-local` auto routes~~ planned to be revived in the v2 vendored fork
- strict + no local endpoint reachable → `MordredSessionRefused` (chains `MordredLocalUnreachable` as `__cause__`, `tests/integration/test_llm_local.py::TestFailureMode`)
- Codex / Claude-CLI primary + strict → startup refuse via `MordredHarnessRefused` (`test_harness_detect.py` + `test_llm_guard_register.py` verify hook registration order)
- Audit log records every refusal / passthrough decision (`test_enforce_audit.py::TestFrozenEnumMembership`, 5 reasons membership invariant)

---

## Phase 3 — Network Paths (`mordred_network`)

Process-scoped selection across Tor / VPN / Clearnet. The selected route is
activated before provider construction and remains stable until process exit.
Completes Story 3.

**Hermes feature dependency**:

- Launches Tor/VPN clients via the `subprocess` module (`tor`/`arti` daemon, Mullvad WireGuard CLI)
- **Phase 0.8 verify complete** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §8 — fixed by PR #9 Codex review): Hermes has **two different regimes** for passing env to subprocesses:
  - **Regime A (blocklist-style, default allow)**: `tools/environments/local.py:_make_run_env`, `tools/browser_tool.py`, etc. `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` are outside the blocklist, so they **propagate to subsequent spawns** via `os.environ.update({...})`
  - **Regime B (allowlist-style, default strip)**: `tools/code_execution_tool.py` only passes through `_SAFE_ENV_PREFIXES`. Proxy variables are **silently dropped** — Mordred **must explicitly register with the `tools.env_passthrough` registry** (otherwise the execute_code child communicates outside the Tor/VPN tunnel)
  - Already-running long-lived subprocesses retain the env frozen at spawn time (in either regime). The `live_subprocess_count` field design for the audit `network.use` (TODO §3.1 M3) is valid
- v1 is **a single global state** (Phase 0.8 verify confirmed the absence of `origin_skill`, [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4). Per-skill auto-path-switching will be considered once the `origin_skill` payload extension lands in v2-H2

### 3.1 Plugin: `mordred_network`

**Files**

- `src/mordred_hermes/network/plugin.yaml` — config under `plugins.mordred_network`, `privacy_lock: true`
- `src/mordred_hermes/network/__init__.py` — in `register(ctx)`, builds the process-global runtime, activates and freezes the configured route before provider clients are constructed, then registers `on_session_start`/`on_session_end`/`pre_api_request`/`pre_tool_call` and one process-exit finalizer
- `src/mordred_hermes/network/paths/tor.py` — Tor daemon manager (v1 default = official `tor` binary; `arti` will be re-evaluated in v2):
  - **torrc generation**: generates `~/.hermes/mordred/tor-data/torrc` from a template (`SOCKSPort 127.0.0.1:<port>`, `ControlPort 127.0.0.1:<port>`, `CookieAuthentication 1`, `DataDirectory ~/.hermes/mordred/tor-data/`)
  - **port conflict resolution**: equivalent to `lsof -i :9050` (probed via `socket.socket(AF_INET).bind(('127.0.0.1', port))`) → 9150 → user-specified `tor_socks_port` → abort
  - **ControlPort client**: issues `getinfo circuit-status` via the `stem` library or raw TCP cookie auth
  - **bootstrap progress**: tails `tor`'s stdout and detects `Bootstrapped 100%` within 30s → `MordredPathBringupFailed` on failure
  - **process management**: launched via `subprocess.Popen`; the process-exit finalizer calls `process.terminate()` (`kill()` after a 5s grace period). Per-turn/session-end hooks do not own the process-global route
- `src/mordred_hermes/network/paths/vpn.py` — Mullvad official client wrapper (`subprocess`):
  - **CLI detection**: `shutil.which("mullvad")` → on failure, try the known macOS path `/Applications/Mullvad VPN.app/Contents/Resources/mullvad` → on failure, `MordredPathBringupFailed("mullvad client not installed")`
  - **bring-up sequence**: (strict only) `mullvad lockdown-mode set on` → `mullvad relay set location <country|auto>` → `mullvad connect` → confirm `Connected` is reached by polling `mullvad status` every 10s (in Mullvad CLI 2026.2, the `always-require-vpn` subcommand was removed and folded into `lockdown-mode`)
  - **liveness probe**: checks the age of the latest handshake via `wg show`, OK if < 180s (assuming the Mullvad client rekeys every 25-120s in the background)
  - **tear-down**: `mullvad disconnect`. Lockdown is kept in place while strict is active
- `src/mordred_hermes/network/paths/clearnet.py` — no-op
- `src/mordred_hermes/network/proxy_env.py` — emits `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` for active path (see M8 §DNS / IPv6 / non-HTTP transport coverage for the NO_PROXY default + URL scheme)
- `src/mordred_hermes/network/provider_transport_flagger.py` — in `on_session_start`, enumerates Hermes provider adapters and warns for known providers that ignore proxy env vars
  - **v1 baseline allowlist** (Python dict, kept in sync with SPEC §Plugin: `mordred_network` v1 baseline allowlist):
    ```python
    KNOWN_PROVIDERS = {
        "anthropic": {"transport": "httpx", "respects_proxy": True, "respects_socks5h": True},
        "openai": {"transport": "httpx", "respects_proxy": True, "respects_socks5h": True},
        "gemini": {"transport": "httpx", "respects_proxy": True, "respects_socks5h": True},
        "mordred-local": {"transport": "httpx", "respects_proxy": True, "respects_socks5h": True, "localhost_only": True},
        "bedrock": {"transport": "boto3", "respects_proxy": True, "respects_socks5h": False, "dns_quirk": True},
        "vertex": {"transport": "google-cloud", "respects_proxy": "partial", "respects_socks5h": False},
    }
    ```
  - **strict mode behavior**: if active path = `tor` and a provider is incompatible, unverified, unknown, or cannot be resolved from config/auth, startup/request egress is refused. A configured Tor/VPN route that is mismatched or not ready, and an internal transport-gate error, also fail closed. Provider refusal preserves the process-global route so concurrent/later gateway activity cannot fall through to clearnet. Lenient warns and continues. If active path = `clearnet` (with `policy=strict + cloud_provider_allowlist`) and a `respects_proxy=False` provider is enabled, warning only
  - **user override**: policy.json may add internal providers, for example `provider_overrides: {"my-internal": {"transport": "httpx", "respects_proxy": true, "respects_socks5h": true, "respects_ipv6_proxy": true, "unverified_baseline": false, "transport_class": "http"}}`. Entries are additive only; the bundled baseline is immutable. Missing safety fields default conservatively. Malformed entries fail closed under strict + Tor and become warnings under lenient/off
- `src/mordred_hermes/network/api.py` — internal Python API:
  - `mordred_network.api.use(path: str)` — activate/reuse a path before freeze; a conflicting frozen route raises restart-required
  - `mordred_network.api.status()` — current state
  - `mordred_network.api.health()` — probe
  - `mordred_network.api.blackout_assert()` — verify network blackout (consumed by keyvault Phase 4)
- `src/mordred_hermes/network/runtime.py` — lazy-loaded subprocess management
- `tests/test_paths.py`, `tests/test_proxy_env.py`, `tests/test_provider_transport_flagger.py`
- `tests/integration/test_tor.py` — docker-compose harness for Tor (`docker compose up tor`)

**Bootstrap order (strict mode)**

- `mordred_network.register()` activates and freezes the configured route before it returns, so provider clients snapshot the already-established proxy environment. Any configuration, activation, or freeze error fails closed with `MordredPathBringupFailed(BaseException)` before client construction
- `on_session_start` only validates/reuses that process route and runs the persisted-provider transport gate. `wait_until_ready()` remains available for diagnostics/legacy callers, but hook registration order and polling are not the initial transport security boundary
- `on_session_end` retains the route; a single process-exit callback performs final teardown

**Concurrency model**

- Active path is process-wide single state; independent per-session/per-skill paths are v2
- `mordred_network.api.use(path)` is idempotent for the active ready route. Registration freezes the route, so a different path or SOCKS isolation token requires a Hermes restart rather than applying last-write-wins
- **Path mismatch for parallel tool_calls (v1)**: per-tool-call, per-skill determination is not possible in v1 (Phase 0.8 verify confirmed the absence of `origin_skill`, [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4). v1 enforcement paths:
  - **install-time**: the `hermes mordred install` wrapper compares SKILL.md frontmatter's `network_requirements` against the active path; a strict mismatch blocks the install
  - **runtime**: single global state only. Even if a clearnet-only skill runs while the active path is tor, it isn't blocked (per-skill detection is impossible)
  - **No automatic path switching is performed** (to avoid the M3 transitive proxy-env failure mode, and because per-skill determination is impossible)
  - Per-tool-call mismatch detection is planned to be revived in v2-H2
- **Parallel requests for the same path**: run in parallel as normal (new subprocesses inherit the parent env, so they transparently flow through the active path)
- **Parallel requests for different paths**: a process cannot safely serve them with shared provider clients. A conflicting route is refused with restart-required semantics. Independent transports and per-session/per-skill SOCKS5 isolation will be considered for v2 (`v2-N1`)

**Path injection into skills**

- Primary v1 mechanism: `register()` sets proxy env vars on `os.environ` before provider construction, so provider clients and subsequently spawned child processes inherit the same route
- `mordred_network.api.use(path)` reuses the active ready route as a no-op. To select a different route, persist it and restart Hermes so all captured transports are rebuilt together
- Per-call env injection from `pre_tool_call` is v2 unless Hermes exposes a subprocess-env hook
- Provider plugins that respect HTTP_PROXY (most do) automatically go through the active path
- For provider plugins with hard-coded transport, the flagger warns at startup
- **NO_PROXY default**: regardless of active path, `proxy_env.py` always includes `localhost,127.0.0.1,::1` in the `NO_PROXY` base (because if the `mordred-local` localhost LLM endpoint went through the proxy, Phase 2's health-check would fail). User-supplied entries are appended from policy.json's `no_proxy: [...]`, with deduplication. Beyond IP literals, domain suffixes like `.local` are also accepted append-only
- **`HTTPS_PROXY` URL scheme**:
  - clearnet path: unset the value (removed)
  - vpn path: unset the value (proxy_env isn't needed since the tunnel handles all IP traffic; however, for non-respecting providers per `provider_transport_flagger`, this relies on the VPN tunnel itself)
  - tor path: `socks5h://127.0.0.1:9050` (with `socks5h`, **DNS is resolved server-side**, preventing leaks). For libraries that don't support SOCKS5h, the flagger warns

**DNS / IPv6 / non-HTTP transport coverage (M8)**

Tunneling all traffic with proxy_env alone cannot be achieved in v1. Document the following alongside SPEC §Threat Model M8, and reflect it in the acceptance gate as well:

- **DNS leak (most critical on the Tor path)**: a non-SOCKS5h HTTP_PROXY URL performs name resolution via the system resolver first → even when using Tor, the query reaches the ISP. v1 enforcement: the Tor path only supports the `socks5h://` URL scheme + major HTTP clients (urllib3 / httpx / requests[socks]). Clients without SOCKS5h support (old `aiohttp` versions, providers that directly manipulate sockets) get a startup warning via a static allowlist, and in strict mode, abort when active
- **IPv6 leak**: many implementations don't respect the HTTPS_PROXY env var. Keep the v1 `disable_ipv6: true` (strict), `false` (lenient/off) policy field, but treat it only as Tor's `ClientUseIPv6 0` preference — it is not host-level enforcement. `provider_transport_flagger` must still abort strict + Tor for providers without verified IPv6 proxy support (lenient warns). Full protection is v2 (`v2-N2`: bundled IPv6 firewall rule injection).
- **Non-HTTP transport (raw TCP/UDP/QUIC/gRPC native)**: enumerated in the v1 baseline via `provider_transport_flagger`'s static allowlist (existing Hermes providers were tested on real hardware in Phase 0.8 verify). In strict mode, session abort when a known-incompatible provider is active

**Path failure & liveness (M9)**

- **Bring-up failure (during path startup)**:
  - Tor: bootstrap timeout 30s (the time until the initial circuit is established; SOCKS5 listen opens within 5s)
  - VPN: WireGuard handshake timeout 10s (until `latest handshake` updates in `wg show`)
  - On failure: strict → raises `MordredPathBringupFailed` + session abort, lenient → user-visible warning + clearnet fallback + audit `network.bringup_failed`, off → silent fallback
- **Liveness probe (mid-session)**:
  - An internal worker thread runs `mordred_network.api.health()` every 30s
  - Tor probe: ControlPort reachable + cookie authentication succeeds +
    `GETINFO circuit-status` is structurally valid. Empty or any reply with a
    non-terminal circuit is healthy; known `FAILED`/`CLOSED`-only replies are
    unhealthy. Unknown syntactically valid uppercase statuses are assumed
    non-terminal for forward compatibility. Auth/control/protocol failures
    remain unhealthy
  - VPN probe: WireGuard `latest handshake` is < 180s ago AND interface state UP
  - Judged path-dropped after 2 consecutive failures (absorbing transient Tor circuit rebuilds)
- **On mid-session drop detection**:
  - strict: raises `MordredPathDropped` on the next `pre_tool_call` (blocks tool execution)
  - lenient: warn + continue (rather than a clearnet fallback, the path-dropped state is retained). To choose clearnet, persist it with `hermes mordred network use clearnet` and restart Hermes so provider clients are rebuilt on that route
  - Always audit `network.path_dropped` (decision=`block` or `warn`, fields `path` / `consecutive_failures` / `last_health_at`)
- **Failure semantics for `mordred_network.api.use(path)`**:
  - Raises `MordredNetworkError` (silent fallback is forbidden)
  - subclasses: `BringupFailed` (path startup failure), `AlreadySwitching` (concurrent switch attempt), `UnknownPath` (unknown path name), `PathSwitchRequiresRestart` (the frozen process route/token conflicts with the request)
  - audit `network.use_failed` emit (decision=`raise`, fields `requested_path` / `error_type` / `prev_path`)

**Transitive proxy-env failure mode (M3)**

Injecting proxy env vars into `os.environ` has a **transitive** hole because
provider clients and child processes snapshot their transport configuration.
v1 closes that live-switch boundary rather than attempting an incomplete
update:

- `register()` activates the configured route before provider construction and then freezes it for the process lifetime
- `api.use()` for the same ready route is a no-op; a different route or isolation token raises `PathSwitchRequiresRestart` without tearing down the current route
- `hermes mordred network use` persists the desired route, but the operator restarts Hermes to rebuild provider clients and child processes together
- Initial transitions retain the `network.use` audit (`prev_path` / `new_path` / `live_subprocess_count`). `live_subprocess_count > 0` remains evidence that an unfrozen/test-only environment update would not take effect transitively
- Independent live transports for separate sessions or skills remain v2 work; a subprocess-env hook alone would not repair provider clients that already captured their proxy transport

### 3.2 Wizard additions

- `hermes mordred network init` asks: default network path, Tor binary path, Mullvad account number (on-demand, separate from `configure`, re-runnable)
  - Sensitive information is written to `~/.hermes/.env` as `MORDRED_MULLVAD_ACCOUNT=...`; `~/.hermes/mordred/credentials/network.json` records the env var reference (PATHS.md §credentials)
  - An empty input preserves the existing secret (a re-run won't erase it); the prompt's default is seeded from the current on-disk value
- `hermes mordred network use <tor|vpn|clearnet>` — persist the next process route; same-route use is a live no-op, while a conflicting frozen route requires restart
- `hermes mordred network status` — print active

### 3.3 Tests

- Unit: path manager state machine
- Integration: docker-compose with Tor container; SOCKS5 reachable assert
- Live (gated by `MORDRED_LIVE_TOR_TEST=1`): Mullvad real connection
- Privacy-check coordination: install-time policy checks a skill declaring `network_requirements: tor`; the operator selects Tor for the next process (confirmed via `policy explain`). There is no tool-time auto-switch

**Phase 3 acceptance**:

- Skill with `network_requirements: tor` runs through Tor when the process was configured with `network use tor` before startup; `origin_skill`-driven tool-time routing remains deferred
- `hermes mordred network use vpn` persists VPN, a conflicting live route is refused, and the next Hermes process activates VPN before provider construction
- `mordred_network.api.status()` returns truthful state
- All bundled provider plugins continue to function under each path

---

## Phase 4 — Key Management (`mordred_keyvault`)

Highest engineering risk. AES DEK wrapping/unwrapping is backed by Secure
Enclave or a login-Keychain software key on macOS and by the packaged TPM 2.0
helper on Linux. The Linux backend is machine-bound and fails closed when the
helper is absent; it has no software fallback. Transparent startup environment
injection and the direct OS blackout fallback remain macOS-only integration
features.

### 4.1 Plugin: `mordred_keyvault`

**Files**

- `src/mordred_hermes/keyvault/plugin.yaml` — `privacy_lock: true`; the
  cross-platform crypto stack is in the `keyvault` extra, macOS bridges in
  `macos`, and Linux builds the packaged TPM helper via `keyvault enable-tpm`
- `src/mordred_hermes/keyvault/__init__.py` — registers the CLI in `register(ctx)`, exposes the internal API
- `src/mordred_hermes/keyvault/native.py` — `Security.framework` wrapper (via pyobjc-framework-Security), lazy import (the `_lazy_import` pattern prevents an ImportError on import for non-macOS)
- `src/mordred_hermes/keyvault/api.py` — public Python API:
  - `generate(...)` — wrapping-key initialization (including the verification-digest flow)
  - `encrypt(key_id, plaintext, purpose)` — AES-GCM encrypt
  - `decrypt(key_id, ciphertext)` — AES-GCM decrypt (after unwrap authorization)
  - `export_backup(passphrase)` — Argon2id (m=46 MiB, t=1, p=1) wrapped backup blob
  - `import_backup(blob, passphrase)` — recovery, rejects on digest mismatch
  - `verify_digest(seed_hash, pass_hash_xor_pow)` — verification-digest match
- `src/mordred_hermes/keyvault/crypto.py` — AES-GCM encrypt/decrypt helpers (the cryptography library)
- `src/mordred_hermes/keyvault/wrap.py` — Secure Enclave-backed wrapping-key integration
- `src/mordred_hermes/keyvault/backup.py` — encrypted secret backup logic; Argon2id (the `argon2-cffi` library) `m=46 MiB, t=1, p=1`, embeds a 16-byte salt + verification digest in the blob
- `src/mordred_hermes/keyvault/recovery.py` — cross-machine recovery; `import_backup` recomputes the digest + rejects on mismatch
- `src/mordred_hermes/keyvault/digest.py` — computes `digest = hash(hash(SeedPhrase), hash(Passphrase) ⊕ top4(PoW))` (BLAKE3-based)
- `src/mordred_hermes/keyvault/seed_display.py` — Seed display flow: blackout assert → 60-sec timer → display → auto-clear
- `src/mordred_hermes/keyvault/network_fallback.py` — a wrapper that directly calls the OS API (`SCNetworkReachability` / `nw_path_monitor` via pyobjc) when `mordred_network.api.blackout_assert` is absent
- `src/mordred_hermes/keyvault/log_encryption.py` — an AES-GCM encryption layer that slots into the Phase 1 audit `Writer` interface. The audit-log DEK is keyvault-wrapped and held in memory only
- Tests: native module mocked for unit; integration runs only on macOS arm64

**Internal Python API surface**

- `mordred_keyvault.api.generate()` → `(key_id, digest, display_token)`. `display_token` is an opaque handle the UI uses to drive Seed-display. Internally, `generate` performs a blackout assert via network-fallback and completes only when offline verification succeeds
- Other plugins import via `from mordred_hermes.keyvault import api`

**Skill opt-in**

- Declared via `metadata.mordred.requires_keyvault: true`
- Enforced at install time by `mordred_privacy_check` (in Phase 1, the metadata is read but it's a no-op; wired in Phase 4)

**Audit-log encryption coupling (slot into Phase 1 audit logger)**

- At Phase 4 launch, factory-swap `keyvault/log_encryption.py`'s `EncryptedWriter` into the `Writer` interface frozen in Phase 1
- Pre-Phase-4 plaintext logs are not retroactively encrypted. The wizard provides `hermes mordred audit purge --before YYYY-MM-DD --yes`
- Decrypt CLI: `hermes mordred audit decrypt --date YYYY-MM-DD` (requires Secure Enclave authorization)
- Interface contract: `class Writer(Protocol): def append(self, entry: dict) -> None: ...` is frozen in Phase 1; `EncryptedWriter` is implemented in Phase 4, and the factory chooses which to use
- Session log encryption is out of scope for v1 (would require Hermes to expose a generic session-log writer seam)

**Network-absent fallback (when `mordred_network` is absent)**

- In `on_session_start`, if `mordred_network.api.blackout_assert` can't be imported, activate `network_fallback.py`
- The fallback implementation only makes direct OS API calls. VPN/Tor path state cannot be determined (only network up/down)
- Security caveat: in a standalone-plugin configuration, keyvault cannot self-detect "transmitting over clearnet." Seed-display's network-blackout check relies only on the OS API. `keyvault init` displays a startup banner recommending pairing with `mordred_network`

### 4.2 Wizard additions

- `hermes mordred keyvault init` — Seed Phrase + Passphrase + PoW generation flow (network-blackout assert → Seed display → offline/manual digest match → keyvault initialize)
- `hermes mordred keyvault list` — list key IDs
- `hermes mordred keyvault verify-digest` — re-display digest for cross-checking
- `hermes mordred keyvault recover --blob <path>` — recovery on different machine
- `hermes mordred audit decrypt --date YYYY-MM-DD` — decrypts via Secure Enclave authorization

### 4.3 Tests

- Unit: backup/recovery roundtrip with mocked native binding
- Unit: fixed-vector tests for `digest.py` (`top4(PoW)` extraction, SPEC-example match)
- Unit: AES-GCM encrypt/decrypt roundtrip and unwrap failure handling with mocked native binding
- Integration (macOS arm64 only, gated by `MORDRED_KEYVAULT_LIVE=1`): real Secure Enclave wrapping-key create + DEK wrap/unwrap + AES-GCM roundtrip
- Integration: with `mordred_network` disabled, run `keyvault init` and confirm `network_fallback` makes the blackout decision via OS APIs
- Integration: PC↔phone pairing flow — v2-F7 deferred unless included in v1 scope late
- Cross-machine recovery: export → deliberate off-by-one Passphrase → import_backup rejects → correct entry succeeds → decrypt

**Phase 4 acceptance**:

- Skill declaring `requires_keyvault: true` blocks install if keyvault not initialized
- Keyvault-protected secret encrypts/decrypts through AES-GCM, DEK wrapped/unwrapped through Secure Enclave authorization
- Backup → wipe → restore → decrypt roundtrip works
- Seed display always runs blackout check (RPC or fallback) first; refused on check failure
- `import_backup` does not complete unless recomputed digest equals embedded digest
- In `mordred_network`-absent envs, `keyvault init` still functions via OS API fallback
- After Phase 4 lands, audit log is AES-GCM encrypted (test by failing decryption with `openssl`)

---

## Cross-cutting concerns

### Documentation

- `docs/dev/UPSTREAM.md` — Hermes upstream tracking strategy (Phase 0)
- `docs/dev/POLICY.md` — policy schema reference (landed Phase 1.1 / 2026-05-10; covers the canonical audit log reason enum + `metadata.mordred.*` spec deviation + `plugins.mordred_privacy_check` config schema + the Phase 3 `disable_ipv6` extension)
- Each plugin's `README.md` — own paths, config keys, internal Python API surface
- Changelog: each PR adds a 1-line entry to `### Changes` / `### Fixes` + `Thanks @<author>`

### Testing posture

- pytest, colocated `tests/test_*.py`, integration `tests/integration/test_*.py`
- mock native bindings, network paths, provider HTTP at unit level
- One integration smoke per plugin boundary
- Live tests gated by env vars (`MORDRED_LIVE_LLM_TEST=1`, `MORDRED_KEYVAULT_LIVE=1`, `MORDRED_LIVE_TOR_TEST=1`)
- CI configuration consistent with Hermes's `scripts/run_tests.sh`

### Type/build/lint posture

- Python >= 3.10, strict typing (`mypy --strict src`)
- ruff (lint + format) — an existing Hermes dependency
- Circular import prevention: each plugin only allows `from mordred_hermes.<other_plugin> import api`; internal modules are never imported

### Boundary discipline

- Mordred plugins import only from `hermes_cli.plugins.PluginContext` — no touching other `hermes_cli` modules
- Native module loading via `_lazy_import` pattern (avoids ImportError on non-macOS)
- Hermes core (`agent/`, `gateway/`, `model_tools.py`, etc.) never references any Mordred-owned path / module
- `privacy_lock: true` is a generic boolean field (a Mordred-internal hint) and contains no Mordred-specific id. When introducing the v2 vendored fork extra (`[hard-lock]`), keep the same generic-field design and don't put Mordred-specific ids, defaults, or recovery policy into the vendored module
- Plugin-side `mordred.degraded.*` fallbacks remain in place permanently as defense in depth

### Versioning & SDK compatibility

- All Mordred plugins are bundled into the single pip package `mordred-hermes`, sharing a common version
- `mordred-min-hermes-version` is declared in `pyproject.toml`'s `[project.metadata]`; each plugin verifies the Hermes version in `on_session_start`
- The Mordred-as-distribution version is managed via `docs/VERSION`
- The upstream-check workflow (`.github/workflows/upstream-check.yml`) detects Hermes hook **name** drift (`VALID_HOOKS` membership) and auto-files an issue (a deep diff of the payload field shape is v2 deferred)

### Hook payload realities (Phase 0.8 verify complete — 2026-05-10)

The actual shape of Hermes hook payloads was **source-code verified in Phase 0.8** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md)). The Phase 1 / 2 / 3 implementations assume these confirmed shapes:

- **`pre_tool_call`** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4): `{tool_name, args, task_id, session_id, tool_call_id}`. **`origin_skill` is absent** — per-skill policy is determined by the install-time `hermes mordred install` wrapper
- **`pre_llm_call`** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5): the payload contains only `model`, `provider` is absent, and the return value is context-injection only (no provider override possible). v1 switches to session-scoped enforcement via `on_session_start`
- **`pre_gateway_dispatch`** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §6): `skip`/`rewrite`/`allow` actions are possible. Matches the docstring; no design change needed
- **`pre_approval_request` / `post_approval_response`** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §7): observer-only (return value ignored); Mordred only emits to the audit log

SPEC §"Plugin-Only Architecture"'s "other items that might require core modification" has already been updated to reflect the Phase 0.8 verify outcome (TODO §0.8 acceptance gate L127 closed).

---

## Risks and unresolved decisions

1. **Verifying the Hermes hook payload shape** — confirmed in Phase 0; implementation details for Phase 1.1 / Phase 2.1 depend on the result
2. ~~**Guaranteed hook ordering in the Hermes plugin loader**~~ — **Phase 0.8 verify complete** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §1): registration order, no priority. Phase 3 strict-mode bootstrap adopts an in-plugin polling fallback
3. **Hermes child process spawn API** — confirm the mechanism for proxy env var inheritance (Phase 3)
4. ~~**Timing of HSeam-1 PR acceptance**~~ → **Resolved (2026-05-07 zero-PR commitment)**: since the policy of not submitting a PR to Hermes upstream is now confirmed, the dependency on acceptance timing goes away. Disable protection is fully handled by plugin-side strict-mode startup refusal (SPEC.md §Plugin-disable protection Tier A). Whether the v2 vendored fork extra (`[hard-lock]`) is needed will be decided separately
5. **`pyobjc-framework-Security` API stability** — the Phase 4 native binding could break with a macOS version update. Target macOS-latest in CI for early detection
6. **Testing Story 1.5 OpenClaw migration behavior** — a means to reproduce a real OpenClaw + Mordred-OpenClaw environment (a Docker image is recommended)

## Recommended execution order

1. **Phase 0** (1-2 days) — venv, plugin scaffold, pyproject.toml, CI, Hermes hook payload verify (once the zero-PR commitment is confirmed, the HSeam-1 PR draft work is unnecessary)
2. **Phase 1** (1 week) — privacy_check + wizard, audit log, install wrapper, Story 2 + partial Story 3
3. **Phase 2** (4-5 days) — llm_guard + mordred-local provider, Story 4
4. **Phase 3** (1-2 weeks) — network, Tor/VPN switching, completes Story 3
5. **Phase 4** (2-3 weeks, pairing v2-F7 deferred) — keyvault, Secure Enclave native binding, Story 5

User-visible MVP = Phase 0 + Phase 1 + Phase 2. This is the minimal "Hermes with Privacy" delivery.
