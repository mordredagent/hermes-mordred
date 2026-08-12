# Hermes Repository Structure

> **Purpose**: Map the upstream Hermes (`hermes-agent`) source tree.
>
> **Path note**: The `../../../…` links in this file are relative to the
> **upstream `hermes-agent` checkout** (snapshot commit below), **not this
> repository** — they do not resolve from here.

## Snapshot

- **Commit**: `d4493e2c6e1eeb1b7f779ab572014ff138a1c050`
- **Describe**: `v2026.4.30-631-gd4493e2c6`
- **Generated**: 2026-05-09
- **Method**: Read-only tree survey of the upstream Hermes source.
- **Caveat**: Hermes evolves rapidly. **Verify against `git log` and live source before relying on this map for code changes.**

---

## Top-level tree (depth = 2, denoised)

```text
hermes-agent/
├─ acp_adapter/                # ACP (Agent Client Protocol) server adapter — auth/events/permissions/session/tools
├─ acp_registry/               # ACP registry artifacts (agent.json, icon.svg)
├─ agent/                      # Agent core: prompt build, context engine, memory, retry, providers glue
│  └─ transports/              #   LLM transports: anthropic / bedrock / chat_completions / codex
├─ assets/                     # Static repo assets (banner.png)
├─ cron/                       # Scheduled routine runner (jobs.py, scheduler.py)
├─ datagen-config-examples/    # Sample data-generation configs (browser tasks, web research)
├─ docker/                     # Docker entrypoint + SOUL.md
├─ docs/                       # Internal docs (plans/)
├─ environments/               # Eval/training environments
│  ├─ benchmarks/              #   Benchmark suites
│  ├─ hermes_swe_env/          #   SWE-bench style env
│  ├─ terminal_test_env/       #   Terminal-tool eval env
│  └─ tool_call_parsers/       #   Per-model tool-call parsing
├─ gateway/                    # Multi-platform messaging gateway core
│  ├─ assets/                  #   Gateway-bundled assets
│  ├─ builtin_hooks/           #   Reserved namespace for always-registered hooks (currently empty — `__init__.py` only)
│  └─ platforms/               #   Platform adapters: slack/discord/telegram/whatsapp/signal/email/...
├─ hermes_agent.egg-info/      # (generated — installed-package metadata, not source)
├─ hermes_cli/                 # CLI entry: `hermes ...` — auth, plugins, skills, gateway, voice, kanban, etc.
├─ locales/                    # i18n strings (de/en/es/fr/ja/zh)
├─ nix/                        # Nix flake modules (devShell, packages, NixOS module)
├─ optional-skills/            # Opt-in skill bundles (15 categories: security/mlops/blockchain/...)
├─ packaging/                  # Release packaging
│  └─ homebrew/                #   Homebrew tap formulas
├─ plans/                      # In-tree planning notes
├─ plugins/                    # 13 built-in plugins (kanban, memory, observability, model-providers, ...)
├─ providers/                  # LLM provider implementations (base.py + per-provider)
├─ scripts/                    # Ops scripts (install.sh, release.py, hermes-gateway, whatsapp-bridge/, ...)
├─ skills/                     # Bundled built-in skills (apple/devops/email/github/...)
├─ tests/                      # Repo-level test suite (acp/agent/cli/cron/e2e/gateway/plugins/...)
├─ tinker-atropos/             # Tinker/Atropos integration (RL-related)
├─ tools/                      # Built-in tool implementations (browser/file/shell/web/MCP/...)
├─ tui_gateway/                # TUI-side gateway: server.py, render.py, ws.py
├─ ui-tui/                     # TUI front-end (TypeScript/React, Ink-based)
├─ web/                        # Web UI (Vite + React)
├─ website/                    # Public website (Docusaurus)
│
├─ cli.py                      # CLI dispatch entry (alongside hermes_cli/main.py)
├─ run_agent.py                # Agent loop entrypoint (`AIAgent` class)
├─ mcp_serve.py                # MCP server entrypoint
├─ batch_runner.py             # Batch job runner
├─ rl_cli.py                   # RL training CLI
├─ mini_swe_runner.py          # Lightweight SWE runner
├─ hermes_constants.py         # Cross-module constants (`get_hermes_home`)
├─ hermes_logging.py           # Logging configuration
├─ hermes_state.py             # Shared state types (`SessionDB`, SQLite + FTS5)
├─ hermes_time.py              # Time utilities
├─ utils.py                    # Misc utilities
├─ model_tools.py              # Model tool registry / dispatch (`handle_function_call`)
├─ toolsets.py                 # Toolset definitions (`_HERMES_CORE_TOOLS`)
├─ toolset_distributions.py    # Toolset distribution config
├─ trajectory_compressor.py    # Trajectory compression
│
├─ pyproject.toml / uv.lock    # Python package config / lockfile
├─ flake.nix / flake.lock      # Nix flake / lockfile
├─ Dockerfile / docker-compose.yml / .dockerignore
├─ MANIFEST.in / .envrc / .gitmodules / .gitattributes / .mailmap
├─ AGENTS.md / README.md / README.zh-CN.md / CONTRIBUTING.md / SECURITY.md / LICENSE
└─ RELEASE_v0.*.md             # Historical release notes (out of scope for this map)
```

---

## Per-directory notes

Each entry is sourced from the directory's `README.md` or top `__init__.py` docstring where present; entries marked **(needs verification)** lack an inline source and should be verified before quoting.

### Core agent + protocol surface

- **`acp_adapter/`** — ACP (Agent Client Protocol) server enabling VS Code / Zed / JetBrains integration: `server.py`, `session.py`, `auth.py`, `events.py`, `permissions.py`, `tools.py`, `entry.py`. (needs verification: README absent.)
- **`acp_registry/`** — ACP registry static artifacts: `agent.json`, `icon.svg`. (needs verification: README absent.)
- **`agent/`** — Agent internals: prompt building (`prompt_builder.py`), context engine (`context_engine.py`, `context_compressor.py`, `context_references.py`), memory (`memory_manager.py`, `memory_provider.py`), model metadata (`model_metadata.py`, `models_dev.py`), retry / error classification (`retry_utils.py`, `error_classifier.py`), provider adapters (`anthropic_adapter.py`, `bedrock_adapter.py`, `gemini_*`, `codex_responses_adapter.py`, `lmstudio_reasoning.py`), trajectory (`trajectory.py`), redaction (`redact.py`), display / onboarding (`display.py`, `onboarding.py`).
  - **`agent/transports/`** — Transport-level wire formats: `anthropic.py`, `bedrock.py`, `chat_completions.py`, `codex.py`, plus `base.py` and shared `types.py`.
- **`gateway/`** — Multi-platform messaging gateway: session orchestration (`session.py`, `session_context.py`), hooks dispatch (`hooks.py`), runtime (`run.py`), pairing / restart / mirror (`pairing.py`, `restart.py`, `mirror.py`), platform registry (`platform_registry.py`), delivery / display config / status, sticker cache, WhatsApp identity glue.
  - **`gateway/builtin_hooks/`** — Currently contains only `__init__.py`. Reserved namespace for hooks that should always register on gateway startup; none are shipped.
  - **`gateway/platforms/`** — 27+ platform adapters (`slack.py`, `discord.py`, `telegram.py`, `whatsapp.py`, `signal.py`, `email.py`, `wecom*`, `feishu*`, `yuanbao*`, `dingtalk.py`, `matrix.py`, `mattermost.py`, `bluebubbles.py`, `homeassistant.py`, `webhook.py`, `api_server.py`, `qqbot/`, etc.) + `ADDING_A_PLATFORM.md`.
- **`hermes_cli/`** — CLI surface (`hermes ...`). Notable files:
  - `plugins.py` — `PluginManager`, `VALID_HOOKS` (16 hooks), `register_hook` / `register_provider` / `register_cli_command`, entry-point discovery (`hermes_agent.plugins`).
  - `plugins_cmd.py` — `hermes plugins` subcommand. Note: in v0.11.0 it scans `<repo>/plugins/` and `~/.hermes/plugins/` only and does **not** display entry-point plugins.
  - `skills_hub.py` — Skill install path. v0.11.0 has no skill-install lifecycle hook.
  - `main.py` / `_parser.py` — Entry dispatch.
  - Domain-specific commands: `auth.py`, `voice.py`, `kanban*`, `cron.py`, `gateway.py`, `slack_cli.py`, `webhook.py`, `setup.py`, `doctor.py`, `models.py`, `profiles.py`, `providers.py`, `clipboard.py`, `pty_bridge.py`, etc.

### Plugin & skill ecosystems

- **`plugins/`** — 13 bundled plugins. Loaded **before** entry-point plugins per `hermes_cli/plugins.py:discover_and_load`:
  - `context_engine/`, `disk-cleanup/`, `example-dashboard/`, `google_meet/`, `hermes-achievements/`, `image_gen/`, `kanban/`, `memory/`, `model-providers/`, `observability/`, `platforms/`, `spotify/`, `strike-freedom-cockpit/`.
- **`skills/`** — Bundled skills shipped by default (25 categories: `apple`, `autonomous-ai-agents`, `creative`, `data-science`, `devops`, `diagramming`, `domain`, `email`, `gaming`, `github`, `media`, `red-teaming`, `social-media`, `software-development`, `yuanbao`, ...). Skills declare metadata via `SKILL.md` frontmatter.
- **`optional-skills/`** — Opt-in bundles, not active by default (15 categories: `autonomous-ai-agents`, `blockchain`, `communication`, `creative`, `devops`, `dogfood`, `email`, `health`, `mcp`, `migration`, `mlops`, `productivity`, `research`, `security`, `web-development`).

### LLM / provider layer

- **`providers/`** — Provider implementations on top of `base.py` (with `__init__.py`). Plugins can register additional providers via `register_provider`.
- **`model_tools.py`**, **`toolsets.py`**, **`toolset_distributions.py`** — Model/toolset configuration & dispatch glue (root level). `model_tools.py` exposes `discover_builtin_tools()` and `handle_function_call()`.

### Operations & lifecycle

- **`cron/`** — Routine scheduler: `jobs.py`, `scheduler.py`.
- **`scripts/`** — Ops scripts: install scripts (`install.sh`/`.cmd`/`.ps1`), `release.py`, `hermes-gateway` launcher, `whatsapp-bridge/` (Go bridge), `build_model_catalog.py`, `build_skills_index.py`, profile / test helpers.
- **`tools/`** — Built-in tool implementations: browser providers (`browser_camofox`, `browser_cdp_tool`, `browser_supervisor`), file/shell/MCP/voice/image/discord/feishu/yuanbao tools, plus `registry.py` (auto-discovery), `path_security.py`, `url_safety.py`, `tirith_security.py`, `osv_check.py`. Tool files self-register at import time via `registry.register()`.
  - **`tools/environments/`** — Terminal backends: local, docker, ssh, modal, daytona, singularity, vercel.
- **`environments/`** — Evaluation / RL environments (`hermes_base_env.py`, `agent_loop.py`, `web_research_env.py`, `agentic_opd_env.py`) + benchmarks, SWE, terminal subenvs.
- **`tinker-atropos/`** — Tinker / Atropos RL training integration. (needs verification: README absent at root, contents not yet inventoried in this pass.)

### UI / surfaces

- **`tui_gateway/`** — Python JSON-RPC backend for the TUI: `server.py`, `transport.py`, `event_publisher.py`, `slash_worker.py`, `ws.py`, `render.py`.
- **`ui-tui/`** — TUI front-end (Ink / React on TypeScript + Babel + Vitest). Subdirs: `packages/`, `scripts/`, `src/`. Entry: `src/entry.tsx`, `src/app.tsx`, `src/gatewayClient.ts`.
- **`web/`** — Browser UI (Vite + React). `src/`, `public/`.
- **`website/`** — Public Docusaurus site. `docs/` (`developer-guide`, `getting-started`, `guides`, `integrations`, `reference`, `user-guide`), `i18n/`, `src/`, `static/`.
- **`assets/`** — `banner.png` only.
- **`locales/`** — i18n YAML for 6 languages (de / en / es / fr / ja / zh).

### Build / packaging

- **`docker/`** — `entrypoint.sh`, `SOUL.md`. Top-level `Dockerfile` + `docker-compose.yml` reference these.
- **`packaging/homebrew/`** — Homebrew tap formula(e).
- **`nix/`** — Nix flake modules: `devShell.nix`, `packages.nix`, `nixosModules.nix`, `python.nix`, `tui.nix`, `web.nix`, `overlays.nix`, `lib.nix`, `checks.nix`, `configMergeScript.nix`, `hermes-agent.nix`.
- **`pyproject.toml`** — Python package config; declares the `hermes_agent.plugins` setuptools entry-point group consumed by external plugins.
- **`flake.nix`** / `flake.lock` — Reproducible build via Nix.

### Testing

- **`tests/`** — Repo-level pytest suite. Subdirs mirror the layout: `acp/`, `acp_adapter/`, `agent/`, `cli/`, `cron/`, `e2e/`, `environments/`, `gateway/`, `hermes_cli/`, `hermes_state/`, `honcho_plugin/`, `integration/`, `openviking_plugin/`, `plugins/`, `providers/`, `run_agent/`, `skills/`, `stress/`, `tools/`, `tui_gateway/`, `website/`, `fakes/` + ~40 root-level `test_*.py`.

### Root-level entrypoints & utilities

| File | Role |
|------|------|
| `cli.py` | Top-level CLI shim (paired with `hermes_cli/main.py`) |
| `run_agent.py` | Agent loop entrypoint (`AIAgent` class — core conversation loop) |
| `mcp_serve.py` | MCP server entrypoint |
| `batch_runner.py` | Batch job runner |
| `rl_cli.py` | RL training CLI |
| `mini_swe_runner.py` | Lightweight SWE runner |
| `hermes_constants.py` | Cross-module constants; `get_hermes_home()` returns the profile-aware data dir |
| `hermes_logging.py` | Logging config (`agent.log`, `errors.log`, `gateway.log`) |
| `hermes_state.py` | `SessionDB` — SQLite session store with FTS5 search |
| `hermes_time.py` | Time utilities |
| `utils.py` | Misc utilities |
| `model_tools.py` | Tool orchestration: `discover_builtin_tools()`, `handle_function_call()` |
| `toolsets.py` | Toolset definitions, `_HERMES_CORE_TOOLS` |
| `toolset_distributions.py` | Toolset distribution config |
| `trajectory_compressor.py` | Trajectory compression |

### Top-level docs

- `AGENTS.md` — Development guide for AI coding assistants and contributors (canonical contributor reference).
- `README.md` / `README.zh-CN.md` — Project intro.
- `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`, `MANIFEST.in`.
- `hermes-already-has-routines.md` — Historical note. (needs verification.)
- `RELEASE_v0.{2..12}.0.md` — Historical release notes; intentionally out of scope for this map.

---

## Out of scope for this map

The following paths are intentionally **excluded** from documentation:

- `.git/`, `.venv/`, `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`, `__pycache__/` — caches and VCS internals.
- `hermes_agent.egg-info/` — generated installed-package metadata.
- `RELEASE_v0.*.md` — historical release notes.
- `.plans/`, `plans/` — in-tree planning notes (private).

Forks or repositories that vendor Hermes as a base may add fork-specific top-level directories (downstream packages, vendor docs, etc.). Such additions are **not part of upstream Hermes** and are deliberately omitted from this map.

---

## Cross-references

- [`AGENTS.md`](https://github.com/NousResearch/hermes-agent/blob/d4493e2c6e1eeb1b7f779ab572014ff138a1c050/AGENTS.md) — Contributor development guide (canonical).
- [`../../website/docs/developer-guide/`](https://github.com/NousResearch/hermes-agent/tree/d4493e2c6e1eeb1b7f779ab572014ff138a1c050/website/docs/developer-guide) — Public developer docs.
- [`../../website/docs/reference/`](https://github.com/NousResearch/hermes-agent/tree/d4493e2c6e1eeb1b7f779ab572014ff138a1c050/website/docs/reference) — Public API reference.
- [`../../gateway/platforms/ADDING_A_PLATFORM.md`](https://github.com/NousResearch/hermes-agent/blob/d4493e2c6e1eeb1b7f779ab572014ff138a1c050/gateway/platforms/ADDING_A_PLATFORM.md) — How to add a new platform adapter.
- [`DESIGN.md`](./DESIGN.md) — Hermes architecture / design overview (this directory).

---

## Maintenance

This document is a **point-in-time snapshot**. Update triggers:

1. New top-level directory added or removed at repo root.
2. Significant restructuring inside one of the subsystems above (e.g. `gateway/`, `plugins/`, `agent/`).
3. Upstream Hermes version bump that changes plugin loader or hook surface.

When updating, refresh the **Snapshot** block (commit, describe, date).
