# Mordred — Specification (Hermes-base)

> **Note**: This SPEC is the specification for Mordred, built on `Hermes (NousResearch/hermes-agent)`.
> The previous OpenClaw-based spec remains at `../../mordred/mordred-mvp-docs/SPEC.md` (deprecated).
> See `MIGRATION.md` for the rationale behind the move to Hermes and the terminology mapping.

## Vision

**Provide a privacy-enhancement layer on top of Hermes as a plugin bundle**.

Mordred is built on the principle of fully leveraging Hermes's plugin SDK and existing capabilities (4 plugin source types, 16 lifecycle hooks, and the registration API via `PluginContext`) without modifying core (independent as a plugin development repository). The privacy layer is distributed as **5 plugins + 1 skill-metadata convention**.

Users can install it with just `pip install mordred-hermes`, and configure/operate it via the `hermes mordred ...` subcommands.

Privacy concerns addressed:

1. **network-path observability** (Phase 3, macOS / Linux / WSL2)
2. **cloud LLM dependency** (Phase 2, macOS / Linux / WSL2)
3. **local secret custody at rest** (Phase 4, **macOS Apple Silicon only in v1**. Linux/WSL2 users run v1 with only the Phase 1-3 protections, relying on OS file permissions (`0600`) for at-rest secret protection. Linux TPM 2.0 / Windows DPAPI / master-password Tier 3 fallback is `v2-OS2`)

The fact that Phase 4 is macOS-only is made explicit at the Vision level too. Read together with the caveats in §Platform Support and §Threat Model (H2).

## Project Identity

### Relationship to Hermes

- **Upstream**: github.com/NousResearch/hermes-agent (MIT License)
- **Current repo**: `Mordred-Hermes/` (the Mordred plugin development repository; not a fork/clone of Hermes upstream)
- **Strategy**: **Option C + Vendored-fork escape hatch** (zero-PR commitment, finalized in MIGRATION.md §10 row 1 / §5 on 2026-05-07) — Hermes core is left unmodified, and 5 plugins are distributed via `pip install mordred-hermes`. **No PRs are submitted to Hermes upstream**
  - `Mordred-Hermes/` requires no upstream rebase (a pure plugin development repository + vendored modules when needed)
  - The 5 plugins are developed under `src/mordred_hermes/<name>/` (the pip distribution layout) and exposed via `[project.entry-points."hermes_agent.plugins"]` in `pyproject.toml`
  - What the old SPEC called a "core seam" is instead handled by **plugin-side wrapper + audit log** (the `mordred.degraded.*` family) for defense-in-depth (Tier A, v1 default)
  - Items that truly need hard enforcement fall under the **vendored fork extra** (Tier B, v2): a patched version of Hermes core modules is redistributed via e.g. `pip install mordred-hermes[hard-lock]`. Out of scope for v1
- **Compatibility goal**: Existing Hermes users can add the privacy layer with just `pip install mordred-hermes && hermes mordred upgrade`. Users migrating from OpenClaw follow 3 steps: `hermes claw migrate` → `pip install mordred-hermes` → `hermes mordred upgrade`

### Platform Support (v1)

| Phase | Platform |
|-------|-------------------|
| Phase 1-3 (network/privacy-check/llm-guard/wizard) | **macOS / Linux / WSL2** (every environment Hermes runs on) |
| Phase 4 (keyvault, Tier 1) | **macOS Apple Silicon only** (Secure Enclave, `Security.framework`) |
| Phase 4 (keyvault, Tier 2/3) | v2: Linux (TPM 2.0) / Windows (DPAPI) deferred to ROADMAP `v2-OS2` |

iOS / Android: Hermes itself has Termux support, but Mordred Phase 4 (keyvault) is out of scope. Only Phase 1-3 can run under Termux (Tor requires additional verification).

### License Note

Hermes is MIT-licensed. Forking, commercial use, and derivative products are permitted. Mordred itself is distributed under MIT as well.

## Threat Model & Accepted Limitations

Mordred defends against:

- **Network observers** (ISP, hostile Wi-Fi, local-network adversaries) — addressed by `mordred_network` (Tor / VPN paths)
- **Cloud LLM operators** seeing prompts and outputs — addressed by `mordred_llm_guard` redirecting to a local-only provider under strict policy
- **Accidental cloud egress** when a user thinks they are local-only — addressed by `mordred_llm_guard` unconditional override under strict policy
- **At-rest secret theft** — addressed by `mordred_keyvault`: local seeds, backups, audit logs, and future signing material are encrypted with AES-GCM data-encryption keys (DEKs) whose wrapping keys are protected by Apple Secure Enclave authorization. The Enclave protects key unwrapping; it does not hold signing keys or run AES itself. Tier 2 (HSM/Keychain/TPM/DPAPI) fallbacks are v2

Mordred does **not** defend against:

- **Malicious skills with truthful metadata** — a skill declaring `network_requirements: clearnet` and being allowed by lenient policy can exfiltrate freely
- **Malicious skills with lying metadata** — Mordred has no skill-metadata signing or integrity verification in v1
- **Local malware / co-resident processes** — `HTTPS_PROXY` env injection is bypassable by direct `connect()` from any process on the same machine. Closing this requires OS-level process isolation (seccomp / sandbox-exec / Endpoint Security), out of reach for the plugin layer (v2)
- **`PATH` hijack of the sekey/tpmkey/winkey helper binary** — `_seckey_helper._find_named_helper()`'s third resolution tier (`shutil.which(name)`, after the `MORDRED_*_HELPER` env override and `~/.local/bin`) trusts whatever the process's `PATH` resolves to. An attacker who can already prepend a writable directory to the user's `PATH` could plant a binary that intercepts the JSON-over-stdio protocol. This requires the same "attacker can already alter the victim's shell environment" precondition as the co-resident-process item above, and the two supported install paths (env var, `~/.local/bin`) are unaffected; kept as v1 accepted risk rather than removing the documented `PATH` fallback (2026-07-07 security review)
- **Skills Hub / agentskills.io registry compromise** — Mordred trusts the registry; no separate signature chain
- **Side-channel timing / traffic analysis** even on Tor
- **Silent plugin-disable** (H3, a v1 mitigation under the zero-PR strategy) — because the policy is to submit no PRs to Hermes upstream (MIGRATION.md §10 row 4), the v1 default is defended via plugin-side **strict-mode startup refusal** (Tier A, see §Plugin-disable protection below). Since the design is to "block at next session start," editing the disable state while a session is running has no effect until the next startup (on the premise that Hermes does not reflect dynamic disablement live, verified in Phase 0.8). Hard enforcement (refusing the disable operation itself) is handled by the v2 `[hard-lock]` extra (vendored fork)
- **Audit-log tampering by attacker with write access as the user** — file mode `0600` is access control, not tamper evidence. Any process running as the user can rewrite history with no detectable trace until Phase 4's HMAC-chain upgrade (v2; PATHS.md §Audit log policy)
- **Air-gap enforcement beyond the standard network stack** — `mordred_network.api.blackout_assert()` detects routable interfaces only; physical air-gap (Bluetooth/USB tethering, hotspot, kernel-level adversaries) remains user responsibility (M4)
- **Screen recording during Seed display** — the 60-second Seed window can be captured by macOS `screencapture`, Loom, Zoom share, OBS, etc. v1 does best-effort screenshot detection only; screen-recording detection is out of scope (M5)

These limitations are explicit; mitigation work is v2+ scope.

### Newly defended via Hermes plugin hooks (no core seam needed)

Because Hermes has a broader hook palette than OpenClaw, many items that the old SPEC said "require a core seam" are **achievable with plugins alone**:

- **Per-tool gating** (e.g. blocking `web_fetch` under strict mode without VPN/Tor active) → implementable via `pre_tool_call`
- **LLM provider override under strict mode** → **not implementable** via ~~`pre_llm_call`~~ (Phase 0.8 verify complete, [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5). The v0.11.0 `pre_llm_call` payload carries only `model`, not `provider`, and its return value is context-injection only. v1 switches to session-scoped enforcement via `on_session_start` instead (see §Story 4 / §Plugin: `mordred_llm_guard`)
- **Gateway dispatch policy** → implementable via `pre_gateway_dispatch` (an additional defense layer not present in the old SPEC)
- **Approval lifecycle observability** → implementable via `pre_approval_request` / `post_approval_response` (strengthened audit for dangerous tool execution)

### Defended via plugin-side strict-mode startup refusal (zero-PR strategy)

- **Silent disablement via `hermes plugins disable mordred_*`** → the v1 default is **plugin-only**: `privacy_lock: true` in `plugin.yaml` functions as an internal Mordred hint, and each Mordred plugin's `on_session_start` aborts strict-mode startup with a `BaseException`-derived exception as soon as it detects a sibling has been disabled (see §Plugin-disable protection below). No PR is submitted to Hermes upstream (MIGRATION.md §10 row 4 zero-PR commitment). If hard enforcement is needed, it is handled in v2 via the `[hard-lock]` extra (vendored fork)

### Plugin-only fallback for missing seams

When the equivalents of the old SPEC's S2 (`originSkill` in tool_call) and S3 (`resolvedProvider` in model_resolve) are not present in Hermes's payloads, the plugin runs in degraded mode (recording `mordred.degraded.*` in the audit log, and falling back to a generic tool-name allowlist and unconditional override). Because of the zero-PR commitment (`MIGRATION.md` §5, 2026-05-07), **no PR is sent to Hermes upstream**. If it's judged that plugin-only cannot achieve this, we re-evaluate whether to escalate to the v2 vendored fork extra (Tier B, `[hard-lock]`) or make the fallback behavior permanent.

**Out-of-band agent harnesses** (Codex, Claude CLI, Cursor, Copilot, ACP adapter): since Hermes has an ACP adapter, some of these can be handled. Under strict mode, if a harness that Mordred cannot enforce is configured as primary, `hermes mordred` startup is refused.

## Plugin-Only Architecture (zero Hermes core modifications, zero-PR strategy)

The old SPEC's "Core Minimal-Change Policy" was redefined as **zero upstream PR** per **MIGRATION.md §10 row 1 / §5, finalized on 2026-05-07**. No modifications to Hermes core are submitted at all in v1:

| Old modification proposal | v1 strategy | v2 escape hatch |
|----------|---------|-------------------|
| ~~HSeam-1: add `privacy_lock: boolean` to `plugin.yaml` in Hermes upstream~~ | **plugin-side only**: `privacy_lock: true` is kept as an internal Mordred hint, and each Mordred plugin's `on_session_start` detects a sibling being disabled and aborts with a `RuntimeError` (§Plugin-disable protection) | Redistribute a vendored fork (a patched version of `hermes_cli/plugins_cmd.py`) via `pip install mordred-hermes[hard-lock]`. Introduced in v2 if hard enforcement becomes necessary |

**Items that would seem to need core modification run on a plugin-side fallback in v1** (no PRs will be sent in the future either; escape to the v2 vendored fork if necessary):

- ~~extension to include `provider_id` / `model_id` in the `pre_llm_call` payload~~ → **Phase 0.8 verify (2026-05-10) complete**: the v0.11.0 `pre_llm_call` payload carries only `model`, not `provider`, and its return value is **context-injection only** (provider override is structurally impossible). `pre_api_request` does carry provider/model/base_url, but it's **observer-only** (its return value is discarded). See [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5 for details and the Phase 2 redesign proposal. v1's `mordred_llm_guard` gives up on per-turn override via `pre_llm_call` and instead switches to a design that refuses-or-rewrites provider configuration (`~/.hermes/config.yaml` or `register_provider`) against strict policy in `on_session_start`
- ~~extension to include `origin_skill` in the `pre_tool_call` payload~~ → **Phase 0.8 verify complete**: in v0.11.0 the payload does not include `origin_skill` (only `tool_name`/`args`/`task_id`/`session_id`/`tool_call_id`; see [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4 for details). Since per-skill policy cannot be implemented via `pre_tool_call`, the install-time guard (the `hermes mordred install` wrapper CLI) that inspects SKILL.md frontmatter is confirmed as the **sole per-skill enforcement path**. The runtime `pre_tool_call` provides only a generic tool-name allowlist
- A pre-install hook at skill install time (`hermes_cli/skills_hub.py`) → create new if needed; until then, substitute with the `hermes mordred install` wrapper
- agent process init / shutdown hook → substituted with the existing `on_session_start` / `on_session_end`

Each plugin probes the shape of the hook payload in `on_session_start`, and if it's missing, records `mordred.degraded.<seam>` in the audit log and runs in degraded mode. The payload shapes confirmed by the Phase 0.8 verify are consolidated in [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) (canonical) — drift watch is `.github/workflows/upstream-check.yml` (weekly, **hook name** drift only; re-verification of payload field shape is a manual bump of this doc triggered by a name-drift signal).

### What Mordred Adds (5 plugins)

All plugins live under `src/mordred_hermes/<name>/` and use only the Hermes plugin SDK (`PluginContext`). Distribution is as a single pip package `mordred-hermes`, supporting loading via the `hermes_agent.plugins` entry point.

1. **`mordred_network`** — dynamic 3-layer path switching across Tor / VPN / Clearnet. Manages the lifecycle of child processes (`tor`/`arti`/Mullvad WireGuard CLI) via Python `subprocess`. Provides proxy environment-variable injection (`HTTPS_PROXY`, `ALL_PROXY`, etc.) into Hermes child processes and an internal Python API (`mordred_network.api.use`, `status`, `blackout_assert`).
2. **`mordred_privacy_check`** — privacy policy enforcement at two checkpoints:
   - **Skill install guard**: while there's no pure hook available, policy is decided by reading `metadata.mordred.network_requirements` from the frontmatter via the `hermes mordred install <skill>` wrapper CLI. Migrates to a hook-based approach once Hermes adds an install hook in the future
   - `pre_tool_call` — generic per-tool policy (e.g. blocking `web_fetch` over Clearnet under strict mode). Per-skill policy too if `origin_skill` is present in the payload; otherwise just a tool-name allowlist
3. **`mordred_llm_guard`** — registers `mordred_llm_guard/local_adapter.py` as a Hermes provider adapter + provider override under strict mode via the `pre_llm_call` hook. Turns a local OpenAI-compatible endpoint (LM Studio / Ollama / vLLM) into a synthetic provider as `mordred-local`
4. **`mordred_keyvault`** — Apple Secure Enclave-backed AES key wrapping (calling `Security.framework` from Python via `pyobjc-framework-Security`). Operated from the `hermes mordred keyvault ...` CLI subtree
5. **`mordred_wizard`** — registers the `hermes mordred ...` subcommand tree via `register_cli_command`. Oversees all CLI for configure / upgrade / install / network / policy / audit / keyvault

### Conventions (not plugins)

- **Mordred skill metadata** — additive privacy fields under the `metadata.mordred.*` namespace (e.g. `metadata.mordred.network_requirements`, `metadata.mordred.requires_keyvault`). Since the namespace is separate from Hermes/agentskills.io's standard frontmatter, there's no conflict. Hermes's own skill loader does not interpret `metadata.mordred.*` (the privacy-check plugin re-parses SKILL.md to make the determination).

### What Mordred Inherits from Hermes (never modified)

- Full CLI surface: `hermes`, `hermes model`, `hermes tools`, `hermes config`, `hermes gateway`, `hermes setup`, `hermes claw migrate`, `hermes update`, `hermes doctor`, `hermes plugins`, `hermes skills`, `hermes logs`, etc.
- The `~/.hermes/config.yaml` configuration format (YAML) and `~/.hermes/.env` (API keys)
- Profile-aware path resolution via `get_hermes_home()`
- Messaging gateway (Telegram, Discord, Slack, WhatsApp, Signal, iMessage, Email, ACP, etc.)
- Skills Hub (built-in) and the agentskills.io standard
- Plugin loader (4 sources: bundled / user / project / pip entry-point)
- Plugin lifecycle hooks (16 types, `hermes_cli/plugins.py:VALID_HOOKS`)
- Provider adapter system (`agent/anthropic_adapter.py`, `bedrock_adapter.py`, etc.)
- Subagent system (`subagent_stop` hook + `delegate_task` tool)
- Cron scheduler (`cron/`)
- Memory system (`plugins/memory/`, honcho/mem0/supermemory)
- Context engine (`plugins/context_engine/`)
- Terminal backends (local/docker/ssh/singularity/modal/daytona/vercel)

### Conditionally inherited (lenient mode only)

- **Agent harnesses** (Codex / Claude CLI / Cursor / ACP clients): inherited under lenient mode. Under strict mode, `mordred_llm_guard` refuses startup if a non-local harness is the configured primary, because harnesses bypass `pre_llm_call` for their own daemon traffic.

### Naming Convention

- Project name: **Mordred**
- CLI command name: **`hermes mordred ...`** (via Hermes's `register_cli_command`)
- Plugin Python module IDs: `mordred_network`, `mordred_privacy_check`, `mordred_keyvault`, `mordred_llm_guard`, `mordred_wizard` (snake_case, following Python module naming conventions)
- pip distribution: **`mordred-hermes`** (single package, all 5 plugins included)
- Configuration topology: per-plugin config under `plugins.mordred_<plugin-id>` in `~/.hermes/config.yaml`. Mordred plugins coordinate shared state (effective policy, active network path) via an internally-imported shared module within Hermes, **not** via a single `mordred:` top-level key
- Skill metadata: `metadata.mordred.*` (same as the old SPEC, maintaining compatibility)
- Mordred-owned filesystem paths: `~/.hermes/mordred/` (audit log, policy snapshot, keyvault state)

## Target User (v1)

**Privacy-focused individual developers**

Persona:

- macOS Apple Silicon or Linux / WSL2 users (Phase 1-3 is multi-platform, Phase 4 is macOS Apple Silicon only)
- Already using Hermes, or a user migrating from OpenClaw (via `hermes claw migrate`)
- Comfortable with the Python ecosystem
- Has experience or willingness to learn local LLM operation (Ollama / LM Studio / vLLM)
- _Nice-to-have, not required_: Web3 / cryptocurrency familiarity (relevant only when v2+ Payment skills land)

Out of scope (v2+): journalists, enterprise IT teams, GUI-only users, Windows native (use WSL2), iOS native.

## User Stories (v1)

### Story 1: Adding the privacy layer for existing Hermes users

As an existing Hermes user, I want to add the privacy layer with `pip install mordred-hermes && hermes mordred upgrade`, reusing my existing `~/.hermes/config.yaml` and skills unchanged.

Behavior:

- Idempotent: re-running is a no-op when state already matches
- If the `plugins.mordred_*` section already exists, show a diff and prompt for overwrite
- Existing skills without `metadata.mordred.*` are treated as `network_requirements: unknown`. Lenient mode (default for upgrade) gives a one-time warning; strict mode blocks, listed in `hermes mordred policy explain`
- Comments and key order in `~/.hermes/config.yaml` are preserved (round-trip writer via `ruamel.yaml`)
- The existing `~/.hermes/mordred/` is preserved unless `--reset` is specified

### Story 1.5: Migration from OpenClaw + Mordred-OpenClaw

Users who were using the old Mordred in an OpenClaw environment follow these 3 steps:

1. `hermes claw migrate` — migrate to Hermes (workspace, config migration)
2. `pip install mordred-hermes` — obtain the Mordred plugin suite
3. `hermes mordred upgrade` — enable the privacy layer

`hermes mordred upgrade` has an assist feature that, when it detects the OpenClaw-era `~/.openclaw/mordred/`, migrates policy / audit log / keyvault state to `~/.hermes/mordred/` (see PLAN.md §1.3 for details).

### Story 2: New user setup

As a new user, I want `hermes mordred configure` to:

1. Optionally spawn `hermes setup` as a child process when `--with-hermes-setup` is passed (run Hermes's standard setup first — opt-in, skipped by default since 2026-07-16)
2. Ask Mordred-specific questions (network policy strict/lenient/off, local LLM endpoint, keyvault initialization opt-in)

This allows Hermes and Mordred to be configured with a single command by passing `--with-hermes-setup`. No Hermes core modifications.

### Story 3: Skill execution and automatic path selection

At skill install time (via the `hermes mordred install <skill>` wrapper), `mordred_privacy_check` parses `metadata.mordred.network_requirements` from the SKILL.md frontmatter and checks it against user policy. Install is blocked on mismatch. At runtime, `mordred_network` injects proxy environment variables into child processes spawned by Hermes. The active path is a single state across the whole gateway (last-write-wins, audited).

> **Note**: Once an install hook is added to Hermes core, the wrapper CLI will be retired in favor of going directly through the hook. Until then, the wrapper is the only policy-enforcement path.

### Story 4: Local LLM enforcement (strict-mode override)

> **Phase 0.8 verify (2026-05-10) complete — redefining Story 4's mechanism**: Hermes v0.11.0's `pre_llm_call` payload carries only `model`, not `provider`, and its return value is **context-injection only** (provider override not possible). `pre_api_request` does carry provider/model/base_url, but it's **observer-only**. Therefore **"redirecting the provider on every turn via `pre_llm_call`" is structurally impossible in v1** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5). v1 switches to **session-scoped enforcement** at `on_session_start`: the combination of strict policy plus a current provider that isn't allowlisted causes startup to be **refused** (v1 default, audit `policy.strict.session_refused`). The alternative of swapping the active provider to the `mordred-local` synthetic provider via `register_provider` + a config patch was confirmed **structurally impossible in v1** by the Codex B2 review (Hermes resolves the active provider before `on_session_start` fires, so a config patch has no effect until the next session) — deferred to the v2 vendored fork (Tier B, `[hard-lock]`). The zero-PR commitment (`MIGRATION.md` §5) is maintained.

When policy is `strict`, `mordred_llm_guard` determines the provider configuration **at session start** and refuses the session if the active provider does not match the `cloud_provider_allowlist` (v1 default). Swapping to the `mordred-local` synthetic provider was confirmed impossible in v1 by the Codex B2 review, so it's deferred to v2. Provider switching after a turn has begun is likewise not done in v1 (a structural constraint). When the provider matches `cloud_provider_allowlist` and `allow_cloud_llm: true`, the session continues (passthrough). See §Audit log policy for detailed audit reason codes (`policy.strict.session_refused`, and the v2-deferred `policy.strict.provider_override_at_session_start`).

When the local endpoint is unreachable, `MordredLocalUnreachable` is raised and the turn is aborted. Lenient mode does not override.

### Story 5: Key management

For skills that declare `metadata.mordred.requires_keyvault: true`, `mordred_keyvault` provides `Security.framework` (via pyobjc) backed AES key wrapping. Keyvault initialization requires physically hand-transcribing the Seed Phrase + Passphrase + PoW, and is not finalized unless the verification-digest flow matches. See SPEC §Plugin: `mordred_keyvault` for details.

### Story 6: Coexistence with Hermes's existing features

Mordred plugins can coexist with Hermes's memory plugin (honcho/mem0), context engine, and observability (langfuse). Each plugin is independent, and Mordred's hooks are called in parallel with other plugins' hooks. **Phase 0.8 verify (2026-05-10) complete**: Hermes v0.11.0's plugin loader guarantees hook ordering by **registration order** (`PluginManager.invoke_hook` at `hermes_cli/plugins.py` L968-1002, no priority system). The plugin load order is bundled → user → project → entry-point, and Mordred (entry-point) is **registered last for every hook**. See [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §1 for details.

## Scope (In) — what we build in v1

### Plugin: `mordred_network`

- **Tor connection (v1 default = official `tor` daemon)**:
  - `arti` (Rust) remains a candidate for the v1 baseline, but the v1 default is the `tor` daemon — because it has the lowest entry barrier for the v1 baseline, with well-established package-manager installs on Linux/macOS
  - **torrc isolation**: Mordred generates **its own torrc** at `~/.hermes/mordred/tor-data/torrc` and does not touch the system-wide `/etc/tor/torrc` or the user's Tor Browser configuration
  - **SOCKS5 listener**: defaults to `127.0.0.1:9050`. If an existing listener (e.g. Tor Browser, the system tor service) is detected via `lsof -i :9050`, v1 shifts through alt port `9150` (colliding with the Tor Browser default) to the port **explicitly specified in `policy.json`'s `tor_socks_port`**. Collision-resolution order: 9050 -> 9150 -> user-specified -> abort with `MordredPathBringupFailed`
  - **ControlPort**: enabled by default at `127.0.0.1:9051` (cookie auth). The cookie file is `~/.hermes/mordred/tor-data/control_auth_cookie`. **Required** for implementing the M9 liveness probe via `getinfo circuit-status`
  - **Bridge / obfs4 / Snowflake**: out of scope for v1 (use in censored environments is v2 `v2-N3`). The startup banner warns that "the v1 default Tor may fail to connect in censorship environments"
  - **Stream isolation (per-skill SOCKS auth)**: not implemented in v1. All skills share the same circuit pool (Tor itself rotates circuits). Circuit separation via per-skill SOCKS5 username/password is v2 `v2-N1`. **Added 2026-06-02**: per-**session** SOCKS5 isolation has landed — `proxy_env.isolation_token` (SOCKS credential) + torrc `IsolateSOCKSAuth` + `on_session_start` wires the Hermes `session_id` into the circuit token. Per-**skill** isolation remains deferred, pending `origin_skill` (v2-H2)
- **Mullvad VPN integration (v1 = official `mullvad` CLI)**:
  - **CLI choice**: v1 uses the Mullvad **official client** (`mullvad` binary; on macOS `/Applications/Mullvad VPN.app/Contents/Resources/mullvad`, on Linux a package such as `apt install mullvad-vpn`). Running `wg-quick` directly ourselves is out of scope for v1 (handling `CAP_NET_ADMIN`/sudo is complex across OSes)
  - **Permissions**: the official client runs in the background as a system service (Linux: systemd unit; macOS: LaunchDaemon), and user commands request the daemon via IPC, so **no additional sudo is required**
  - **Killswitch (lockdown mode)**: under strict mode, `mullvad lockdown-mode set on` is enforced at bring-up (in Mullvad CLI 2026.2 the `always-require-vpn` subcommand was removed and folded into `lockdown-mode`). The OS creates no clearnet route at all when the VPN drops. Under lenient/off, the user's setting is respected (if lockdown is off, only a warning is issued)
  - **DNS leak prevention**: since the Mullvad client forces resolution through the in-tunnel resolver, there is no DNS leak in v1 (mitigated, unlike the M8 IPv6 leak)
  - **Relay selection**: defaults to `auto` (Mullvad picks the geographically nearest relay). User override via e.g. `mullvad_relay_country: "jp"` in policy.json. Multihop / wireguard-over-tor are out of scope for v1
  - **Tear-down**: `mullvad disconnect` is run in `on_session_end`. Under strict mode, `mullvad lockdown-mode set off` is **not** run at the same time (lockdown is kept in place); the user exits it by starting the next session or disabling manually
  - **Platform**: macOS Apple Silicon, Ubuntu/Debian baseline. Windows is out of scope for v1 (the same platform stance as Phase 4 keyvault being macOS-only)
- Clearnet (no-op path)
- **`provider_transport_flagger` v1 baseline allowlist** (verified on real hardware in Phase 0.8):
  - **Known compatible (respects HTTPS_PROXY + SOCKS5h)**: `anthropic` SDK (httpx), `openai` SDK (httpx), `gemini` (`google-genai` SDK, httpx baseline — corrected from the older `google-generativeai`/requests by the Phase 0.8 real-hardware verify; see the live-verify results in [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §Out of scope)
  - **conditional**: the `mordred-local` localhost provider — excluded from proxy routing by the NO_PROXY default and works that way, though SOCKS5h is irrelevant here
  - **Known partial / needs monitoring**: `bedrock` (boto3) — respects HTTPS_PROXY but has a quirk in botocore's DNS-resolution path, with possible DNS leak under strict + tor. `vertex` (google-cloud SDK) — some transports bypass HTTPS_PROXY; under strict mode a warning is shown and the decision is left to the user
  - **Known incompatible (candidates for startup abort under v1 strict mode when active)**: any provider beyond the above that holds a raw socket / its own transport is enumerated by the Phase 0.8 verify
  - The above is **finalized via real-hardware testing in the Phase 0.8 task before v1 ships**. The actual allowlist is distributed as a Python dict (a declarative module) bundled with the plugin, and is user-overridable from policy.json (entries can only be added, not removed)
- Subprocess lifecycle: the Tor/VPN client is started in the `on_session_start` hook (when policy requires it), torn down in `on_session_end`
- Dynamic path-switching via internal Python API (e.g. `mordred_network.api.use(path)`)
- Path injection: sets `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` on spawned child processes. **NO_PROXY default**: `localhost,127.0.0.1,::1` (required to exclude Phase 2's `mordred-local` localhost communication from proxy routing). User-added entries are appended from policy.json's `no_proxy: [...]`
- **Transport coverage (M8, v1)**: proxy_env tunnels **HTTP(S) traffic only**. The following are out of the v1 defense scope, as stated explicitly in SPEC §Threat Model:
  - **DNS resolution**: with a normal `HTTPS_PROXY=http://...`, Python/curl and similar tools **resolve the name via the system resolver before** connecting to the proxy, so even over Tor the DNS query leaks to the ISP. v1's enforced mitigation: over the Tor path, use `HTTPS_PROXY=socks5h://127.0.0.1:9050` (`socks5h` performs server-side resolution). Libraries that don't respect SOCKS5h (some older HTTP clients) get a warning from provider_transport_flagger. Over the VPN path this is mitigated because the tunnel itself handles the DNS query. v2: full defense via bundled DNS-over-Tor / `mordred-dns-resolver`
  - **IPv6 traffic**: many HTTP clients bypass proxy_env for IPv6 endpoints. In v1, if a provider has an IPv6-only endpoint, traffic **does not go through the proxy** (a clearnet leak). Under strict mode, `disable_ipv6: true` in policy.json (default true) restricts the v1 baseline to IPv4 only. This is mitigated over the VPN path since the tunnel handles IPv6, and IPv4 is forced over the Tor path (with limited real-world impact since Tor itself has only limited IPv6 exit support)
  - **Non-HTTP transport (raw TCP, UDP, QUIC, gRPC, WebSocket)**: whether HTTPS_PROXY takes effect depends on the client library. SSE / standard WebSocket (WS-over-HTTP upgrade) usually respect it, but provider plugins holding a raw socket bypass it. Warned via provider_transport_flagger's static allowlist; under strict mode, startup aborts if a known-incompatible provider is active
- **Path failure semantics (M9, v1)**:
  - **Bring-up failure** (Tor bootstrap timeout / VPN handshake fail): strict aborts the session with `MordredPathBringupFailed`; lenient shows a user-visible warning + clearnet fallback (emits audit `network.bringup_failed`); off falls back silently
  - **Liveness probe**: an internal worker thread runs `mordred_network.api.health()` at a 30s interval (Tor: SOCKS5 reachability + circuit-established check; VPN: WireGuard handshake recency + interface up). Judged path-dropped after 2 consecutive failures
  - **Mid-session drop**: strict raises `MordredPathDropped` on the next `pre_tool_call` (blocking tool execution); lenient warns + continues (keeping the path-dropped state; **no automatic clearnet fallback** — the user is expected to switch explicitly via `hermes mordred network use clearnet`). Audit `network.path_dropped` is always emitted
  - **`use(path)` failure**: raises `MordredNetworkError` (subclasses: `BringupFailed`, `AlreadySwitching`, `UnknownPath`). Silent fallback is prohibited
- **Concurrency model (v1)**:
  - Active path is **gateway-wide single state** — `mordred_network.api.use(path)` is last-write-wins, audit-logged on switch
  - **Path mismatch for parallel tool_calls**: runtime per-skill path-mismatch detection is **not done in v1** — since the Phase 0.8 verify confirmed that `origin_skill` is **absent** from the `pre_tool_call` payload ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4), per-skill blocking at runtime is structurally impossible. Per-skill enforcement exists only at install-time (`hermes mordred install <skill>`). Automatic path switching is likewise not done in v1 (to avoid the M3 transitive failure mode). Once the `origin_skill` payload extension lands upstream, runtime detection will be reconsidered in v2-H2
  - **Parallel requests for the same path**: no restriction, executes in parallel as usual
  - **Parallel requests for different paths**: not serialized (handled via block / warn semantics). Per-skill SOCKS5 stream isolation (Tor only) is under consideration for v2
- Provider transport flagging: enumerates Hermes provider adapters at startup and issues a warning for any that ignore proxy env vars (v1 uses a static known-incompatible allowlist; per-provider declaration is v2)
- Strict-mode bootstrap order: registering `mordred_network`'s `on_session_start` before `mordred_privacy_check` ensures privacy-check makes its determination after the active path is settled. **Phase 0.8 verify complete** ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §1): the Hermes plugin loader invokes hook callbacks in **registration order** (no priority system), and since entry-point plugins (all 5 of Mordred's) load after bundled/user/project, the registration order among Mordred plugins is determined by the declaration order of the `hermes_agent.plugins` entry-point group. An in-plugin probe wait (`wait_for(api.status().ready, timeout=5s)`) is adopted as the default bootstrap path — since there's no upstream priority control, the design minimizes dependence on registration order

### Plugin: `mordred_privacy_check`

- **Skill install guard** (via the `hermes mordred install <skill>` wrapper):
  - Reads SKILL.md from the install source path and extracts `metadata.mordred.network_requirements` from the frontmatter
  - Strict + `clearnet` → block
  - Strict + missing metadata → block with `policy.strict.unknown_metadata`
  - Lenient + missing metadata → allow + warning
- `pre_tool_call` — generic per-tool allowlist (configurable). Default strict-mode blocklist: builtin `web_fetch`, `web_search` when active network path is Clearnet. Per-skill determination too if `origin_skill` is present in the payload; otherwise just a tool-name allowlist
- Policy state: loaded from `plugins.mordred_privacy_check` in `~/.hermes/config.yaml` at `on_session_start`, cached in memory. Reload is explicit via `hermes mordred policy reload`
- Audit logging: see §Operational Guarantees

### Plugin: `mordred_llm_guard`

- Implements the synthetic provider `mordred-local` as `mordred_llm_guard/local_adapter.py` (an adapter bundled with the plugin). Follows the Hermes provider adapter pattern and delegates to a local OpenAI-compatible endpoint (LM Studio / Ollama / vLLM)
- **Phase 0.8 verify (2026-05-10) complete**: in v0.11.0, `pre_llm_call` is context-injection only with no provider override possible, and `pre_api_request` is observer-only ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5). Enforcement is therefore **settled session-scoped at `on_session_start`** (per-turn dynamic override is out of scope for v1):
  - strict policy + current provider **matches** `cloud_provider_allowlist` + `allow_cloud_llm: true` -> session continues (passthrough)
  - strict policy + current provider does not match cloud_provider_allowlist, or `allow_cloud_llm: false` -> session is refused and exits (v1 default, audit `policy.strict.session_refused`). The alternative of swapping the active provider to `mordred-local` via `register_provider` + a config patch (audit `policy.strict.provider_override_at_session_start`) was confirmed structurally impossible in v1 by the Codex B2 review, so it's **deferred to v2** (Tier B `[hard-lock]` vendored fork)
  - lenient/off -> do nothing
- Local-unreachable fail-fast: `mordred-local` raises `MordredLocalUnreachable` on health-check failure
- Harness refusal: scans configured agents at `on_session_start`; aborts startup under strict mode when a harness-based primary (Codex/Claude CLI/Cursor/ACP client) is configured

### Plugin: `mordred_keyvault`

#### Key hierarchy

`mordred_keyvault` protects the combination of **Seed Phrase + Passphrase + PoW**. Complies with the BIP39 standard; the user physically hand-writes the 24-word Seed and Passphrase.

```
secret      = SeedPhrase (24 words) + Passphrase + PoW       ← protected (user transcribes by hand)
dek         = random 256-bit AES-GCM data-encryption key     ← generated by keyvault
ciphertext  = AES-GCM(secret, dek)                           ← stored on disk as backup/state
wrappingKey = Secure Enclave-backed non-exportable key       ← authorizes DEK unwrap only
wrappedDek  = wrap(dek, wrappingKey)                         ← stored next to ciphertext
```

Design decisions:

- **Withdrawn**: a design where the Secure Enclave holds/derives the signing key is not adopted in v1
- **Adopted**: the Secure Enclave is used only as the authorization boundary for wrapping/unwrapping the AES DEK
- `dek` is never stored in plaintext (exists in memory only during encryption/decryption)
- `Passphrase + PoW` is part of `secret`, not derivation material for `dek` (if the Enclave is destroyed, the secret the user wrote down allows re-wrapping on a different machine)
- Biometric authentication is only an authorization mechanism, not a cryptographic operation

Limitations:

- Local secrets at rest protection: guards against disk theft, backup exposure, and accidental plaintext disclosure
- Cannot protect against a compromised running gateway handling the secret after it has been unwrapped
- Runtime signing isolation is out of scope for v1; addressed by future Payment work (`v3-P1`)

#### Key generation and verification digest

Key generation is **mandatory and one-shot**. To prevent mis-transcription, it is not finalized until the verification digest matches.

Conceptual formula:

```
digest = hash( hash(SeedPhrase), hash(Passphrase) ⊕ top4(PoW) )
```

> **Notation note (code-reviewer LOW-1, 2026-05-14)**: the `⊕` here is shorthand for "XOR the 4 bytes of `top4(PoW)` into the **first 4 bytes** of `hash(Passphrase)`, leaving bytes `[4:32]` of `hash(Passphrase)` unchanged". Read as a full-width XOR (32-byte vs. 32-byte with zero-padding), the formula would be ambiguous and a naive implementation could end up XOR-padding `top4(PoW)` to 32 bytes. The Concrete algorithm below is canonical; the conceptual formula is for high-level intuition only.

**Concrete algorithm (canonical, Phase 4 PR2 step-0 freeze 2026-05-14)**:

```
H               := BLAKE3 (32-byte digest mode)
seed_hash       := H(SeedPhrase as UTF-8 bytes)            # 32 bytes
pass_hash       := H(Passphrase as UTF-8 bytes)            # 32 bytes
top4            := PoW_bytes[0:4]                          # PoW is a precomputed BLAKE3-based artifact;
                                                           # caller passes the raw bytes, top4 = first 4 bytes
masked_pass[0:4]  := pass_hash[0:4] XOR top4              # XOR affects ONLY the first 4 bytes
masked_pass[4:32] := pass_hash[4:32]                       # remaining 28 bytes unchanged
digest          := H(seed_hash || masked_pass)             # 32 bytes
```

Resolved ambiguities:
- `top4(PoW)` is `PoW_bytes[:4]`; PoW is NOT re-hashed inside `compute_digest` (caller is responsible for PoW computation, see §`mordred_keyvault` PoW section)
- `⊕` operates on **4 bytes only**, into the first 4 bytes of `pass_hash`. Bytes `[4:32]` of `pass_hash` pass through unchanged. (Rationale: SPEC notation explicitly says `top4`, not `pad_to_32(PoW)` — the masking is intentionally narrow so cross-machine recovery only requires transmitting the 4-byte mask, not 32 bytes.)
- Outer hash combines via byte concatenation `seed_hash || masked_pass` (64 bytes total input)
- All BLAKE3 invocations use the unkeyed, 32-byte default output (no `derive_key` / `keyed_hash` mode)
- String inputs (`SeedPhrase`, `Passphrase`) are UTF-8 encoded **as-is** at this layer. Unicode normalization is the caller's responsibility — implemented by `mordred_keyvault.api` (Phase 4 PR4). PR4 step-0 freeze (2026-05-15, codex HIGH #1) splits normalization: seed phrase uses `NFKD + casefold + whitespace-collapse` (BIP39 word-list tolerance); passphrase uses `NFKD only` (preserves case and whitespace entropy). See §"PR4 API contract" below for the exact `_normalize_seed_phrase` / `_normalize_passphrase` definitions.

**Fixed test vector** (Phase 4 PR2 baseline, BLAKE3 1.0.8):

| Field         | Value (hex unless noted)                                              |
| ------------- | --------------------------------------------------------------------- |
| `seed_phrase` | `"test seed"` (UTF-8: `746573742073656564`)                           |
| `passphrase`  | `"test pass"` (UTF-8: `746573742070617373`)                           |
| `pow_bytes`   | `deadbeef` + `00` × 28 (32 bytes total)                               |
| `seed_hash`   | `c18818fa275b46e46836d45540512fb2561a66924b2962d6675ef71c7cdcecf0`    |
| `pass_hash`   | `734cedd9a49ec88207d0c58f757899bd2dc21cf65b6fa0958ff40c81e4ee08eb`    |
| `top4`        | `deadbeef`                                                            |
| `masked_pass` | `ade15336a49ec88207d0c58f757899bd2dc21cf65b6fa0958ff40c81e4ee08eb`    |
| **`digest`**  | **`25c17b1e1b249dd278f6de52e6e0dddf855fe9943177c99c5428fc1c321b5c93`**|

This vector is pinned in `tests/test_keyvault_digest.py::TestSpecFixedVector` and acts as the regression anchor for the digest algorithm. Any future change that perturbs the vector requires a SPEC update + reason in the PR description.

**Operator tooling**: The standalone `scripts/keyvault_offline_digest.py` (stdlib + `blake3` only, no `mordred_hermes` import) is the canonical implementation an operator runs on the air-gapped second device. It reproduces the algorithm above plus the seed/passphrase normalization defined in §"PR4 API contract". The script's `--self-test` flag validates the same fixed vector pinned above. Operator preparation and step-by-step recipe live in `setup.md` §"Offline verification digest".

Confirmation flow (PC = the machine running the Hermes process):

| Input location                 | Input       | Output                                             |
| ------------------------------ | ----------- | -------------------------------------------------- |
| PC (Hermes process)            | SeedPhrase  | `hash(SeedPhrase)`                                 |
| Separate offline medium/device | Passphrase  | `hash(Passphrase) ⊕ top4(PoW)`                     |
| Combine                        | Both halves | verify `digest` matches the locally computed value |

- The v1 default is offline/manual verification while PC is in network blackout. QR + local LAN pairing is v2 (`v2-F7`)
- PoW (BLAKE3-based) deters real-time phishing replication — the concrete algorithm is frozen in the next section, §"Proof-of-Work (PoW) algorithm"
- During cross-machine recovery, mis-transcription is detected by comparing against the first-generation digest embedded in the backup blob

#### Proof-of-Work (PoW) algorithm (Phase 4 PR10 step-0 freeze, 2026-05-16)

The `pow_bytes` input to `compute_digest` is prepared by the caller. Since PR10 required `keyvault init` to generate this artifact, the v1 algorithm is frozen here.

**Purpose**: PoW is a **seed-bound computational artifact**, forcing a one-time fixed cost to be paid at init. Because it's bound to the seed, it can be deterministically recomputed from the same seed during recovery on a different machine, so there's no need to separately hand-transcribe the PoW (only the 4 bytes of `top4(PoW)` are passed to the offline medium — consistent with the rationale for the `⊕` narrow mask in §"Key generation and verification digest").

**Concrete algorithm (canonical)**:

```
H                    := BLAKE3 (32-byte digest mode; unkeyed — same as digest.py)
POW_PREFIX           := b"MRPOW\x01"          # 6 bytes: domain-separation tag ‖ version 1
POW_DIFFICULTY_BITS  := 20                     # v1 baseline (tunable; see caveat below)

preimage(n)  := POW_PREFIX ‖ normalized_seed_utf8 ‖ n.to_bytes(8, "little")
                # normalized_seed is the output of api._normalize_seed_phrase (NFKD + casefold
                # + whitespace-collapse). n is a uint64 counter starting from 0
find smallest n such that leading_zero_bits(H(preimage(n))) >= POW_DIFFICULTY_BITS
pow_bytes    := H(preimage(n))                 # 32 bytes — the BLAKE3 digest of the winning preimage
```

- `top4(PoW) = pow_bytes[:4]` (consistent with the digest formula). The higher the difficulty, the more leading zero bits `top4` has, but `top4` is for **mis-transcription detection** on the passphrase half, not a security boundary (the primary detection is the `hmac.compare_digest` over the full 32-byte digest).
- Deterministic: `pow_bytes` is a function of the normalized seed only. Recovery recomputes the same value from the transcribed seed.
- If `n` reaches `2**64` (astronomically unlikely), `PowExhausted` is raised.

**Caveat (subject to codex step-0 review)**: `POW_DIFFICULTY_BITS = 20` (≈1.4M BLAKE3 hashes, under 1 second on modern hardware) is a conservative baseline. Rigorous difficulty analysis against real-time phishing is out of scope for v1 and deferred to security review / v2. The constant is consolidated in one place at module level in `mordred_keyvault.pow` so it can be tuned in the future. Note that since recovery also recomputes the PoW, raising the difficulty proportionally affects recovery time as well.

**Fixed test vectors** (BLAKE3 1.x, pinned in `tests/test_keyvault_pow.py`):

| Field                 | Value                                                              |
| --------------------- | ------------------------------------------------------------------ |
| `normalized_seed`     | `"test seed"` (UTF-8: `746573742073656564`)                        |
| `POW_PREFIX`          | `4d52504f5701` (`MRPOW` ‖ `0x01`)                                  |
| **difficulty 8** (human-checkable worked example) | `n = 519` |
| → `pow_bytes`         | `00faa270f9d4a1047cd3f00002d6bd6c3ded6d151e2542ee21742a4665b56ac2` |
| → `top4`              | `00faa270`                                                         |
| **difficulty 20** (v1 production `POW_DIFFICULTY_BITS`) | `n = 1449850` |
| → `pow_bytes`         | `00000df459e58f525449c530a547d48ba70e488f7ed15f9c810ae7a76bd0e7c9` |
| → `top4`              | `00000df4`                                                         |

The difficulty-8 vector is for hand-calculation verification (reached at `n = 519`); the difficulty-20 vector is the v1 production regression anchor. Any change that alters either requires a SPEC update + a reason in the PR.

#### `keyvault init` flow (Phase 4 PR10)

`hermes mordred keyvault init` runs the one-shot key-generation flow in the following order:

1. **Generate**: `keyvault` generates a 24-word BIP39 mnemonic (256-bit entropy + SHA-256 checksum) and computes the PoW via `pow.compute_pow(normalized_seed)`. The Passphrase is entered interactively by the user (not echoed to the PC screen).
2. **prepare**: `api.prepare_generate(seed, passphrase, pow_bytes)` → `(SeedDisplayHandle, expected_digest)` (in-memory only, no disk mutation).
3. **display**: `seed_display.display_seed(handle, surface)` — network blackout assert (fail-closed) → M4/M5 banner → displays **only the Seed** on the terminal with a 60s timer (the Passphrase is never rendered).
4. **offline confirm**: the user transcribes the seed + passphrase + `top4(PoW)` onto an offline medium, independently computes the digest, and enters that digest into the CLI.
5. **finalize**: `api.confirm_generate(handle, user_digest, backend=_SecKeyBackend())` — only on digest match does it durably persist the Secure Enclave key + `meta.json`; on mismatch, zero state change and `keyvault.init_denied`.

#### Seed phrase display security

1. **Network blackout (M4 caveat)**: before display, `mordred_network.api.blackout_assert()` verifies the host is disconnected. On macOS via `SCNetworkReachability` / `nw_path_monitor` (through pyobjc). On Linux, substituted with `ip link show` / `nmcli` (since Phase 4 is macOS-only, the Linux fallback is v2)
   - **Fallback**: when `mordred_network` is absent, keyvault falls back to a thin wrapper that calls the OS API directly
   - **Detection scope limits (M4)**: `blackout_assert` detects only **paths visible to the OS's standard network stack**. The following cannot be detected, so physical air-gapping is the user's responsibility:
     - Bluetooth / USB tethering / personal hotspot (when the OS does not, or is not made to, recognize it as WAN)
     - NICs running outside a virtual machine / container, host-side VPNs, virtual switches
     - Malicious kernel modules or ring-0 loaders (a root-compromised environment)
     - Cases where an external NIC connected via Thunderbolt / DMA is hidden from the OS
   - Before display, the `keyvault init` startup banner prompts the user to "visually confirm that Wi-Fi/Ethernet/Bluetooth/USB tethering is physically disconnected"
2. **Show only the Seed on the PC**. The Passphrase is never rendered on the PC screen
3. **Verification is offline by default in v1**: the Passphrase half is entered on a separate device or hand-written
4. **Display timeout & capture caveats (M5)**: the Seed auto-clears after 60 seconds. The v1 defense scope regarding capture is as follows:
   - **Screenshot detection**: best-effort only (polling macOS `CGDisplayRegisterReconfigurationCallback` + `CGScreenIsBeingCaptured`). The Seed display is cleared immediately upon detection + audit log `keyvault.seed_display_aborted_screenshot` (frozen in the Phase 4 reason enum)
   - **Screen recording (M5, out of v1 detection scope)**: screen recording via macOS `screencapture -v`, Loom, Zoom share, OBS, QuickTime Player is **not detected**. Adoption of the `CGDisplayStream`-based detection API is deferred in v1 on API-stability grounds, to be re-evaluated in v2
   - **Remote desktop (VNC / Screen Sharing / SSH X11 forwarding / `tmate` / `mosh`)**: not detected. The user is responsible for closing remote sessions before the Seed display
   - **Camera / physical shoulder-surfing**: naturally out of detection scope
   - The pre-display startup banner warns: "view the Seed only on the local machine's physical screen; stop any screen recorder / screen-sharing tool / remote desktop"
   - The 60-second timer is based on a monotonic clock (`time.monotonic()`), resistant to wall-clock tampering

#### Protection-tier hierarchy (fallback)

1. **TEE present (Tier 1, v1)**: Secure Enclave (`Security.framework` via pyobjc)
2. **No TEE (Tier 2, v2)**: Keychain/HSM/TPM/DPAPI
3. **Neither (Tier 3, v2)**: master-password-derived key

> **Tier 2 — Linux TPM 2.0 (v2-OS2)**: `hermes mordred keyvault enable-tpm` builds the `mordred-hermes-tpmkey` helper, which backs the wrapping key with a non-extractable TPM P-256 key + on-chip ECDH (same WMK wire format). This is **machine-binding** — a copied key-blob is useless on another host — but **NOT Touch-ID-equivalent**: the MVP has no per-use user-presence gate (no PIN/PCR prompt), unlike the Tier-1 Secure Enclave's biometric-per-decrypt. Per-use gating is a deferred follow-up. (Phase 2a/2c shipped the Rust crate + CLI; the `tss-esapi` TPM backend is Phase 2b.)

#### Implementation interface

- Add `pyobjc-framework-Security` to `mordred-hermes`'s macOS extra (`pip install mordred-hermes[macos]`)
- The `Security.framework` wrapper is implemented in `mordred_keyvault/native.py`, with lazy import (using the `_lazy_import` pattern so it doesn't raise `ImportError` at import time on Linux/WSL2)
- Internal Python API (shared across Mordred plugins) — see §"PR4 API contract & MREN envelope wire format" for the canonical form frozen at PR4 step-0 (2026-05-15):
  - `mordred_keyvault.api.prepare_generate(seed, passphrase, pow_bytes) -> (SeedDisplayHandle, expected_digest)` — in-memory only, no persistence
  - `mordred_keyvault.api.confirm_generate(handle, user_confirmed_digest, *, ...) -> GenerateResult` — Keychain + meta.json mutation only on digest match; rollback on mismatch (codex BLOCKER #2)
  - `mordred_keyvault.api.generate(seed, passphrase, pow_bytes, expected_digest, *, ...) -> GenerateResult` — non-interactive convenience (for tests / automation); the wizard CLI requires the two-phase form
  - `mordred_keyvault.api.encrypt(key_id, plaintext, purpose, *, ...) -> envelope_id` — managed storage; AES-GCM encrypt + persist `.gcm` envelope; returns envelope_id
  - `mordred_keyvault.api.decrypt(key_id, envelope_id, purpose, *, ...) -> bytes` — a caller-supplied `purpose` is required (defends against cross-purpose replay, codex HIGH #2); decrypts after unwrap authorization
  - `mordred_keyvault.api.export_backup(key_id, passphrase, *, ...) -> bytes` — an MRKV blob containing a manifest with all ciphertext re-wrapped under an Argon2id-KEK (codex BLOCKER #1)
  - `mordred_keyvault.api.import_backup(blob, passphrase, *, seed_phrase, pow_bytes, ...) -> str` — verifies the digest → decrypts the manifest → re-wraps each DEK under a new Enclave key
  - `mordred_keyvault.api.verify_digest(seed, passphrase, pow_bytes, *, expected) -> None` — confirms digest match after applying split normalization
- Skill opt-in: declares `metadata.mordred.requires_keyvault: true`; enforced by `mordred_privacy_check` at install time

#### Backup wire format versioning (Phase 4 PR2 freeze, 2026-05-14)

`mordred_keyvault.backup.export()` produces a self-describing blob with the layout

```
magic(4)="MRKV" | version(1) | kdf_id(1) | m_cost(4 BE) | t_cost(4 BE) | p_cost(4 BE)
                | salt(16) | verification_digest(32) | aes_blob_len(4 BE) | aes_blob(*)
```

with `HEADER_LEN = 70` for `version=1`. The AAD bound to the AES-GCM ciphertext is `magic ‖ version ‖ kdf_id ‖ m_cost ‖ t_cost ‖ p_cost ‖ salt ‖ verification_digest` (66 bytes). Tampered headers therefore fail `InvalidTag` at decrypt time, separately from `BackupCorrupt` structural rejects.

> **Migration policy (code-reviewer LOW-2, 2026-05-14)**: a `version=2` blob is **not** required to keep `HEADER_LEN = 70`. Decoders must read the `version` byte first and dispatch on it; `parse_header` for `version=1` raises `BackupCorrupt` on any other version (the policy in PR2). When introducing `version=2`:
>
> 1. Keep `magic = b"MRKV"` and `version` at byte offset 4 stable — these are the dispatch keys.
> 2. Bump the SPEC table above with the version-2 layout, list which fields moved, and update any consumers reading `HEADER_LEN` as a constant.
> 3. AAD construction may change but must remain field-set-deterministic so re-encrypting the same secret + parameters yields the same ciphertext under a fixed nonce.
> 4. Migration tools should detect version=1 blobs and re-export as version=2 with a fresh nonce — never silently upgrade the blob in place (preserves the original verification digest's transcription evidence).

DOS guards on parsed KDF params (Phase 4 PR2 integration finding): `parse_header` rejects `m_cost > 1 GiB`, `t_cost > 64`, or `p_cost > 16` (and any value ≤ 0). Without these caps a tampered cost-param byte can force `decrypt_body` into a multi-GiB Argon2 allocation before AAD authentication has a chance to fail. The caps must be re-evaluated when introducing a stronger KDF profile (a future "v2 profile" with `m_cost=256 MiB, t=4` for higher-security keyvaults stays within them).

#### Wrap wire format & algorithm (Phase 4 PR3 freeze, 2026-05-14)

The Secure-Enclave-backed DEK wrap is the Tier-1 protection step from the [Protection-tier hierarchy](#protection-tier-hierarchy-fallback) above. `mordred_keyvault.wrap.wrap_dek(dek, key_id)` produces a self-describing 127-byte blob:

```
magic(4)="MRKW" | version(1) | alg_suite(1) | key_id_hash(16) | ephemeral_pub(65) | wrapped_dek(40)
```

Field reference for `version = 1`:

| Offset | Length | Field | Notes |
| --- | --- | --- | --- |
| 0 | 4 | `magic` | ASCII `MRKW`. Dispatch key, never changes across versions. |
| 4 | 1 | `version` | `1`. Dispatch key for future format bumps. |
| 5 | 1 | `alg_suite` | `1` = `(P256_ECDH_RAW, HKDF_SHA256, AES256_KW_RFC3394)`. Reserved values: `0` invalid, `2-255` future. |
| 6 | 16 | `key_id_hash` | First 16 bytes of `SHA-256(key_id_bytes)`. Used for Keychain lookup + audit log; never the cleartext `key_id`. |
| 22 | 65 | `ephemeral_pub` | SEC1 uncompressed P-256 (`0x04 ‖ X(32) ‖ Y(32)`). Freshly generated by `wrap_dek` via `cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(SECP256R1())` (which itself draws from the OS RNG via OpenSSL `BN_rand_range`) — wrap is **never** deterministic and never reuses the ephemeral key. Hand-rolled scalar generation via `secrets.token_bytes` is intentionally avoided (codex review-fix-2 NIT-1) because it would require a manual modular-reduction step against the curve order. |
| 87 | 40 | `wrapped_dek` | RFC 3394 AES-KW output for a 32-byte DEK (`8 + 32 = 40` bytes; the fixed IV/AIV is internal to RFC 3394, so the blob has **no separate IV field** — codex review BLOCKER-2). |

`HEADER_LEN = 127` for `version=1`. The parser rejects any other version with `WrapParseError`.

**Algorithm — `wrap_dek(dek, key_id)`** (offline, no Enclave authorization, no user prompt):

1. Lookup the Enclave **public** key for `key_id` via `SecKeyCopyPublicKey` on a Keychain lookup (`kSecAttrApplicationTag = "mordred-hermes.wrap." + key_id_hash`).
2. Generate an ephemeral P-256 keypair in software (`cryptography` library, never persisted).
3. Raw ECDH: pass the ephemeral private key + Enclave public key to `SecKeyCopyKeyExchangeResult` with `kSecKeyAlgorithmECDHKeyExchangeStandard` (NOT `…X963SHA256` — codex review HIGH-1; we want raw ECDH output, then a single explicit HKDF, not double-derive).
4. HKDF-SHA256 derive a 32-byte AES-KEK: `salt = b""`, `info = magic || version(1) || alg_suite(1) || key_id_hash(16) || ephemeral_pub(65)` (87 bytes; binds every non-secret blob field to the KEK — codex review HIGH-2).
5. `wrapped_dek = AES-KW(KEK, dek)` per RFC 3394 (32-byte DEK → 40-byte output, integrity-protected by the AIV).
6. Emit the blob; do NOT emit an audit-log entry (wrap is unauthorized, fast, no decision boundary).

**Algorithm — `unwrap_dek(blob, key_id)`** (authorized, may prompt the user):

1. `parse_header(blob)` — reject if `len(blob) != 127`, `magic != b"MRKW"`, `version != 1`, `alg_suite != 1`, or `key_id_hash != SHA-256(key_id)[:16]`. Each rejection raises `WrapParseError`.
2. Lookup Enclave **private** key by Keychain query (same `kSecAttrApplicationTag` namespacing). Missing → `WrapKeyNotFound`.
3. Decode `ephemeral_pub` as SEC1 P-256; reject invalid curve points with `WrapParseError`.
4. Call `SecKeyCopyKeyExchangeResult(enclave_private, ECDHKeyExchangeStandard, ephemeral_pub, params)`. This triggers the access-control prompt (Touch ID / Optic ID / passcode). On `errSecUserCancelled` / `errSecAuthFailed` / `errSecInteractionNotAllowed` / `errSecAuthorizationCanceled`, emit `keyvault.unwrap_denied` with translated `native_error_code` and raise `WrapAuthCancelled` (chains the native `NSError` via `__cause__`).
5. HKDF-SHA256 with the same `info` constructed in wrap step 4 (binds blob fields to KEK; a tampered `ephemeral_pub` produces a different KEK → AES-KW unwrap fails AIV check).
6. `dek = AES-KW-Unwrap(KEK, wrapped_dek)`. AIV mismatch → `WrapIntegrityError`.
7. Emit `keyvault.unwrap_authorized` with `key_id_hash` (16-char hex prefix) and return `dek`.

**Access-control attributes for the Enclave key** (set at `generate_wrapping_key` time, persisted in the Keychain):

| Attr | Value | Rationale |
| --- | --- | --- |
| `kSecAttrKeyType` | `kSecAttrKeyTypeECSECPrimeRandom` | P-256, the only curve the Enclave supports. |
| `kSecAttrKeySizeInBits` | `256` | Required by `ECSECPrimeRandom`. |
| `kSecAttrTokenID` | `kSecAttrTokenIDSecureEnclave` | Bind the private key to the Enclave; the public key is freely exportable. |
| `kSecAttrIsPermanent` | `True` | Survives reboot — `wrap` needs to look up the public key without re-prompting. |
| `kSecAttrApplicationTag` | `b"mordred-hermes.wrap." + key_id_hash` | Namespaced lookup; avoids collision with other apps. |
| `kSecAttrLabel` | `"Mordred wrapping key " + key_id_hash[:8].hex()` | Human-readable in Keychain Access.app. |
| `kSecAttrAccessControl` | `SecAccessControlCreateWithFlags(.privateKeyUsage \| .biometryCurrentSet, accessible: .whenPasscodeSetThisDeviceOnly)` | Touch/Optic ID required — `.biometryCurrentSet` is biometry-only with no passcode fallback; an Enclave-capable Mac without enrolled biometry cannot create or use the key (codex review MEDIUM-2; reaffirmed PR9). `.biometryCurrentSet` invalidates the key if the user adds/removes biometrics — protects against the "stolen device with attacker biometric enrolled" attack. `.whenPasscodeSetThisDeviceOnly` ensures the key cannot exist on a device without a passcode and never syncs to iCloud Keychain. |

Capability detection (codex review MEDIUM-1): `is_secure_enclave_available()` does NOT check `platform.machine() == 'arm64'`. Intel Macs with the T2 chip also have a Secure Enclave reachable through the same API. Detection probes capability via a throwaway key-generate-then-delete cycle (with `.privateKeyUsage` only, no biometry, so it cannot prompt) — non-`Darwin` platforms short-circuit to `False` without touching pyobjc.

**Internal Python surface (frozen for PR4 callers — codex review LOW-2)**:

```python
class WrapError(Exception): ...                 # base; all PR3 errors derive from here
class WrapParseError(WrapError): ...            # malformed blob (length, magic, version, alg_suite, key_id_hash mismatch, invalid EC point)
class WrapIntegrityError(WrapError): ...        # AES-KW AIV check failed (tampered wrapped_dek or ephemeral_pub)
class WrapNativeUnavailable(WrapError): ...     # Security.framework not importable (non-macOS or pyobjc missing)
class WrapAuthCancelled(WrapError): ...         # user denied biometry / passcode prompt; emit keyvault.unwrap_denied
class WrapKeyNotFound(WrapError): ...           # Keychain has no item for this key_id (key revoked or wrong device)
class WrapKeyAlreadyExists(WrapKeyNotFound): ...  # duplicate key_id at generation time; WrapKeyNotFound subclass so historical `except` sites keep catching it

def generate_wrapping_key(key_id: str, *, backend: NativeBackend) -> bytes: ...     # returns SEC1 uncompressed P-256 pubkey, 65 bytes
def get_wrapping_key_public(key_id: str, *, backend: NativeBackend) -> bytes: ...   # SEC1 uncompressed P-256, 65 bytes
def delete_wrapping_key(key_id: str, *, backend: NativeBackend) -> None: ...        # removes Keychain item; idempotent
def wrap_dek(dek: bytes, key_id: str, *, backend: NativeBackend) -> bytes: ...      # offline; returns 127-byte blob
def unwrap_dek(blob: bytes, key_id: str, *, audit_sink: AuditSink, backend: NativeBackend) -> bytes: ...
```

`api.py` (Phase 4 PR4) is the only callsite — internal API contract for `mordred_keyvault.api.generate` / `encrypt` / `decrypt` / `export_backup` / `import_backup` derives from this surface.

**Migration policy** (mirrors PR2 backup wire format L428-433): a future `version=2` must keep `magic = b"MRKW"` and `version` at byte offset 4 stable as dispatch keys; bump the table above; do not silently upgrade existing blobs in place (preserves provenance evidence).

#### PR4 API contract & MREN envelope wire format (Phase 4 PR4 step-0 freeze, 2026-05-15)

The planning-stage codex review of PR4 (BLOCKER × 3 + HIGH × 5 + MEDIUM × 3 + LOW × 1) is incorporated below. The freeze covers `api.py` public surface, MREN envelope format, normalization split, two-phase generation, opaque `SeedDisplayHandle`, managed storage, file-safety semantics, and the four new audit codes.

##### Mordred normalization (split: seed phrase vs passphrase, codex HIGH #1)

The PR2 freeze (L349) said "(NFKD + casefold + single-space collapse) is the caller's responsibility". Codex pre-implementation review flagged that applying this uniformly to passphrase weakens entropy (casefold conflates distinct Unicode strings; whitespace collapse drops information). PR4 splits normalization:

```python
def _normalize_seed_phrase(s: str) -> str:
    # BIP39 + tolerance: NFKD decompose, strip Cf-category chars,
    # casefold, collapse runs of whitespace.
    # Seed phrases are word lists — casefold and whitespace tolerance are correct.
    # Cf-strip handles invisible clipboard noise (ZWSP / ZWJ / BOM / soft hyphen);
    # these are NFKD-stable and str.split() does not treat them as whitespace,
    # so without an explicit drop they survive normalization and silently
    # produce a different digest (code-reviewer MEDIUM-1, 2026-05-15).
    decomposed = unicodedata.normalize("NFKD", s)
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Cf")
    return " ".join(stripped.casefold().split())

def _normalize_passphrase(s: str) -> str:
    # BIP39 reference normalization: NFKD only. No casefold, no whitespace
    # collapse, NO Cf strip — preserves the exact entropy of the input. A user
    # who chose to embed an invisible char did so intentionally; recovery
    # requires reproducing the same bytes. The verify-digest mismatch at
    # recovery time surfaces any clipboard-injected invisible char visibly.
    return unicodedata.normalize("NFKD", s)
```

Both apply at `api.py` boundaries (`prepare_generate` / `verify_digest` / `import_backup`). `digest.compute_digest` continues to receive already-normalized UTF-8 bytes as PR2 freeze. The existing fixed test vector (L355-362) remains valid for ASCII inputs (`"test seed"` / `"test pass"` have no NFKD decomposition and no casefold delta). PR4 adds new fixed vectors covering Japanese precomposed/decomposed equivalence on the seed side and entropy preservation on the passphrase side.

##### Two-phase generate (codex BLOCKER #2)

SPEC §Key generation and verification digest mandates that key generation be "mandatory and one-shot" and finalize only after the verification digest matches. A single-call `generate(seed, passphrase, pow)` cannot enforce that — Keychain state and `meta.json` would be created before the user has confirmed via the offline channel. PR4 splits into two phases:

```python
def prepare_generate(
    seed_phrase: str,
    passphrase: str,
    pow_bytes: bytes,
) -> tuple[SeedDisplayHandle, bytes]:
    # In-memory only. Computes digest from normalized inputs. Returns:
    #   - handle: opaque SeedDisplayHandle for Seed display flow (PR5 will consume)
    #   - expected_digest: 32-byte digest for user to confirm via offline channel
    # NO Keychain creation, NO meta.json write, NO digests/ commit, NO audit emit.
    # Pure function with respect to disk state.
    ...

def confirm_generate(
    handle: SeedDisplayHandle,
    user_confirmed_digest: bytes,
    *,
    key_id: str | None = None,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> GenerateResult:
    # Reads the prepared digest via handle.expected_digest() — the
    #   confirm-side egress: it does NOT consume the handle (consume() is
    #   the display flow's egress, so prepare -> display-seed -> confirm
    #   works), but on an expired deadline it wipes the seed payload before
    #   raising SeedDisplayExpired.
    # Verifies user_confirmed_digest matches that digest via hmac.compare_digest.
    # On mismatch: emit keyvault.init_denied (sink failure chained as
    #   __context__), raise VerificationDigestMismatch; NO mutation. The
    #   handle is not consumed, so the caller may retry with a corrected
    #   digest on the same handle.
    # On match:
    #   0. Re-init guard: v1 keyvault is single-key (Story 5). If meta.json
    #      already has any key, raise RuntimeError. Checked once unlocked
    #      (before init_started, to avoid a dangling audit event) and again
    #      authoritatively under the lock (TOCTOU-safe).
    #   1. Emit keyvault.init_started (audit-sink failure aborts; durability barrier).
    #   2. Under one .lock hold: re-check the re-init guard, then
    #      wrap.generate_wrapping_key(key_id, backend=...) — key_id=None
    #      resolves to the "default" literal; a duplicate raise here is
    #      OUTSIDE the rollback scope so a pre-existing key is not deleted.
    #   3. Still under .lock: write digests/<key_id_hash>.commit FIRST, then
    #      meta.json LAST. meta.json is the transaction commit point —
    #      save_meta replaces it atomically. Rollback deletes the Enclave
    #      key + the orphaned commit file, and best-effort repairs the
    #      meta.json row in the rare case the atomic rename committed before
    #      a later fsync raised.
    #   4. Emit keyvault.init_completed (sink failure suppressed; init has already succeeded).
    # ``backend`` is required (no None default) — matches encrypt/decrypt;
    #   the production backend is a later step so there is no None fallback.
    ...

def generate(
    seed_phrase: str,
    passphrase: str,
    pow_bytes: bytes,
    expected_digest: bytes,
    *,
    key_id: str | None = None,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> GenerateResult:
    # Non-interactive convenience: prepare → confirm in one call.
    # Tests and future automation use this. Wizard CLI MUST use the two-phase form.
    # Delegates fully to confirm_generate (no in-generate digest pre-check):
    # confirm_generate reads the handle's digest, compares, and emits
    # keyvault.init_denied on mismatch — so a non-interactive mismatch gets
    # the same audit trail as the interactive path.
    handle, _prepared = prepare_generate(seed_phrase, passphrase, pow_bytes)
    try:
        return confirm_generate(handle, expected_digest, key_id=key_id, backend=backend,
                                audit_sink=audit_sink, home=home)
    finally:
        # No display flow consumes the handle in the non-interactive path,
        # so generate() wipes the seed itself (consume() under the lock) on
        # both the success and the raise paths.
        with contextlib.suppress(SeedDisplayExpired):
            handle.consume()
```

##### SeedDisplayHandle (opaque, codex BLOCKER #3)

A frozen dataclass with `seed_phrase: str` would expose the seed via `repr`, equality comparison, hash-based memoization, and long-lived object retention. PR4 defines `SeedDisplayHandle` as an opaque class with:

```python
class SeedDisplayHandle:
    __slots__ = ("_payload", "_consumed", "_deadline", "_expected_digest", "_lock")

    def __init__(
        self,
        normalized_seed: str,
        deadline_monotonic: float,
        expected_digest: bytes,
    ) -> None:
        self._payload = bytearray(normalized_seed.encode("utf-8"))  # wipeable
        self._consumed = False
        self._deadline = deadline_monotonic  # time.monotonic() + 60.0 by default
        # 32-byte digest baked in by prepare_generate; confirm_generate
        # uses this as the compare target for hmac.compare_digest against
        # the user-typed value (defense-in-depth: even if the caller forgot
        # to verify before calling confirm_generate, the handle still
        # raises on mismatch). Coerced through bytes(...) and length-checked.
        self._expected_digest = bytes(expected_digest)
        self._lock = threading.Lock()  # serializes consume() across threads

    def __repr__(self) -> str:
        return "<SeedDisplayHandle redacted>"

    def __eq__(self, other: object) -> bool:
        raise TypeError("SeedDisplayHandle does not support equality (would leak via comparison oracle)")

    __hash__ = None  # unhashable: cannot land in dict/set/cache by accident

    # __copy__ / __deepcopy__ / __reduce__ / __reduce_ex__ / __getstate__
    # / __setstate__ all raise TypeError — the default object machinery
    # would otherwise duplicate or serialize the slotted _payload and leak
    # the seed (or let a duplicate consume() it after the original wiped).

    def consume(self) -> str:
        # One-shot. Returns the normalized seed string, then zero-fills internal bytes.
        # The whole body runs under self._lock so the one-shot guarantee holds
        # even if the handle is shared across threads.
        # After consume(): subsequent calls raise RuntimeError("handle already consumed").
        # If time.monotonic() > self._deadline: raise SeedDisplayExpired, wipe, do not return.
        # consume() is the DISPLAY FLOW's egress for the seed.
        ...

    def expected_digest(self) -> bytes:
        # confirm_generate's read-only egress: returns the prepared
        # verification digest WITHOUT consuming the handle. The deadline
        # guard fires only while the seed is still live (not _consumed):
        # an expired, never-consumed handle is wiped before raising
        # SeedDisplayExpired; once consume() has wiped the seed the deadline
        # is moot, so expected_digest() returns the digest even past the
        # deadline (a slow user confirming after the display window still
        # succeeds). Callable repeatedly.
        ...
```

> **Step-D extension (2026-05-15, PR4c-1)**: the original step-0 freeze
> listed 3 slots; this proved inconsistent with the `confirm_generate`
> comment "Verifies user_confirmed_digest matches handle's prepared
> digest" because the handle had no compare target. Two slots were
> appended during PR4c-1 (the first three are preserved in SPEC order):
>
> - `_expected_digest` (4th) — the BLAKE3 compare target. Coerced through
>   `bytes(...)` so a caller-passed `bytearray` / `memoryview` cannot
>   alias-mutate it post-construction, and length-validated (== 32) at
>   construction time.
> - `_lock` (5th) — a per-handle `threading.Lock` serializing `consume()`;
>   without it two threads sharing a handle could both pass the one-shot
>   guard and release the seed twice.
>
> PR4c-1 also added `__copy__` / `__deepcopy__` / `__reduce__` /
> `__reduce_ex__` / `__getstate__` / `__setstate__` guards (all raise
> `TypeError`) so the default copy / pickle / state-dump machinery
> cannot duplicate or serialize the seed payload. CPython-level
> introspection (`gc.get_referents`, `ctypes`, a debugger) remains out
> of scope — defending it would require C-level work.

Phase 4 PR7 `seed_display.py` layers the screen-blackout-assert + M4/M5 warning banner + 60s monotonic display loop + screenshot detection on top of this class. `SeedDisplayHandle` is **not** relocated — it stays in `api.py` and `seed_display.display_seed` consumes it, so api.py callers are unaffected (the original plan said "relocate", but keeping it in `api.py` keeps the contract narrow as PR4 intended). `display_seed(handle, surface, ...)`: blackout assert (`network_fallback.resolve_blackout_assert`, fail-closed) → `surface.banner(SEED_DISPLAY_BANNER)` → screenshot pre-check → `handle.consume()` → 60s `time.monotonic()` timer polling `CGScreenIsBeingCaptured` → `finally` auto-clear. A detected capture clears the surface, emits `keyvault.seed_display_aborted_screenshot`, and raises `SeedDisplayAborted`.

##### MREN envelope (managed storage, decrypt requires purpose)

```
offset  bytes  field
0       4      magic = b"MREN"
4       1      version = 1
5       16     key_id_hash = SHA-256(key_id)[:16]
21      16     purpose_hash = SHA-256(purpose)[:16]
37      127    wrapped_dek (RFC 3394 AES-KW under Enclave-derived KEK, PR3 MRKW prefix verbatim)
164     4      aes_blob_len (uint32 big-endian)
168     N      aes_blob = nonce(12) || ciphertext || tag(16)
```

AAD = bytes `[0:164]` (`magic || version || key_id_hash || purpose_hash || wrapped_dek`). Any header byte flip invalidates the GCM tag, mirroring PR2/PR3 integrity story. Total envelope size: `196 + len(plaintext)` bytes minimum (the 127-byte MRKW prefix is itself wrapped-dek-only; the +N bytes are ciphertext + tag).

API surface (managed storage — keyvault owns persistence):

```python
def encrypt(
    key_id: str,
    plaintext: bytes,
    purpose: str,
    *,
    backend: NativeBackend | None = None,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> str:
    # Generates fresh DEK (secrets.token_bytes(32)); offline-wraps via wrap.wrap_dek;
    # AES-GCM encrypts plaintext under DEK with AAD bound to header. Persists to
    # ciphertexts/<key_id_hash_hex>/<purpose_hash_hex>/<envelope_id>.gcm via atomic
    # tmp+rename+fsync under .lock, file mode 0600. Returns envelope_id
    # (URL-safe base64 of 16 random bytes, ~22 chars).
    ...

def decrypt(
    key_id: str,
    envelope_id: str,
    purpose: str,
    *,
    backend: NativeBackend | None = None,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> bytes:
    # Reads envelope; verifies envelope.purpose_hash == SHA-256(purpose)[:16] via
    # hmac.compare_digest BEFORE invoking wrap.unwrap_dek. Cross-purpose attempts
    # raise WrapParseError without spending a biometric prompt or emitting audit
    # (mirrors PR3 review-fix-1 HIGH-1 "no emit for parse errors"). On purpose match:
    # unwraps DEK (PR3 wrap layer emits keyvault.unwrap_authorized or _denied via
    # codes #19/#20 — api.decrypt does NOT double-emit), then AES-GCM decrypts.
    ...
```

Per-ciphertext DEK rationale (codex OD-1 confirmed): each `encrypt` generates a fresh 32-byte DEK. AES-GCM nonce reuse across plaintexts is structurally eliminated. The 127-byte MRKW prefix per envelope is acceptable overhead; the biometric-prompt-per-decrypt UX cost is acceptable for Tier 1 posture (v2-F5 may add a configurable in-memory grace window).

##### export_backup / import_backup (ciphertext-rewrap manifest, codex BLOCKER #1)

Codex flagged that an Enclave-only DEK wrap is unrecoverable across machines (Enclave keys are non-exportable). PR4 implements full ciphertext portability via a passphrase-derived KEK manifest: each envelope is unwrapped, the AAD is rebound from the per-device MRKW prefix to a portable form, and on import the envelope is reconstructed with a fresh Enclave wrap on the destination device. The DEK travels in the manifest (encrypted-at-rest by the passphrase-derived KEK), so the destination device never needs the source device's Enclave key.

**Portable manifest AAD**: `manifest_aad = b"MRMN" || key_id_hash(16) || purpose_hash(16)` — exactly 36 bytes, fully reconstructible from `(key_id, purpose)` on the import side. It does NOT include the MRKW prefix because that prefix is per-device and changes on each machine.

```python
def export_backup(
    key_id: str,
    passphrase: str,
    *,
    backend: NativeBackend | None = None,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> bytes:
    # 1. Walk ciphertexts/<sha256(key_id)[:16].hex()>/**/*.gcm.
    # 2. For each envelope file, parse the MREN wire format (SPEC §MREN envelope above):
    #    extract wrapped_dek_blob (offset 37, 127 bytes), aes_blob (offset 168, len from
    #    aes_blob_len field), purpose_hash (offset 21, 16 bytes), envelope_id (filename
    #    minus .gcm).
    # 3. Reconstruct the envelope's original AAD = envelope_bytes[0:164]
    #    (magic || version || key_id_hash || purpose_hash || wrapped_dek_blob).
    # 4. Call wrap.unwrap_dek(wrapped_dek_blob, key_id, backend=...) to recover the 32-byte
    #    DEK (single biometric prompt covers the whole batch — SecKeyCopyKeyExchangeResult
    #    sessions amortize one user gesture across all envelopes in the same call frame;
    #    if Enclave behavior changes in a future macOS, fall back to one-prompt-per-envelope
    #    and document in PR description).
    # 5. AES-GCM-decrypt the original aes_blob under the recovered DEK with the original AAD
    #    → original_plaintext.
    # 6. Compute portable manifest_aad = b"MRMN" || key_id_hash(16) || purpose_hash(16)
    #    (36 bytes, no MRKW prefix).
    # 7. AES-GCM-re-encrypt: manifest_aes_blob = AES-GCM-encrypt(DEK, original_plaintext,
    #    aad=manifest_aad) with a fresh 96-bit nonce. Output bytes = nonce(12)||ciphertext||tag(16).
    # 8. Append a manifest entry (manifest_aad is recomputable on import from key_id +
    #    purpose, so it is NOT stored in the entry):
    #      {
    #        "purpose_hash_hex": "<32 hex chars>",
    #        "envelope_id":      "<URL-safe b64, 22 chars>",
    #        "dek_hex":          "<64 hex chars>",
    #        "manifest_aes_blob_b64": "<base64 of step-7 output>",
    #      }
    # 9. Serialize manifest as canonical JSON:
    #      manifest_json = json.dumps({
    #        "version": 1,
    #        "key_id": <plaintext key_id>,
    #        "envelopes": [<entry>, ...],
    #      }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    # 10. Argon2id-derive KEK_passphrase from passphrase + fresh 16-byte salt
    #     (m=46 MiB, t=1, p=1 — same parameters as PR2 backup.export).
    # 11. manifest_body = AES-GCM-encrypt(KEK_passphrase, manifest_json,
    #     aad=PR2_backup_header_aad) (PR2 backup wire format AAD already binds salt + KDF
    #     params + verification_digest).
    # 12. Pack PR2 MRKV blob with verification_digest from digests/<sha256(key_id)[:16].hex()>.commit
    #     and manifest_body as the AES blob payload (PR2 backup.export contract).
    # 13. Emit keyvault.backup_exported (#24, fields: key_id_hash, blob_version=1,
    #     kdf_id=1, envelope_count = len(manifest.envelopes)).
    # Returns the MRKV blob bytes; file persistence is the caller's responsibility.
    ...

def import_backup(
    blob: bytes,
    passphrase: str,
    *,
    seed_phrase: str,
    pow_bytes: bytes,
    backend: NativeBackend | None = None,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> str:
    # 1. recovery.parse_header(blob) — PR2 contract; raises BackupCorrupt on parse failure.
    # 2. Recompute verification digest from normalized (seed_phrase, passphrase, pow_bytes)
    #    using api._normalize_seed_phrase + api._normalize_passphrase + digest.compute_digest.
    #    Compare with the header's verification_digest field via 32-byte length guard +
    #    hmac.compare_digest. Mismatch → raise RecoveryDigestMismatch + emit
    #    keyvault.recovery_digest_mismatch (#17).
    # 3. Argon2id-derive KEK_passphrase from passphrase + parsed salt.
    # 4. AES-GCM-decrypt manifest_body → manifest_json. AAD = PR2 backup header AAD.
    # 5. Parse manifest JSON; validate "version" == 1.
    # 6. imported_key_id = manifest["key_id"]. backend.generate_enclave_key(imported_key_id)
    #    on this device → new Enclave wrapping key.
    # 7. For each manifest entry (in declared order):
    #    a. Recompute manifest_aad = b"MRMN" || sha256(imported_key_id)[:16] ||
    #       bytes.fromhex(entry["purpose_hash_hex"]) (36 bytes, identical to export step 6).
    #    b. plaintext = AES-GCM-decrypt(bytes.fromhex(entry["dek_hex"]),
    #                                   b64decode(entry["manifest_aes_blob_b64"]),
    #                                   aad=manifest_aad).
    #    c. new_wrapped_dek = wrap.wrap_dek(dek_bytes, imported_key_id, backend=...) — offline,
    #       produces a fresh 127-byte MRKW blob bound to THIS device's Enclave public key.
    #    d. new_key_id_hash = sha256(imported_key_id)[:16].
    #       new_envelope_aad = b"MREN" || version(1) || new_key_id_hash ||
    #                           bytes.fromhex(entry["purpose_hash_hex"]) || new_wrapped_dek
    #       (164 bytes total — identical layout to step-C MREN envelope §AAD).
    #    e. new_aes_blob = AES-GCM-encrypt(dek_bytes, plaintext, aad=new_envelope_aad) with a
    #       fresh 96-bit nonce. Output bytes = nonce(12) || ciphertext || tag(16).
    #    f. envelope_bytes = new_envelope_aad ||
    #                        len(new_aes_blob).to_bytes(4, "big") || new_aes_blob.
    #    g. Persist envelope_bytes to
    #       ciphertexts/<new_key_id_hash.hex()>/<entry["purpose_hash_hex"]>/<entry["envelope_id"]>.gcm
    #       via the step-B atomic + fsync + flock helpers.
    # 8. Write meta.json (add row for imported_key_id) and
    #    digests/<new_key_id_hash.hex()>.commit (32 bytes = recomputed verification digest)
    #    under .lock with atomic semantics.
    # 9. Return imported_key_id.
    # 10. On any mid-import failure after step 6: rmtree(home / "mordred" / "keyvault"
    #     / "ciphertexts" / new_key_id_hash.hex()) and backend.delete_enclave_key(imported_key_id),
    #     then re-raise. Steps 1-5 are pre-mutation (no rollback needed).
    ...
```

**Manifest wire format** (inside the MRKV body, after PR2 header parse + AES-GCM decrypt):

```
Mordred Manifest v1 — UTF-8 JSON with canonical separators:
{
  "version": 1,
  "key_id": "<plaintext key_id>",
  "envelopes": [
    {
      "purpose_hash_hex": "<32 hex chars = sha256(purpose)[:16].hex()>",
      "envelope_id":      "<URL-safe base64, 22 chars, no padding>",
      "dek_hex":          "<64 hex chars = 32-byte DEK>",
      "manifest_aes_blob_b64": "<base64 of nonce(12)||ciphertext||tag(16)>"
    }
  ]
}
```

`manifest_aad` is **not stored in the manifest entry** — it is recomputed deterministically on import from `(manifest["key_id"], entry["purpose_hash_hex"])` so a manifest with a tampered `key_id` or `purpose_hash_hex` fails AES-GCM tag verification on import. This is the AAD-binding integrity story: any field that participates in `manifest_aad` is implicitly authenticated; tampering one field flips the GCM tag.

**Why re-encrypt** (rather than ship the original `aes_blob` unmodified): the original envelope's AAD includes the per-device MRKW prefix (`wrapped_dek_blob`, 127 bytes). The destination device has a different Enclave key and therefore a different MRKW prefix, so the original AAD cannot be reconstructed there. AES-GCM does NOT allow rebinding AAD without re-encryption — that is by design (AAD is part of the tag computation). The export side therefore decrypts under the original AAD, the manifest side carries plaintext under a *portable* AAD (no MRKW component), and the import side re-encrypts under the new device's envelope AAD. The plaintext is exposed in memory only inside `export_backup` and `import_backup`; it never touches disk.

##### File-safety semantics (step-B foundation, codex HIGH #4)

All keyvault filesystem operations MUST:

- Open files with `os.open(path, O_NOFOLLOW)` to refuse symlink-following (symlink → `KeyvaultPermissionError`).
- Reject existing files whose mode is not `0600` and directories whose mode is not `0700` via `fstat` after open (mode mismatch → `KeyvaultPermissionError`).
- Write atomically: `<file>.tmp + fsync(tmp_fd) + os.replace(tmp, final) + fsync(parent_dir_fd)`.
- Hold an exclusive `fcntl.flock` on `~/.hermes/mordred/keyvault/.lock` (mode `0600`) for the duration of any write transaction (covers generate, encrypt, export, import).
- On `meta.json` corruption (JSON parse failure / missing required keys / `version` mismatch): raise `KeyvaultCorruptError` whose `str()` does NOT include the corrupted contents (audit-safety — corrupted JSON could include secret-shaped bytes from a partially-overwritten file).

##### Audit emissions for PR4 (4 new reason codes #21-24)

See `POLICY.md` §"Phase 4 PR4 step-0 freeze" for the full table. Summary:

| # | Code | Emit site | Decision |
| --- | --- | --- | --- |
| 21 | `keyvault.init_started` | `confirm_generate` durability barrier | `allow` |
| 22 | `keyvault.init_completed` | `confirm_generate` success | `allow` |
| 23 | `keyvault.init_denied` | `confirm_generate` digest mismatch | `block` |
| 24 | `keyvault.backup_exported` | `export_backup` success | `allow` |

`encrypt` and `decrypt` are NOT audited at the api layer (codex OD-3): `encrypt` has no auth gate (wrap is offline), and `decrypt` already inherits #19/#20 via the wrap layer.

##### Capability-probe fail-on-skip (codex HIGH #5)

`is_secure_enclave_available()` returning `False` while `MORDRED_KEYVAULT_LIVE=1` is set in the environment MUST cause the live test suite to **fail** (not skip). The integration test fixture asserts the capability and the env var consistency before any per-test skip logic.

#### Explicitly out of v1

- Encryption of binaries/folder names/file names → `v2-F6`
- per-skill file-encryption mapping → `v2-F6`
- HSM/TPM/master-password fallback → `v2-OS2`
- Secure Enclave-backed signing isolation, Payment signing → `v3-P1`
- Session log encryption → requires a session-log writer seam on the Hermes side

### Plugin: `mordred_wizard` (CLI Extension)

Registers the `hermes mordred ...` subcommand tree via `PluginContext.register_cli_command("mordred", help, setup_fn, handler_fn)`. Builds the argparse subparser hierarchy inside `setup_fn(subparser)`.

Subcommands:
- `hermes mordred configure` — asks Mordred-specific questions; with `--with-hermes-setup` it first spawns `hermes setup` as a child process (skipped by default)
- `hermes mordred upgrade` — Story 1 / 1.5 single-command migration
- `hermes mordred install <skill>` — skill installation via privacy-check (a substitute until a skill install hook is added to Hermes core)
- `hermes mordred network init` — on-demand network-privacy setup (Tor / VPN / clearnet + Mullvad); separate from `configure`, re-runnable (blank Mullvad answer keeps the current secret). `--non-interactive` is flag-driven (`--path` / `--tor-binary` / `--tor-socks-port` / `--mullvad-relay` / `--mullvad-killswitch`); `--clear-mullvad` removes the stored secret. The Mullvad secret is never accepted as a CLI flag.
- `hermes mordred network use <tor|vpn|clearnet>` — manual override
- `hermes mordred network status` — show current active path
- `hermes mordred policy show` — print effective policy
- `hermes mordred policy explain <skill-id>` — explain why a given skill is allowed/blocked
- `hermes mordred policy dry-run <skill-path>` — predict install-time decision without installing
- `hermes mordred policy reload` — invalidate in-memory policy cache
- `hermes mordred audit tail [-n N]` — print last N entries from `~/.hermes/mordred/audit.log`
- `hermes mordred audit grep <pattern>` — search audit log
- `hermes mordred keyvault init` — Seed Phrase + Passphrase + PoW generation flow
- `hermes mordred keyvault list` — list key IDs (no key material)
- `hermes mordred keyvault verify-digest` — re-display digest
- `hermes mordred keyvault recover --blob <path>` — recovery on different machine
- `hermes mordred audit decrypt --date YYYY-MM-DD` — from Phase 4 onward, decrypts encrypted historical logs via Secure Enclave authorization

## Operational Guarantees & Caveats

### Audit log policy

- Path: `~/.hermes/mordred/audit.log`
- File mode: `0600` (user-only)
- Format: newline-delimited JSON (NDJSON), single writer per Hermes process, append-only
- Concurrency: serialized via an in-process write queue; multi-process scenarios are unsupported in v1
- Rotation: daily roll to `audit.log.YYYY-MM-DD`, gzip after rotation, size cap 10 MB per current file (force-rotate), retention 30 days
- Redaction: `reason` strings are a fixed enum (free-text params / full skill content are never logged). The `ReasonCode` `Literal` in `src/mordred_hermes/privacy_check/_audit_reasons.py` is the type-level source of truth for the enum; see [`POLICY.md`](./POLICY.md) §Audit log `reason` enum for the human-readable canonical list. 12 codes were frozen at Phase 1.1 step-0, with only closed-set additions per phase thereafter (Phase 3 PR1 added `network.*` +4 → Phase 4 PR2-§4.1 added `keyvault.*`/`policy.*` +10 → the PR #39 follow-up added `mordred.degraded.audit_encryption_unavailable` +1, **27 codes currently**). Existing codes are never removed or renamed
- Encryption: Phase 1-3 is plaintext NDJSON at file mode `0600`. From Phase 4 onward, new entries are encrypted with AES-GCM (the DEK is keyvault-wrapped, held in memory only)
- Phase staging: the `audit.py` writer freezes a swappable Writer interface in Phase 1, factory-swapped to `EncryptedWriter` in Phase 4

Audit entry shape (synthetic example):

```json
{
  "ts": "2026-04-29T12:34:56.000Z",
  "event": "pre_tool_call",
  "decision": "block",
  "reason": "policy.strict.clearnet",
  "tool_name": "web_fetch",
  "skill_id": "example-skill"
}
```

Fields: `ts` (ISO-8601 UTC), `event` (hook name), `decision` (`allow`/`block`/`override`/`warn`), `reason` (fixed enum), `skill_id`/`tool_name`/`provider_id` (one or another depending on the event), and optional event-specific fields.

#### Encrypted audit-log wire format (`MRAL` v1, Phase 4 PR6 freeze)

From Phase 4 onward, `EncryptedWriter` in `keyvault/log_encryption.py` (a Phase 1 `Writer` Protocol implementation) encrypts new entries with AES-GCM. The file is line-oriented — 1 entry = 1 line, preserving `O_APPEND`'s whole-entry atomicity while avoiding the need to re-encrypt the entire file:

```
Line 0   header   {"fmt":"MRAL","ver":1,"key_id":<str>,"wdek":<base64>}
Line 1+  entry    base64( nonce(12) ‖ AES-GCM-ciphertext ‖ tag(16) )
```

- `wdek` is a 127-byte `MRKW` blob produced by wrapping the audit-log DEK with `keyvault.wrap.wrap_dek`. Only the **wrapped DEK** goes to disk; the plaintext 32-byte DEK exists only in the writer's memory (its reference is discarded on `close()`).
- The DEK is **lazily generated on the first append**, not at writer creation, fresh per file. `wrap_dek` is an offline operation using the Enclave public key with no biometric prompt — **writing does not cross the authorization boundary**.
- Each entry's AES-GCM AAD = `MAGIC ‖ version ‖ SHA-256(header line)`. Since the header line contains a file-specific random `wdek`, the digest differs per file, so splicing entries from another file, or replay after tampering with the header, fails the tag check.
- Atomicity caveat: an encrypted line at maximum size (4000-byte plaintext) is about 5.4 KiB, exceeding POSIX `PIPE_BUF` (4096). `O_APPEND` atomicity is not guaranteed with concurrent multi-process writers, but since v1 does not support multi-process audit writes (§1.1 M1), invariant #2 holds under the single-process, single writer-lock model.
- Rotation is the same as the Phase 1 NDJSONWriter (daily + size cap + gzip + 30-day retention). Each rotation gets a fresh file + DEK + header. Existing foreign files (pre-Phase-4 plaintext logs, or encrypted files from another session whose DEK cannot be unwrapped without a prompt) are **rotated aside rather than overwritten**.
- Decryption is `keyvault.log_encryption.decrypt_log_file` — it unwraps the DEK via `wrap.unwrap_dek` (the Secure Enclave authorization boundary, emitting `keyvault.unwrap_authorized`), and transparently handles gzip-rotated files too. Structural / integrity errors raise `AuditLogDecryptError`; prompt rejection (`WrapAuthCancelled`) and missing key (`WrapKeyNotFound`) are propagated unwrapped so the CLI can distinguish them.
- The Keychain key id for the audit-log wrapping key is `mordred.audit-log` (`AUDIT_LOG_KEY_ID`). No new audit code — the unwrap audit is already emitted by `wrap.unwrap_dek`.

### Plugin-disable protection (plugin-side only, zero-PR strategy)

There is a risk that enforcement gets silently disabled if the user runs e.g. `hermes plugins disable mordred_privacy_check`.

**Tier A (v1 default, plugin-only strict-mode startup refusal, H3)**:

Because **zero upstream PR** was finalized in MIGRATION.md §10 row 4 (2026-05-07), v1 performs a fail-closed startup refusal on the plugin side. This is not "limited to a warning" — it is a defense that raises a `BaseException`-derived exception to stop strict-mode session startup itself:

1. At the start of each Mordred plugin's `on_session_start`, scan the sibling list `["mordred_network", "mordred_privacy_check", "mordred_llm_guard", "mordred_keyvault", "mordred_wizard"]` for any that appear in the disabled-plugins list (the equivalent of `hermes plugins list --disabled` — verified against the real API in Phase 0.8)
2. If policy is `strict` and even one sibling is disabled: raise a refusal exception equivalent to `MordredSiblingDisabled("Mordred strict mode requires all sibling plugins enabled; disabled: [...]. Re-enable via 'hermes plugins enable <name>' or downgrade policy to lenient.")` (a direct `BaseException` subclass — an `Exception` subclass such as `RuntimeError` won't work, since it would be swallowed by Hermes `invoke_hook`'s `except Exception:` wrapper and fail to stop the session), aborting the session

   > **Exception propagation contract** (2026-05-13): the refusal exception must escape Hermes `invoke_hook`'s `except Exception:` wrapper. `privacy_check/hooks.py` is legacy and **derives from `SystemExit`**; the new refusal classes from Phase 2 `llm_guard` onward (`MordredHarnessRefused` / `MordredSessionRefused`) **derive directly from `BaseException`** (so that cleanup-style `except SystemExit:` doesn't misdetect a policy refusal as a CLI exit — see `src/mordred_hermes/llm_guard/_exceptions.py`). The latter is canonical, and `privacy_check` is a candidate for unifying onto a `BaseException` subclass (`MordredSiblingDisabled` envisioned) in a follow-up. The exception names/message examples above are illustrative — the implementation follows the derivation rule above, phase by phase.
3. Simultaneously records `mordred.degraded.disable_unprotected` (decision=`block`) in the audit log
4. For `policy=lenient` / `off`, only a warning is issued (for compatibility)
5. `privacy_lock: true` in `plugin.yaml` is kept as an internal Mordred hint (used to auto-expand the sibling list; it carries no meaning on the Hermes upstream side)

**Tier B (v2 deferred, vendored fork extra)**:

Once hard enforcement is truly needed, the `pip install mordred-hermes[hard-lock]` extra is provided. It carries a patched version of `hermes_cli/plugins_cmd.py` under `vendor/hermes/<version>/`, and while `mordred-hermes[hard-lock]` pins to a specific Hermes version via `dependencies` in `pyproject.toml` at install time, it refuses the disable operation itself on the core side. No PR is submitted to Hermes upstream; it is distributed as a vendored fork. Out of scope for v1.

**Important caveat (see §Threat Model "does NOT defend against")**: Tier A is designed to block **at the next session start**. "Immediate stop if disabled while running" is out of scope for v1 (on the premise that Hermes does not reflect a plugin's dynamic disablement while a session is running, verified in Phase 0.8). The defense flow is: disable edited between sessions → next session's strict startup → block.

### Policy file caching

- Loaded at `on_session_start` (when the Hermes session starts)
- Cached in-memory for the session lifetime
- Reload via `hermes mordred policy reload` (an internal function call; a fs watcher is not introduced in v1)
- Intentional tradeoff: prevents hot-path file reads; policy edits require an explicit reload

### Plugin Versioning & Compatibility

- All 5 plugins are bundled in the single pip package `mordred-hermes`, sharing a common version
- Declares `mordred-min-hermes-version` in `[project.metadata]` of `pyproject.toml`; each plugin verifies the Hermes version in `on_session_start`
- Detects changes to Hermes upstream's hook payload types via CI (GitHub Actions), automatically filing an issue when compatibility breaks
- `mordred-hermes`'s own version is managed in `docs/VERSION` (same as the old SPEC)

### Observability

- All hook decisions (allow / block / override) are logged via the audit log policy above
- `hermes mordred policy explain <skill-id>` gives a per-skill decision trace
- `hermes mordred policy dry-run <skill-path>` predicts install-time decision without filesystem mutation
- `hermes mordred network status` reports active path + health
- LLM Guard prints the active provider override target in the startup banner
- Operates in parallel with Hermes's observability plugins (langfuse, etc.) without conflict

## Scope (Out) — explicitly deferred

> Motivation, dependencies, and priorities for post-v1 work live in [`ROADMAP.md`](./ROADMAP.md). This section only enumerates what is **excluded** from v1.

- Phase 4 keyvault on Linux / Windows native (v2-OS2)
- Harness-aware LLM Guard enforcement (v2)
- GUI controls (v2)
- Payment skills using `mordred_keyvault` (v3-P1)
- Per-skill independent network paths (v2; v1 is gateway-wide single-state)
- Skill metadata signing / integrity verification (v2)
- Multi-user / multi-tenant on a single machine (v2)
- Mordred-specific telemetry or crash reporting (v2; inherits Hermes's existing telemetry behavior)
- iOS / Android native Mordred apps (v2; only Hermes's Termux support is usable, for Phase 1-3)
- Large-scale changes to Hermes core (permanently out of scope. The zero-PR commitment means no PRs are submitted to Hermes upstream at all in v1; if hard enforcement becomes necessary in v2, it's handled via a vendored fork in the `[hard-lock]` extra; MIGRATION.md §10 row 4)

## MVP Phasing

If full v1 scope is too large for a single milestone, ship in this order. Each phase is independently usable.

1. **Phase 1 — Privacy primitives**: `mordred_privacy_check` (with skill install wrapper) + `metadata.mordred.network_requirements` + `mordred_wizard configure/upgrade/policy`. Partially achieves Story 2 and Story 3
2. **Phase 2 — LLM enforcement**: `mordred_llm_guard` + `mordred-local` synthetic provider (full Hermes adapter surface). Achieves Story 4. Adds a `pre_tool_call` generic allowlist to privacy-check
3. **Phase 3 — Network paths**: `mordred_network` (Tor + VPN + Clearnet switching, on_session_start/end lifecycle, provider transport flagging). Completes Story 3
4. **Phase 4 — Key management**: `mordred_keyvault` (Secure Enclave-backed AES key wrapping via pyobjc). Achieves Story 5. The largest engineering risk; deferrable

User-visible MVP = Phase 1 + Phase 2. This is the minimal "Hermes with Privacy" delivery.

## Operational Setup (one-time)

Required before starting development:

1. Confirm the `Mordred-Hermes/` repository (the Mordred plugin development repo; the environment must already have Hermes itself via `pip install hermes-agent`)
2. Create the `~/.hermes/` profile (automatic when running `hermes setup`)
3. Scaffold the 5 plugins: create the following in each `src/mordred_hermes/<name>/` directory
   - `plugin.yaml` — manifest (`name`, `version`, `description`, `author`, `privacy_lock`, `config_schema`)
   - `__init__.py` — entry, defines `register(ctx: PluginContext) -> None`
   - `*.py` — runtime modules (lazy import for native/heavy deps)
   - `tests/test_*.py` — pytest, colocated
   - `README.md` — Mordred-owned paths, config keys, internal API surface
4. Declare the `hermes_agent.plugins` entry point in `pyproject.toml` (the `mordred-hermes` package):
   ```toml
   [project.entry-points."hermes_agent.plugins"]
   mordred_network = "mordred_hermes.network"
   mordred_privacy_check = "mordred_hermes.privacy_check"
   mordred_llm_guard = "mordred_hermes.llm_guard"
   mordred_keyvault = "mordred_hermes.keyvault"
   mordred_wizard = "mordred_hermes.wizard"
   ```
5. CI workflow: `.github/workflows/ci.yml` (pytest + ruff + mypy), `.github/workflows/upstream-check.yml` (detects Hermes hook **name** drift; diffing payload field shape is v2)
6. ~~Submitting the HSeam-1 PR~~ → **Removed**: because of the zero-PR commitment (MIGRATION.md §10 row 4, finalized 2026-05-07), no PR is submitted to Hermes upstream. Disable protection is fully handled by the plugin-side strict-mode startup refusal (§Plugin-disable protection Tier A). If hard enforcement becomes necessary in v2, the `[hard-lock]` extra (vendored fork) is added
