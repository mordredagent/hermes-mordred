# Mordred — Specification (Hermes-base)

> **Note**: This SPEC is the specification for Mordred, built on `Hermes (NousResearch/hermes-agent)`.
> The previous OpenClaw-based spec remains at `../../mordred/mordred-mvp-docs/SPEC.md` (deprecated).
> See `MIGRATION.md` for the rationale behind the move to Hermes and the terminology mapping.

## Vision

**Provide a privacy-enhancement layer on top of Hermes as a plugin bundle**.

Mordred is built on the principle of fully leveraging Hermes's plugin SDK and existing capabilities (4 plugin source types, 16 lifecycle hooks, and the registration API via `PluginContext`) without modifying core (independent as a plugin development repository). The privacy layer is distributed as **6 plugins + 1 skill-metadata convention**.

Users can install it with just `pip install hermes-mordred`, and configure/operate it via the `hermes-mordred ...` subcommands.

Privacy concerns addressed:

1. **network-path observability** (Phase 3, macOS / Linux / WSL2)
2. **cloud LLM dependency** (Phase 2, macOS / Linux / WSL2)
3. **local secret custody at rest** (Phase 4: Secure Enclave with a
   login-Keychain software fallback on macOS; packaged TPM 2.0 helper on
   Linux. Linux deliberately has no software-key fallback and fails closed
   when the TPM helper is unavailable. Windows-native protection remains
   deferred)

The backend-specific guarantees and remaining platform limitations are made
explicit at the Vision level. Read them together with §Platform Support and
§Threat Model (H2).

## Project Identity

### Relationship to Hermes

- **Upstream**: github.com/NousResearch/hermes-agent (MIT License)
- **Current repo**: `hermes-mordred/` (the Mordred plugin development repository; not a fork/clone of Hermes upstream)
- **Strategy**: **Option C + Vendored-fork escape hatch** (zero-PR commitment, finalized in MIGRATION.md §10 row 1 / §5 on 2026-05-07) — Hermes core is left unmodified, and 6 plugins are distributed via `pip install hermes-mordred`. **No PRs are submitted to Hermes upstream**
  - `hermes-mordred/` requires no upstream rebase (a pure plugin development repository + vendored modules when needed)
  - The plugins are developed under `src/mordred_hermes/` and exposed via `[project.entry-points."hermes_agent.plugins"]` in `pyproject.toml`; `mordred_e2e` uses the `extension/` package rather than a directory matching its entry-point suffix
  - What the old SPEC called a "core seam" is instead handled by **plugin-side wrapper + audit log** (the `mordred.degraded.*` family) for defense-in-depth (Tier A, v1 default)
  - Items that truly need hard enforcement fall under the **vendored fork extra** (Tier B, v2): a patched version of Hermes core modules is redistributed via e.g. `pip install hermes-mordred[hard-lock]`. Out of scope for v1
- **Compatibility goal**: Existing Hermes users can add the privacy layer with just `pip install hermes-mordred && hermes-mordred upgrade`. Users migrating from OpenClaw follow 3 steps: `hermes claw migrate` → `pip install hermes-mordred` → `hermes-mordred upgrade`

### Platform Support (v1)

| Phase | Platform |
|-------|-------------------|
| Phase 1-3 (network/privacy-check/llm-guard/wizard) | **macOS / Linux / WSL2** (every environment Hermes runs on) |
| Phase 4 (keyvault, macOS) | Secure Enclave on supported Macs, with a software P-256 key in the login Keychain as the fail-safe fallback |
| Phase 4 (keyvault, Linux) | **TPM 2.0 MVP complete** via the packaged `mordred-hermes-tpmkey` helper; machine-bound and fail-closed, with no software fallback |
| Phase 4 (keyvault, Windows native) | Deferred (DPAPI / TPM; ROADMAP `v2-OS2`) |

iOS / Android: Hermes itself has Termux support, but Mordred Phase 4
(keyvault) remains out of scope there. Only Phase 1-3 can run under Termux
(Tor requires additional verification).

### License Note

Hermes is MIT-licensed. Forking, commercial use, and derivative products are permitted. Mordred itself is distributed under MIT as well.

## Threat Model & Accepted Limitations

Mordred defends against:

- **Network observers** (ISP, hostile Wi-Fi, local-network adversaries) — addressed by `mordred_network` (Tor / VPN paths)
- **Cloud LLM operators** seeing prompts and outputs — addressed by `mordred_llm_guard` redirecting to a local-only provider under strict policy
- **Accidental cloud egress** when a user thinks they are local-only — addressed by `mordred_llm_guard` unconditional override under strict policy
- **At-rest secret theft** — addressed by `mordred_keyvault`: local seeds,
  backups, audit logs, and signing material are encrypted with AES-GCM
  data-encryption keys (DEKs). The wrapping key is protected by Secure Enclave
  or the login-Keychain fallback on macOS, and by a non-extractable TPM P-256
  key on Linux. These backends protect key unwrapping; they do not run AES
  itself. Windows-native DPAPI/TPM support remains deferred

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
- **LLM provider rewrite under strict mode** → **not implementable** via ~~`pre_llm_call`~~ (Phase 0.8 verify complete, [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5). Its return value is context-injection only. v1 instead treats `on_session_start` as an audit-only disk pre-check and uses the resolved `provider` in `pre_api_request` for the authoritative refusal (see §Story 4 / §Plugin: `mordred_llm_guard`)
- **Gateway dispatch policy** → implementable via `pre_gateway_dispatch` (an additional defense layer not present in the old SPEC)
- **Approval lifecycle observability** → implementable via `pre_approval_request` / `post_approval_response` (strengthened audit for dangerous tool execution)

### Defended via plugin-side strict-mode startup refusal (zero-PR strategy)

- **Silent disablement via `hermes plugins disable mordred_*`** → the v1 default is **plugin-only**: `privacy_lock: true` is a declarative marker on the five manifest-backed plugins, mirrored by the fixed six-entry `SIBLING_PLUGINS` canonical list (including `mordred_e2e`). Each runtime plugin's shared `on_session_start` integrity callback aborts strict-mode startup with `MordredIntegrityRefused(BaseException)` as soon as it detects a disabled entry (see §Plugin-disable protection below). No code discovers or expands the list from the marker. No PR is submitted to Hermes upstream (MIGRATION.md §10 row 4 zero-PR commitment). If hard enforcement is needed, it is handled in v2 via the `[hard-lock]` extra (vendored fork)

### Plugin-only fallback for missing seams

When the equivalents of the old SPEC's S2 (`originSkill` in tool_call) and S3 (`resolvedProvider` in model_resolve) are not present in Hermes's payloads, the plugin runs in degraded mode (recording `mordred.degraded.*` in the audit log, and falling back to a generic tool-name allowlist and unconditional override). Because of the zero-PR commitment (`MIGRATION.md` §5, 2026-05-07), **no PR is sent to Hermes upstream**. If it's judged that plugin-only cannot achieve this, we re-evaluate whether to escalate to the v2 vendored fork extra (Tier B, `[hard-lock]`) or make the fallback behavior permanent.

**Out-of-band agent harnesses** (Codex, Claude CLI, Cursor, Copilot, ACP adapter): since Hermes has an ACP adapter, some of these can be handled. Under strict mode, if a harness that Mordred cannot enforce is configured as primary, `hermes-mordred` startup is refused.

## Plugin-Only Architecture (zero Hermes core modifications, zero-PR strategy)

The old SPEC's "Core Minimal-Change Policy" was redefined as **zero upstream PR** per **MIGRATION.md §10 row 1 / §5, finalized on 2026-05-07**. No modifications to Hermes core are submitted at all in v1:

| Old modification proposal | v1 strategy | v2 escape hatch |
|----------|---------|-------------------|
| ~~HSeam-1: add `privacy_lock: boolean` to `plugin.yaml` in Hermes upstream~~ | **plugin-side only**: `privacy_lock: true` is kept as a declarative marker, while a fixed six-plugin canonical list drives the shared integrity callback. Strict refusal raises `MordredIntegrityRefused(BaseException)` (§Plugin-disable protection) | Redistribute a vendored fork (a patched version of `hermes_cli/plugins_cmd.py`) via `pip install hermes-mordred[hard-lock]`. Introduced in v2 if hard enforcement becomes necessary |

**Items that would seem to need core modification run on a plugin-side fallback in v1** (no PRs will be sent in the future either; escape to the v2 vendored fork if necessary):

- ~~extension to include `provider_id` / `model_id` in the `pre_llm_call` payload~~ → **Phase 0.8 verify (2026-05-10) complete**: `pre_llm_call` carries only `model`, not `provider`, and its return value is **context-injection only** (provider rewrite is structurally impossible). `pre_api_request` carries provider/model/base_url and discards callback return values, but a `BaseException`-derived refusal still stops egress through Hermes's hook wrapper. See [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5. v1 therefore performs an audit-only disk pre-check in `on_session_start`, then authoritatively validates the actual runtime provider in `pre_api_request`
- ~~extension to include `origin_skill` in the `pre_tool_call` payload~~ → the current consumed Hermes contract does not include `origin_skill` (see [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4). Since per-skill policy cannot be implemented via `pre_tool_call`, the install-time `hermes-mordred install` guard that inspects SKILL.md frontmatter is the sole per-skill enforcement path. The runtime hook provides only a generic tool-name guard
- A pre-install hook at skill install time (`hermes_cli/skills_hub.py`) → create new if needed; until then, substitute with the `hermes-mordred install` wrapper
- agent process init / shutdown hook → network setup uses plugin `register()` plus an `atexit` finalizer so the process route exists before provider clients and outlives turn/session hooks; other plugins continue to use the existing session hooks where process ownership is not required

The fields Mordred consumes are defined in `tools/hook_payload_contract.json`
and explained in [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md). The local compatibility
test and `.github/workflows/upstream-check.yml` verify both hook names and those
payload fields against the installed Hermes release and upstream `main`.

### What Mordred Adds (6 plugins)

All plugins live under `src/mordred_hermes/` and use only the Hermes plugin SDK (`PluginContext`). Distribution is as a single pip package `hermes-mordred`, supporting loading via the `hermes_agent.plugins` entry point.

> **Naming convention — read before copying any code path from this document.**
> Throughout this SPEC, `mordred_network`, `mordred_keyvault`, … are **entry-point
> names**, not importable modules. They are the plugin identities Hermes sees (and
> what you list under `plugins.enabled` in `config.yaml`). The **import path is
> different** — everything ships inside the single `mordred_hermes` package. So a
> reference like `mordred_keyvault.api.encrypt(...)` or
> `mordred_llm_guard/local_adapter.py` designates the *keyvault plugin's* `api`
> module, importable as `mordred_hermes.keyvault.api`. `import mordred_keyvault`
> raises `ModuleNotFoundError`.
>
> | Entry-point name | Import path (`pyproject.toml` `[project.entry-points."hermes_agent.plugins"]`) |
> |---|---|
> | `mordred_network` | `mordred_hermes.network` |
> | `mordred_privacy_check` | `mordred_hermes.privacy_check` |
> | `mordred_llm_guard` | `mordred_hermes.llm_guard` |
> | `mordred_keyvault` | `mordred_hermes.keyvault` |
> | `mordred_wizard` | `mordred_hermes.wizard` |
> | `mordred_e2e` | `mordred_hermes.extension.gateway_plugin` |

1. **`mordred_network`** — process-scoped route selection across Tor / VPN / Clearnet. Activates and freezes the route before provider construction, then manages child-process lifecycle (`tor`/`arti`/Mullvad WireGuard CLI) via Python `subprocess` until process exit. Provides proxy environment-variable injection (`HTTPS_PROXY`, `ALL_PROXY`, etc.) and an internal Python API (`mordred_network.api.use`, `status`, `blackout_assert`); changing a frozen route requires restart.
2. **`mordred_privacy_check`** — privacy policy enforcement at two checkpoints:
   - **Skill install guard**: while there's no pure hook available, policy is decided by reading `metadata.mordred.network_requirements` from the frontmatter via the `hermes-mordred install <skill>` wrapper CLI. Migrates to a hook-based approach once Hermes adds an install hook in the future
   - `pre_tool_call` — generic per-tool policy (e.g. blocking `web_fetch` over Clearnet under strict mode). Per-skill policy too if `origin_skill` is present in the payload; otherwise just a tool-name allowlist
3. **`mordred_llm_guard`** — registers `mordred_llm_guard/local_adapter.py` as a Hermes provider adapter + provider override under strict mode via the `pre_llm_call` hook. Turns a local OpenAI-compatible endpoint (LM Studio / Ollama / vLLM) into a synthetic provider as `mordred-local`
4. **`mordred_keyvault`** — AES key wrapping backed by Secure Enclave or the
   login Keychain on macOS and TPM 2.0 on Linux. Operated from the
   `hermes-mordred keyvault ...` CLI subtree
5. **`mordred_wizard`** — owns the canonical `hermes-mordred ...` command tree
   and registers the same handlers with Hermes as an optional compatibility
   surface. Oversees all CLI for configure / upgrade / install / network /
   policy / audit / keyvault
6. **`mordred_e2e`** — gateway messaging E2E enforcement from the `extension/` package: decrypts authenticated inbound envelopes, records reply context, and re-encrypts outbound Slack/Discord replies

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
- CLI command name: **`hermes-mordred ...`** (the standalone console script;
  canonical in documentation and operator guidance)
- Plugin Python module IDs: `mordred_network`, `mordred_privacy_check`, `mordred_keyvault`, `mordred_llm_guard`, `mordred_wizard`, `mordred_e2e` (snake_case, following Python module naming conventions)
- pip distribution: **`hermes-mordred`** from `0.1.0a16` (single real package,
  all Mordred plugins included). The previous **`mordred-hermes`** PyPI project
  becomes a metadata-only compatibility shim after the new name is reserved;
  see `MIGRATION.md` §6
- Configuration topology: per-plugin config under `plugins.mordred_<plugin-id>` in `~/.hermes/config.yaml`. Mordred plugins coordinate shared state (effective policy, active network path) via an internally-imported shared module within Hermes, **not** via a single `mordred:` top-level key
- Skill metadata: `metadata.mordred.*` (same as the old SPEC, maintaining compatibility)
- Mordred-owned filesystem paths: `~/.hermes/mordred/` (audit log, policy snapshot, keyvault state)

## Target User (v1)

**Privacy-focused individual developers**

Persona:

- macOS or Linux / WSL2 users. Phase 1-3 is multi-platform; Phase 4 key
  custody supports macOS and Linux TPM 2.0, while transparent startup
  injection and the direct OS blackout fallback retain the macOS-only
  limitations documented below
- Already using Hermes, or a user migrating from OpenClaw (via `hermes claw migrate`)
- Comfortable with the Python ecosystem
- Has experience or willingness to learn local LLM operation (Ollama / LM Studio / vLLM)
- _Nice-to-have, not required_: Web3 / cryptocurrency familiarity (relevant only when v2+ Payment skills land)

Out of scope (v2+): journalists, enterprise IT teams, GUI-only users, Windows native (use WSL2), iOS native.

## User Stories (v1)

### Story 1: Adding the privacy layer for existing Hermes users

As an existing Hermes user, I want to add the privacy layer with `pip install hermes-mordred && hermes-mordred upgrade`, reusing my existing `~/.hermes/config.yaml` and skills unchanged.

Behavior:

- Idempotent: re-running is a no-op when state already matches
- If the `plugins.mordred_*` section already exists, show a diff and prompt for overwrite
- Existing skills without `metadata.mordred.*` are treated as `network_requirements: unknown`. Lenient mode (default for upgrade) gives a one-time warning; strict mode blocks, listed in `hermes-mordred policy explain`
- Comments and key order in `~/.hermes/config.yaml` are preserved (round-trip writer via `ruamel.yaml`)
- The existing `~/.hermes/mordred/` is preserved unless `--reset` is specified

### Story 1.5: Migration from OpenClaw + Mordred-OpenClaw

Users who were using the old Mordred in an OpenClaw environment follow these 3 steps:

1. `hermes claw migrate` — migrate to Hermes (workspace, config migration)
2. `pip install hermes-mordred` — obtain the Mordred plugin suite
3. `hermes-mordred upgrade` — enable the privacy layer

`hermes-mordred upgrade` has an assist feature that, when it detects the OpenClaw-era `~/.openclaw/mordred/`, migrates policy / audit log / keyvault state to `~/.hermes/mordred/` (see PLAN.md §1.3 for details).

### Story 2: New user setup

As a new user, I want `hermes-mordred configure` to:

1. Optionally spawn `hermes setup` as a child process when `--with-hermes-setup` is passed (run Hermes's standard setup first — opt-in, skipped by default since 2026-07-16)
2. Ask Mordred-specific questions (network policy strict/lenient/off, local LLM endpoint, keyvault initialization opt-in)

This allows Hermes and Mordred to be configured with a single command by passing `--with-hermes-setup`. No Hermes core modifications.

### Story 3: Skill execution and automatic path selection

At skill install time (via the `hermes-mordred install <skill>` wrapper), `mordred_privacy_check` parses `metadata.mordred.network_requirements` from the SKILL.md frontmatter and checks it against user policy. Install is blocked on mismatch. At process registration, `mordred_network` activates one route and injects its proxy environment before provider clients are constructed; child processes spawned later inherit it where Hermes permits. The active path is process-wide and frozen: same-path reuse is idempotent, while a conflicting path requires a restart.

> **Note**: Once an install hook is added to Hermes core, the wrapper CLI will be retired in favor of going directly through the hook. Until then, the wrapper is the only policy-enforcement path.

### Story 4: Local LLM enforcement (strict-mode override)

> **Phase 0.8 verify (2026-05-10) complete — redefining Story 4's mechanism**: Hermes's `pre_llm_call` payload cannot support provider rewrite. `pre_api_request` does carry the provider/model/base_url resolved for the actual primary request; although its return value is observer-only, a `BaseException` refusal escapes the hook wrapper. v1 therefore uses `on_session_start` for disk-state pre-checks and enforces primary strict policy authoritatively in `pre_api_request`. A non-allowlisted runtime provider or a provider/endpoint mismatch is refused immediately before egress (`policy.strict.session_refused`). Hermes 0.19 auxiliary LLM calls bypass that hook, so Mordred guards their resolver seams and validates each concrete client before use. Automatic swapping to `mordred-local` remains structurally impossible and is deferred to the v2 vendored fork (Tier B, `[hard-lock]`). The zero-PR commitment (`MIGRATION.md` §5) is maintained.

When policy is `strict`, `mordred_llm_guard` validates Hermes's request-resolved provider in **every `pre_api_request`**. A provider outside `cloud_provider_allowlist` is refused before egress; an allowlisted cloud provider also requires an actual, provider-owned HTTPS `base_url` without userinfo/query/fragment. Azure Foundry remains strict-unsupported until policy can pin an exact resource endpoint; accepting the vendor suffix would allow a different tenant/resource destination. Missing, malformed, or mismatched endpoints are refused before any `prompt-once` decision and audited as `policy.strict.cloud_endpoint_mismatch` followed by `policy.strict.session_refused`. Audit/log endpoint displays are bounded, origin-only values with credential-bearing components removed. `mordred-local` is revalidated as a loopback endpoint and its runtime URL must equal the configured `local_llm_endpoint` apart from a trailing slash. Swapping providers remains deferred to v2.

Hermes 0.19 auxiliary tasks (compression, vision, title generation, and
fallbacks) call clients outside `pre_api_request`. Their declared routes are
checked at session start, and the concrete clients returned by Hermes's
`_get_cached_client`, `_get_provider_chain`, `resolve_provider_client`, and
`resolve_vision_provider_client` seams pass through the same provider/endpoint
guard. Strict startup fails closed if a required seam is missing or replaced.

Under `strict`, `mordred-local` is loopback-only. Both the configured
`local_llm_endpoint` and the resolved runtime `base_url` must be HTTP(S), must
not contain userinfo/query/fragment, must match apart from a trailing slash, and
must use either the exact loopback IP literal
`127.0.0.1` / `::1` or `localhost`; every current DNS result for `localhost`
must itself be loopback. When a process proxy is active, both `NO_PROXY`
spellings gain those exact hosts before the model client is used, and the
health probe independently sets `trust_env=False`. This boundary is checked
before the probe. An invalid endpoint or failed probe is audited as
`policy.strict.session_refused` and aborts via `MordredSessionRefused`.
Lenient/off and other non-strict compatibility modes do not apply the
loopback boundary.

### Story 5: Key management

For skills that declare `metadata.mordred.requires_keyvault: true`, `mordred_keyvault` provides `Security.framework` (via pyobjc) backed AES key wrapping. Keyvault initialization requires physically hand-transcribing the Seed Phrase + Passphrase + PoW, and is not finalized unless the verification-digest flow matches. See SPEC §Plugin: `mordred_keyvault` for details.

### Story 6: Coexistence with Hermes's existing features

Mordred plugins can coexist with Hermes's memory plugin, context engine, and
observability integrations. Hook callbacks run in registration order and Hermes
exposes no priority API that Mordred relies on. Each Mordred plugin orders its
own callbacks explicitly; cross-plugin safety uses readiness checks and must not
depend on entry-point enumeration order. See [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md)
§1.

## Scope (In) — what we build in v1

### Plugin: `mordred_network`

- **Tor connection (v1 default = official `tor` daemon)**:
  - `arti` (Rust) remains a candidate for the v1 baseline, but the v1 default is the `tor` daemon — because it has the lowest entry barrier for the v1 baseline, with well-established package-manager installs on Linux/macOS
  - **torrc isolation**: Mordred generates **its own torrc** at `~/.hermes/mordred/tor-data/torrc` and does not touch the system-wide `/etc/tor/torrc` or the user's Tor Browser configuration
  - **SOCKS5 listener**: defaults to `127.0.0.1:9050`. If an existing listener (e.g. Tor Browser, the system tor service) is detected via `lsof -i :9050`, v1 shifts through alt port `9150` (colliding with the Tor Browser default) to the port **explicitly specified in `policy.json`'s `tor_socks_port`**. Collision-resolution order: 9050 -> 9150 -> user-specified -> abort with `MordredPathBringupFailed`
  - **ControlPort**: enabled by default at `127.0.0.1:9051` (cookie auth). The cookie file is `~/.hermes/mordred/tor-data/control_auth_cookie`. **Required** for implementing the M9 liveness probe via `getinfo circuit-status`
  - **Bridge / obfs4 / Snowflake**: out of scope for v1 (use in censored environments is v2 `v2-N3`). The startup banner warns that "the v1 default Tor may fail to connect in censorship environments"
  - **Stream isolation (SOCKS auth)**: per-session and per-skill isolation are not implemented in v1. `proxy_env.isolation_token` remains an optional process-scoped building block: when supplied before route activation, it becomes the SOCKS credential used with torrc `IsolateSOCKSAuth` for the lifetime of that Hermes process. Session hooks never replace it, because provider clients snapshot proxy configuration at construction. Changing the token after activation therefore requires a process restart. Per-session/per-skill isolation remains deferred pending a client/runtime architecture that can provide independent transports (and `origin_skill` for per-skill routing, v2-H2)
- **Mullvad VPN integration (v1 = official `mullvad` CLI)**:
  - **CLI choice**: v1 uses the Mullvad **official client** (`mullvad` binary; on macOS `/Applications/Mullvad VPN.app/Contents/Resources/mullvad`, on Linux a package such as `apt install mullvad-vpn`). Running `wg-quick` directly ourselves is out of scope for v1 (handling `CAP_NET_ADMIN`/sudo is complex across OSes)
  - **Permissions**: the official client runs in the background as a system service (Linux: systemd unit; macOS: LaunchDaemon), and user commands request the daemon via IPC, so **no additional sudo is required**
  - **Killswitch (lockdown mode)**: under strict mode, `mullvad lockdown-mode set on` is enforced at bring-up (in Mullvad CLI 2026.2 the `always-require-vpn` subcommand was removed and folded into `lockdown-mode`). The OS creates no clearnet route at all when the VPN drops. Under lenient/off, the user's setting is respected (if lockdown is off, only a warning is issued)
  - **DNS leak prevention**: since the Mullvad client forces resolution through the in-tunnel resolver, there is no DNS leak in v1 (mitigated, unlike the M8 IPv6 leak)
  - **Relay selection**: defaults to `auto` (Mullvad picks the geographically nearest relay). User override via e.g. `mullvad_relay_country: "jp"` in policy.json. Multihop / wireguard-over-tor are out of scope for v1
  - **Tear-down**: `mullvad disconnect` is run by the process-exit finalizer, not `on_session_end`. Under strict mode, `mullvad lockdown-mode set off` is **not** run at the same time (lockdown is kept in place); the user exits it by starting the next process or disabling manually
  - **Platform**: macOS and Ubuntu/Debian baseline. Windows is out of scope for v1
- Clearnet (no-op path)
- **`provider_transport_flagger` v1 baseline allowlist** (verified on real hardware in Phase 0.8):
  - **Known compatible (respects HTTPS_PROXY + SOCKS5h)**: `anthropic` SDK (httpx), `openai` SDK (httpx), `gemini` (`google-genai` SDK, httpx baseline — corrected from the older `google-generativeai`/requests by the Phase 0.8 real-hardware verify; see the live-verify results in [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §Out of scope)
  - **conditional**: the `mordred-local` localhost provider — excluded from proxy routing by the NO_PROXY default and works that way, though SOCKS5h is irrelevant here
  - **Known partial / needs monitoring**: `bedrock` (boto3) — respects HTTPS_PROXY but has a quirk in botocore's DNS-resolution path, with possible DNS leak under strict + tor. `vertex` (google-cloud SDK) — some transports bypass HTTPS_PROXY; under strict mode a warning is shown and the decision is left to the user
  - **Known incompatible (candidates for startup abort under v1 strict mode when active)**: any provider beyond the above that holds a raw socket / its own transport is enumerated by the Phase 0.8 verify
  - The above is **finalized via real-hardware testing in the Phase 0.8 task before v1 ships**. The actual allowlist is distributed as a Python dict (a declarative module) bundled with the plugin. `policy.json provider_overrides` may add transport facts for internal providers, but cannot replace a bundled baseline entry; missing safety facts default conservatively
  - **Fail-closed gate integrity**: strict + Tor refuses providers that are incompatible, unverified, unknown, or unresolved. `on_session_start` checks persisted `config.yaml model.provider` / `auth.json active_provider`, and `pre_api_request` repeats the gate against the provider Hermes resolved for that exact request; CLI, environment, one-shot, and gateway overrides therefore cannot evade the transport evidence check. `pre_api_request` also refuses when configured Tor/VPN does not match the active route or that protected route is not ready. Malformed `provider_overrides` and internal errors while reading runtime state or evaluating either gate are audited as `network.transport_incompatible` and raise `MordredPathBringupFailed`. Every provider refusal preserves the process-scoped route so each later event and concurrent gateway session remains protected instead of falling through to clearnet. Lenient/off warn and continue
- Subprocess lifecycle: `mordred_network.register()` starts the configured Tor/VPN/clearnet route and freezes it before returning, which is before provider clients snapshot proxy settings. `on_session_start` only validates and reuses that route; `on_session_end` never owns it. A single process-exit finalizer tears it down
- Stable route API: `mordred_network.api.use(path)` is a no-op when the requested path is already ready. Once registration has frozen the route, a different path (or a different SOCKS isolation token) is refused with restart-required semantics; persist the desired setting and restart Hermes so provider clients and the process route are rebuilt together
- Path injection: sets `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` on spawned child processes. **NO_PROXY default**: `localhost,127.0.0.1,::1` (required to exclude Phase 2's `mordred-local` localhost communication from proxy routing). User-added entries are appended from policy.json's `no_proxy: [...]`
- **Transport coverage (M8, v1)**: proxy_env tunnels **HTTP(S) traffic only**. The following are out of the v1 defense scope, as stated explicitly in SPEC §Threat Model:
  - **DNS resolution**: with a normal `HTTPS_PROXY=http://...`, Python/curl and similar tools **resolve the name via the system resolver before** connecting to the proxy, so even over Tor the DNS query leaks to the ISP. v1's enforced mitigation: over the Tor path, use `HTTPS_PROXY=socks5h://127.0.0.1:9050` (`socks5h` performs server-side resolution). Libraries that don't respect SOCKS5h (some older HTTP clients) get a warning from provider_transport_flagger. Over the VPN path this is mitigated because the tunnel itself handles the DNS query. v2: full defense via bundled DNS-over-Tor / `mordred-dns-resolver`
  - **IPv6 traffic**: many HTTP clients bypass proxy_env for IPv6 endpoints. In v1, if a provider has an IPv6-only endpoint, traffic may **not go through the proxy** (a clearnet leak). `disable_ipv6: true` renders Tor's `ClientUseIPv6 0`, but that does not disable host IPv6 or constrain provider SDK sockets. Therefore strict + Tor aborts for providers without verified IPv6 proxy support regardless of this advisory setting; lenient warns. This is mitigated over the VPN path since the tunnel handles IPv6. Full host-level enforcement is deferred to v2-N2.
  - **Non-HTTP transport (raw TCP, UDP, QUIC, gRPC, WebSocket)**: whether HTTPS_PROXY takes effect depends on the client library. SSE / standard WebSocket (WS-over-HTTP upgrade) usually respect it, but provider plugins holding a raw socket bypass it. Warned via provider_transport_flagger's static allowlist; under strict mode, startup aborts if a known-incompatible provider is active
- **Path failure semantics (M9, v1)**:
  - **Bring-up failure** (Tor bootstrap timeout / VPN handshake fail): strict aborts the session with `MordredPathBringupFailed`; lenient shows a user-visible warning + clearnet fallback (emits audit `network.bringup_failed`); off falls back silently
  - **Liveness probe**: an internal worker thread runs `mordred_network.api.health()` at a 30s interval (Tor: SOCKS5 reachability + circuit-established check; VPN: WireGuard handshake recency + interface up). Judged path-dropped after 2 consecutive failures
  - **Mid-session drop**: strict raises `MordredPathDropped` on the next `pre_tool_call` (blocking tool execution); lenient warns + continues while keeping the path-dropped state. There is **no automatic clearnet fallback**. To choose clearnet, persist it with `hermes-mordred network use clearnet` and restart Hermes so provider clients are rebuilt on that route. Audit `network.path_dropped` is always emitted
  - **`use(path)` failure**: raises `MordredNetworkError` (including `BringupFailed`, `AlreadySwitching`, `UnknownPath`, and `PathSwitchRequiresRestart`). Silent live switching after provider construction is prohibited
- **Concurrency model (v1)**:
  - Active path is **process-wide single state**, activated before provider construction and frozen for the process lifetime. Same-path reuse is idempotent; a conflicting path requires a restart rather than applying last-write-wins
  - **Path mismatch for parallel tool_calls**: runtime per-skill path-mismatch detection is **not done in v1** — since the Phase 0.8 verify confirmed that `origin_skill` is **absent** from the `pre_tool_call` payload ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §4), per-skill blocking at runtime is structurally impossible. Per-skill enforcement exists only at install-time (`hermes-mordred install <skill>`). Automatic path switching is likewise not done in v1 (to avoid the M3 transitive failure mode). Once the `origin_skill` payload extension lands upstream, runtime detection will be reconsidered in v2-H2
  - **Parallel requests for the same path**: no restriction, executes in parallel as usual
  - **Parallel requests for different paths**: a process cannot safely provide different routes because provider clients share the frozen transport. A conflicting request is blocked with restart-required semantics. Independent per-session/per-skill routes and SOCKS5 stream isolation are under consideration for v2
- Provider transport flagging: resolves the active Hermes provider at startup and again from every `pre_api_request` payload, evaluates it against the immutable baseline plus additive `policy.json provider_overrides`, and applies the strict-Tor fail-closed behavior above
- Strict-mode bootstrap order: `mordred_network.register()` activates and freezes the configured route before it registers session callbacks or returns control to Hermes. Provider clients are therefore constructed only after the route and proxy environment are ready; activation/configuration failures raise `MordredPathBringupFailed(BaseException)` and refuse process startup. Hook registration order and `wait_until_ready()` are no longer the security boundary for initial transport activation

### Plugin: `mordred_privacy_check`

- **Skill install guard** (via the `hermes-mordred install <skill>` wrapper):
  - Reads SKILL.md from the install source path and extracts `metadata.mordred.network_requirements` from the frontmatter
  - Strict + `clearnet` → block
  - Strict + missing metadata → block with `policy.strict.unknown_metadata`
  - Lenient + missing metadata → allow + warning
- `pre_tool_call` — generic per-tool allowlist (configurable). Default strict-mode blocklist: builtin `web_fetch`, `web_search` when active network path is Clearnet. Per-skill determination too if `origin_skill` is present in the payload; otherwise just a tool-name allowlist
- Policy state: loaded from `plugins.mordred_privacy_check` in `~/.hermes/config.yaml` at `on_session_start`, cached in memory. Reload is explicit via `hermes-mordred policy reload`
- Audit logging: see §Operational Guarantees

### Plugin: `mordred_llm_guard`

- Implements the synthetic provider `mordred-local` as `mordred_llm_guard/local_adapter.py` (an adapter bundled with the plugin). Follows the Hermes provider adapter pattern and delegates to a local OpenAI-compatible endpoint (LM Studio / Ollama / vLLM). Under strict policy, “local” is enforced as the exact HTTP(S) literal `127.0.0.1` / `::1`, or `localhost` whose DNS results are all loopback; the same check covers policy and runtime URLs before any probe or model request.
- **Phase 0.8 verify (2026-05-10) complete**: `pre_llm_call` is context-injection only and cannot rewrite providers. `on_session_start` performs an audit-only disk pre-check; `pre_api_request` authoritatively enforces the actual runtime provider before egress ([`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) §5):
  - strict policy + current provider **matches** `cloud_provider_allowlist` + `allow_cloud_llm: true` + concrete `base_url` is a provider-owned HTTPS endpoint -> request continues (passthrough)
  - strict policy + missing/malformed/non-HTTPS/provider-mismatched `base_url` -> request is refused before prompting (audit `policy.strict.cloud_endpoint_mismatch` then `policy.strict.session_refused`)
  - strict policy + current provider does not match cloud_provider_allowlist, or `allow_cloud_llm: false` -> session is refused and exits (v1 default, audit `policy.strict.session_refused`). The alternative of swapping the active provider to `mordred-local` via `register_provider` + a config patch (audit `policy.strict.provider_override_at_session_start`) was confirmed structurally impossible in v1 by the Codex B2 review, so it's **deferred to v2** (Tier B `[hard-lock]` vendored fork)
  - lenient/off -> do nothing
- Hermes 0.19 auxiliary LLM routes bypass `pre_api_request`; strict validates their declared config at session start and wraps the four resolver seams listed in Story 4. Resolver drift or an unbound returned client fails closed before auxiliary egress.
- Local endpoint fail-fast: strict mode rejects invalid/non-loopback endpoints before probing, and translates health-check failure into `MordredSessionRefused`
- Harness refusal: scans configured agents at `on_session_start`; aborts startup under strict mode when a harness-based primary (Codex/Claude CLI/Cursor/ACP client) is configured

### Plugin: `mordred_keyvault`

#### Key hierarchy

`mordred_keyvault` protects the combination of **Seed Phrase + Passphrase + PoW**. Complies with the BIP39 standard; the user physically hand-writes the 24-word Seed and Passphrase.

```
secret      = SeedPhrase (24 words) + Passphrase + PoW       ← protected (user transcribes by hand)
dek         = random 256-bit AES-GCM data-encryption key     ← generated by keyvault
ciphertext  = AES-GCM(secret, dek)                           ← stored on disk as backup/state
wrappingKey = backend-protected P-256 key                    ← authorizes DEK unwrap only
wrappedDek  = wrap(dek, wrappingKey)                         ← stored next to ciphertext
```

Design decisions:

- **Withdrawn**: a design where the native hardware backend holds/derives the
  wallet signing key is not adopted in v1
- **Adopted**: the selected native backend protects only the P-256 key used
  for wrapping/unwrapping the AES DEK (Secure Enclave or login Keychain on
  macOS; TPM 2.0 on Linux)
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

`hermes-mordred keyvault init` runs the one-shot key-generation flow in the following order:

1. **Generate**: `keyvault` generates a 24-word BIP39 mnemonic (256-bit entropy + SHA-256 checksum) and computes the PoW via `pow.compute_pow(normalized_seed)`. The Passphrase is entered interactively by the user (not echoed to the PC screen).
2. **prepare**: `api.prepare_generate(seed, passphrase, pow_bytes)` → `(SeedDisplayHandle, expected_digest)` (in-memory only, no disk mutation).
3. **display**: `seed_display.display_seed(handle, surface)` — network blackout assert (fail-closed) → M4/M5 banner → displays **only the Seed** on the terminal with a 60s timer (the Passphrase is never rendered).
4. **offline confirm**: the user transcribes the seed + passphrase + `top4(PoW)` onto an offline medium, independently computes the digest, and enters that digest into the CLI.
5. **finalize**: `api.confirm_generate(handle, user_digest, backend=_SecKeyBackend())` — only on digest match does it durably persist the selected backend key + `meta.json`; on mismatch, zero state change and `keyvault.init_denied`.

#### Seed phrase display security

1. **Network blackout (M4 caveat)**: before display,
   `mordred_network.api.blackout_assert()` verifies the host is disconnected
   and is the supported path on both macOS and Linux. When
   `mordred_network` is absent, keyvault has a direct
   `SCNetworkReachability` fallback on macOS only; a Linux `ip` / `nmcli`
   direct fallback remains deferred and therefore fails closed
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

1. **macOS Secure Enclave**: hardware-backed P-256 with the configured
   authorization policy
2. **macOS login-Keychain fallback**: software P-256, used when Secure
   Enclave access is unavailable
3. **Linux TPM 2.0**: non-extractable TPM P-256 key with on-chip ECDH;
   no software fallback
4. **Windows native / external HSM / master-password tiers**: deferred

> **Linux TPM 2.0 (MVP complete 2026-06-09)**:
> `hermes-mordred keyvault enable-tpm` builds and installs the packaged
> `mordred-hermes-tpmkey` helper. A copied key blob is useless on another
> host, but this is machine binding rather than Touch-ID-equivalent presence:
> the MVP has no per-use PIN/PCR prompt. Per-use gating remains a follow-up.

#### Implementation interface

- Add `pyobjc-framework-Security` to `hermes-mordred`'s macOS extra (`pip install hermes-mordred[macos]`)
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
| 6 | 16 | `key_id_hash` | First 16 bytes of `SHA-256(logical_key_id_bytes)`. Binds the portable wire object and identifies audit events; it is not the native-store selector for profile-scoped keys. |
| 22 | 65 | `ephemeral_pub` | SEC1 uncompressed P-256 (`0x04 ‖ X(32) ‖ Y(32)`). Freshly generated by `wrap_dek` via `cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(SECP256R1())` (which itself draws from the OS RNG via OpenSSL `BN_rand_range`) — wrap is **never** deterministic and never reuses the ephemeral key. Hand-rolled scalar generation via `secrets.token_bytes` is intentionally avoided (codex review-fix-2 NIT-1) because it would require a manual modular-reduction step against the curve order. |
| 87 | 40 | `wrapped_dek` | RFC 3394 AES-KW output for a 32-byte DEK (`8 + 32 = 40` bytes; the fixed IV/AIV is internal to RFC 3394, so the blob has **no separate IV field** — codex review BLOCKER-2). |

`HEADER_LEN = 127` for `version=1`. The parser rejects any other version with `WrapParseError`.

The wire `key_id` is a portable **logical id**. Current profiles separately
derive and persist a deterministic `native_key_id` from the absolute keyvault
root and logical id. The native id selects the physical SE/TPM/Keychain item;
it is deliberately excluded from MRKW and portable backup manifests. Metadata
without `native_key_id` is legacy and continues to select the logical id for
read/ECDH compatibility.

**Algorithm — `wrap_dek(dek, key_id, native_key_id=...)`** (offline, no Enclave authorization, no user prompt):

1. Lookup the native **public** key using `native_key_id` (or the logical `key_id` for a legacy row). Keychain tags hash that physical selector; file-backed helpers receive the resulting opaque tag.
2. Generate an ephemeral P-256 keypair in software (`cryptography` library, never persisted).
3. Raw ECDH: pass the ephemeral private key + Enclave public key to `SecKeyCopyKeyExchangeResult` with `kSecKeyAlgorithmECDHKeyExchangeStandard` (NOT `…X963SHA256` — codex review HIGH-1; we want raw ECDH output, then a single explicit HKDF, not double-derive).
4. HKDF-SHA256 derive a 32-byte AES-KEK: `salt = b""`, `info = magic || version(1) || alg_suite(1) || key_id_hash(16) || ephemeral_pub(65)` (87 bytes; binds every non-secret blob field to the KEK — codex review HIGH-2).
5. `wrapped_dek = AES-KW(KEK, dek)` per RFC 3394 (32-byte DEK → 40-byte output, integrity-protected by the AIV).
6. Emit the blob; do NOT emit an audit-log entry (wrap is unauthorized, fast, no decision boundary).

**Algorithm — `unwrap_dek(blob, key_id, native_key_id=...)`** (authorized, may prompt the user):

1. `parse_header(blob)` — reject if `len(blob) != 127`, `magic != b"MRKW"`, `version != 1`, `alg_suite != 1`, or `key_id_hash != SHA-256(key_id)[:16]`. Each rejection raises `WrapParseError`.
2. Lookup the native **private** key using the separately resolved physical selector. Missing → `WrapKeyNotFound`.
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
| `kSecAttrApplicationTag` | `b"mordred-hermes.wrap." + SHA-256(native_key_id)[:16]` | Namespaced, profile-isolated physical lookup. For legacy rows `native_key_id == logical key_id`. |
| `kSecAttrLabel` | `"Mordred wrapping key " + SHA-256(native_key_id)[:8].hex()` | Human-readable in Keychain Access.app without exposing either id. |
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

def generate_wrapping_key(key_id: str, *, backend: NativeBackend, native_key_id: str | None = None) -> bytes: ...
def get_wrapping_key_public(key_id: str, *, backend: NativeBackend, native_key_id: str | None = None) -> bytes: ...
def delete_wrapping_key(key_id: str, *, backend: NativeBackend, native_key_id: str | None = None) -> None: ...
def wrap_dek(dek: bytes, key_id: str, *, backend: NativeBackend, native_key_id: str | None = None) -> bytes: ...
def unwrap_dek(blob: bytes, key_id: str, *, audit_sink: AuditSink, backend: NativeBackend, native_key_id: str | None = None) -> bytes: ...
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
    #   - handle: opaque SeedDisplayHandle consumed by seed_display.display_seed
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
    #      has any main key or any pending/committed native-key ownership
    #      record (including audit-key records), raise RuntimeError. Checked
    #      once unlocked (before init_started, to avoid a dangling audit
    #      event) and again authoritatively under the lock (TOCTOU-safe).
    #   1. Emit keyvault.init_started (audit-sink failure aborts; durability barrier).
    #   2. Under the stable lifecycle + per-root lock: re-check the re-init
    #      guard, derive the profile-scoped native_key_id, and durably write a
    #      top-level pending_native_key ownership journal BEFORE native
    #      generation. A helper may publish a key and then report a durability
    #      error; reset can safely recover that deterministic physical id.
    #   3. Generate through wrap.generate_wrapping_key(logical_key_id,
    #      native_key_id=...). key_id=None resolves to logical "default".
    #   4. Still under the same hold: write digests/<key_id_hash>.commit FIRST,
    #      then durably save the meta row containing logical key_id +
    #      native_key_id WHILE RETAINING pending_native_key (ownership commit).
    #      Only a second durable meta save removes pending_native_key. A
    #      first-save post-rename error plus failed native rollback therefore
    #      leaves row+pending and every normal operation fails closed. Failure
    #      of the second cleanup never rolls back the durably-owned key: a
    #      visible valid row with no pending is safe; a visible pending remains
    #      incomplete and requires reset.
    #   5. Emit keyvault.init_completed (sink failure suppressed; init has already succeeded).
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
    # 5. Parse manifest JSON; validate "version" == 1. Require a genuinely
    #    fresh destination: no main row, pending main journal, committed audit
    #    ownership, pending audit journal, digest, or ciphertext artifact.
    # 6. imported_key_id = manifest["key_id"]. Derive this destination
    #    profile's native_key_id, persist pending_native_key, then generate the
    #    physical key on this device. The portable logical id is unchanged.
    # 7. For each manifest entry (in declared order):
    #    a. Recompute manifest_aad = b"MRMN" || sha256(imported_key_id)[:16] ||
    #       bytes.fromhex(entry["purpose_hash_hex"]) (36 bytes, identical to export step 6).
    #    b. plaintext = AES-GCM-decrypt(bytes.fromhex(entry["dek_hex"]),
    #                                   b64decode(entry["manifest_aes_blob_b64"]),
    #                                   aad=manifest_aad).
    #    c. new_wrapped_dek = wrap.wrap_dek(dek_bytes, imported_key_id,
    #       native_key_id=..., backend=...) — offline, and produces a fresh
    #       127-byte MRKW blob whose wire hash remains logical while its DEK is
    #       bound to THIS profile's physical public key.
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
    # 8. Write digests/<new_key_id_hash.hex()>.commit, then durably save a meta
    #    row carrying imported_key_id + native_key_id while retaining
    #    pending_native_key. A separate save clears pending only after that
    #    ownership commit succeeds, under the same lifecycle/per-root lock.
    # 9. Return imported_key_id.
    # 10. On failure through the first ownership save: delete only the scoped
    #     native_key_id and remove transaction artifacts, then re-raise. If
    #     native deletion fails, retain row+pending (when the rename landed) or
    #     pending-only so reset can retry. After ownership save succeeds,
    #     pending cleanup failure never deletes the key.
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
- Acquire the stable parent-side `.keyvault.lifecycle.lock` before the per-root
  `keyvault/.lock`, and hold them across every operation that must serialize
  with reset (generate, encrypt/decrypt, export/import, and auxiliary audit-key
  provisioning). Reset holds the stable lifecycle lock through native deletion
  and root removal. Public metadata/status snapshots join that lifecycle lock
  and re-check the parent reset journal before reading. Reset durably flushes
  root removal before unlinking the journal; a failed journal-unlink flush
  re-publishes the recovery bytes before returning an error.
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
- External HSM, Windows-native DPAPI/TPM, and master-password backends →
  `v2-OS2` (Linux TPM 2.0 is already shipped)
- Secure Enclave-backed signing isolation, Payment signing → `v3-P1`
- Session log encryption → requires a session-log writer seam on the Hermes side

### Plugin: `mordred_wizard` (CLI Extension)

Provides the canonical `hermes-mordred ...` console-script tree. The wizard
also passes the same parser setup to
`PluginContext.register_cli_command("mordred", help, setup_fn, handler_fn)` as
an optional host-CLI compatibility surface.

Subcommands:
- `hermes-mordred configure` — asks Mordred-specific questions; with `--with-hermes-setup` it first spawns `hermes setup` as a child process (skipped by default)
- `hermes-mordred upgrade` — Story 1 / 1.5 single-command migration
- `hermes-mordred install <skill>` — skill installation via privacy-check (a substitute until a skill install hook is added to Hermes core)
- `hermes-mordred network init` — on-demand network-privacy setup (Tor / VPN / clearnet + Mullvad); separate from `configure`, re-runnable (blank Mullvad answer keeps the current secret). `--non-interactive` is flag-driven (`--path` / `--tor-binary` / `--tor-socks-port` / `--mullvad-relay` / `--mullvad-killswitch`); `--clear-mullvad` removes the stored secret. The Mullvad secret is never accepted as a CLI flag.
- `hermes-mordred network use <tor|vpn|clearnet>` — persist the next process route; same-route use is a live no-op, while a conflicting frozen route requires restart
- `hermes-mordred network status` — show current active path
- `hermes-mordred policy show` — print effective policy
- `hermes-mordred policy explain <skill-id>` — explain why a given skill is allowed/blocked
- `hermes-mordred policy dry-run <skill-path>` — predict install-time decision without installing
- `hermes-mordred policy reload` — invalidate in-memory policy cache
- `hermes-mordred audit tail [-n N]` — print last N entries from `~/.hermes/mordred/audit.log`
- `hermes-mordred audit grep <pattern>` — search audit log
- `hermes-mordred keyvault init` — Seed Phrase + Passphrase + PoW generation flow
- `hermes-mordred keyvault list` — list key IDs (no key material)
- `hermes-mordred keyvault verify-digest` — re-display digest
- `hermes-mordred keyvault recover --blob <path>` — recovery on different machine
- `hermes-mordred audit decrypt --date YYYY-MM-DD` — from Phase 4 onward, decrypts encrypted historical logs via the selected native backend

## Operational Guarantees & Caveats

### Audit log policy

- Path: `~/.hermes/mordred/audit.log`
- File mode: `0600` (user-only)
- Format: newline-delimited JSON (NDJSON), append-only
- Concurrency: serialized by an in-process lock and a stable hidden sidecar
  `fcntl.flock` spanning format checks, rotation, append, and rollback.
  Encrypted writers also verify active inode/header ownership before reusing
  their process-local DEK
- Rotation: daily roll to `audit.log.YYYY-MM-DD`, gzip after rotation, size cap 10 MB per current file (force-rotate), retention 30 days
- Redaction: `reason` strings are a fixed enum (free-text params / full skill content are never logged). The `ReasonCode` `Literal` in `src/mordred_hermes/privacy_check/_audit_reasons.py` is the type-level source of truth for the enum; see [`POLICY.md`](./POLICY.md) §Audit log `reason` enum for the human-readable canonical list. Closed-set additions through the prompt, transport-gate, and provider-endpoint-binding follow-ups bring the current total to **31 codes**. Existing codes are never removed or renamed
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
Line 0   legacy header   {"fmt":"MRAL","ver":1,"key_id":<str>,"wdek":<base64>}
Line 0   current header  {"fmt":"MRAL","ver":1,"key_id":<str>,"native_key_id":<str>,"wdek":<base64>}
Line 1+  entry    base64( nonce(12) ‖ AES-GCM-ciphertext ‖ tag(16) )
```

- `wdek` is a 127-byte `MRKW` blob produced by wrapping the audit-log DEK with `keyvault.wrap.wrap_dek`. Only the **wrapped DEK** goes to disk; the plaintext 32-byte DEK exists only in the writer's memory (its reference is discarded on `close()`).
- `key_id` remains the logical `mordred.audit-log` id and is what MRKW/audit
  hashes bind. Current headers additionally persist the deterministic
  profile-scoped `native_key_id` used for physical lookup. Only an absent
  field selects the legacy logical native id; JSON null, the wrong type, or a
  value that does not re-derive for the selected keyvault root fails before
  native I/O. This lets old and new rotated MRAL files coexist.
- The DEK is **lazily generated on the first append**, not at writer creation, fresh per file. `wrap_dek` is an offline operation using the selected backend's public key and therefore does not invoke private-key authorization — **writing does not cross the authorization boundary**.
- Each entry's AES-GCM AAD = `MAGIC ‖ version ‖ SHA-256(header line)`. Since the header line contains a file-specific random `wdek`, the digest differs per file, so splicing entries from another file, or replay after tampering with the header, fails the tag check.
- Atomicity: an encrypted line at the 4000-byte plaintext limit is about
  5.4 KiB. Writers do not rely on `PIPE_BUF` (a pipe/FIFO property) for
  regular-file atomicity: cooperating processes hold the stable sidecar lock
  through the write-all loop and any truncate rollback. An MRAL writer whose
  active inode/header was replaced wipes its stale DEK, rotates the successor
  intact, and creates a fresh independently decryptable file.
- Rotation is the same as the Phase 1 NDJSONWriter (daily + size cap + gzip + 30-day retention). Each rotation gets a fresh file + DEK + header. Existing foreign files (pre-Phase-4 plaintext logs, or encrypted files from another session whose DEK cannot be unwrapped without a prompt) are **rotated aside rather than overwritten**.
- Decryption is `keyvault.log_encryption.decrypt_log_file` — it snapshots a
  regular non-symlink source under the same audit sidecar used by writers,
  releases that sidecar, then unwraps the DEK via `wrap.unwrap_dek` at the
  selected native-backend boundary (emitting `keyvault.unwrap_authorized`).
  The whole logical read holds the keyvault lifecycle lease and transparently
  handles gzip-rotated files. Structural / integrity errors raise
  `AuditLogDecryptError`; prompt rejection (`WrapAuthCancelled`) and missing
  key (`WrapKeyNotFound`) are propagated unwrapped so the CLI can distinguish
  them.
- The logical audit wrapping-key id is `mordred.audit-log`
  (`AUDIT_LOG_KEY_ID`); current profiles derive a separate physical id from
  the keyvault root. No new audit code is emitted—the unwrap decision still
  records only the logical key-id hash through `wrap.unwrap_dek`.
- That logical id is reserved and cannot be selected as the main key id
  (including through an imported backup). Auxiliary generation first saves
  `pending_audit_key`, then saves `audit_key` while retaining pending, and
  finally clears pending in a second durable metadata save. The scoped audit
  factory uses `EncryptedWriter` only for a validated `audit_key` record with
  no pending record; a published-but-uncommitted or cleanup-uncertain key stays
  on the marked plaintext fallback. Re-running provisioning is idempotent. An
  exact deterministic duplicate may be adopted only when a freshly committed
  pending record proves the key predated this attempt, or when an existing
  row+pending state proves generation previously succeeded; pending-only retry
  after a native durability error remains fail-closed. Legacy main rows
  continue to select the historical global audit key when these new scoped
  records are absent; either scoped audit ownership field beside a legacy main
  row is inconsistent and forces the marked plaintext fallback.

### Plugin-disable protection (plugin-side only, zero-PR strategy)

There is a risk that enforcement gets silently disabled if the user runs e.g. `hermes plugins disable mordred_privacy_check`.

**Tier A (v1 default, plugin-only strict-mode startup refusal, H3)**:

Because **zero upstream PR** was finalized in MIGRATION.md §10 row 4 (2026-05-07), v1 performs a fail-closed startup refusal on the plugin side. This is not "limited to a warning" — it is a defense that raises a `BaseException`-derived exception to stop strict-mode session startup itself:

1. Each runtime plugin (`mordred_privacy_check`, `mordred_network`, `mordred_llm_guard`, `mordred_keyvault`, and `mordred_e2e`) registers the same integrity callback on `on_session_start`. It scans `["mordred_network", "mordred_privacy_check", "mordred_llm_guard", "mordred_keyvault", "mordred_e2e", "mordred_wizard"]` for any entry disabled by either the deny-list or an opt-in allowlist. Registering the callback from every runtime sibling is essential: disabling `mordred_privacy_check` must not disable its own detector.
2. If policy is `strict` and even one sibling is disabled: raise `MordredIntegrityRefused("Mordred strict mode requires all sibling plugins enabled; disabled: [...]. Re-enable via 'hermes plugins enable <name>' or downgrade policy to lenient.")` (a direct `BaseException` subclass — an `Exception` subclass such as `RuntimeError` would be swallowed by Hermes `invoke_hook`'s `except Exception:` wrapper), aborting the session

   > **Exception propagation contract** (2026-05-13; unified 2026-07-28): refusal exceptions must escape Hermes `invoke_hook`'s `except Exception:` wrapper and must not masquerade as CLI exits. `MordredIntegrityRefused`, `MordredHarnessRefused`, and `MordredSessionRefused` therefore derive directly from `BaseException`, not `Exception` or `SystemExit`.
3. Simultaneously records `mordred.degraded.disable_unprotected` (decision=`block`) in the audit log
4. For `policy=lenient` / `off`, only a warning is issued (for compatibility)
5. `privacy_lock: true` remains a declarative marker on the five plugins that
   have `plugin.yaml`; Hermes ignores it. Runtime enforcement uses the explicit
   six-entry `privacy_check._runtime.SIBLING_PLUGINS` tuple, mirrored by the
   wizard's canonical plugin list. The marker does not auto-discover or expand
   either list.

**Tier B (v2 deferred, vendored fork extra)**:

Once hard enforcement is truly needed, the `pip install hermes-mordred[hard-lock]` extra is provided. It carries a patched version of `hermes_cli/plugins_cmd.py` under `vendor/hermes/<version>/`, and while `hermes-mordred[hard-lock]` pins to a specific Hermes version via `dependencies` in `pyproject.toml` at install time, it refuses the disable operation itself on the core side. No PR is submitted to Hermes upstream; it is distributed as a vendored fork. Out of scope for v1.

**Important caveat (see §Threat Model "does NOT defend against")**: Tier A is designed to block **at the next session start**. "Immediate stop if disabled while running" is out of scope for v1 (on the premise that Hermes does not reflect a plugin's dynamic disablement while a session is running, verified in Phase 0.8). The defense flow is: disable edited between sessions → next session's strict startup → block. This remains plugin-only enforcement: if every runtime Mordred plugin is disabled, no plugin callback can execute; preventing that operation itself requires Tier B/core control.

### Policy file caching

- Loaded at `on_session_start` (when the Hermes session starts)
- Cached in-memory for the session lifetime
- Reload via `hermes-mordred policy reload` (an internal function call; a fs watcher is not introduced in v1)
- Intentional tradeoff: prevents hot-path file reads; policy edits require an explicit reload

### Plugin Versioning & Compatibility

- All Mordred plugins are bundled in the single pip package `hermes-mordred`, sharing a common version
- Declares `min-hermes-version` in `[tool.mordred]` of `pyproject.toml`; the
  install dependency and the `hermes-floor` CI job enforce the same floor
- Detects changes to consumed Hermes hook names and payload fields in local and
  scheduled CI
- Sources the package version from `src/mordred_hermes/__about__.py`; use
  `tools/bump_version.py` to update its human and manifest mirrors

### Observability

- All hook decisions (allow / block / override) are logged via the audit log policy above
- `hermes-mordred policy explain <skill-id>` gives a per-skill decision trace
- `hermes-mordred policy dry-run <skill-path>` predicts install-time decision without filesystem mutation
- `hermes-mordred network status` reports active path + health
- LLM Guard prints the active provider override target in the startup banner
- Operates in parallel with Hermes's observability plugins (langfuse, etc.) without conflict

## Scope (Out) — explicitly deferred

> Motivation, dependencies, and priorities for post-v1 work live in [`ROADMAP.md`](./ROADMAP.md). This section only enumerates what is **excluded** from v1.

- Phase 4 keyvault on Windows native (v2-OS2); Linux TPM 2.0 is shipped
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
3. **Phase 3 — Network paths**: `mordred_network` (Tor + VPN + Clearnet process-scoped route, registration/exit lifecycle, provider transport flagging). Completes Story 3
4. **Phase 4 — Key management**: `mordred_keyvault` (Secure Enclave /
   login-Keychain wrapping on macOS and TPM 2.0 wrapping on Linux). Achieves
   Story 5. The largest engineering risk; independently deployable

User-visible MVP = Phase 1 + Phase 2. This is the minimal "Hermes with Privacy" delivery.

## Operational Setup (one-time)

Required before starting development:

1. Confirm the `hermes-mordred/` repository (the Mordred plugin development repo; the environment must already have Hermes itself via `pip install hermes-agent`)
2. Create the `~/.hermes/` profile (automatic when running `hermes setup`)
3. Scaffold the plugins: create the following in each `src/mordred_hermes/<name>/` directory
   - `plugin.yaml` — manifest (`name`, `version`, `description`, `author`, `privacy_lock`, `config_schema`)
   - `__init__.py` — entry, defines `register(ctx: PluginContext) -> None`
   - `*.py` — runtime modules (lazy import for native/heavy deps)
   - `tests/test_*.py` — pytest, colocated
   - `README.md` — Mordred-owned paths, config keys, internal API surface

   `mordred_e2e` (added later, package dir `extension/`) is the one exception to this scaffold — it has no `plugin.yaml` manifest.
4. Declare the `hermes_agent.plugins` entry point in `pyproject.toml` (the `hermes-mordred` package):
   ```toml
   [project.entry-points."hermes_agent.plugins"]
   mordred_network = "mordred_hermes.network"
   mordred_privacy_check = "mordred_hermes.privacy_check"
   mordred_llm_guard = "mordred_hermes.llm_guard"
   mordred_keyvault = "mordred_hermes.keyvault"
   mordred_wizard = "mordred_hermes.wizard"
   mordred_e2e = "mordred_hermes.extension.gateway_plugin"
   ```
5. CI workflow: `.github/workflows/ci.yml` (pytest + ruff + mypy), `.github/workflows/upstream-check.yml` (detects consumed Hermes hook-name and payload-field drift)
6. ~~Submitting the HSeam-1 PR~~ → **Removed**: because of the zero-PR commitment (MIGRATION.md §10 row 4, finalized 2026-05-07), no PR is submitted to Hermes upstream. Disable protection is fully handled by the plugin-side strict-mode startup refusal (§Plugin-disable protection Tier A). If hard enforcement becomes necessary in v2, the `[hard-lock]` extra (vendored fork) is added
