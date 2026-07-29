# Mordred Roadmap (post-v1, Hermes-base)

> **Note**: This ROADMAP describes post-v1 work on the `Hermes (NousResearch/hermes-agent)` base. The old OpenClaw-based version remains at `../../mordred/mordred-mvp-docs/ROADMAP.md` (deprecated).

This document describes work **outside the MVP (v1)**. `SPEC.md` and `PLAN.md` define v1's locked scope. This file collects both "items deferred from v1" and "items explicitly never to be done".

Expected to be updated more frequently than SPEC/PLAN. Priority and ordering are fluid.

## Legend

- **Priority**: H = start immediately after v1 ships / M = decide after user feedback / L = long-term
- **Depends on**: required Hermes hook seam, OS API, external library
- **Risk**: engineering or contractual concerns

---

## Remaining browser-extension gateway integration

- **Background**: the 2026-06-30/07-01 standalone-repo split initially left the
  browser-extension server in the old repo-root `gateway/extension_*.py`
  package. At that point this repository contained only the pairing CLI and
  keyvault signing surface, so pairing correctly failed closed when the
  counterpart was absent.
- **Completed (2026-07-10)**: the server, pairing, crypto, chat, RPC, history,
  and their tests were ported into `mordred_hermes.extension` (#30). The
  packaged foreground launcher `hermes-mordred extension serve` followed in
  #32. `extension pair` now uses the packaged pairing backend first and keeps
  `gateway.extension_pairing` only as a compatibility fallback for older
  full-gateway checkouts.
- **Current state**: standalone pairing and serving work from this
  distribution. The packaged chat bridge binds to the `gateway` / `run_agent`
  runtime shipped by `hermes-agent`, and the wallet/RPC bridge calls
  `keyvault.extension_sign`; neither requires the old fork-side modules. The
  ported extension test suite lives under `tests/extension/`.
- **Remaining gap**: the server is foreground-only unless an operator manages
  it with a supervisor. Hermes exposes no plugin boot hook that can
  automatically start it as part of normal gateway startup.
- **Checklist**:
  - Decide whether to add an upstream plugin boot hook, document a
    launchd/systemd service, or keep explicit `extension serve` as the
    permanent lifecycle boundary.
  - Preserve compatibility with a full gateway already listening on the
    extension port and with the legacy `gateway.extension_pairing` fallback.
  - Keep the `extension`, `ethereum`, and optional `messaging` extras plus the
    ported tests aligned as the protocol evolves.
- **Priority**: M (lifecycle integration only; standalone functionality is
  already shipped)

---

## v2 candidates: Hermes hook extensions (PR candidates)

Re-evaluates items the old SPEC listed under "Core minimal seams" as extension points in Hermes. Corresponds to the mapping table in `MIGRATION.md` §2.

### v2-H1: Skill install hook

- **Motivation**: in v1, policy can only be enforced via the `hermes mordred install <skill>` wrapper CLI. If a user runs `hermes skills install <skill>` directly, it bypasses enforcement
- **Depends on**: a PR adding `pre_skill_install` / `post_skill_install` hooks to `hermes_cli/skills_hub.py` in Hermes core
- **Scope**: the Mordred plugin parses frontmatter in the install hook → evaluates policy → returns block/allow
- **Risk**: PR review delays would delay unifying the plugin's install path
- **Priority**: H (closes the UX gap already identified in v1 around going through the wrapper)

### v2-H2: Add `origin_skill` to the `pre_tool_call` payload

- **Motivation**: v1's `pre_tool_call` payload carries no skill-ownership information, so per-skill tool control isn't possible (only a generic tool-name allowlist)
- **Depends on**: a PR in Hermes core that traces the skill-originated tool dispatch path and adds `origin_skill` to the payload
- **Scope**: enables Mordred's `mordred_privacy_check` to implement per-skill policy
- **Risk**: tool calls fired from outside a skill (e.g., directly from the gateway) remain `origin_skill=None`
- **Priority**: M

### v2-H3: Add `provider_id` / `model_id` to the `pre_llm_call` payload

- **Motivation**: if v1's `pre_llm_call` payload doesn't include provider/model information, strict mode can only act as an unconditional override (no cloud allow-list passthrough possible)
- **Depends on**: either confirmation via Hermes Phase 0.8 verify that it's "already included in the payload," or a PR if not
- **Scope**: upgrades cloud allow-list passthrough from degraded mode to normal mode
- **Priority**: H (core functionality for a privacy product)

### v2-H4: Plugin loader hook priority control

- **Motivation**: to guarantee the v1 strict-mode bootstrap order (network → privacy_check), the plugin uses a polling fallback internally. Ideally, priority would be declared at registration time
- **Depends on**: a PR extending the Hermes `register_hook(name, callback, priority: int = 0)` API
- **Scope**: the Mordred plugin guarantees ordering via priority=100 / priority=50
- **Priority**: M

---

## v2 candidates: OS integration (largest defense expansion)

Territory unreachable from the Plugin SDK. Requires native bindings / OS-level integration.

### v2-OS1: Local malware / co-resident process mitigations

- **Motivation**: the largest gap explicitly excluded from the v1 threat model. `HTTPS_PROXY` injection can be bypassed by any process on the same machine via a direct `connect()`
- **Depends on**: macOS — `sandbox-exec` profiles / Endpoint Security Framework. Linux — `seccomp` / `landlock`. Windows — AppContainer
- **Scope**: run skill child processes spawned by Hermes under an OS sandbox. Restrict network / file / process-spawn access
- **Risk**: an improper profile could break legitimate skills. Apple Endpoint Security requires an entitlement review
- **Priority**: H (directly tied to credibility as a privacy tool)

### v2-OS2: Remaining keyvault platforms and authorization tiers

- **Current baseline**:
  - macOS: Secure Enclave on supported systems, with a software P-256
    login-Keychain fallback
  - Linux: TPM 2.0 **MVP complete** through the packaged helper; machine-bound,
    no software fallback
- **Remaining motivation**: add Windows-native custody and stronger
  authorization choices without weakening the shipped platform floors.
- **Depends on**:
  - Windows: DPAPI / CNG TPM
  - External hardware: PKCS#11 / FIDO2 token integration
  - Linux TPM presence: a PIN/PCR policy above the current machine-binding tier
- **Scope**: extend the existing `NativeBackend` selection and migration
  surfaces; OS-specific Tor/VPN work is tracked separately from key custody
- **Priority**: M
- **Linux completion detail (2026-06-09)**: Phase 1 (platform-neutral seam) +
  Phase 2a (`native/tpmkey-helper` Rust crate) + Phase 2b (`tss-esapi`
  backend with a deterministic ECC P-256 storage primary and on-chip
  `ECDH_ZGen`) + Phase 2c (`keyvault enable-tpm` CLI and wheel packaging) all
  landed. The `tpmkey-helper-tpm` CI job verifies with `swtpm`, and ECDH parity
  against software P-256 demonstrates `wrap.py` HKDF compatibility. This is
  machine binding, not Touch-ID-equivalent per-use presence.

---

## v2 candidates: feature expansion

Increases the granularity and coverage of the existing plugins.

### v2-F1: Per-skill independent network paths

- **Motivation**: v1 activates one process-wide route before provider clients are constructed and freezes it for the process lifetime. Same-route reuse is idempotent; a conflicting route is refused and requires a Hermes restart. Concurrent skills therefore intentionally share that route and cannot request independent transports
- **Depends on**: v2-H2 (`origin_skill` in `pre_tool_call`) + independent per-request/provider-client transports + per-subprocess proxy env injection via the Hermes child-process spawn API
- **Scope**: `mordred_network` provisions independent paths per skill and enforces the path declared in skill metadata, without mutating the process-global transport captured by other clients
- **Priority**: M

### v2-F2: Skill metadata signing / integrity verification

- **Motivation**: v1 can't defend against "a skill whose metadata lies" (excluded from the threat model)
- **Depends on**: a signing chain on the agentskills.io / Skills Hub side, local public-key management, and a PR adding a signature-verification hook to Hermes core (close to the forever-out-of-scope line, so it needs review)
- **Scope**: hash of the skill `frontmatter` + publisher signature; `mordred_privacy_check` verifies at install time
- **Risk**: mandatory signing leans toward modifying the core loader and sits close to the forever-out-of-scope line. **Keep the design contained within the Plugin SDK**
- **Priority**: M

### v2-F3: GUI controls

- **Motivation**: v1 is CLI-only. The UX for policy switching, path status, and audit-log review is weak
- **Depends on**: nothing in particular (choice of Tauri / Electron / SwiftUI)
- **Scope**: a status-bar app or dedicated GUI; a thin client over internal gateway RPC
- **Priority**: L

### v2-F4: Tamper-resistant audit logs

- **Motivation**: v1 audit logs are plaintext files; tamperable under the local-malware threat
- **Depends on**: nothing in particular (self-contained within the plugin)
- **Scope**: a hash chain (each entry contains the hash of the previous entry) or an append-only file format
- **Priority**: M

### v2-F5: Multi-user / multi-tenant

- **Motivation**: v1 assumes a single user / single machine
- **Depends on**: a major extension of the config schema, keyvault user isolation
- **Priority**: L (unnecessary for the individual-developer target)

### v2-F6: Trace-minimization layer (binary / folder / file-name encryption)

- **Motivation**: for legal/forensic resistance, leave no plaintext trace on disk of "when the user ran which skill." Phase 4 audit-log encryption protects only the audit log's **content** — file names, folder structure, and binaries remain plaintext
- **Depends on**: `mordred_keyvault` Tier 1 completion; investigation into whether this can be implemented as a plugin-owned overlay or requires an additive seam in Hermes
- **Scope**:
  - Encrypt skill artifacts (binaries, subdirectories) at the file/folder-name level with a keyvault-wrapped DEK, decrypting + mounting only at time of use (to the extent the Plugin SDK allows)
  - `mordred_keyvault` owns the per-skill file-encryption mapping table
  - The decrypted path exists only in memory; never write the cleartext form back to the filesystem (consider FUSE-T or macOS FileProvider)
- **Risk**: leans toward loader-level modification, close to the forever-out-of-scope line. Start only after a Plugin SDK-internal design or an explicit soft-fork strategy review. Requires selecting an OS-level transparent-FS facility (FileProvider, FUSE-T, etc.)
- **Priority**: M (escalate to H if the threat model demands it — e.g., journalist/activist use cases become concrete)

### v2-F7: Seed-display PC↔phone pairing UI

- **Motivation**: v1's `mordred_keyvault` is designed to separate passphrase entry via phone (QR + mDNS + self-signed-TLS localhost pairing). This is a design-level safety requirement, but implementing it would eat up about a week of the Phase 4 budget, so it's deferred
- **Depends on**: `mordred_keyvault` Tier 1 completion; selection of the phone-side UI (PWA / native SwiftUI / Android Compose)
- **Scope**:
  - PC side: localhost HTTPS server (self-signed TLS, mDNS advertisement, LAN-only listener)
  - Phone side: QR scan → passphrase entry → submit the digest half
  - The pairing session is single-use with a 5-minute timeout
- **Risk**: phone-side self-signed TLS UX (Safari/Chrome cert warnings); mDNS name collisions; defending against on-LAN MITM (PoW + pairing-ID confirmation)
- **Priority**: M (the v1 degraded flow displays both halves on the PC, weakening the UX-level safety guarantee; a candidate for early promotion)

### v2-F8: `config.yaml` at-rest transparent decryption

- **Motivation**: store `~/.hermes/config.yaml` in the vault and transparently decrypt it at startup (extending at-rest encryption to config, alongside `.env` / agent memory). The `.env` surface (`keyvault/_runtime_env.py`) and the agent-memory surface (`vault set-memory-key`) were both completed in v1 — the config.yaml surface has now also **landed via PR #86 (opt-in, 2026-06-03)**.
- **Why this was deferred from v1**:
  - **Low value**: secrets are designed to flow through environment variables (`.env` → `os.environ`, `hermes_cli.config.get_env_value`), and `config.yaml` is **configuration-only**. Each provider's `api_key` default is `""`, falling back to env vars like `OPENAI_API_KEY` when unset (`hermes_cli/config.py`). Real-world `config.yaml` files also contain no secrets. There's little to protect.
  - **Structural blocker (high cost)**: `config.yaml` has a single canonical loader, `hermes_cli/config.py:load_config()` (with mtime/size caching), but `cli.py` (`CLI_CONFIG = load_cli_config()` at module-import time) / `hermes_logging.py` / `hermes_time.py` / `rl_cli.py` all read it **directly via `yaml.safe_load` at import time (i.e., before the plugin loads)**. The plugin's `register()` runs after these, and **no pre-config-load hook exists either**. So a register()-time shim like the one used for `.env` can't get transparent decryption in place in time (`.env` works because it's consumed lazily).
- **Depends on**: one of the following —
  - (a) Add a pre-config-load decryption seam to Hermes core (vendored-fork **Tier B**, `UPSTREAM.md §Tier B`). **Breaks the zero-PR / plugin-only commitment.**
  - (b) A `sitecustomize` / `.pth` mechanism that intercepts interpreter startup. Preserves plugin-only status but is highly invasive to the startup path, with high risk of unexpected side effects.
- **Risk**: (a) requires a decision to break the plugin-only policy. (b) is a heavy, surprising mechanism that affects every interpreter startup.
- **Priority**: L → **landed (opt-in; decided not to enable by default)**. Secrets are already covered on the env / vault `.env` side, so this is defense-in-depth. The decision on default-enablement closed on 2026-06-03 — opt-in (`enable-config-decrypt`) is the permanent design (see Decision below).
- **Status (2026-06-03): mechanism (b) was rebuilt and landed — PR #86 merged (commit `a16e97102`)**. The initial PR #85 was closed in review, but a revised version with guards added was **merged as PR #86**. The `.pth` startup hook (`keyvault/_config_bootstrap.py` / `_pth_bootstrap.py` / `wizard/config_decrypt_cli.py`) runs **before** the import-time eager read, resolving each of #85's blockers:
  - **Narrow engagement / supply-chain**: the `.pth` file force-included at the site-packages root has a single inline guard, and imports `_pth_bootstrap` **only** when launched via the `hermes` / `hermes-mordred` console script (or with `MORDRED_CONFIG_DECRYPT=1`). It never touches pytest / pip / a plain REPL / a venv that merely happens to be named "hermes", and never probes the device key store either.
  - **`python -m hermes_cli`**: **not supported at site-init time** — at the point the `.pth` runs, `sys.argv[0]` is still `'-m'` (runpy's resolution happens afterward), so `_looks_like_hermes` returns false and it doesn't engage. Either launch via the console script, or use `MORDRED_CONFIG_DECRYPT=1` for `-m` launches. (The `/hermes_cli/` path branch is never produced by an actual `-m` launch; it only matches when argv is passed explicitly.)
  - **Profile**: home is resolved via `hermes_home()`, and the **only** thing honored is `HERMES_HOME` (a non-default sticky `active_profile` merely emits a warning and still returns `~/.hermes`; a one-off `-p/--profile` is also invisible at site-init time). The opt-in marker is per-home, so an unmanaged home is a clean no-op — to bring a non-default profile's `config.yaml` under the hook, export `HERMES_HOME`.
  - **Concurrency**: `reseal_config` closes the slow-open TOCTOU window with `unlink(missing_ok=True)`, and leaves plaintext in place if the vault open fails. The next `materialize_config` re-syncs the leftover plaintext to self-heal (disk-wins).
  - **Fail-closed**: a Hermes process that has engaged aborts with `SystemExit(1)` on a decryption error rather than starting with a default/stale config. If the manifest remains but the anchor is missing, it's treated as anchor deletion and refused.
  - **Opt-in lifecycle** (the console script is currently `hermes-mordred …`; `hermes mordred …` will work once Hermes 0.12+'s entry-point CLI wiring lands): `hermes-mordred vault enable-config-decrypt` enrolls `<home>/config.yaml`, writing the marker (`<home>/mordred/config-vault.marker`) only after a clean enroll. `disable-config-decrypt` removes the marker and guarantees readable plaintext (restoring the vault copy if it's sealed). Recovery escape hatch: `MORDRED_CONFIG_DECRYPT=0 hermes-mordred vault disable-config-decrypt` bypasses the hook (so disabling isn't blocked by the very hook it's trying to remove).
  - **Trade-off**: while a managed process is running, plaintext `config.yaml` exists on disk (mode `0o600`, weaker than `.env`'s memory-only injection) — the cost of supporting the eager direct readers without modifying Hermes core. Since `config.yaml` holds no secrets by design in the first place (`api_key` default `""` → `.env` fallback), this is defense-in-depth.
  - **Decision (2026-06-03): do not enable by default — opt-in is the permanent design**. The asymmetry of the reasoning: `config.yaml` holds no secrets by design (`api_key` default `""` → `.env` fallback), and the load-bearing at-rest surfaces (`.env` / agent memory) are already encrypted. Meanwhile, defaulting to ON would impose "`SystemExit(1)` startup abort on decryption failure + plaintext on disk while managed + the auto-exec `.pth` supply-chain surprise (a concern flagged by the scanner on PR #85)" on **every user**, including those who never asked for encryption. That cost isn't worth paying for a file with no secrets. So the explicit opt-in via `hermes-mordred vault enable-config-decrypt` is kept. The "leave no trace" requirement for high-threat users is better handled separately under v2-F6 (trace-minimization).
  - **E2E verified (2026-06-03) → v2-F8 complete**: verified the full config.yaml lifecycle (init→enable→reseal→materialize→disable + fail-closed) end-to-end on real Apple Silicon Secure Enclave hardware. Added 2 live-gated tests to `tests/integration/test_keyvault_macos.py` (`MORDRED_KEYVAULT_LIVE=1`, with `MORDRED_SEKEY_UNATTENDED=1` for no Touch ID, 4/4 passing). Currently opt-in (not enabled in the dev venv), 98% coverage.

---

## v3+ candidates: Payment layer

The other half of Mordred's reason for existing. Large-scale work to begin once v2 stabilizes.

### v3-P1: Payment skills

- **Motivation**: v1's `mordred_keyvault` protects seed/payment secrets at rest via Enclave-authorized AES key wrapping. For crypto-payment and smart-contract skills to be provided safely, additional runtime signing isolation is needed
- **Depends on**: v1 Phase 4 (`mordred_keyvault`) completion, v2-OS1 (process sandbox) completion, and a dedicated signing-backend design. Without all three in place, a path opens for "decrypting locally but silently sending to the cloud"
- **Scope**: signing JSON-RPC, transaction assembly, gas estimation, pre-signature preview UI, transaction safeguard policy
- **Risk**: Web3 skill developers could cause a major incident. The spec needs to explicitly define the liability boundary for misdirected funds
- **Priority**: H (a Mordred differentiator)

### v3-P2: x402 / agent payment protocol integration

- **Motivation**: a path for AI agents to settle API charges directly. Pairs naturally with the Mordred keyvault
- **Depends on**: v3-P1
- **Priority**: M

---

## v2+ candidates: miscellaneous

### v2-X1: Mordred-branded mobile apps

- **Motivation**: Hermes only supports Termux; there's no dedicated mobile UI for Mordred
- **Scope**: PWA or native iOS/Android. Existing desktop keyvault custody is
  available on macOS and Linux TPM 2.0, but neither backend makes keys directly
  available to a mobile app; mobile custody and pairing require their own
  design
- **Priority**: L

### v2-X2: Mordred-specific telemetry / crash reporting

- **Motivation**: v1 inherits Hermes's existing telemetry behavior
- **Risk**: a privacy tool sending telemetry is contradictory. **Put the destination and the collected fields entirely under user control**
- **Priority**: L (discussion first)

### v2-X3: Documentation reorganization — DONE (2026-06-25, ahead of GA)

- **Status**: complete. Originally planned for after GA, but moved up to align with the retirement of the `.ja.md` companion track.
- **Motivation**: `docs/` had grown flat and bloated. Wanted to reorganize docs by audience.
- **How it was actually done (changed from the original proposal)**: adopted a **two-way split by audience** rather than by topic (`strategy/` / `spec/` / `ops/`) —
  - [`user/`](../user/): for operators (QUICKSTART, USAGE)
  - [`dev/`](./): developer/project docs (SPEC, KEYVAULT_BACKENDS, SECRETS_ENV_ENCRYPTION, PLAN, TODO, PATHS, POLICY, HARNESS_PRIVACY, HOOK_PAYLOADS, MIGRATION, UPSTREAM, CI, ROADMAP, setup, VERSION)
  - [`dev/hermes/`](./hermes/): Hermes upstream reference (DESIGN, STRUCTURE)
- **Migration**: moved all files with `git mv` (preserving history), bulk-updated cross-references across the repo (~50 locations: src docstrings / tests / CI path-triggers / each README / the `pyproject.toml` Documentation URL), and rewrote the `docs/README.md` index for the user/dev structure.
- **Priority**: L (non-functional) — complete.

---

## Forever out of scope

Items Mordred will **not** do, because they would break the soft-fork / plugin-only strategy.

- **Large-scale changes to Hermes core + PRs to Hermes upstream**
  Zero-PR commitment (`MIGRATION.md` §5, 2026-05-07): **no** PRs will be submitted to Hermes upstream, ever. The v1 default is plugin-only (Tier A: wrapper CLI + audit log + strict-mode startup refusal); only items that truly need hard enforcement are addressed in v2 via a vendored-fork extra (`mordred-hermes[hard-lock]`, Tier B). Mordred-specific IDs, defaults, and recovery policy are kept on the plugin side, never placed in core (including vendored modules)
- **Loader / registry behavior changes**
  - Mandatory skill signing (loader-enforced)
  - References from core to Hermes-specific IDs (`mordred-*`)
  - A top-level `mordred:` config key (no top-level section added to Hermes config)
  - Rewriting the provider-resolution pipeline (v2-H3 is payload extension only)
- **Changing the CLI name**
  Keep `hermes mordred ...`. Don't create a standalone CLI like `hermes-mordred` (don't break Hermes users' operational habits)
- **Metadata namespace collisions**
  Use only `metadata.mordred.*`; never rewrite `metadata.hermes.*` or agentskills.io standard keys
- **Follow-up to OpenClaw upstream**
  Fully separated from OpenClaw (Story 1.5 provides migration assistance only for users who came to Hermes via `hermes claw migrate`; no PRs to or syncing with OpenClaw itself)

---

## Update rules for this document

- Before v1 ships: move items judged "deferred" during SPEC/PLAN finalization into this document
- After v1 ships: re-evaluate priority (H/M/L) based on user feedback
- When starting v2: promote ROADMAP items into SPEC/PLAN
- When adding an item to "forever out of scope": always include the reasoning in the text (just "won't do it" isn't sufficient)
