# Mordred — Implementation Plan (Hermes-base)

> **Status**: current implementation map. Completed PR-by-PR history lives in
> Git and PR descriptions; this document describes the architecture to maintain
> now. [`SPEC.md`](./SPEC.md) defines behavior and [`TODO.md`](./TODO.md) lists
> open work.

Mordred is a standalone Python distribution loaded through
`hermes_agent.plugins`. It does not fork Hermes and does not submit changes to
Hermes upstream.

## Current architecture

One Hermes entry point, `mordred` (`plugin.py`), registers these components in
this order: keyvault, llm_guard, network, privacy_check, e2e, wizard. The
component names below are the pre-0.2.0a0 entry-point names, which survive as
config section names (`plugins.mordred_network`, ...).

| Component (former entry point) | Implementation | Responsibility |
|---|---|---|
| `mordred_privacy_check` | `privacy_check/` | Skill policy, runtime tool guard, audit log |
| `mordred_wizard` | `wizard/` | Standalone and host CLI surfaces |
| `mordred_llm_guard` | `llm_guard/` | Provider, endpoint, and harness enforcement |
| `mordred_network` | `network/` | Process-wide Tor/VPN/clearnet route |
| `mordred_keyvault` | `keyvault/` | Vault, hardware key, backup, and signing |
| `mordred_e2e` | `extension/gateway_plugin.py` | Slack/Discord E2E gateway hook, Telegram tools |

Shared policy, path, audit, YAML, provider, and terminal boundaries live at the
package root. The extension package also contains the standalone localhost
WebSocket server.

## Phase 0 — Operational Setup (one-time, blocking everything else)

Phase 0 is complete. Its rules remain the baseline for every change.

### 0.1 Repo & venv Check

- Run development work from the repository `.venv` created by
  `uv sync --all-extras`.
- Confirm `mordred_hermes.__file__` points into `src/` before testing local code.
- Isolate mutating CLI tests with `HERMES_HOME`; read-only status commands may
  use the normal profile.
- Treat `~/.hermes/hermes-agent/venv` as the released production environment.

### 0.2 Hermes Upstream Tracking Strategy (optional)

- No rebase or fork synchronization is required.
- The optional `hermes-upstream` remote is for source inspection only.
- `.github/workflows/upstream-check.yml` checks both the latest PyPI release and
  upstream `main` for hook-name and consumed-payload drift.

### 0.3 Mordred-owned paths (kept in sync with PATHS.md)

Persistent state is resolved from the active Hermes profile. Most private
state is beneath `<hermes-home>/mordred/`; extension state lives under
`<hermes-home>/extension/`, and the encryption facade deliberately manages
selected Hermes-owned `.env`, config, memory, and workspace targets.
[`PATHS.md`](./PATHS.md) owns the complete paths, permissions, writers, and
readers.

### 0.4 Plugin scaffolding pattern

- Each component provides a module-level `register(ctx)`; the single
  `mordred` entry point (`mordred_hermes.plugin`) calls them in order. No
  `plugin.yaml` ships: Hermes builds entry-point manifests from the entry-point
  name and the distribution metadata.
- The entry point names a module, not `module:register`; Hermes loads the
  module and calls `register` itself.
- Plugin boundaries expose narrow Protocols under `TYPE_CHECKING` rather than
  importing optional Hermes internals at runtime.

### 0.5 `mordred-hermes` Package Scaffold

- Python floor: 3.11; Hermes floor: 0.13.0.
- Version source: `src/mordred_hermes/__about__.py`, read by Hatch.
- Human marker, plugin manifests, the development-setup pin, and compatibility
  shim pins are synchronized by `python tools/bump_version.py <version>`; the
  top-level README remains version-agnostic and relies on its PyPI badge.
- Base install stays small. Platform and feature dependencies remain in the
  `keyvault`, `macos`, `extension`, `ethereum`, `messaging`, `tor-control`, and
  integration extras.
- `hermes-mordred` is the canonical user-facing CLI across the full Hermes
  support range. Hermes 0.19.0+ can expose the same handlers through an
  additional host-CLI compatibility surface after the plugins are enabled.
  Command examples use the canonical form; README mentions the host form only
  as a compatibility note.
- The public distribution rename is staged at the package boundary: reserve
  `hermes-mordred` independently, publish the real `0.1.0a16` distribution,
  then publish a metadata-only `mordred-hermes` shim. The import tree,
  entry-point IDs, persistent state, and native helper identifiers do not
  change. [`CI.md`](./CI.md) §Normal release owns the ordering and compatibility
  contract.

### 0.6 CI workflow

CI owns lint, formatting, strict typing, unit tests, the supported Python/OS
matrix, optional-feature coverage, package smoke tests, the Hermes floor,
hermetic Tor/TPM coverage, and native helper builds. Details and release policy
live in [`CI.md`](./CI.md).

### 0.7 ~~HSeam-1 PR~~ → Zero-PR commitment (deferred to v2 vendored fork)

No upstream PR is created. Strict mode detects a disabled Mordred sibling at
session start and aborts through the shared integrity callback. A future
vendored `hard-lock` extra remains only a roadmap option.

## Phase 1 — Privacy Primitives (`mordred_privacy_check` + metadata + wizard)

### 1.1 Plugin: `mordred_privacy_check`

- Parse `metadata.mordred.*` at skill-install time and evaluate network and
  keyvault requirements before delegation to Hermes.
- Enforce the generic strict-mode tool blocklist at `pre_tool_call`; Hermes does
  not supply `origin_skill`, so per-skill runtime enforcement is unavailable.
- Write typed audit events through the shared writer factory. Continue auditing
  with an explicit degraded marker if encrypted logging cannot be opened.
- Run sibling-plugin integrity checks at session start and poison later tool
  calls after a strict refusal.

### 1.2 Skill metadata namespace

The supported extension remains under `metadata.mordred`, with validation and
defaults defined by [`POLICY.md`](./POLICY.md). Unknown metadata is blocking in
strict mode and warning-only in lenient mode.

### 1.3 Plugin: `mordred_wizard`

The wizard owns configuration, status, policy inspection, skill-install
dispatch, network and keyvault ceremonies, encryption lifecycle, audit
inspection, plugin discovery, migration, and extension launcher commands.
Interactive flows fail safely without a TTY and destructive actions require
explicit confirmation or `--yes`.

### 1.4 Tests

Keep policy decisions pure and table-tested. Cover audit serialization,
degraded behavior, CLI parsing, non-interactive refusal, YAML preservation, and
isolated `HERMES_HOME` state.

## Phase 2 — LLM Enforcement (`mordred_llm_guard` + `mordred-local` provider)

### 2.1 Plugin: `mordred_llm_guard` (landed)

- Register the synthetic `mordred-local` provider from policy.
- Refuse known external agent harnesses under strict policy.
- Enforce the resolved primary request in `pre_api_request` using both provider
  identity and the actual `base_url`.
- Guard Hermes auxiliary LLM client construction separately because those
  calls can bypass the primary request hook.
- Permit cloud traffic only when policy, provider identity, and a
  provider-owned HTTPS endpoint all agree.

### 2.2 Wizard additions (landed)

`configure` owns policy mode, cloud allowance, provider allowlist, local model
endpoint/model ID, prompt-once behavior, and harness selection. Non-interactive
updates preserve unspecified existing values.

### 2.3 Tests (landed)

Cover provider aliases, endpoint ownership, loopback validation, harness
refusal, local endpoint health, prompt-once state, and auxiliary-client guards
without making live provider calls.

## Phase 3 — Network Paths (`mordred_network`)

### 3.1 Plugin: `mordred_network`

- Select one process-wide route before provider clients are constructed.
- Build Tor/VPN/clearnet settings without mutating an already-active conflicting
  route; changing routes requires a Hermes restart.
- Inject proxy variables only through the guarded environment boundary and
  reject known incompatible transports under strict policy.
- Monitor route health and fail closed after a strict route drops.

### 3.2 Wizard additions

`network init`, `network use`, and `network status` own operator interaction.
Secrets are written to `.env`; policy and credentials files contain references,
not copied credentials.

### 3.3 Tests

Unit tests cover route state, environment filtering, provider compatibility,
timeouts, and liveness. Docker supplies hermetic Tor/SOCKS coverage; Mullvad is
an explicitly gated live-device test.

## Phase 4 — Key Management (`mordred_keyvault`)

### 4.1 Plugin: `mordred_keyvault`

- Use Secure Enclave with login-Keychain fallback on macOS and the packaged TPM
  2.0 helper on Linux; Linux has no software fallback.
- Store encrypted envelopes and metadata under the profile-owned keyvault root
  with atomic writes, process locks, permission checks, and purpose-bound AAD.
- Provide recovery seed/digest, portable backup export/import in both the
  Python API and operator CLI, passphrase recovery, audit encryption, Ethereum
  keys, extension signing, and the macOS-only config/env materialize-and-inject
  shims plus the agent-memory at-rest encryption runtime (a wrapper around the
  memory tool seam, fail-closed).
- Keep native imports lazy so unsupported platforms can still import the
  package and report capabilities.

### 4.2 Wizard additions

The CLI owns `keyvault init/list/verify-digest/export/recover/reset`, native
helper installation, Ethereum subcommands, the lower-level vault interface,
and the `encryption` facade. Export collects recovery material through masked
prompts and publishes a new mode-`0600` MRKV snapshot without replacement.
The facade's `memory` target drives key provisioning, the marker, eager
migration, and the `setup` step for agent-memory at-rest encryption.

### 4.3 Tests

Pure-Python tests cover formats, normalization, storage, backup rollback,
recovery ordering, and fake native backends. CI builds both helpers and runs a
software TPM. Real Secure Enclave validation remains manually gated. A CI
canary test runs the memory-encryption hook against the installed upstream
memory tool, so an upstream seam refactor fails the build instead of
regressing silently.

## Cross-cutting concerns

### Documentation

Use [`README.md`](./README.md) as the only developer index. Keep current contracts in
SPEC/POLICY/PATHS/HOOK_PAYLOADS, operational policy in CI/setup, and future work
in TODO/ROADMAP. Git and PR descriptions hold change history; package-local
plugin READMEs are not separate documentation authorities.

### Testing posture

The default suite is hermetic: the root `tests/conftest.py` defaults
`HERMES_HOME` to a fresh temporary directory (cleaned up at process exit)
before anything imports `mordred_hermes`, unless the caller already set
`HERMES_HOME` — an explicit value always wins untouched. Live tests require
their documented environment gate and never run accidentally. A test that
needs its own isolated or per-test `HERMES_HOME` still sets/unsets it
explicitly (e.g. via `monkeypatch`) rather than relying on ambient state.

### Type/build/lint posture

Run pytest, Ruff lint/format check, and
`mypy --strict src tools scripts/keyvault_offline_digest.py` through uv.
Optional imports stay behind lazy or `TYPE_CHECKING` boundaries so CI's reduced
extras remain valid.

### Boundary discipline

- No upstream Hermes modifications.
- No implicit writes outside the active Hermes home.
- No plaintext secret values in policy, credentials references, logs, or error
  messages.
- No network fallback that bypasses the selected route.
- Fail closed for key custody and mandatory E2E; audit fail-open only where the
  explicit degraded marker preserves observability.

### Versioning & SDK compatibility

The package and all plugin manifests share one version. The machine contract in
`tools/hook_payload_contract.json`, its static scanner, and compatibility tests
detect Hermes drift. The 0.13.0 floor and latest release are tested separately.

### Hook payload realities (Phase 0.8 verify complete — 2026-05-10)

Mordred consumes only the fields listed in
[`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md). The current contract is verified
against installed Hermes and upstream `main`; the original 0.11.0 survey is
historical context, not the source of truth.

## Risks and unresolved decisions

- Proposed Linux private Telegram support: review the
  [design](SPEC.md#linux-private-telegram-design) and
  [implementation plan](#linux-private-telegram-implementation-plan) before execution.
  The proposal uses a dedicated TPM-wrapped memory key rather than the
  macOS-only file vault; it is not yet implemented.

- Automatic lifecycle integration for `extension serve` is undecided.
- Hermes still provides no `origin_skill` for per-skill runtime enforcement.
- Process-wide provider/proxy construction prevents independent concurrent
  per-skill routes.
- Co-resident malware and OS-level traffic bypass remain outside the plugin
  threat boundary.
- Secure Enclave and live LLM paths require periodic on-device validation.
  Live VPN validation is manual-only, including its explicitly dispatched
  GitHub Actions workflow.

## Recommended execution order

1. Pick an unchecked item from [`TODO.md`](./TODO.md) and confirm it belongs to
   the current release rather than the roadmap.
2. Update SPEC/PLAN first when behavior or cross-plugin contracts change.
3. Implement one plugin per PR and update its canonical SPEC/PLAN/PATHS/POLICY
   sections in the same PR.
4. Run the reduced-extras compatibility checks when touching optional
   dependency code.
5. Record one-line Changes/Fixes entries in the PR description; do not create a
   `CHANGELOG.md`.

Current in-flight item: agent-memory at-rest encryption, in three PRs — docs
first, then the keyvault runtime hook, then the wizard lifecycle and `setup`
step.

## Linux Private Telegram Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans
> for the recommended in-session execution, or superpowers:subagent-driven-development
> if selected by the user. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable private Telegram on Linux with TPM-protected memory and verify
the complete flow on EC2 without weakening existing privacy checks.

**Architecture:** A dedicated Linux memory-key provider reuses TPM wrapping and
the existing memory hook; it does not depend on the macOS-only file vault.
CLI and Desktop select platform-specific hardware/setup paths. Deliver the
cross-component contract first and implementation slices in dependency order.

**Tech Stack:** Python 3.11+, pytest, existing cryptography/wrap helpers, Rust
TPM helper/libtss2, FastAPI, existing Desktop JavaScript, Ubuntu EC2 and swtpm.

**Spec:** [Linux Private Telegram Design](SPEC.md#linux-private-telegram-design).
Status: implementation authorized on 2026-10-07. The separately requested
unchanged-code NitroTPM baseline (Task 0A) is complete. Component implementation
is complete on `feat/linux-private-telegram`; final real-device acceptance
is recorded in CI.md. Live-account acceptance and PR publication remain pending.
Implementation scenarios are covered by the named suites; individual test names
may differ from the initial plan. References to component PR commits below mean
local component commits until publication is explicitly selected.

### Global Constraints

- Python 3.11 remains the minimum; no Hermes upstream changes or PRs.
- Linux requires a working TPM 2.0 helper; no software-key fallback.
- Memory remains AES-256-GCM in the existing `memory_crypto` format.
- macOS retains existing key storage, `.env` injection, and setup behavior.
- No portable recovery/export for the Linux memory key in this feature.
- Use isolated `HERMES_HOME`, profile-owned native key storage, and port 7799.
- Never log credentials, OTP/2FA, plaintext messages, memory keys, or passphrases.
- Land SPEC/PLAN contracts first; one component per implementation PR to `dev`.
- All Python checks use `uv run` or the intended `.venv/bin/python`.

### Review Focus

- An old Hermes interpreter or already running gateway must not consume a new
  sealed profile without the TPM-aware hook: Tasks 2 and 3 test this boundary.
- A profile switch or a conflicting ambient key must not reuse another home's
  key: Task 2 tests runtime resolution; Task 3 tests explicit adoption.
- Missing/corrupt TPM state after setup must preserve ciphertext and refuse:
  Tasks 1, 2, and 6 cover hardware, file, and process boundaries.
- Interrupted or concurrent setup/disable/purge must not rotate or lose the
  only key: Tasks 1 and 3 cover retry, publication, and concurrent resealing.
- Older Desktop assets/API responses must never imply Linux is ready merely
  because its platform is recognized: Task 5 tests compatibility and readiness.

### Task 0: Contract review and docs-first slice

**Files:** `docs/dev/SPEC.md`, `PLAN.md`, `TODO.md`, `PATHS.md`.
**Interfaces:** Produces the approved provider/lifecycle/API contracts below.

- [x] Review dedicated TPM memory-key custody against the alternative of a full
  Linux file-vault port, including lack of portable recovery and freshness.
- [x] Finalize proposed support/path language while clearly separating pending
  work from currently shipped macOS-only support. Preserve all existing headings.
- [x] Run `uv run pytest -q tests/test_docs_links.py`; expect all links to pass.
- [x] Create the docs-only commit before implementation commits; preserve user edits.
- [ ] Publish the docs-first and component PRs to `dev`, using the repository's
  Changes/Fixes convention, after the user selects integration.

### Task 0A: Verify the unchanged Linux TPM implementation first

**Files:** Existing `native/tpmkey-helper/`, `keyvault/wrap.py`,
`keyvault/_seckey_backend.py`, and `extension/telegram/tee.py`; record evidence
in `docs/dev/CI.md` and sanitized local artifacts. This is a baseline probe,
not implementation of Linux Telegram support.

**Interfaces:** Exercise the production JSON helper protocol, Python
`wrap_dek`/`unwrap_dek`, and `TeeSecretStore` with synthetic secrets. These are
three separate layers; successful Rust tests alone do not prove Python wiring.

- [x] Pin the unchanged baseline to `f3211c6fb20b42d610feb00cfd6ed8d20681c888`.
  Record package import paths and build hashes. Keep results distinct from
  later feature commits so a new change cannot hide an existing defect.
- [x] Review the baseline Linux CI log, checking that `MORDRED_TPM_TEST=1` and
  the swtpm TCTI were set rather than merely counting tests that return early.
  Planning evidence: the baseline
  [TPM CI job](https://github.com/mordredagent/hermes-mordred/actions/runs/37553702848/job/112574899420)
  passed all 64 tests, including key generation, duplicate rejection, public-key
  retrieval, P-256 ECDH parity, blob substitution rejection, and deletion.
- [x] At the user's request, prioritize actual NitroTPM over another emulator
  run: clone the stopped validation disk into a NitroTPM-enabled UEFI AMI and
  run the pinned source in a separate checkout and test home. Run
  `env MORDRED_TPM_TEST=1 TCTI=device:/dev/tpmrm0 cargo test --locked -- --test-threads=1`
  from `native/tpmkey-helper`. All 64 tests passed; no gated TPM assertion was
  skipped. The prior non-TPM EC2 remained stopped.
- [x] Build the actual helper and call its stdin/stdout protocol from separate
  processes: probe, generate, public_key, ECDH, duplicate generate, missing-key
  lookup, delete, and idempotent delete. Compare ECDH with Python P-256.
- [x] Exercise the installed Python backend through `wrap_dek`/`unwrap_dek`
  and `TeeSecretStore.store`/`load` using synthetic values and the real helper.
  Verify the wrap survives process restart and actual EC2 stop/start with
  persistent state. Check file modes and that no plaintext secret is on disk.
- [x] Select an unavailable device, corrupt test-owned ciphertext, try a wrong
  profile, and copy opaque key blobs to a second actual NitroTPM. Every access
  refused; valid ciphertext remained usable after restoring the test input.
  No software fallback or replacement keys were used.
- [x] Prepare a NitroTPM-enabled Linux test target as described in Task 6.
  First verify available ECC curves, P-256 ECDH, permissions, and helper probe.
  Run the native gated suite with `TCTI=device:/dev/tpmrm0` (or the detected
  real device), then run Python production smoke tests with the test/emulator
  environment overrides removed. Repeat across process and EC2 stop/start.
- [x] Report a baseline matrix: native helper, Python wrapping, Telegram secret
  store, emulator, and NitroTPM each get an independent pass/fail/not-run result.
  If a layer fails, investigate and fix it in a separate keyvault/native slice
  before Task 1; re-run the same reproducer. If the EC2 TPM lacks required
  algorithms, do not treat emulator success as proof of EC2 hardware support.

Result: actual NitroTPM custody, Python integration, cross-instance rejection,
stop/start persistence, CLI installation, and deletion all passed. No baseline
product defect was found in these exercised paths. Linux memory encryption
remains inactive, as expected. Full evidence scope and limitations are recorded
in [CI.md](CI.md#manual-live-device-validation-log).

### Task 1: Keyvault — isolated Linux memory-key custody

**Files:** Create `src/mordred_hermes/keyvault/_memory_key.py` and
`tests/test_keyvault_memory_key.py`; reuse `_seckey_backend.py`,
`_seckey_helper.py`, `_storage.py`, and `wrap.py` without changing their formats.

**Interfaces:** The new module exports:

```python
MEMORY_KEY_PROVIDER_VERSION = 1
def memory_key_path(home: Path) -> Path: ...
def memory_key_id(home: Path) -> str: ...
def linux_memory_backend(home: Path) -> NativeBackend: ...
def load_linux_memory_key(*, home: Path, backend: NativeBackend | None = None) -> bytes: ...
def ensure_linux_memory_key(*, home: Path, adopted_key: bytes | None = None,
                            backend: NativeBackend | None = None) -> bytes: ...
def delete_linux_memory_key(*, home: Path, backend: NativeBackend | None = None) -> None: ...
```

Use `MemoryKeyError` for custody failures and retain the cause. Missing hardware
must never construct a software or Keychain backend. Delete is a low-level
primitive; only the lifecycle can authorize deletion after memory restoration.

- [x] Write failing tests `test_tpm_key_survives_new_process`,
  `test_two_profiles_have_distinct_keys`, `test_no_software_fallback`,
  `test_corrupt_or_missing_key_never_regenerates`,
  `test_concurrent_enable_publishes_one_key`, and
  `test_publication_failure_preserves_existing_material`. Assert 32-byte keys,
  a 127-byte wrapped blob, mode `0600`/parent `0700`, no plaintext key on disk,
  no symlink following, and unchanged old material on failure.
- [x] Run `uv run pytest -q tests/test_keyvault_memory_key.py`; confirm failure
  because the provider is absent, not because a real TPM was accidentally used.
- [x] Implement the interfaces, home-derived identity, explicit TPM helper
  selection, private atomic no-replace publication, and interprocess locking.
  Inspect existing profile-native-ID conventions before finalizing the adapter.
- [x] Rerun the new tests plus `tests/test_keyvault_tpm_dispatch.py` and
  `tests/test_keyvault_profile_native_ids.py`; all must pass.
- [x] Commit the keyvault slice after Task 2 also passes; no wizard/UI edits in
  this component PR. Document the new path with the contract.

### Task 2: Keyvault — runtime resolution and actual-interpreter probes

**Files:** Modify `keyvault/_memory_key.py`, `_memory_hook.py`,
`_runtime_probe.py`; extend `tests/test_keyvault_memory_hook.py`,
`test_keyvault_memory_integration.py`, `test_keyvault_runtime_probe.py`, and
`test_keyvault_memory_hook_canary.py` (paths beneath `src/mordred_hermes/` or
`tests/` respectively).

**Interfaces:** Add to `_memory_key.py`:

```python
def resolve_memory_key(*, home: Path, platform: str,
                       environ: Mapping[str, str]) -> bytes | None: ...
```

Keep `runtime_memory_encryption_available`'s existing signature for the
non-mutating capability probe, and add to `_runtime_probe.py`:

```python
def runtime_memory_key_available(*, home: Path,
                                 runtime_python: Path | None = None,
                                 timeout: float = 10.0) -> tuple[bool, str]: ...
```

The latter unwraps through the installed provider and tests a synthetic
encrypt/decrypt round trip in RAM. It reports only success or a sanitized reason.

- [x] Add failing tests `test_linux_hook_resolves_live_home_key`,
  `test_managed_key_failure_never_falls_back_to_environment`,
  `test_sealed_memory_preserved_without_tpm`,
  `test_linux_hook_installs_before_plugin_registration`,
  `test_linux_probe_rejects_old_provider`, and
  `test_actual_runtime_probe_roundtrip_emits_no_secret`.
  Include safe mode, profile changes, corrupt ciphertext, and a different venv.
- [x] Run the four named existing test files with `uv run pytest -q`; capture
  the expected new failures before changing the runtime.
- [x] Route `_HookConfig.key` through the provider without import-time hardware
  access or a process-global key cache. Preserve macOS environment semantics.
  Translate custody failures to the hook's existing fail-closed errors.
- [x] Extend Linux capability checks to require provider version 1 and implement
  the RAM-only key probe, including bounded timeout and sanitized output.
- [x] Rerun those tests and Task 1 tests. Run the upstream memory canary using
  the installed Hermes seam, not only fakes. Commit the keyvault PR.

### Task 3: Wizard — Linux memory lifecycle and uninstall

**Files:** Modify `wizard/memory_cli.py`, `encryption_cli.py`,
`_runtime_gate.py`, and `uninstall_cli.py`; extend
`tests/test_wizard_memory_cli.py`, `test_wizard_runtime_gate.py`,
`test_uninstall_cli.py`; create `tests/test_wizard_linux_memory.py`.

**Interfaces:** Preserve enable/disable/purge entry points. Add optional
`supported_platforms: tuple[str, ...] = ("darwin",)` to `runtime_gate`; only the
memory caller passes `("darwin", "linux")`. Consume Task 1 custody and Task 2
probes. Do not enable Linux `.env` or config status as a side effect.

- [x] Write failing tests `test_linux_enable_never_opens_file_vault`,
  `test_key_probe_failure_leaves_marker_and_memories_unchanged`,
  `test_existing_sealed_memory_requires_verified_adoption`,
  `test_disable_reenable_reuses_key`, `test_purge_refuses_concurrent_reseal`,
  `test_uninstall_restores_linux_memory_before_removing_hook`, and
  `test_status_never_unwraps_or_claims_env_support`.
- [x] Run those four test files and record the expected new failures.
- [x] Implement Linux gates, explicit adoption validation, provision/probe/arm
  ordering, and migration through existing sealing helpers. Require the actual
  runtime and identified gateways to pass. A probe bypass never bypasses TPM
  or key validation. Refuse already running incompatible processes.
- [x] Implement Linux disable/purge/uninstall through the dedicated provider;
  retain keys until plaintext restoration succeeds and no sealed files remain.
  Preserve recoverable state and accurate errors after partial failures.
- [x] Extend memory status with Linux capability/artifact/drift checks without
  decrypting. Re-run all four test files and existing encryption status tests.
  Confirm macOS behavior and `.env`/config gate behavior remain unchanged.
- [x] Commit this wizard slice together with Task 4 after both pass.

### Task 4: Wizard — Telegram setup and diagnostics

**Files:** Modify `wizard/telegram_setup_cli.py`, `telegram_cli.py` as needed;
extend `tests/extension/test_telegram_setup.py` and
`tests/test_keychain_prompt_counts.py`.

**Interfaces:** Preserve `run_checks() -> list[Check]` and CLI arguments. Add
the hardware-neutral `hardware` check while retaining the legacy
`secure_enclave` check. Reuse existing `enable_tpm()` / `enable_se()`.

- [x] Add failing tests `test_linux_setup_uses_tpm_and_memory_only`,
  `test_linux_doctor_reports_tpm_without_keychain`,
  `test_linux_setup_explains_presence_and_recovery_limits`, and
  `test_macos_setup_preserves_shared_flow`. Assert no Linux env enrollment,
  Xcode instructions, fake Touch ID promise, or printed secrets.
- [x] Run the two named suites, then implement OS-aware setup and remediation.
  Explain recovery and unattended TPM access before provisioning. Use host-local
  model wording and platform-appropriate restart instructions.
- [x] Rerun both suites and Task 3 tests; commit the wizard PR. Linux CLI support
  can now be tested with synthetic fixtures before Desktop changes land.

### Task 5: Desktop/extension — Linux setup and compatibility

**Files:** Modify `desktop/api.py`, `desktop/assets/desktop/plugin.js`, and
Telegram guidance in `extension/telegram/tee.py`/`skill/SKILL.md` as needed;
extend `tests/extension/test_desktop_api.py`, `test_desktop_platform.py`,
`test_telegram_memory_guard.py`, and `test_telegram_hermes_tools.py`.

**Interfaces:** Add `async def hardware_build() -> Any` at `/hardware/build`.
Keep `/enclave/build` Darwin-only. Implement the status metadata and Linux
memory-enable response contract from the design; preserve existing errors on
unsupported operating systems and macOS compatibility behavior.

- [x] Add failing tests `test_linux_hardware_build_dispatches_tpm`,
  `test_linux_memory_enable_does_not_create_vault_passphrase`,
  `test_linux_status_separates_platform_support_from_readiness`,
  `test_unsupported_platform_has_no_setup_side_effects`, and
  `test_old_client_or_missing_metadata_fails_safely`.
- [x] Run the four named suites, then implement API and page changes. Select
  hardware labels and build errors from explicit metadata; eliminate English
  text matching as a readiness predicate. Retain all Telegram privacy gates.
- [x] Rerun the four suites. Check JavaScript syntax with
  `node --input-type=module --check < src/mordred_hermes/desktop/assets/desktop/plugin.js`.
- [x] Exercise the actual packaged Desktop in Task 6, then commit this slice.
  Update `docs/user/TELEGRAM.md` and related user-facing claims only with the
  supported/tested hardware scope and explicit recovery limitation.

### Task 6: EC2 — progressive integration and acceptance

**Files:** Create `tests/integration/test_linux_telegram_tpm.py` and an
operator runbook in `docs/dev/setup.md`; update `docs/dev/CI.md` with observed results.
Add hermetic coverage to `.github/workflows/ci.yml` without adding automatic
live account/hardware tests. Commit integration changes in a final dedicated
validation PR, after component PRs.

**Interfaces:** Integration tests require explicit
`MORDRED_LINUX_TELEGRAM_TEST=1` and a test-owned `HERMES_HOME`. A synthetic client
drives `TelegramService`; no account or model credentials are required for the
repeatable path. Native TPM tests retain `MORDRED_TPM_TEST=1` / `TCTI` conventions.

- [x] Recover the earlier AWS profile, instance ID, SSH key path, and host-key
  evidence from local validation artifacts; inspect instance/AMI TPM state.
  This planning pass already found the stopped instance and absent TPM support.
- [x] At feature execution time reuse the NitroTPM instances from Task 0A,
  refresh their public
  IP and restricted SSH ingress if necessary, and verify its host key. Create a
  new checkout and test home; preserve the earlier Desktop build and evidence.
- [x] Use Task 0A's unchanged Linux baseline for comparison and capture each
  feature build's interpreter/package paths.
  Install only CI extras in one venv (`dev,keyvault,extension`), and include
  `telegram` in a separate feature/integration venv.
- [x] After Tasks 1–2, run TPM wrap/read/write across fresh processes on actual
  NitroTPM; keep an additional swtpm run as hermetic CI coverage.
  After Tasks 3–4, enable, seal, restart Hermes, read/write, disable/re-enable,
  and purge synthetic memory. Assert no plaintext/key leaks and no fallback on
  emulator loss, wrong profile, corrupt key, or unsupported memory seam.
- [x] After Task 5, verify the packaged Desktop page, TPM build action, memory
  setup, diagnostics, and restart. Install into Desktop's actual interpreter,
  compare installed asset hashes, and retain screenshots. Reuse the previous
  Xvfb/Openbox setup with software rendering where needed. Tunnel loopback
  services; do not expose Desktop, TPM emulator, or gateway ports publicly.
- [x] Reuse the verified NitroTPM targets and AMI from Task 0A; provision a
  replacement only if they are unavailable, with a reviewed launch configuration.
  Use encrypted EBS, scoped access, tags, and bounded test lifetime. Probe P-256/ECDH and run the
  same custody/lifecycle tests against the device, without an emulator `TCTI`.
  A copied disk without original TPM state must not open sealed material.
- [x] Run synthetic Telegram sync/list/ask/cancel through CLI/service, extension,
  and Desktop boundaries with real TPM custody. Check read-only RPC enforcement,
  encrypted archive files, sealed memory, and Venice/local-only routing.
- [ ] Run the separate operator-assisted live Telegram acceptance flow: login,
  minimal read-only sync, one question, cancellation, and logout. Record a
  pending gate if credentials or an eligible account are unavailable; never
  report synthetic success as live account success.
- [x] Run `uv run pytest -q`, Ruff check/format, strict mypy with reduced extras,
  `shellcheck scripts/*.sh native/*/build.sh`, and coverage (at least 80%) on
  Linux. Run relevant macOS regressions and gated Secure Enclave validation if
  shared hardware behavior changed. Use the existing CI Python 3.11–3.13 matrix.
- [x] Self-review the plan's five failure modes against results; request an
  independent implementation review under the execution skill before merging.
  Store sanitized evidence and separate emulator/NitroTPM/live-account results
  in the CI manual log; update pending TODO items only when their gates pass.
- [x] Stop task-owned EC2 instances, verify final states, and report residual
  volumes/AMIs and any incomplete acceptance gates. Never delete earlier test
  resources or existing accounts/data as an implicit cleanup step.

### Planning review

The plan covers custody, early runtime behavior, lifecycle, UI compatibility,
documentation, and actual EC2 validation. Task 0A verifies the existing TPM
implementation before any new memory or Telegram behavior is implemented.
The dedicated Linux key was selected and implemented inline, sequentially
across component boundaries. One independent whole-branch review found four
security/compatibility issues; regression tests reproduced each before the
fixes. The final validation log distinguishes actual NitroTPM, swtpm, synthetic
Telegram, and the pending operator-assisted live-account gate.
# Windows product completion execution

Execute the remaining work continuously in isolated component worktrees. This
plan extends the unmerged Windows design/helper/filesystem/wallet slices
(#189–#194); those slices are prerequisites, not completion. The binding
requirements are SPEC.md §Windows product completion contract. Each component
must receive its own tested implementation PR targeting `dev`; do not merge
without a separate instruction. Documentation is English.

## Completion dependencies and implementation order

| Task | Depends on | Files / responsibility | Verification before PR |
| --- | --- | --- | --- |
| C1a: checked lifecycle primitives | #192 | `_private_fs/`, shared storage tests | deletion/metadata/enumeration/append/rename failure injection, native ACL/reparse/hardlink/identity and process-lock tests |
| C1b: confidential shared parent | C1a | distinct `_private_fs` directory/file admission and checked absence | safe inherited ACLs accepted, private boundary unchanged, unsafe grants/owners/reparse/ancestor absence refused, new files private before bytes |
| C2: shared policy transaction | C1 | `_policy_io.py`, `_yaml_io.py`, shared caller coordinator | cross-directory pending-marker failures, nested writer coordination and hostile cache inputs |
| C3: wizard configuration | C2 | `wizard/policy_writer.py`, `env_file_writer.py`, `credentials_writer.py`, cleanup backups | concurrent policy/config/dotenv updates, preserved YAML, unsafe-state refusal, native configure rerun |
| C4: native install/helper | #190, C1b | `scripts/install.ps1`, wizard interpreter/launcher resolution, native helper command and setup/status | PowerShell 5.1 and pwsh, spaces/non-ASCII, selected venv identity, owned launcher upgrade/removal, sdist/wheel installation |
| C7a: shared audit operations | C1 | `_audit_io.py`, `_log_rotation.py` | stable transaction, append rollback, no-replace rotation, compression and identity-bound retention |
| C5: keyvault lifecycle/runtime | C1, C7a, #190, #194 | keyvault memory storage, markers, capture/export, runtime discovery/hooks, encrypted audit and file-vault gates | real CNG custody, failure preservation, runtime discovery refusal, foreign-user denial, restart/reboot, isolated reset and excluded recovery refusal |
| C6: wizard encryption lifecycle | C3–C5 | wizard memory/Telegram/export/reset/uninstall orchestration and excluded seal/recovery gates | installed Hermes runtime consumes encrypted memory, no plaintext removal before verified runtime, verified backups and honest status |
| C7b: audit and privacy callers | C7a, C5 | privacy writer, then wizard audit CLI in separate PRs | multi-process NDJSON/MRAL append, rollback, rotation/compression, retention/purge identity and uncertain outcomes |
| C8: policy consumers | C2 | network, llm_guard, privacy readers in separate component PRs | pending marker and ACL changes invalidate previously allowed cached decisions, safe defaults only for clean absence |
| C9: network routes | C1 | network Tor/VPN discovery, private daemon state and process lifecycle | quoted paths, startup cleanup, native Tor transport, real applicable VPN route, strict refusal without clearnet fallback |
| C10: extension state | C1, C5 | pairing/history/Telegram custody and archive lifecycle | concurrent one-use/replay/revoke, corrupt state refusal, encrypted restart/import/search/logout/reset |
| C11: Desktop/gateway | C4–C6, C10 | extension Desktop install/API/UI and process/shutdown handling | actual Desktop launch, local-model prerequisite, CNG memory enable, gateway Ctrl-C/port release and restart |
| C12: integrated acceptance | C3–C11 | CI, packaging and documentation | source and sdist-derived wheel, ordinary-user Server and Windows 11 virtual environment, full installation-to-use matrix |

C1 means C1a and C1b together. C4's interpreter/PowerShell work can proceed while
C1/C2 are developed, but its executable publication depends on C1b's trusted
parent checks; do not duplicate an ACL implementation in the installer.
C8 and C9 are separate
network changes and must not race in one checkout. Shared audit changes precede
both privacy and keyvault callers. Write each task's detailed interfaces and
regression cases before changing its product code; do not invent caller APIs
independently in parallel worktrees. Review each component against its contract,
then perform an integrated review of all combined dependencies.

## Completion execution constraints

1. Preserve existing POSIX behavior and data formats. Add failing regression
   cases for changed security behavior, then implement and run relevant tests.
2. Build a combined local integration branch from the unmerged prerequisites;
   do not merge any PR to `dev`. Keep each component's incremental diff clear.
3. Native tests use fresh synthetic state and the selected `.venv` interpreter.
   Keep production `~/.hermes`, the production extension port, Linux validation
   fixtures and earlier TPM fixtures unchanged.
4. Reuse the existing AWS host only after checking its state. Set bounded local
   and remote auto-stop deadlines before expensive validation, and confirm
   stopped state afterward. Do not provision a new paid Cloud PC implicitly.
5. Use virtual Windows 11 x64 where no physical PC is available. Record license
   eligibility and provisioning separately from product acceptance. Windows
   on ARM is a separate target and does not validate the x64 native helper.
6. Run repository formatting/lint/type/package checks and relevant native
   suites for each component. Run the integrated coverage suite after combining
   the reviewed component commits; CI's reduced extras remain mandatory.
7. Finish by recording actual evidence, remaining external gates and PR
   dependencies. A plan, green helper CI, or one migrated caller is not Windows
   product completion.


### Checked Windows audit session implementation

C7a depends on C1b identities/checked absence as well as C1a lifecycle primitives.
Add a checked private-admission assertion to the transaction capability, then
implement shared `audit_session(path, transaction=None)` and immutable bounded
snapshots/probes in a root module. Keep existing POSIX audit functions unchanged.
Add session-taking rotation/name enumeration/retention helpers with no hidden
lock acquisition. Require no-overwrite, checked raw retention, bounded gzip,
identity-bound deletion and compound uncertainty tests, plus ordinary-user
Windows process contention and source/wheel checks. Migrate encrypted keyvault
and plaintext/CLI consumers only in their later component PRs.


C4 native acceptance additionally exercises actual Cargo hardlinked release
output through the separate bounded public-input capability. Cover source
reparse/foreign-writer refusal, read/identity/cleanup faults and ordinary-user
package-bound build/probe; retain destination/receipt refusal tests unchanged.

### Windows C5 dedicated custody implementation

Follow SPEC.md §Windows dedicated custody and memory lifecycle. These are
separate implementation slices, not a claim that Windows support is complete.

| Slice | Scope | Dependencies and exit evidence |
| --- | --- | --- |
| Shared prerequisite | Confidential bounded enumeration and public binary-SID principal seam; C2 protected Mordred loan and monotonic publication receipt | C1b/C2; reject protected names and confidential loans; caught uncertainty and child/outer cleanup tests |
| C5a: custody/lifecycle | Flat Windows ownership schema, profile/role IDs, explicit create-only enrollment, load-only provider and role journals | Shared prerequisite, native CNG helper; freeze exact current/retained records first; alias/copy, concurrent enrollment and native failure tests |
| C5b: memory storage/hooks | Checked inherited-safe memory adapter, markers, ciphertext writes and drift backups | C5a; no raw upstream Windows publication; adoption, broken seals, partial disable/purge and lifecycle race tests |
| C5c: runtime discovery/proof | Reuse C4 interpreter resolver; typed known/unknown process inventory; installed hook and CNG memory proof | C4, C5a/b for final proof; ordinary-user denied/working inventory, actual interpreter and no subprocess-under-lock tests |
| C5d: encrypted audit adapter | Independent audit role/generation lease and checked encrypted writer/reader | C5a, C7a; retained history, borrowed callback, DEK invalidation and uncertainty tests |
| C5e: capability/reset boundaries | Truthful excluded file-vault gates and flat role-specific reset/purge | C5a/b/d; no mutation on excluded paths, retained audit/Telegram ownership and ambiguous deletion journals |
| C6: wizard consumers | Explicit native-custody init, proven memory enable/disable/purge and unsupported-path guidance | C3/C4 and relevant C5 slices; no force-proof bypass; real installed flow and failure preservation |

C5c inventory work may proceed against its typed contract while custody is
implemented; its final key proof waits for C5a/b. C7b privacy/CLI and C10 Telegram
remain separate component PRs and consume the shared identity/lifecycle services.
Do not turn audit callbacks into initialization paths or implement another
native-key selector scheme in Telegram.

Keep the full macOS file-vault `_storage` rewrite out of these Linux-tier slices.
Flat custody does not require recursive deletion. Schedule checked tree lifecycle
as a separate foundation dependency before recursive C6/C10 cleanup; preserve
unknown retained trees rather than substituting `shutil.rmtree`.

Acceptance includes wrong-user/token refusal, same-identity rename, copied-home
refusal, no key generation after BAD_KEYSET, all publication/delete journal
failure points, bounded memory backup enumeration, unknown-process refusal and
post-probe generation revalidation. Preserve POSIX tests and run reduced-extras
checks, ordinary-user Server source/sdist-wheel tests and separate Windows 11
installation-to-use checks. Native memory/audit evidence does not establish
Telegram account/model, Desktop or recursive uninstall acceptance.

### Managed installation image prerequisite for gateway inventory

Add a separate shared filesystem slice implementing
`inspect_managed_installation_image(path) -> FileMetadata` before revising C5c
ordinary-user gateway exclusions. Reuse native pinned path, security descriptor
and handle operations; require OS/administrator-managed ownership and absence
of current-user/untrusted mutation grants on the executable and relevant
ancestor namespace. Check identities and security before return, retain cleanup
failures, and never modify descriptors or files. Include public-image hardlinks,
user-owned/writable lookalikes, ancestor replacement, junctions, held mutation
handles and failure classification in native tests. Existing private and
confidential admission rules must remain unchanged.

C5c keeps all positively current-owned argv inspection. Plausible interpreter,
Hermes/Desktop, generic-host and hinted records stay unknown when denied; only
stable, noncandidate images admitted by the new capability are outside the
supported inventory. Test the exclusions against ordinary Server source and
sdist-wheel runs, including known-empty after the controlled gateway exits.
Run these machine-wide gateway fixtures sequentially. C5b/C5c managed-hook and
runtime-proof admission must enforce the same supported interpreter boundary.
Record the unsupported opaque-runtime limitation and retain Windows 11 as a
separate acceptance gate.
