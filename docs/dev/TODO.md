# Mordred — TODO (Hermes-base)

> **Status**: open work only. Completed implementation history is available in
> Git and merged PR descriptions. [`PLAN.md`](./PLAN.md) describes the current
> architecture and [`ROADMAP.md`](./ROADMAP.md) holds deferred product ideas.

Select work from this file only when its dependencies and target release are
clear. Preserve the zero-upstream-PR commitment and the one-plugin-one-PR rule.

## Standalone-repo repair backlog (2026-07-01)

The standalone packaging, CI, release, documentation, and browser-extension
server repairs are complete. One lifecycle choice remains:

- [ ] Decide automatic lifecycle integration for the packaged extension server:
  document launchd/systemd, keep explicit `extension serve`, or revisit only if
  Hermes adds a plugin-owned service boot hook. Preserve compatibility with a
  full gateway already using port 7788.

## Phase 0 — Operational Setup (blocks all later phases)

Phase 0 is complete. Keep its acceptance gates green on every change.

### Open decisions

None for the current release.

### 0.1 Confirm repo & venv

- [x] Repo `.venv` is the canonical editable development environment.
- [x] Mutating CLI validation supports isolated `HERMES_HOME` state.

### 0.2 Hermes upstream tracking strategy (optional, rebase not recommended)

- [x] Use PyPI plus a read-only upstream checkout for compatibility checks; do
  not rebase or submit upstream PRs.

### 0.3 Reserve Mordred-owned filesystem paths (kept in sync with PATHS.md)

- [x] Ownership, permissions, writers, and readers are defined in
  [`PATHS.md`](./PATHS.md).

### 0.4 Plugin scaffolding (five plugins)

- [x] Five manifest-backed plugins and the manifest-less `mordred_e2e` entry
  point ship from `src/mordred_hermes/`.
- [ ] If a future `hard-lock` extra is approved, add the version-pinned vendored
  Hermes module under `vendor/hermes/<version>/` without changing the normal
  plugin-only install.

### 0.5 `mordred-hermes` package scaffold

- [x] Package metadata, extras, six entry points, console script, dynamic
  version source, native assets, and PyPI publishing are in place.
- [ ] At each release, run `python tools/bump_version.py <version>` and verify
  `tests/test_packaging_versions.py`; never edit individual version surfaces by
  hand.
- [x] Reserve `hermes-mordred==0.0.0.dev0` on TestPyPI and PyPI through
  `release.yml` mode `reserve-rename`; do not rename the root distribution
  before both reservations are verified.
- [x] After reservation, publish the real `hermes-mordred==0.1.0a16` package,
  then the metadata-only `mordred-hermes==0.1.0a16` compatibility shim, using
  the TestPyPI-first order in `MIGRATION.md` §6.
- [x] Switch the installer and user documentation to `hermes-mordred`, verify
  the `0.1.0a15` upgrade path, and only then rename the GitHub repository and
  refresh all Trusted Publisher repository claims.

### 0.6 CI workflow

- [x] CI covers supported Python/OS cells, lint, strict typing, unit tests,
  package smoke, the Hermes floor, optional extras, Tor, TPM, and helper builds.

### 0.7 ~~HSeam-1 PR~~ → Zero-PR commitment (deferred to v2 vendored fork)

- [x] Strict plugin-disable protection is implemented entirely on the plugin
  side.
- [ ] If `hard-lock` is ever implemented, reassess whether the plugin-side
  `mordred.degraded.disable_unprotected` fallback is still required.

### 0.8 Verify Hermes hook payloads against real code

- [x] Consumed hook fields are machine-readable in
  `tools/hook_payload_contract.json` and checked against the installed release
  and upstream `main`.

### Acceptance gate (Phase 0)

- [x] A clean `uv sync --all-extras` environment can discover all six entry
  points and run the default suite.

## Phase 1 — Privacy Primitives (`mordred_privacy_check` + metadata + wizard)

Phase 1 is complete for the current release.

### Open decisions

None. Per-skill runtime enforcement remains a v2 dependency on
`origin_skill` in Hermes hook payloads.

### 1.1 `mordred_privacy_check` plugin

- [x] Install-time metadata policy, generic runtime tool guard, typed audit log,
  and strict sibling-plugin integrity refusal are implemented.

### 1.2 Skill metadata namespace

- [x] `metadata.mordred.*` is documented and validated.

### 1.3 `mordred_wizard` plugin

- [x] Configuration, status, policy, audit, migration, encryption, network,
  keyvault, plugin discovery, and extension commands are implemented.

### 1.4 Tests (Phase 1)

- [x] Policy, audit, parser, non-interactive, YAML, and isolated-home behavior is
  covered by the default suite.

### 1.5 Docs and bookkeeping (Phase 1)

- [x] User and developer guides are separated by audience.
- Keep one-line `### Changes` / `### Fixes` entries in every PR description;
  this project intentionally has no `CHANGELOG.md`.

### Acceptance gate (Phase 1)

- [x] Strict/lenient/off behavior is deterministic and audited.

## Phase 2 — LLM Enforcement (`mordred_llm_guard` + `mordred-local` provider)

### Open decisions

- [ ] Reconsider automatic provider swapping only if a future vendored Hermes
  layer can change the resolved provider before clients are constructed.

### PR1 prep findings (Codex review 2026-05-13)

The lasting finding is that `pre_llm_call` cannot rewrite the provider.
`pre_api_request` and auxiliary-client guards are the current enforcement
boundaries.

### 2.1 `mordred_llm_guard` plugin

- [x] Local provider registration, harness refusal, primary request enforcement,
  endpoint ownership checks, and auxiliary-client guards are implemented.

### 2.2 Wizard additions (Phase 2)

- [x] Local/cloud policy configuration and prompt-once behavior are implemented.

### 2.3 Tests (Phase 2)

- [x] Provider, endpoint, harness, health, prompt, and auxiliary paths have
  hermetic coverage.

### Acceptance gate (Phase 2)

- [x] Strict policy refuses non-allowlisted or endpoint-mismatched cloud traffic
  before egress.

## Phase 3 — Network Paths (`mordred_network`)

### Open decisions (resolved 2026-05-09 / 2026-05-13)

The current release uses one process-wide route. Independent per-skill routes
remain deferred.

- [ ] Live-verify the Bedrock DNS behavior with a real AWS account before
  changing its conservative incompatibility classification.
- [ ] Live-verify Vertex proxy behavior with the real Google Cloud SDK before
  changing its conservative classification.
- [ ] Revisit per-session/per-skill SOCKS isolation only after Hermes exposes
  `origin_skill` and supports independently constructed transports.

### 3.1 `mordred_network` plugin

- [x] Route activation, proxy environment, provider compatibility, process
  freeze, liveness, and strict drop handling are implemented.

### 3.2 Wizard additions (Phase 3)

- [x] `network init/use/status` and secret-reference storage are implemented.

### 3.3 Tests (Phase 3)

- [x] Unit and hermetic Tor coverage run in CI; live VPN remains explicitly
  gated.

### Acceptance gate (Phase 3)

- [x] Strict mode cannot silently fall back from the selected route to clearnet.

## Phase 4 — Key Management (`mordred_keyvault`)

Phase 4 is complete for the current release.

### Open decisions

Windows-native custody, stronger Linux presence policy, and external hardware
tokens remain roadmap work.

### 4.1 `mordred_keyvault` plugin

- [x] Platform keys, vault formats, backup/recovery, audit encryption,
  config/env/memory integration, Ethereum support, and extension signing are
  implemented.

### 4.2 Wizard additions (Phase 4)

- [x] Keyvault, native-helper, vault, encryption, and workspace CLI surfaces are
  implemented.

### 4.3 Tests (Phase 4)

- [x] Pure-Python, fake-backend, helper-build, software-TPM, and opt-in live
  Secure Enclave paths are defined.

### Acceptance gate (Phase 4)

- [x] Backup, reset, restore, and decrypt round trips fail closed and preserve
  rollback guarantees.

## Cross-cutting (ongoing through the operational phase)

- Keep documentation links valid and documentation English-only.
- Re-run on-device Secure Enclave, live LLM, and live VPN checks after changing
  their gated paths; record the date and result in [`CI.md`](./CI.md).
- Keep `SPEC.md`, `PLAN.md`, `PATHS.md`, `POLICY.md`, and machine contracts in
  sync with behavior changes.
- Keep each implementation PR scoped to one plugin. Land cross-plugin contract
  documentation first.
