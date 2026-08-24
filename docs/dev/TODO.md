# Mordred — TODO (Hermes-base)

> **Status**: actionable current-release work only. Completed work is in Git
> history and merged PR descriptions; deferred product work is in
> [`ROADMAP.md`](./ROADMAP.md). [`PLAN.md`](./PLAN.md) describes the
> implementation that exists today.

Every item here must have a known owner boundary and a testable completion
condition. Preserve the zero-upstream-PR commitment and one-plugin-one-PR rule.

## Standalone-repo repair backlog (2026-07-01)

The original repair backlog is complete. One extension-operability decision is
still actionable:

- [ ] Decide and document the supported long-running lifecycle for
  `extension serve`: explicit foreground operation, operator-managed
  launchd/systemd examples, or integration through a future safe Hermes
  service hook. Preserve coexistence with a standalone service or compatible
  legacy/custom gateway already using port 7788, and define restart behavior
  after package upgrades.

## Phase 0 — Operational Setup (blocks all later phases)

No open setup work. Keep the gates in [`CI.md`](./CI.md) green.

### Open decisions

None for the current release.

### 0.1 Confirm repo & venv

No open work. Use the repository `.venv` and isolate mutating CLI validation
with `HERMES_HOME`.

### 0.2 Hermes upstream tracking strategy (optional, rebase not recommended)

No open work. Compatibility checks are read-only and no upstream PRs are sent.

### 0.3 Reserve Mordred-owned filesystem paths (kept in sync with PATHS.md)

No open work. Any new path must update [`PATHS.md`](./PATHS.md) in the same
change.

### 0.4 Plugin scaffolding (five plugins)

No open work. The heading is retained as a stable historical anchor; the
current package exposes five manifest-backed plugins plus `mordred_e2e`.

### 0.5 `mordred-hermes` package scaffold

No open work. Release mechanics belong to [`CI.md`](./CI.md) §Normal release.

### 0.6 CI workflow

No open work. Workflow YAML and [`CI.md`](./CI.md) own the current gates.

### 0.7 ~~HSeam-1 PR~~ → Zero-PR commitment (deferred to v2 vendored fork)

No current-release work. A mandatory vendored enforcement layer, if approved,
must move from [`ROADMAP.md`](./ROADMAP.md) through SPEC/PLAN before code.

### 0.8 Verify Hermes hook payloads against real code

No open work. Maintain `tools/hook_payload_contract.json` whenever a consumed
field changes.

### Acceptance gate (Phase 0)

The package must discover all six entry points and pass the documented checks
from a clean supported environment.

## Phase 1 — Privacy Primitives (`mordred_privacy_check` + metadata + wizard)

No open Phase 1 implementation work.

### Open decisions

None for the current release. Per-skill runtime provenance is deferred.

### 1.1 `mordred_privacy_check` plugin

No open work.

### 1.2 Skill metadata namespace

No open work.

### 1.3 `mordred_wizard` plugin

No open Phase 1 work. The backup-export operator surface is tracked under
Phase 4 because it depends on keyvault semantics.

### 1.4 Tests (Phase 1)

No open work beyond tests required by a concrete behavior change.

### 1.5 Docs and bookkeeping (Phase 1)

No separate backlog. Documentation changes accompany the behavior they
describe, and PR descriptions carry `### Changes` / `### Fixes` entries.

### Acceptance gate (Phase 1)

Strict, lenient, and off decisions remain deterministic and auditable.

## Phase 2 — LLM Enforcement (`mordred_llm_guard` + `mordred-local` provider)

No open implementation work for the current enforcement model.

### Open decisions

Automatic provider replacement requires a pre-client-construction boundary and
remains in the roadmap; current strict behavior is refusal, not redirection.

### PR1 prep findings (Codex review 2026-05-13)

Stable anchor: `pre_llm_call` cannot rewrite the provider. The live boundaries
are `pre_api_request` plus the auxiliary-client guards.

### 2.1 `mordred_llm_guard` plugin

No open work.

### 2.2 Wizard additions (Phase 2)

No open work.

### 2.3 Tests (Phase 2)

No open hermetic work. Live-provider checks are listed under Phase 3 because
they validate transport classification.

### Acceptance gate (Phase 2)

Strict policy refuses a non-allowlisted, unresolved, or endpoint-mismatched
provider before egress.

## Phase 3 — Network Paths (`mordred_network`)

The implementation is complete; two conservative provider classifications
still need real-account evidence before they can be relaxed.

### Open decisions (resolved 2026-05-09 / 2026-05-13)

- [ ] Live-verify Bedrock DNS and proxy behavior with a real AWS account.
  Record the environment, SDK version, selected route, and result without
  recording credentials. Change the conservative classification only in a
  separate `mordred_network` change with a regression test.
- [ ] Live-verify Vertex proxy behavior with the real Google Cloud SDK under
  the same evidence and test requirements.

Per-session/per-skill routing remains deferred until Hermes supplies trusted
origin provenance and independently constructed transports.

### 3.1 `mordred_network` plugin

No open implementation work.

### 3.2 Wizard additions (Phase 3)

No open work.

### 3.3 Tests (Phase 3)

Complete the two live-provider checks above; ordinary unit, Tor, and
manual-Mullvad coverage remain governed by [`CI.md`](./CI.md).

### Acceptance gate (Phase 3)

Strict mode must never retry a selected protected route over clearnet.

## Phase 4 — Key Management (`mordred_keyvault`)

Portable backup export and import are available through both the crypto/storage
API and the operator CLI.

### Open decisions

- [x] Select the single initialized logical key automatically, collect recovery
  inputs through masked prompts, require a new `--output` path, and cover an
  isolated export/recover round trip. Secrets are never accepted in argv or
  written to logs.

### 4.1 `mordred_keyvault` plugin

No open format/API work for export: `keyvault.api.export_backup()` already
returns an MRKV blob. Keep its wire compatibility unchanged while adding the
operator surface.

### 4.2 Wizard additions (Phase 4)

- [x] Add `hermes-mordred keyvault export --output <path>` backed by
  `keyvault.api.export_backup()`.
- [x] Write the output atomically as a mode-`0600` regular file, refuse unsafe
  destinations, avoid printing secret inputs or blob contents, and leave no
  partial output on failure.
- [x] Verify the blob in tests against an isolated fresh profile/fake backend
  without mutating the source profile.
- [x] Update Quickstart/Usage/README to recommend
  export-before-reset, cross-profile key migration, or attended-to-unattended
  key replacement.

### 4.3 Tests (Phase 4)

- [x] Cover parser/help, interactive and non-interactive secret handling,
  permissions, existing-output refusal, atomic failure cleanup, successful
  round trip, wrong-passphrase failure, and source-profile preservation.

### 4.4 Agent-memory at-rest encryption (cross-plugin: keyvault + wizard)

- [x] Docs: specify the sealed memory file format, arming rule, seam
  coverage, and lifecycle in SPEC/PLAN/PATHS/ROADMAP (this PR).
- [x] Keyvault runtime: the memory-hook wrapper around the memory tool seam,
  the capability probe, and the CI canary against the installed upstream.
- [x] Wizard lifecycle: `encryption enable/disable/purge memory`, `status`
  drift, and the `setup` `memory-encryption` step.
- [x] Live verification on Apple Silicon with a running gateway (2026-08-20).
- [x] Record the live-verification result in [`CI.md`](./CI.md) §Manual
  live-device validation log (2026-08-20).

### Acceptance gate (Phase 4)

A CLI-produced blob recovers successfully into an isolated fresh profile while
the source remains usable, and failure paths leave no partial destination.

## Phase 5 — Secure Home (`mordred_wizard`)

### Open decisions

- Phase 2 `init` ceremony: the exact `hdiutil`/`diskutil` volume-creation
  flow, and enforcing interactive-stdin-only password collection.
- Phase 4 unlock trust boundary: automatic Keyvault-based unlock is deferred
  until it is explicit where the unlock key may live without landing inside
  the encrypted `HERMES_HOME` it unlocks.
- Phase 4 launchd/Desktop env delivery: `launchctl setenv` vs. a plist
  `EnvironmentVariables` block for processes that do not inherit the CLI's
  shell environment.
- Audit-trail emission for `adopt` and for verification refusals (e.g.
  `UUID_MISMATCH`) is deliberately deferred: the audit log lives inside a
  `HERMES_HOME`, so which home should record a pre-mount event needs a SPEC
  decision before this is wired up.

### 5.1 Phase 1 implementation

- [x] `secure-home` paths/probe modules: the fail-closed verification
  chain, the `~/.config/hermes-mordred/secure-home.json` config contract,
  and the `fdesetup`/`diskutil` read-only probes.
- [x] `secure-home status | adopt | run` CLI commands in `mordred_wizard`.
- [x] Unit tests mocking `fdesetup`/`diskutil`/exec through an injectable
  runner, covering the verification chain and both exact fail-closed
  messages.
- [x] Gated live macOS integration test
  (`tests/integration/test_secure_home_macos.py`), manual-only behind
  `MORDRED_LIVE_SECURE_HOME_TEST=1` plus the `integration` marker.
- [x] Docs: SPEC/PLAN/TODO/PATHS/USAGE updated in this PR.
- [ ] Live-device validation run on Apple Silicon, recorded in
  [`CI.md`](./CI.md) §Manual live-device validation log.

### Acceptance gate (Phase 5, Phase 1 slice)

- Unit suite green.
- `ruff check` / `ruff format --check` / `mypy --strict` clean, and
  `shellcheck` clean on any touched shell scripts.
- The live gated test (`MORDRED_LIVE_SECURE_HOME_TEST=1`) passed on Apple
  Silicon and the result is logged in [`CI.md`](./CI.md) §Manual
  live-device validation log.

## Cross-cutting (ongoing through the operational phase)

- Keep maintained documentation indexed, English-only, free of stale local
  links and brittle line-number references.
- Keep SPEC, PLAN, PATHS, POLICY, HOOK_PAYLOADS, and machine contracts aligned
  with code in the same change.
- Run the relevant manual/live validation after touching its gated path and
  record the result in [`CI.md`](./CI.md).
- Keep each implementation PR scoped to one plugin; land cross-plugin contract
  documentation first.
