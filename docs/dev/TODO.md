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
current package exposes one entry-point plugin, `mordred`, with six components.

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

The package must discover the `mordred` entry point and pass the documented checks
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

## Cross-cutting (ongoing through the operational phase)

### Linux private Telegram (proposed)

- [x] Review the [design](SPEC.md#linux-private-telegram-design) and
  [implementation plan](PLAN.md#linux-private-telegram-implementation-plan); land contracts
  before component implementation PRs (contract PR #181).
- [x] Verify the unchanged Linux TPM helper, Python wrap/unwrap, and Telegram
  secret-store path on actual EC2 NitroTPM before feature development (2026-10-07).
  Cross-instance rejection, stop/start persistence, CLI setup, and deletion
  passed; 64 native and 172 focused Python tests passed. CI swtpm evidence
  remains separate. See [CI.md](CI.md#manual-live-device-validation-log).
- [x] Keyvault: TPM-wrapped memory-key custody, runtime resolution, and probes.
- [x] Wizard: Linux memory lifecycle, uninstall, Telegram setup and diagnostics.
- [x] Desktop/extension: platform-aware hardware and memory setup, preserving
  macOS behavior and existing client/API compatibility.
- [x] Verify synthetic custody/service integration independently on actual EC2
  NitroTPM and swtpm; verify the packaged Linux Desktop setup.
- [x] Operator-assisted live Telegram login, minimal sync, and private-model
  questions on actual EC2 NitroTPM (2026-10-07).
- [ ] Live-account cancel/logout and live Hermes/Desktop question UI acceptance.
- [x] Split publication into contract, keyvault, wizard, and Desktop/extension
  PRs targeting `dev`, in dependency order.

### Ongoing maintenance

- Keep maintained documentation indexed, English-only, free of stale local
  links and brittle line-number references.
- Keep SPEC, PLAN, PATHS, POLICY, HOOK_PAYLOADS, and machine contracts aligned
  with code in the same change.
- Run the relevant manual/live validation after touching its gated path and
  record the result in [`CI.md`](./CI.md).
- Keep each implementation PR scoped to one plugin; land cross-plugin contract
  documentation first.
## Windows keyvault wallet storage

- [ ] Land the wallet storage contract before its dependent keyvault PR.
- [x] Complete WW1–WW2 in [PLAN.md](PLAN.md#windows-wallet-storage-implementation-plan).
- [ ] Design shared safe deletion/lifecycle contracts before remaining keyvault
  storage, memory provision/reset/purge and plaintext capture migration.
- [ ] Finish wizard/install, network, policy/LLM guard, privacy/audit and
  extension/Desktop migration, Windows 11 and full installation-to-use acceptance.
  Passing wallet storage tests does not establish these capabilities.



## Windows native support

- [x] Investigate native Windows feasibility and identify actual AWS NitroTPM
  image candidates; preserve the existing Linux validation environment.
- [x] Prove CNG P-256 ECDH and unchanged MRKW interoperability on actual AWS
  Windows under a credentialed non-administrator user.
- [x] Record Phase 0 host/persistence/device-binding outcomes and unmet scope.
- [x] Review the Windows SPEC and helper implementation plan before production
  implementation; in-session execution approved.
- [ ] Submit the cross-component contract docs before the implementation PR.
- [x] Implement and live-validate the standalone Windows CNG helper (PLAN W1–W4).
- [ ] Implement secure Windows filesystem primitives and migrate callers in
  separate component PRs without weakening POSIX behavior.
- [ ] Extend keyvault memory custody, wizard, network, policy/privacy and
  Desktop/extension through their respective plans and Windows acceptance gates.
- [ ] Add the Windows CI/packaging matrix and a separate Windows 11 Desktop
  acceptance run before advertising general native Windows product support.

# Windows product completion backlog

The full Windows port is **incomplete**. The helper (#190), private filesystem
(#192) and wallet caller (#194) have bounded evidence; they do not complete the
tasks below. Follow PLAN.md §Windows product completion execution and keep
component PRs separate. Virtual Windows 11 is acceptable; a physical PC is not
required.

- [ ] C1: checked file lifecycle and audit primitives, with native failure tests.
- [ ] C2: shared canonical policy/config read and transaction coordination.
- [ ] C3: wizard policy/config/dotenv/credentials and safe cleanup backups.
- [ ] C4: native Windows installer, interpreter/launcher resolution and CNG
  helper CLI/setup/status integration.
- [ ] C5: keyvault memory/custody, runtime hooks/discovery, capture/export,
  generation/reset, encrypted audit and excluded file-vault recovery gates.
- [ ] C6: wizard encryption/Telegram/vault lifecycle, upgrade and uninstall.
- [ ] C7a: shared audit append/rotation/compression/retention prerequisites.
- [ ] C7b: audit privacy and CLI migration after keyvault integration.
  Part 1 (privacy_check factory, probe, hooks and install wrapper) routes
  Windows writers through native audit custody with checked plaintext only for
  clean absence and fail-closed refusals otherwise. Independent review, native
  Windows CI, live CNG, C5e predicate adoption and the separate part 2 wizard
  audit CLI remain.
- [ ] C8: network/LLM/privacy checked readers and fail-closed cache decisions.
  The network slice routes every Windows network decision through one checked
  canonical generation (host-tested; native Windows source/wheel validation of
  `tests/test_network_windows_policy_native.py` is still required).
- [ ] C9: native Tor/VPN route behavior and process cleanup.
  The network route slice adds the native Windows Tor lifecycle (checked
  `.exe` discovery, private `tor-data` state, startup cleanup, kill-on-close
  job, exact teardown) and explicit VPN capabilities: Mullvad and WireGuard
  are `not-ported-on-windows` (product limitation), custom needs validated
  executables, strict never falls back to clearnet (host-tested; native
  source/wheel runs of `tests/test_network_windows_routes_native.py`, real
  route evidence, wizard presentation (C6) and Windows 11 remain required).
  C9 review residuals (documented gaps; only the inventory refusal wording changed):
  - A Tor that exits immediately is reported only as exited or with "stdout
    closed before bootstrap". This applies before its identity is recorded
    or before bootstrap. Tor's own first output lines, which carry its
    reason (for example a rejected torrc or DataDirectory), are discarded.
    Surfacing a bounded, sanitized tail of that output is still open.
  - The startup inventory refuses any current-user process whose command
    line names this profile's torrc, not only Tor images (for example an
    editor opened on the torrc). The refusal now says "an unrecorded
    process". Narrowing the match to Tor images (image identity) is still
    open; the refusal stays conservative and never stops the process.
- [ ] C10: extension pairing/history/Telegram storage and lifecycle.
  C10a routes Windows pairing, attestation, WebAuthn, history and the wallet
  snapshot fingerprint through checked private storage (host-tested; native
  Windows source/wheel validation of
  `tests/extension/test_extension_windows_storage_native.py` is still required).
  C10b Telegram custody/archive remains open. Follow-ups:
  - [ ] Wizard `extension pair`: report a checked-storage refusal from
    `generate_code` (`storage_unavailable` / `storage_uncertain`) instead of a
    raw traceback.
  - [ ] Browser extension client: handle `storage_unavailable` /
    `storage_uncertain` in `pair_fail`, `auth_fail` and `error` frames, the
    additive `auth_challenge.storage_error`, and `attestation_key_missing`.
  - [ ] C11: move the synchronous checked extension-storage lock off the
    gateway event loop (challenge, auth currency check, history clear).
  - [ ] History: explain or relieve the 64 MiB `history.enc` bound; an
    oversized blob blocks saves until `history_clear`.
  - [ ] Operator unpair command for the documented `attestation_key_missing`
    recovery (today `clear_pairing()` from the Hermes Python).
- [ ] C11: Windows Desktop installation/capabilities and gateway lifecycle.
- [ ] C12: integrated source/wheel CI, ordinary-user Server tests, virtual
  Windows 11 installation-to-use acceptance, and required live service gates.

### Windows C5 custody execution order

The approved contract is in [SPEC.md](SPEC.md#windows-dedicated-custody-and-memory-lifecycle)
and the scoped sequence is in [PLAN.md](PLAN.md#windows-c5-dedicated-custody-implementation).
Implementation and acceptance remain open:

- [ ] Shared prerequisite: confidential memory enumeration and binary-SID
  principal API; protected C2 transaction proxy and publication receipts.
- [ ] C5a: freeze exact flat current/retained ownership and pending-journal
  schemas; implement identity-bound create-only custody and load-only providers.
  C5a now supplies the exact v1 schema, inert enrollment/load, retained role
  leases, read-only memory inventory and positive-deletion cleanup. Local tests
  and the explicit native fixture are implemented; independent review and
  ordinary-user Server/Windows 11 acceptance remain required before completion.
- [ ] C5b: checked memory storage/hooks, markers, adoption and flat lifecycle.
- [ ] C5c: reuse C4 runtime selection, implement known/unknown process inventory,
  and require actual installed-runtime memory proof without a force override.
- [ ] C5d: independent audit role leases and C7a encrypted writer integration.
  The opt-in provider/writer/reader, exact retained-selector lookup and checked
  publication receipts are implemented. Independent review, native source/wheel
  CNG and Windows 11 acceptance remain; C7b factory/CLI adoption is separate.
- [ ] C5e: excluded file-vault refusal and flat role reset/deletion journals.
  C5e now supplies pure capability predicates (no aggregate readiness flag),
  pre-mutation `KeyvaultUnsupportedOnWindows` guards, retained excluded-artifact
  reports and journaled role-specific `reset_role`. Independent review, native
  Windows CI, real CNG/Windows 11 acceptance and C6 routing remain open.
  Fix round 1: predicates are non-blocking; the unported `_storage` secret
  store reports `secret_store` / `not-ported-on-windows` and refuses before
  any mkdir. Remaining: design a checked Windows secret-store port; C6/C7b
  must gate audit/Telegram role reset on their consumers because reset does
  not consult the gateway inventory; C6 status/doctor must route retained
  secret-store refusals (now raised by the Windows lifecycle-lock guard).
- [ ] C6: explicit native-custody/audit initialization and wizard memory flows;
  preserve separate C7b privacy/CLI and C10 Telegram migrations.
  C6 now supplies `keyvault native init`, proof-bound `encryption
  enable/disable/purge memory`, capability-routed `status`/`encryption
  status`/`setup`, excluded vault/seal refusals before key generation and the
  Windows uninstall (memory restore, memory-only `--purge-data`, no recursive
  removal, `--erase-encrypted` refused). Remaining: independent review, scoped
  Windows CI, the gated `test_wizard_windows_memory_live.py` source and
  sdist-wheel runs, Windows 11 acceptance, wizard journal reconciliation,
  Telegram (C10b), audit CLI (C7b part 2) and Desktop (C11) routing.
  Review fix round 1: uninstall `--purge-data` plans the disable for inert
  custody and purges memory custody inside step a (every refusal precedes
  step b); enable/setup print the no-presence/no-portable-recovery notice when
  they create the key; `keyvault reset` refuses first on Windows. Still open:
  armed-with-problems memory renders `paused` instead of `on`, and
  `--purge-data` removes the CNG helper while audit/Telegram custody is kept.
- [ ] Design and implement checked tree lifecycle before recursive cleanup;
  do not make it an implicit requirement for flat memory enrollment/purge.
- [ ] Verify ordinary-user Server and Windows 11 installed flows, preserving
  ciphertext after missing hardware, token denial and uncertain operations.

- [ ] Managed image admission fix round: role-based ancestor policy (upper
  ancestors admit entry-creation rights, parent and image stay strict),
  storage-admission lock test, native fixture/probe evidence.
- [ ] C5c R2: managed-image classification of denied non-plausible images,
  removal of the fixed OS list, ordinary-user source/wheel known-empty proof.
- [ ] Enforce the same supported C4 interpreter boundary in Windows managed
  memory hooks and installed-runtime proof; document opaque-runtime limits.
- [ ] C5c phase 2: `prove_windows_memory_runtime` and
  `validate_windows_runtime_proof` are implemented with portable real-child
  tests. Independent review, scoped Windows CI, explicit real-CNG source and
  sdist-wheel runs and Windows 11 acceptance remain; C6 must route Desktop
  launchers by passing the authoritative interpreter.

### Windows memory storage follow-up (C5b)

- [ ] Review and accept checked Windows storage/hooks independently; native
  source/sdist-wheel inherited-ACL and real CNG installed-Hermes validation
  remain controller-owned until recorded.
- [ ] After C5c installed proof is frozen, implement reusable enable/seal,
  disable/decrypt, marker transitions and purge verification with exact
  physical-home/SID/generation/epoch/wrapped-digest proof preconditions.
  Expose no bool/callback proof bypass; C5a continues to own deletion journals.
- [ ] C5b-2 lifecycle: `enable_memory_encryption`,
  `disable_memory_encryption`, marker transitions and
  `verify_memory_purge_candidates` are implemented with portable real-proof
  tests. Independent review, scoped Windows CI, the explicit real-CNG
  `test_windows_memory_proof_live.py` source and sdist-wheel runs, C6 routing
  of the ceremonies and Windows 11 acceptance remain.
- [ ] Implement checked atomic Windows plaintext Journey memory mutations;
  first-slice refusal is a preserved functional gap, not complete integration.
- [ ] Complete separate C6 ceremony consumers and ordinary-user Windows 11
  installed product acceptance.
- [ ] C5b review follow-ups deferred from fix round 1: replace scattered
  `sys.platform == "win32"` hook branches with install-time dispatch and split
  `_memory_hook.py`; return `{"ok": False}` instead of raising for unmappable
  Windows journey sources; cut per-call inventory/stat/unwrap cost (shape B
  reads three times per mutation); strengthen the native process-lock test
  beyond `poll() is None`.

### Windows Telegram custody follow-up (C10b)

- [ ] Review the custody-role credential store, checked archive and
  forget ceremony independently; native source/sdist-wheel runs of
  `tests/test_windows_telegram_native.py` and the gated real-CNG
  `tests/test_windows_telegram_live.py` remain controller-owned.
- [ ] C6-telegram: route wizard telegram setup/login/logout on Windows through
  `default_secret_store()`, the explicit `enroll_role("telegram")` ceremony
  (mapping `telegram_not_enrolled`), `require_presence=False` after the
  machine-bound disclosure, and `wipe_archive(forget=True)` for `--forget`;
  replace the raw `_orphaned_archive_present` scan.
- [ ] C11: Desktop/login adoption of the seam and of the presence opt-out
  (`login_flow` keeps calling `ensure_key()`, which refuses on Windows).
- [ ] Live Telegram account gate and Windows 11 installation-to-use acceptance.
- [ ] C6: never rotate the telegram role (`retain_current=True`) without
  re-sealing `credentials.sealed` under the new generation first; otherwise
  credentials and archive become `secrets_corrupt`. Not offering rotation is
  acceptable.
