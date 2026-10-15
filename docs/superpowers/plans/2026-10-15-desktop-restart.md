# Desktop Restart Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Mordred's restart button restart Hermes Desktop truthfully and safely, then publish `0.3.0a2` through the existing release gates.

**Architecture:** A shared page control replaces the messaging-gateway restart call with the feature-detected Electron relaunch bridge, only for a proven local connection. The control owns confirmation, bounded progress and manual recovery; Python update APIs and Hermes upstream remain unchanged.

**Tech Stack:** Existing JavaScript/React plugin, Python pytest with Node behavior harness, uv, GitHub Actions and PyPI Trusted Publishing.

**Spec:** [Approved design contract](#approved-design-contract) below records the approved in-chat design. Read alongside `docs/dev/SPEC.md` (Desktop integration), `docs/dev/PLAN.md` (C11), `docs/dev/UPSTREAM.md` (Zero-PR commitment), and `docs/dev/CI.md` (Normal release).

## Global Constraints

- All documentation is written in English; preserve existing headings.
- Feature PR targets `dev`; releases use `dev` → `main` and exact-SHA final acceptance.
- No Hermes upstream changes, new dependencies, backend restart endpoint or process-kill workaround.
- Use `uv run` / `.venv/bin/…`; never alter production keys, configuration, installation provenance or metadata to make this UI fix pass.
- Work in `/Users/kazuko/dev/work/intmax/hermes-mordred-desktop-restart`, branch `fix/desktop-restart`.
- User authorized planning, inline implementation and release; proceed through the existing checks without additional permission gates.

## Review Focus

- The connection changes while its registry is loading: an old local result must never relaunch a newly selected remote session.
- A slow capability lookup resolves after timeout or unmount: it must never trigger a delayed relaunch.
- The relaunch Promise resolves but Electron remains open: show recovery instructions, not success or an enabled duplicate request.
- Another Desktop window has active work: focused-session busy state is insufficient; explicit whole-app confirmation is required.
- Running code is newer than installed metadata: wording must not promise an upgrade or conceal the mismatch.

---

## Approved Design Contract

The old `restartBackend()` calls `host.restartGateway()`, which restarts messaging, not the Desktop process importing Mordred. It also ignores the API's `false` result. Remove that route entirely from repair/update restart actions.

Both panels use `RestartHermesControl()`, labelled **Restart Hermes Desktop**. An inline confirmation explains that all Desktop windows restart and active work can be interrupted; actions are **Restart now** and **Cancel**. This matters because the installed Electron bridge calls `app.relaunch()` followed by backend shutdown and `app.exit()`, bypassing ordinary active-work quit confirmation.

Automatic restart requires callable `window.hermesDesktop.relaunchApp`, callable `host.state.connectionId.get`, and callable `host.connections`. Match the current connection id to a registry row whose `kind` is exactly `local`; missing, ambiguous, remote or failed observations use manual instructions. Never infer local ownership from a null id, platform, URL or `host.activeConnectionId() === null`. Re-read identity after the asynchronous registry lookup and immediately before invoking the bridge.

Show pending feedback immediately after confirmation, disable repeat actions and use one 30,000 ms deadline covering lookup and relaunch waiting. Ignore late continuations after timeout/disposal. Promise resolution means only that the request was accepted: pending remains until the app exits or the deadline displays manual recovery. Rejection shows an inline failure. No automatic retry, success toast, old eight-second recheck, or fallback messaging restart. Clean up timers on unmount; never invoke the bridge after unmount. Once an IPC request was sent, keep it latched for that page lifetime to avoid duplicate queued relaunches.

Manual instructions distinguish an unsupported local Desktop from a remote/unknown backend: completely quit and reopen local Hermes, or restart Hermes on the machine serving the selected connection. Do not claim that restarting the local app restarts a remote backend.

Version mismatch copy reads **Running Mordred: X. Installed package metadata: Y.** Explain that they differ and restarting reloads the installed environment; do not call it a newer version or claim mismatch proves a completed update. Keep the server's existing structured `restart_required` decision.

Production diagnosis found base-Python `_editable_impl_hermes_mordred.pth` pointing at the original repository (`0.3.0a1`), while the selected Hermes environment and package-manager member contain `0.2.0a1` from another worktree. Preserve that evidence. Actual UI QA may back up and stage only the page asset; no environment repair or metadata rewrite is part of this fix.

## File Map

- `src/mordred_hermes/desktop/assets/desktop/plugin.js`: shared restart lifecycle and truthful mismatch copy.
- `tests/test_desktop_windows_page.py`: execute actual handlers with mocked SDK, bridge and clocks.
- `docs/user/USAGE.md`: user-visible restart behavior and fallback.
- `docs/dev/SPEC.md`, `docs/dev/PLAN.md`: synchronize the Desktop behavior contract without renaming headings.
- `docs/dev/CI.md`: record actual Desktop validation evidence in the existing manual log.
- Version surfaces changed exclusively by `tools/bump_version.py`: `src/mordred_hermes/__about__.py`, `docs/dev/VERSION`, `docs/dev/setup.md`, `packaging/mordred-hermes-compat/pyproject.toml`.

### Task 1: Implement and test the shared restart control

**Files:** Modify `plugin.js` and `tests/test_desktop_windows_page.py` from the file map.

**Interfaces:**
- Consumes `host.state.connectionId.get(): string | null`, `host.connections(): Promise<Array<{id: string, kind: string}>>`, optional `window.hermesDesktop.relaunchApp(): Promise<void>`.
- Produces `RestartHermesControl(): ReactElement`, used by both `RepairPanel` and `UpdatePanel`; neither caller supplies a restart/recheck callback.
- Internal capability helper, if extracted: `desktopRestartCapability(): Promise<{kind: 'local', connectionId: string} | {kind: 'manual', reason: string}>`; caller owns deadline and stale-result checks.

- [x] Extend `render_page` with stable refs, effect disposal, deferred promises and a controllable timer queue; retain existing component test behavior.
- [x] Add `test_restart_local_confirmation_and_pending`: click opens confirmation; cancel yields zero IPC calls; confirm immediately shows pending; double-click invokes relaunch exactly once; gateway restart count is zero.
- [x] Add `test_restart_manual_capability_fallbacks` parametrized for absent bridge/SDK, null or unmatched identity, remote row and rejected registry lookup; assert visible manual remedy and zero relaunch calls.
- [x] Add `test_restart_route_change_and_late_lookup`: switch identity during lookup, resolve after timeout, and resolve after unmount; every case must make zero relaunch calls.
- [x] Add `test_restart_request_outcomes`: synchronous throw and rejection show inline failure; resolved and never-settled IPC remain pending until the 30,000 ms deadline, then show manual recovery without claiming success or allowing a duplicate request.
- [x] Add `test_restart_unmount_cleans_timer`: dispose the mounted control, assert timer cancellation and no state writes from late async continuations.
- [x] Add `test_both_panels_use_desktop_restart_control` and `test_version_mismatch_is_neutral`: render both panels' restart action; running `0.3.0a1` / installed `0.2.0a1` must show both facts and no “new version” promise. Assert confirmation mentions all windows and interrupted work.
- [x] Run `uv run pytest -q tests/test_desktop_windows_page.py`; confirm new behavioral assertions fail for the current implementation before changing production code.
- [x] Implement the contract in `plugin.js`; replace the old restart handler and obsolete structural test expectations. Keep the component self-contained and the existing update/repair job APIs intact.
- [x] Run `uv run pytest -q tests/test_desktop_windows_page.py` and `uv run python tools/run_critical_tests.py`; require pass, including existing page syntax validation.
- [x] Inspect the diff and commit the tested UI fix and tests with `fix(desktop): restart the Desktop app after Mordred changes`.

### Task 2: Synchronize documentation and exercise actual Desktop

**Files:** Modify `docs/user/USAGE.md`, `docs/dev/SPEC.md`, `docs/dev/PLAN.md`, `docs/dev/CI.md`.

**Interfaces:** Consumes Task 1's control and labels; produces documented behavior and timestamped actual-UI evidence including backend identity before/after.

- [ ] Update the existing user section to describe whole-app confirmation, pending/failure/manual fallback and neutral metadata mismatch. Add the same bounded contract to the existing Desktop spec/plan sections.
- [ ] Record initial Desktop/backend PIDs, selected runtime paths and health. Confirm source provenance before restarting; preserve the known base-Python editable-path explanation.
- [ ] Back up the installed Desktop `plugin.js` and stage only Task 1's asset using the discovered production page path; verify its bytes match the reviewed asset. Keep the backup path in QA evidence and restore it if staging fails.
- [ ] Through the actual UI, open the new control and cancel once; verify the app and backend PIDs are unchanged and no restart was issued.
- [ ] Through the actual UI, confirm restart; observe immediate pending state, Desktop reopen and a different Desktop backend PID. Verify Mordred health and both version fields after reopening; mismatch persistence is recorded truthfully, not treated as restart failure.
- [ ] Record outcomes and limitations in the manual validation log. Automated tests cover unsupported/remote/timeout cases that are not safely reproducible on the live installation.
- [ ] Run `git diff --check` and `uv run pytest -q tests/test_desktop_windows_page.py`; commit the documentation and actual-UI evidence with `docs(desktop): document app restart behavior and validation`.

### Task 3: Freeze, review and integrate `0.3.0a2` into dev

**Files:** Version surfaces listed above; review the entire feature branch.

**Interfaces:** Consumes passing implementation and actual-UI evidence; produces a merged `dev` PR with nonempty `### Fixes` release-note entries and synchronized version `0.3.0a2`.

- [ ] Check both distribution indexes and repository releases for an existing `0.3.0a2`; do not reuse a published version or silently overwrite artifacts.
- [ ] Run `uv run python tools/bump_version.py 0.3.0a2`, then `uv run pytest -q tests/test_packaging_versions.py`; require all pinned surfaces to agree.
- [ ] Run the final full local acceptance once: `uv run pytest --cov=src/mordred_hermes`, `uv run ruff check src tests scripts`, `uv run ruff format --check src tests scripts`, `uv run mypy --strict src tools scripts/keyvault_offline_digest.py`, `shellcheck scripts/*.sh native/*/build.sh`; require pass and coverage at least 80%.
- [ ] Obtain the required fresh whole-branch reviewer using `superpowers:requesting-code-review`; include the approved contract, tests, actual-UI evidence and five Review Focus cases. Resolve findings and rerun checks affected by any changes.
- [ ] Commit the synchronized bump, push `fix/desktop-restart`, and open the PR to `dev` with concise `### Fixes` and validation evidence. Complete required CI; do not bypass failures or merge with unresolved review findings.
- [ ] Merge the accepted PR to `dev` and record its commit/PR link for release notes.

### Task 4: Release through main, TestPyPI and PyPI

**Files:** No ad hoc workflow changes; follow `docs/dev/CI.md` → `Normal release (runbook)` and `.github/workflows/release.yml`.

**Interfaces:** Consumes integrated `dev` version `0.3.0a2`; produces canonical and shim distributions, exact-SHA annotated tag `v0.3.0a2`, and a GitHub prerelease.

- [ ] Open `dev` → `main` release PR, aggregate included `### Changes` / `### Fixes`, wait for final CI, and merge. Record the resulting exact `main` SHA.
- [ ] Wait for accepted final CI evidence on that exact `main` SHA: successful actual jobs, complete workers/packs and retained acceptance artifact. Ordinary/critical/docs CI is insufficient; dispatch final CI if required.
- [ ] Dispatch `release.yml --ref main` with `target=testpypi`, `mode=release`, `expected-version=0.3.0a2`, `skip-ci-gate=false`; require green build/publish at the recorded SHA.
- [ ] In a fresh temporary venv, install exact `hermes-mordred==0.3.0a2` from TestPyPI with PyPI dependencies. Verify installed metadata, the single `mordred` plugin entry point and `hermes-mordred --version`; inspect the shipped asset for the new restart control.
- [ ] Dispatch TestPyPI `mode=compat`; use another fresh venv to install exact `mordred-hermes==0.3.0a2`, verify canonical dependency/version, uninstall only the shim, and verify canonical runtime and CLI remain.
- [ ] Confirm `main` still equals the accepted release SHA, then repeat canonical-first publication and both fresh-venv checks on production PyPI with the same version and no gate bypass.
- [ ] Require the production compat run's `github-release` job to pass; inspect the annotated tag's exact commit, GitHub prerelease flag and notes. Do not create/move a tag manually. If finalization fails after upload, diagnose and rerun only failed jobs on that run.
- [ ] Report release/PR links, package version, verification evidence and any remaining production provenance limitation. A production install change is a separate deliberate rollout; do not repair the editable-path mismatch implicitly.
