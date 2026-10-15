# Minimal Routine CI and Consolidated Release Validation Implementation Plan

**Status:** Proposed revision 2; planning only, no implementation performed.
**Planner:** Astra, responding to the request to reduce CI further than 13 ordinary / 15 final jobs.

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` after this plan is approved. The current request authorizes planning, not implementation.

**Goal:** Make normal CI three jobs by default, add platform work only for relevant changes, and consolidate comprehensive final validation into six jobs.
**Architecture:** Linux always runs the whole default suite for ordinary code changes. A small explicit path table selects optional macOS/Windows workers and additional check steps; shared security, infrastructure and unknown changes select final validation. Release accepts only final evidence for the exact release SHA.
**Tech Stack:** GitHub Actions, pytest, pip, existing native selectors, Rust/Cargo and Swift.
**Spec:** `AGENTS.md`, `docs/dev/CI.md`, `docs/dev/PLAN.md` §0.6 and `docs/dev/setup.md`. This proposal deliberately changes the current ready-PR/full-matrix policy.

## Recommendation

Use **three ordinary jobs**: policy, Ubuntu Python 3.12 validation, acceptance. Add at most one macOS and one Windows worker when their boundaries are affected. Stop scheduling the eight separate support jobs on every change; preserve their assertions as conditional steps in the relevant worker. Final validation has six jobs total.

| Option | Ordinary jobs | Final jobs | Main tradeoff |
|---|---:|---:|---|
| **Recommended: minimal Linux + selected platforms** | **3 normally; 4–5 when needed** | **6** | Unrelated changes lose immediate native macOS/Windows feedback |
| Simpler all-platform baseline | 5 every code change | 6 | More setup and platform work, but fewer scope decisions |
| Linux-only until release | 3 | 6 | Native failures can escape all ordinary merges; not recommended for this repository |

This is materially smaller than the previous 13/15-job proposal. It does not rename existing work into hidden additional jobs: helper, floor, feature, packaging and integration checks become steps on the existing workers. One Windows job means **one Windows runner including `winkey-helper`**.

## Measured baseline and estimated effect

Evidence: `/tmp/hermes-mordred-ci-baseline-2026-10-12.json`, containing 13 comparable current successful full runs; older differently shaped runs are excluded. A sample is [run 38137124988](https://github.com/mordredagent/hermes-mordred/actions/runs/38137124988).

| Configuration | Jobs | Raw summed runner time | Workflow wall time |
|---|---:|---:|---:|
| Current full CI | 25 | Measured median **192.15 min** | Measured median **18.80 min** |
| Proposed ordinary, Linux-only scope | 3 | Planning budget **8–12 min** | Approximately one Linux suite, about **6–10 min** before variability |
| Proposed ordinary with native/platform work | 4–5 | Depends on selected modules/check packs | A broad Windows selection can take **40–50 min** |
| Proposed final | 6 | Planning budget **75–95 min**, possibly higher after consolidation | Approximately **40–50+ min**, dominated by one Windows runner |

The ordinary arithmetic proxy retains only each historical run's policy + Ubuntu 3.12 cell: median **7.25 minutes**, range **5.30–7.95**, before acceptance and any conditional check steps. The final proxy retains Linux 3.11/3.13, macOS 3.11, one Windows interpreter's native work, and all support checks: median **80.88 minutes**, range **72.58–88.88**. It still includes duplicated historical setup, which consolidation may reduce. These are scope projections, not A/B benchmarks; they are not billed minutes or dollar costs.

Thus a narrow ordinary run could use roughly **94–96% less raw runner time** than today's full run. This applies to the eligible narrow route, not every change or the whole release lifecycle. Final consolidation mostly reduces job/setup duplication; it does not remove most of the remaining test work. One Windows runner trades lower compute for longer final latency. Caches alone cannot provide comparable savings: the representative run spent about 121.9 minutes in Windows pytest and only 6.9 minutes installing its shard dependencies.

## Jobs and test scope

| Job | Ordinary | Final |
|---|---|---|
| `ci-policy` | Complete diff, conservative scope outputs | Same classifier; final forced by event/override |
| `linux` | One Ubuntu worker, Python 3.12: **entire default pytest suite**, coverage ≥80%, reduced-extras strict mypy, Ruff/format, shellcheck, status-skill guard; selected support steps | Two Ubuntu workers, Python 3.11 and 3.13: same entire suite/coverage/mypy. Static checks and all support steps run on 3.11 only |
| `macos` | Optional one worker, Python 3.12: entire default suite, coverage ≥80%, reduced-extras+macOS mypy, relevant helper steps | One worker, Python 3.11: entire suite/coverage/mypy, status-skill guard, Swift helper, TPM helper macOS checks |
| `windows` | Optional one worker, Python 3.12: critical preset + complete selected native module families; relevant helper/wheel steps | One worker, Python 3.11: **all 84 native modules once**, Windows helper formatting/clippy/stable/MSRV/scoped Python tests, sdist-derived wheel smoke |
| `CI acceptance` | Verify exactly the selected workers/step packs succeeded; record ordinary scope | Verify all four execution workers and all final step packs; record final scope |

Final count is policy 1 + Linux matrix 2 + macOS 1 + Windows 1 + acceptance 1 = **6**. Ordinary is 3–5. No separate full-marker runner, feature-extras runner, package runner, floor runner, Tor runner or native-helper runner remains.

Support checks on Linux 3.11 final run in this order: main reduced-extras checks, feature-extra import assertions/focused suites, Hermes 0.13.0 floor suite, canonical/compatibility package smoke, Tor/SOCKS/provider integration, TPM Rust checks/MSRV, swtpm Rust and Linux Telegram integration. Each retains its original command/assertions. Keep the main, feature, floor, integration and fresh-wheel Python environments separate; adding extras to the main typing environment would invalidate its current guarantee. macOS/Windows likewise keep installed-wheel smoke outside checkout and isolated from source imports. Use pip download caches across these clean environments.

Ordinary uses one interpreter version, 3.12. Final uses two, 3.11/3.13, with macOS/Windows/support Python fixed at 3.11. Across the lifecycle three versions remain represented. There is **no final macOS 3.13 or Windows 3.13 native coverage**, and Windows 3.12 is selected ordinary coverage only. The 3.13 upper-edge signal becomes Linux-only. This is deliberate sampling, not proof that every supported OS/version combination works. If two versions globally is preferred later, use ordinary 3.11; it needs no additional matrix design.

## Event policy

| Event | Selected work |
|---|---|
| Ordinary ready PR | 3-job ordinary route plus relevant optional platform/check packs |
| Known draft PR | Linux critical preset instead of entire suite; add critical native platform feedback when mapped. Explicitly feedback only |
| Shared security/bootstrap/native/install/dependency/CI change, or unknown/incomplete scope | Final once ready; draft remains feedback unless explicitly overridden |
| Existing PR event with `ci:full` already present | Final |
| PR targeting `main` | Final |
| `dev` push | Ordinary only with a trusted accepted exact-`before` baseline and complete change classification; otherwise final |
| `main` push or manual dispatch | Final unconditionally |
| Pure allowlisted docs PR | Two jobs: policy, then `CI acceptance` running documentation contract checks itself |
| Unknown/malformed event | Final |

Keep existing PR event types: opened, synchronize, reopened, ready_for_review, converted_to_draft. Do not add `labeled` events or no-op modes: a label-only run could cancel useful same-ref CI. Applying `ci:full` alone does not trigger a run; apply before ready conversion or a subsequent synchronize/reopen event. A manual branch-HEAD run is full evidence for that branch SHA, not evidence for a synthetic PR merge commit and not a substitute for required PR-triggered checks.

Do not automatically skip the `dev` post-merge run or replace it with critical tests merely because the PR passed. Actual merge SHAs/context can differ. Its normal cost is now one Linux suite. The existing concurrency cancellation remains useful, but ordinary `before..after` classification is allowed only if the exact `before` commit already has trusted acceptance. Initial/force pushes, missing ancestry, previous pending/failed/cancelled validation or unavailable evidence select final, preventing cancelled high-risk work from being forgotten.

## Scope rules: explicit and bounded

All code paths below are relative to `src/mordred_hermes/`. Priority is: forced-final event → sensitive boundary → known ordinary/platform rule → unknown final. New/deleted/unmapped source or test files select final until the rule table is deliberately extended. Renames evaluate both old and new paths. Existing ordinary modules continue to run in the whole Linux suite; there is no changed-test dependency graph for Linux.

| Changed boundary | Ordinary additions, or escalation |
|---|---|
| Known portable component logic, formatting and presentation files outside rules below | Linux whole suite only. Initial prefixes: existing files in `llm_guard/`, `privacy_check/`, `extension/`, `network/`; exact platform/security overrides below win. Wizard ordinary allowlist: `_term.py`, `_prompt_io.py`, `_network_answers.py`, `_defaults.py`, `_typing.py`, `policy_explainer.py`; unknown wizard paths select final |
| `network/**` except `guidance.py`, `_exceptions.py`, `_typing.py` if present | Linux Tor/SOCKS/provider integration + one Windows worker with the entire network family |
| `llm_guard/_windows_policy.py`; `privacy_check/_windows_audit.py`; component policy changes `llm_guard/_policy_settings.py`, `privacy_check/policy.py`, `privacy_check/_checked_policy.py` | One Windows worker with complete LLM/privacy policy families; Linux still runs all containing suites. Do not escalate merely because a component is named security/privacy |
| Windows-named files in known extension/Telegram code; `desktop/**` excluding installers | One Windows worker with the complete extension/Desktop/Telegram family. Mac-dependent Desktop capture/member code also requests macOS |
| `desktop/_capture.py`, `desktop/member.py`, `privacy_check/_keyvault_probe.py`, and existing macOS-native test modules | macOS whole suite; Desktop also retains its Windows family. Swift/helper implementation changes are native and therefore final |
| Ethereum/QR/Telegram optional-feature owners: `keyvault/ethereum.py`, `keyvault/_bip32.py`, `wizard/keyvault_eth_cli.py`, `wizard/extension_pair_cli.py`, `extension/telegram/**`, wallet/signing test modules | Feature-extra import proof and focused suites in a separate Linux environment. Sensitive keyvault/authentication owners below take precedence and receive this in final |
| Upstream-consumption seams: `llm_guard/local_adapter.py`, `network/provider_transport_flagger.py`, `network/hooks.py`, `privacy_check/hooks.py`, `extension/gateway_plugin.py`, `extension/telegram/hermes_tools.py` | Linux Hermes-floor pack; other matching platform/feature packs also run |
| `README.md`, shipped web/assets, package asset-contract tests | Linux canonical/compatibility package smoke. Add Windows wheel smoke on its worker for Windows shipped assets; installer/dependency/build machinery below forces final |
| `plugin.py`, `_plugin_identity.py`, `_home.py`, `_runtime_bootstrap.py`, `_pth_bootstrap.py`, `_windows_runtime.py` | Final: initialization/runtime identity crosses components and platforms |
| `_private_fs/**`, `_config_io.py`, `_yaml_io.py`, `_file_lock.py`, `_policy_io.py`, `_policy_types.py`, `_audit_io.py`, `_audit_session.py`, `_audit_support.py`, `_log_rotation.py` | Final: checked storage, custody/policy publication and audit consistency |
| `keyvault/**`, `dbcrypt/**`; extension `crypto.py`, `e2e.py`, `pairing.py`, `webauthn.py`, `rpc.py`, `api.py`; Telegram `memory_guard.py`, `secrets.py`, `windows_secrets.py`, `_windows_archive.py`, `store.py`, `hardening.py` | Final: crypto, persistent secrets, authentication, memory/database custody; whole modules and relevant live-device paths remain mandatory |
| Wizard configure/credential/policy/storage/install/uninstall orchestration; `desktop/install.py`, `desktop/_windows_assets.py` | Final. Exact initial paths/patterns: `wizard/configure.py`, `credentials_writer.py`, `env_file_writer.py`, `policy_writer.py`, `*_vault*`, `*keyvault*`, `*memory*`, `*encryption*`, `*database*`, `*install*`, `setup_cli.py`, `config_decrypt_cli.py`, `env_decrypt_cli.py`, `workspace_cli.py` |
| Repository `native/**`, `scripts/install.sh`, `scripts/install.ps1`, `scripts/keyvault_offline_digest.py`, `packaging/**`, `pyproject.toml`, `uv.lock`, `.github/**`, `tools/**`, `AGENTS.md`; corresponding sensitive tests | Final, including every retained support pack |
| New/unknown source, tests, scripts or package-root helpers | Final until explicitly classified |

The finite table must be checked against the actual current tracked inventory during implementation. It is an ownership rule, not proof of absence of indirect effects. Avoid silently granting ordinary eligibility to future files through a broad glob: record existing allowlisted paths, and require review when adding files.

Windows family selection intersects the frozen 84-module selector, preserves order and selects whole modules: network `tests/test_network_windows_*.py`; LLM `tests/test_llm_windows_policy*.py`; privacy `tests/test_windows_privacy_*.py`; extension/Desktop/Telegram `tests/extension/test_*windows*.py`, `tests/test_desktop_windows_*.py`, `tests/test_windows_telegram_*.py`, `tests/test_wizard_windows_telegram*.py`, plus `tests/test_desktop_capture.py`, `tests/extension/test_desktop_api.py`, `tests/extension/test_desktop_platform.py`, `tests/extension/test_extension_serve_shutdown.py`. Every modified known test module runs whole on its relevant worker. Unknown test ownership selects final. Critical node IDs already covered by a selected module are deduplicated.

Ordinary support steps run only for their owner: Tor for transport/network; feature-extra pack for optional features; package smoke for shipped assets; floor for an explicitly mapped upstream-consumption seam. TPM, Swift and Windows helper changes are sensitive/native changes and therefore final initially; there is no need to invent a broad dynamic helper dependency map. Final always runs every support pack. Existing manual VPN/Secure Enclave/live CNG/live LLM/device requirements remain separate and unchanged.

## Global constraints

- Preserve the Python >=3.11 and Hermes 0.13.0 floors; this plan changes CI sampling, not runtime support metadata.
- Keep the 80% coverage floor on every executed POSIX default-suite cell and reduced-extras strict typing.
- Preserve every selected module's assertions/parameter cases, all 84 final Windows modules, and relevant explicit live-device validation.
- Keep immutable action SHAs, Cargo `--locked`, English documentation, existing heading names, and zero upstream PRs.

## Review focus

1. Cheap or stale evidence must not authorize release; Task 1 tests exact SHA/ref/event/attempt and final-only acceptance.
2. Incomplete diffs or cancelled predecessor runs must not hide prior changes; Tasks 1–2 test cumulative PR diffs and exact accepted `dev` baselines.
3. New files and renamed boundaries must not acquire cheap eligibility accidentally; Task 2 tests both rename paths and unknown ownership.
4. Consolidated environments must preserve reduced extras, the Hermes floor and checked homes; Task 3 validates separate interpreters, dependency profiles and step-scoped flags.
5. Consolidation must execute all expected versions/packs and native cases; Task 3 validates unique per-worker manifests and the complete Windows node-ID union.

## Implementation tasks

### Task 1: Make reduced scope and final evidence unambiguous

**Files:** `tools/ci_test_policy.py`, `tests/test_ci_test_policy.py`, `.github/workflows/ci.yml`, new `tools/check_ci_evidence.py`, new `tests/test_ci_evidence.py`, `.github/workflows/release.yml`.

- [ ] Define `mode=critical|ordinary|docs|final`; `linux_versions` is `["3.12"]` ordinary/critical, `["3.11","3.13"]` final, empty docs; optional macOS/Windows booleans; selected blocking step-pack IDs. No generic “green means full” interpretation remains.
- [ ] Add an always-evaluated acceptance job. It requires every expected worker/pack to succeed and every unrequested worker to be skipped; failure/cancellation/missing evidence refuses acceptance. Matrix results cannot conceal a missing expected interpreter. Draft records feedback-only status and cannot provide merge/release acceptance.
- [ ] Record schema version, mode, repository/workflow/ref/event, exact tested SHA, PR head/base/merge context, expected/executed workers/packs and run/attempt in `ci-acceptance-evidence-<run_id>-<run_attempt>/evidence.json`. Validate the artifact against Actions metadata in the evidence checker, including eligible `push`/manual events for release; PR evidence is not branch-release evidence. Artifact publication happens only after acceptance checks succeed. Docs checks execute directly inside this job, keeping docs at two workers total.
- [ ] Implement `check_ci_evidence.py --repo OWNER/REPO --sha SHA --branch BRANCH --minimum-mode ordinary|final`. Ordinary permits ordinary/final only for the `dev` baseline; release always requests final and exact branch SHA. Production still separately requires `main`; TestPyPI preserves its selected branch. Reject mismatched workflow/ref/SHA/attempt, skipped jobs, malformed/expired evidence and incomplete/API-failed lookup.
- [ ] Add tests for cheap-green release rejection, missing final support packs, skipped expected workers, both final Linux versions, exact-before baseline handling, stale PR context, malformed data and selected-branch TestPyPI versus main-only production. Run `.venv/bin/python -m pytest -q tests/test_ci_test_policy.py tests/test_ci_evidence.py tests/test_packaging_versions.py tests/test_finalize_release.py`.

### Task 2: Implement complete-diff routing with a small ownership table

**Files:** new `tools/ci_change_scope.py`, new `tools/ci_scope_paths.json`, new `tests/test_ci_change_scope.py`, `tools/ci_test_policy.py`.

**Interfaces:** `Scope.mode` represents file scope; event routing in `ci_test_policy.py` applies draft feedback and forced-final overrides to that scope. Frozen `ChangedPath(path: str, status: Literal["added","modified","removed","renamed"], previous_path: str | None = None)` and `Scope(mode: Literal["ordinary","docs","final"], macos: bool, windows: bool, windows_modules: tuple[str,...], packs: tuple[str,...], reason: str)`. `select_scope(changes: Sequence[ChangedPath], *, complete: bool, native_modules: Sequence[str]) -> Scope` implements the priority table. Pack IDs are `features`, `floor`, `package`, `tor`, `swift`, `tpm`, `swtpm`, `winkey`, `windows-wheel`; final selects all.

- [ ] Create the explicit current-path inventory and overrides from the scope table. Test each source family and high-risk override; new tracked paths must be assigned or conservatively final. Do not classify a new file as safe solely because a prefix matches.
- [ ] Enumerate the entire cumulative PR diff with paginated PR files, count verification and both rename paths. For `dev` push, require Task 1's trusted accepted exact-before baseline before using `before..after`; force/initial push, missing history or incomplete evidence selects final.
- [ ] Pin tests for code followed by docs-only commits, mixed-platform changes, unrelated component edits, new files, renamed boundary crossings, pagination limits, missing base and cancelled prior validation. Confirm ordinary portable changes select Linux only; a mapped Windows edit adds exactly one Windows worker and no hidden helper job.
- [ ] Add docs-only eligibility only for existing Markdown under `docs/user/`; exclude README, developer policy/version/setup contracts, skills and native assets. Run complete docs contract modules: `tests/test_docs_links.py`, `tests/test_ux_guidance_guard.py`, `tests/test_packaging_versions.py`, `tests/test_user_installer.py`. Metadata uncertainty selects final.
- [ ] Run `.venv/bin/python -m pytest -q tests/test_ci_change_scope.py tests/test_ci_test_policy.py tests/test_critical_test_runner.py tests/test_native_test_shards.py`. Inspect the chosen reasons for representative historical diffs before enabling routing.

### Task 3: Consolidate all checks into the three OS workers

**Files:** `.github/workflows/ci.yml`, `tests/test_ci_test_policy.py`, `tests/test_native_test_shards.py`, `tests/test_critical_test_home.py`; optional small execution helpers under `tools/` only where removing repeated shell code improves reviewability.

- [ ] Replace the current execution-job fan-out with Linux matrix, optional macOS and optional Windows. Ordinary Linux remains the full default suite, not a reduced test subset. Keep 80% coverage per executed POSIX cell and the strict reduced-extras typing command `mypy --strict src tools scripts/keyvault_offline_digest.py`.
- [ ] Move existing support-job commands into blocking worker step packs, using the explicit ownership and final flags. Keep feature import assertions, Hermes floor version assertion, sdist→wheel package path, immutable action SHAs, Cargo `--locked`, MSRV and emulated/live distinctions. Each pack has explicit working directory and step-scoped environment; never export `MORDRED_TPM_TEST`, live flags or helper overrides globally. Preserve immediate PowerShell `$LASTEXITCODE` checks so an earlier failure cannot be hidden by a later successful command. Do not use `continue-on-error` to mask failed packs.
- [ ] Preserve separate clean Python environments for main reduced extras, optional features, floor and integration; fresh wheel smoke stays outside checkout. Use one macOS extras install and pip/Cargo download/build caches keyed appropriately. Do not change latest-PyPI resolution to a locked local environment.
- [ ] Final Windows executes the existing named native step's 84-module selector with `--shard-index 1 --shard-count 1`, then helper checks/wheel smoke. Keep that full selector visible for the external harness, the independent original-82-module digest and all added modules. Ordinary Windows runs critical + complete family modules, with checked home established before imports.
- [ ] Publish one unique worker manifest artifact per OS/interpreter/run/attempt (`ci-worker-evidence-<os>-<python>-<run_id>-<run_attempt>/worker.json`), recording the actual test interpreter and each expected pack's result. Acceptance must collect the exact expected manifest set and validate run/attempt/SHA; never rely on shared matrix job outputs, which can overwrite each other. Record per-worker/per-pack completion and use explicit result checking in acceptance; final TPM coverage requires both Linux and macOS pack results, not one generic `tpm=success` flag. A failure early in a consolidated worker may stop later dependent packs; it must never produce accepted final evidence. Upload available JUnit/coverage even on failure and record which packs did not execute. Re-running that worker repeats more work than the previous separate-job design; this is a consolidation tradeoff.
- [ ] Test focused workflow/selector invariants, run Ruff/format and strict typing for modified tools, then one representative Linux-only ordinary run, one mapped platform run and one complete final run. Verify final Windows node-ID union with no dropped/duplicated cases. Start with Windows final timeout 90 minutes and Linux final timeout 60 minutes, then tune from measurements without shortening test-level security timeouts.

### Task 4: Update policy and roll out the smaller gate atomically

**Files:** `AGENTS.md`, `docs/dev/CI.md`, `docs/dev/PLAN.md` §0.6, `docs/dev/TODO.md` §0.6, `docs/dev/setup.md`; preserve existing headings and write English.

- [ ] Document three-job default, conditional platform checks, six-job final, the explicit omitted OS/version combinations and delayed-discovery risk. Existing required-check names/matrices change; future protection should require `CI acceptance`, not conditionally skipped legacy jobs.
- [ ] Document merge rules: ordinary acceptance can authorize a mapped non-foundation code merge; sensitive/unknown changes require final on the current PR merge context. Any head/base change invalidates prior context. Branch protection is currently unavailable, so this remains an operational rule until protection can enforce it.
- [ ] Document release sequence: final release-PR validation, merge, final run on the exact new `main` SHA, then manual publication. Cheap ordinary/docs/draft runs never count. Preserve TestPyPI-only explicit bypass and forbid production bypass.
- [ ] Land reduced routing and release-evidence hardening together; never deploy a temporary cheap-green release loophole. Run one full final integration validation, not repeated broad suites for unchanged prose. Leave the user's untracked `docs/dev/UBUNTU_MANUAL_INSTALL_NOTES.md` untouched.

## Review risks, measurements and further limits

The recommended three-job route intentionally stops executing unselected native platforms, Hermes floor, extras, wheel smoke and live-network integration on unrelated changes. Some cross-platform/dependency defects will appear at final validation instead of the ordinary PR. The policy table makes this tradeoff explicit; the full Linux suite remains the broad daily regression net.

Collect at least three Linux-only ordinary runs, representative 4/5-job platform runs and three final runs. Track actual mode/pack selection, test counts, cold/warm cache, workflow wall time and raw runner time including cancelled attempts. The percentage of changes that fall back to final determines aggregate savings; do not infer it from a single small edit. Do not weaken boundary classification or test assertions to make a runtime estimate come true.

No schedule is added initially: it would spend more minutes, and releases already require final validation. No blanket pytest parallelism, widened stateful fixtures, reduced security timeouts or omitted parameter matrices are part of this plan. If 40–50-minute final Windows latency is unacceptable, an explicit optional single-version three-shard mode is possible, but it changes the requested one-Windows-runner preference.

Further reducing workflow count by reusing PR evidence on a `dev` push requires exact tested-context equivalence, not nearby SHA or matching filenames. Defer that optimization rather than weakening the fresh release gate. The selected design already removes most routine work with a small, reviewable number of rules.

GitHub's [required-check documentation](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks) explains why skipped jobs/whole-workflow filters cannot substitute for explicit acceptance. The official [setup-python cache documentation](https://github.com/actions/setup-python#caching-packages-dependencies) distinguishes cached downloads from installed environments; cache savings must be measured.
