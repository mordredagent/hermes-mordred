# Mordred — CI Policy (Hermes-base)

> **Note**: This document describes the CI strategy of the Mordred plugin development repository (`Mordred-Hermes/`). The old OpenClaw-based version remains at `../../mordred/mordred-mvp-docs/CI.md` (deprecated).

The old version had a complex setup that disabled 42 workflows inherited from OpenClaw upstream in the fork. With the move to Hermes, Mordred's positioning changed to a **plugin development repository**, so CI is dramatically simplified as well.

## Why it got simpler

`Mordred-Hermes/` is not a fork of Hermes upstream — it's a **repository dedicated to the Mordred plugin**. It has none of Hermes upstream's release lane / signing keys / Blacksmith runner / CodeQL enterprise tier, and doesn't need to imitate any of it.

Responsibilities CI must fulfill:

1. Mordred plugin (`src/mordred_hermes/*`) tests are green
2. Lint / format / type check are green
3. (Optional) Detecting Hermes upstream hook-signature drift

Everything else is upstream's responsibility, and runs in upstream's CI.

## Standalone-repo adaptations (2026-07-01)

When this repo split off from `Mordred-Hermes-monorepo` (see ROADMAP.md §"Browser-extension gateway counterpart (deferred)"), `.github/workflows/` was left out entirely, and this document was the only thing that survived the split — still describing workflows that no longer existed. Restoring them requires reflecting the following changed assumptions:

- **`hermes-agent` is now published on PyPI** (confirmed `hermes-agent==0.14.0`, 2026-07-01). The old design's premises — "`hermes-agent` isn't on PyPI so a root install is required" and "the `fresh-venv-resolution` job (H1) asserts install **fails** without it" — no longer hold. `pip install -e .` resolves `hermes-agent` on its own. The `fresh-venv-resolution` job is **retired**: H1's purpose (fail-fast when `hermes-agent` is absent) is moot now that it's always resolvable from PyPI
- **`upstream-check.yml` no longer needs `git clone`**: `pip install hermes-agent` unpacks its source (plain `.py` files, not compiled) into site-packages, so `tools/check_hook_payload_drift.py --hermes-root <site-packages>` works directly (verified locally)
- The following were initially left out of the 2026-07-01 restoration and were **restored on 2026-07-06** (same adaptation pattern: PyPI install, flat repo-root paths, `HERMES_HOME` isolation on pytest steps):
  - `.github/workflows/release.yml` (PyPI Trusted Publishing) — workflow restored (`reserve` builds `packaging/name-reservation/`, `release` builds the repo root). The one-time external operator setup (pending publishers + GitHub Environments, see §"`release.yml` details" §"Initial setup") was **completed on 2026-07-07** and the M7 name reservation (`mode=reserve`) was dispatched and verified on both TestPyPI and PyPI (`mordred-hermes 0.0.0.dev0`)
  - `.github/workflows/integration-vpn.yml` — restored; still `workflow_dispatch`-only and requires the `MORDRED_MULLVAD_ACCOUNT` repo secret (paid resource) before it can be dispatched
  - the `integration-tor` / `tpmkey-helper` / `tpmkey-helper-tpm` jobs inside `ci.yml` — restored; `native/**` was added to the `ci.yml` paths filter so Rust-crate changes trigger CI. These jobs are not branch-protection required checks (required checks stay the two `test` 3.12 cells)

## Active workflows

| Path | Purpose | Status |
|------|---------|--------|
| `.github/workflows/ci.yml` | Per-PR / push: `test` (matrix; ruff + mypy + pytest) + `hermes-floor` + `integration-tor` + `tpmkey-helper` + `tpmkey-helper-tpm` jobs | **restored** (5 jobs) |
| `.github/workflows/upstream-check.yml` | Weekly detection of Hermes hook signature + payload drift | **restored** (simplified `git clone` to `pip install hermes-agent`) |
| `.github/workflows/labeler.yml` | Auto-labels PRs by path (mordred-* paths) | **restored** |
| `.github/workflows/integration-vpn.yml` | `workflow_dispatch`-only: live Mullvad VPN integration test (PR3b, pairs with the `integration-tor` job) | **restored** (needs `MORDRED_MULLVAD_ACCOUNT` secret before dispatch) |
| `.github/workflows/release.yml` | `workflow_dispatch`-only: PyPI publish for `mordred-hermes` (M7) | **restored** (operator setup + M7 name reservation completed 2026-07-07, §Initial setup) |

The detail sections below are left as they were in the pre-split design (historical record). Where they conflict, the "Standalone-repo adaptations" note above takes precedence.

## `ci.yml` details

See `.github/workflows/ci.yml` for the implementation. `ci.yml` consists of **5 jobs**:

1. **`test`** — the unit-test job across the matrix (OS × Python). ruff + mypy + pytest, plus a cheap `hermes-mordred policy dry-run skills/mordred-status` step that guards against `skills/mordred-status/SKILL.md` drifting out of sync with the live CLI
2. **`hermes-floor`** — pins `hermes-agent==0.13.0` (the floor declared by `pyproject.toml`'s `hermes-agent>=0.13.0`; 0.13.0 is hermes-agent's first PyPI release — the job's own first run proved the old 0.11.0 floor was never installable), installs `mordred-hermes` on top of it, asserts the resolver did not silently upgrade it off the pin, then runs the unit suite against that exact combination. Every other job resolves the latest PyPI `hermes-agent`, so without this job the declared floor is never actually exercised
3. **`integration-tor`** — hermetic Tor Docker integration-test job (Linux-only; macOS runners have no Docker)
4. **`tpmkey-helper`** — verifies the `native/tpmkey-helper` Rust crate (the Linux TPM 2.0 helper) on both ubuntu and macOS with `cargo fmt --check` / `cargo clippy -D warnings` / `cargo test`. Builds the pure-function layer (wire / SEC1 codec / 32-byte ECDH-Z left-pad / blob store / neutral error taxonomy) on both OSes to guarantee, on real Linux, "a Linux build that can't be verified on a macOS dev host." The Linux leg also builds the v2-OS2 Phase 2b `tss-esapi` TPM backend (`cfg(target_os="linux")`), so it installs libtss2-dev + libclang; the backend's live tests are gated behind `MORDRED_TPM_TEST` and run in job 5
5. **`tpmkey-helper-tpm`** — v2-OS2 Phase 2b. Starts a `swtpm` software TPM on ubuntu and verifies the `tss-esapi` backend end-to-end with `MORDRED_TPM_TEST=1` (generate / public_key / delete / ECDH parity against software P-256). Tests share a single swtpm command server, so `--test-threads=1`

Key points:

- **paths filter (differs by trigger type)**:
  - `pull_request` trigger: `src/**`, `tests/**`, `tools/**`, `native/**`, `pyproject.toml`, `uv.lock`, `.github/workflows/ci.yml`, `docs/dev/CI.md`
  - `push` (`main`, `dev`) trigger: the same list minus `docs/dev/CI.md` (docs-only changes are checked in the PR and not re-run on push)
- **concurrency**: the `ci-${{ github.ref }}` group + `cancel-in-progress: true` automatically cancels older runs on the same PR
- **permissions**: top-level `contents: read` — every job in this workflow only reads the checked-out source; nothing here needs to write anywhere
- **`test` job — install**: `pip install -e ".[dev,keyvault,extension]"` resolves `hermes-agent` directly from PyPI (no monorepo root install step); macOS runners additionally install the `macos` extra (pyobjc Security/SystemConfiguration/Quartz bridges)
- **`keyvault` extra (all platforms)**: installs the cross-platform crypto stack (`cryptography` / `argon2-cffi` / `blake3`) on every runner, so that `mypy --strict src tools` / pytest can resolve the keyvault modules on Linux too (these packages themselves are cross-platform; the macOS-only restriction on keyvault *functionality* is gated by the pyobjc bridge below)
- **`test` job — steps**: ruff lint → ruff format check → `mypy --strict src tools` → pytest (coverage XML) → SKILL.md drift guard. `mypy` covers `tools/` as well as `src/` to match `pyproject.toml`'s `[tool.mypy] files` setting — CLI args override config `files`, so omitting `tools` here would silently stop checking it
- **Matrix**: macOS Apple Silicon (confirms Phase 4 keyvault behavior) × Ubuntu (confirms Phase 1-3 multi-platform behavior) × Python 3.11 / 3.12 / 3.13 (aligned with Hermes upstream's `requires-python = ">=3.11"`). 3.13 was added as a new cell and should be watched for a cycle — `fail-fast: false` means a 3.13-only failure (e.g. a lagging pyobjc/blake3 wheel) won't block the 3.11/3.12 cells
- **pip caching**: `test`, `hermes-floor`, and `integration-tor` all pass `cache: pip` to `actions/setup-python@v5`
- **`hermes-floor` job**: standalone (no `needs:`), Python 3.12 on ubuntu-24.04. Pins `hermes-agent==0.13.0`, installs `mordred-hermes[dev,keyvault,extension]` on top of it, then a guard step reads back the installed `hermes-agent` version via `importlib.metadata` and fails the job if it isn't still `0.13.0` (which would mean the floor itself went untested). Runs the default unit suite (`pytest`; `pyproject.toml`'s `addopts` already excludes `-m integration`) **minus two deselected latest-tracking drift detectors** (`test_replica_matches_hermes_source` — the provider replica byte-matches the *installed* hermes and deliberately tracks PyPI-latest; `test_known_provider_slugs_are_real_hermes_ids` — requires provider ids only recognised from hermes-agent 0.18.0). Including them would force floor == latest forever; both still run at latest in the `test` job
- **`integration-tor` job**: `needs: test`. Installs `mordred-hermes[dev,integration]`, builds the Docker image under `tests/integration/docker/tor/`, and runs the Tor + SOCKS5h + provider-transport integration tests with `pytest -m integration`
- **`tpmkey-helper` / `tpmkey-helper-tpm` caching**: both jobs cache `~/.cargo/registry`, `~/.cargo/git`, and `native/tpmkey-helper/target` via the GitHub-owned `actions/cache@v4` (not the third-party `Swatinem/rust-cache`, consistent with this repo's supply-chain stance — see the `tor-control` extra's `stem`-gating rationale in `pyproject.toml`), keyed on `${{ runner.os }}-...-${{ hashFiles('native/tpmkey-helper/Cargo.lock') }}`
- **coverage**: saved as an artifact named `coverage-${os}-py${version}` via `actions/upload-artifact@v4`. Codecov integration is a separate PR (to be enabled after adding the token as a repo secret)
- **Live tests** (`MORDRED_LIVE_LLM_TEST=1` / `MORDRED_KEYVAULT_LIVE=1`) do not run by default and have **no** CI workflow automation — there is no `workflow_dispatch` for either suite. The only live-gated suite with a `workflow_dispatch` is VPN (`MORDRED_LIVE_VPN_TEST=1`, `integration-vpn.yml`, see below). For the keyvault/LLM suites, the compensating control is the manual on-device validation log below (§Manual live-device validation log)

## `integration-vpn.yml` details

See `.github/workflows/integration-vpn.yml` for the implementation. This is the live integration-test workflow that pairs with `ci.yml`'s `integration-tor` job — while the Tor side always runs in CI (the `integration-tor` job), the VPN side is split out into this separate workflow.

- **trigger**: `workflow_dispatch` only — never runs automatically on push / PR. The Mullvad account number is a paid resource, and bring-up mutates the runner's actual network state
- **input**: `mullvad_version` (the Mullvad client version; semver or `latest`)
- **secrets**: requires `MORDRED_MULLVAD_ACCOUNT` (the 16-digit account number) as a repo secret
- **Procedure**: install `hermes-agent` (root) + `mordred-hermes[dev]` → install the official Mullvad daemon on the runner → run `pytest -m integration tests/integration/test_vpn.py` with `MORDRED_LIVE_VPN_TEST=1` → always `mullvad disconnect` / `account logout` in teardown

## Manual live-device validation log

- **2026-05-25**: the operator reported successful on-device validation of the hardware/network-gated suite that's excluded from the default PR CI:
  - `MORDRED_KEYVAULT_LIVE=1 pytest -m integration tests/integration/test_keyvault_macos.py -v` — run on actual macOS Secure Enclave hardware.
  - `MORDRED_LIVE_VPN_TEST=1 MORDRED_MULLVAD_ACCOUNT=... pytest -m integration tests/integration/test_vpn.py -v` — run against a real Mullvad CLI / daemon session.

The Tor path is covered separately by the hermetic Docker-based `integration-tor` CI job. It requires neither host VPN state nor Secure Enclave hardware.

## `upstream-check.yml` details

See `.github/workflows/upstream-check.yml` for the implementation (DECIDE 0.1: confirmed for introduction in v1, 2026-05-09). Key points:

- **schedule**: weekly on Monday 03:00 UTC (`cron: "0 3 * * 1"`) + `workflow_dispatch`
- **permissions**: `contents: read` + `issues: write` (for automatically filing an issue when drift is detected)
- **Drift detection**: after `git clone --depth 1` of Hermes upstream, run `pip install -e ./hermes-upstream` to reliably pull in transitive deps (PyYAML, etc.) before importing `hermes_cli.plugins.VALID_HOOKS` (relying on a sys.path hack instead would misdetect the runner's missing deps as `__MISSING__`). Compares the retrieved hook list against the results of grepping the Mordred plugin's `register_hook("...")` calls
- **Phase 0 caveat**: since the Phase 0 plugin is a no-op stub, there are 0 `register_hook` calls. Don't fail even when the required-set is empty (drift detection becomes meaningful once Phase 1.x starts calling hooks)
- **If `VALID_HOOKS` disappears**: a constant rename on the Hermes upstream side is also treated as a drift signal, and an issue is filed as `__VALID_HOOKS_REMOVED__`
- **Issue filing**: when a diff occurs, an issue is automatically filed with the `actionable` + `upstream-drift` labels. If an `upstream-drift` issue is already open, dedup logic **appends a comment instead of filing a new issue** (preventing issue pile-up from weekly reruns). When payload field drift is detected, the issue body also lists the missing fields per call site
- **Payload field drift detection (added 2026-06-12, TODO L474)**: in addition to hook **names** (`VALID_HOOKS` membership), `tools/check_hook_payload_drift.py` scans the upstream source with pure `ast` and cross-checks whether every `invoke_hook("<name>", key=value, ...)` dispatch site in core passes the payload fields Mordred consumes (`tools/hook_payload_contract.json`) — no import or install required. `tests/test_hook_payload_drift.py` enforces that the contract keys exactly match the plugin's `register_hook` calls, and that same test's canary runs the identical check against the vendored fork (this repository's own Hermes tree) on every CI run

## `labeler.yml` details

The implementation consists of 2 files:

- `.github/labeler.yml` — the mapping table between labels and path globs (`actions/labeler@v5` schema)
- `.github/workflows/labeler.yml` — drives `actions/labeler@v5` on `on: pull_request_target`

Labels need to be created in the repository ahead of time (one-time `gh label create`):

```sh
gh label create plugins/mordred-network        --color 1F77B4 --description "mordred_network plugin"
gh label create plugins/mordred-privacy-check  --color 1F77B4 --description "mordred_privacy_check plugin"
gh label create plugins/mordred-llm-guard      --color 1F77B4 --description "mordred_llm_guard plugin"
gh label create plugins/mordred-keyvault       --color 1F77B4 --description "mordred_keyvault plugin"
gh label create plugins/mordred-wizard         --color 1F77B4 --description "mordred_wizard plugin"
gh label create actionable                     --color D73A4A --description "Needs maintainer action"
gh label create upstream-drift                 --color FB8500 --description "Hermes upstream signature drift"
gh label create docs                           --color 0E8A16 --description "Documentation only"
gh label create ci                             --color 6F42C1 --description "CI/CD configuration"
```

Because it uses `pull_request_target`, labels are applied even to PRs from forks. Permissions are only `contents: read` + `pull-requests: write` (it never checks out the PR HEAD code — label mutation only).

## `release.yml` details

See `.github/workflows/release.yml` for the implementation (M7, TODO §0.5 L70). Publishes `mordred-hermes` to PyPI / TestPyPI. **`workflow_dispatch` only** — since a PyPI publish is irreversible (a deleted version/filename can never be re-uploaded), it doesn't run automatically.

- **Authentication**: PyPI Trusted Publishing (OIDC). No API tokens are stored at all. The `publish` job obtains a short-lived OIDC token with `id-token: write` permission, and `pypa/gh-action-pypi-publish` authenticates with it
- **`target` input**: a choice of `testpypi` / `pypi`. Gated via GitHub Environments (`testpypi` / `pypi`) — setting required reviewers on the `pypi` Environment inserts a manual approval step before production publishing
- **`mode` input**:
  - `reserve` — builds the empty stub in `packaging/name-reservation/` (`0.0.0.dev0`). A one-time reservation to protect the name from squatting before v1 docs go public
  - `release` — builds the real package (`mordred-hermes/`, `0.1.0a0`+). Used for normal releases after the name reservation
- **build job guard**: `reserve` mode verifies the artifact is `0.0.0.dev0`, and `release` mode conversely verifies it is *not* `0.0.0.dev0`, preventing mode mix-ups
- **Version-ordering invariant**: `0.0.0.dev0 < 0.1.0a0` (PEP 440). Because the stub sorts lower than the real package, the reservation stub never blocks a subsequent real release. `tests/test_packaging_versions.py` pins this invariant

### Initial setup (one-time, manual by the operator)

> **Completed 2026-07-07**: all 6 steps have been carried out. Reservation of `mordred-hermes 0.0.0.dev0` was confirmed live on both TestPyPI and PyPI (runs `28832255704` / `28832311414`). **Deviation**: step 4's required reviewers on the `pypi` Environment could not be configured under the current billing plan (private repo) (HTTP 422), so it's unset — being `workflow_dispatch`-only substitutes for the manual gate. Add required reviewers once the repo goes public or the plan changes.

Because uploading to PyPI is an irreversible public release, the operator **performs the following manually** (out of scope for CI automation):

1. **Confirm the PyPI name is available**: verify that <https://pypi.org/project/mordred-hermes/> and <https://test.pypi.org/project/mordred-hermes/> are unregistered
2. **Register a pending publisher (TestPyPI)**: TestPyPI → Account settings → Publishing → "Add a new pending publisher":
   - PyPI Project Name: `mordred-hermes`
   - Owner: `InternetMaximalism` / Repository: `mordred-hermes`
   - Workflow name: `release.yml` / Environment name: `testpypi`
3. **Register a pending publisher (PyPI)**: likewise on the PyPI side, with Environment name = `pypi`
4. **Create GitHub Environments**: create `testpypi` and `pypi` under repository Settings → Environments. Configuring required reviewers on `pypi` is recommended
5. **Run the name reservation**: Actions → "Release (PyPI publish)" → Run workflow → verify with `target=testpypi, mode=reserve` → after confirming success, do the real reservation with `target=pypi, mode=reserve`
6. After the reservation is complete, mark the checkbox at `TODO.md` §0.5 L70 (M7) as `[x]`

### Normal release (runbook)

After the name reservation, every real release follows this procedure (the flow verified with the initial `0.1.0a0`):

1. **Version bump (mandatory)** — `python tools/bump_version.py <new-version>` bulk-updates `src/mordred_hermes/__about__.py` (canonical) + `docs/dev/VERSION` + every `plugin.yaml` + the README.md / docs/dev/setup.md install pins. PEP 440-compliant (`0.1.0a1` / `0.1.0b0` / `0.1.0rc0` / `0.1.0` GA / `0.1.1` patch, etc.). **PyPI can never reuse a filename once it's been used** (yanking/deleting doesn't allow re-upload), so re-releasing a version that's already been published is physically impossible — always bump. `tests/test_packaging_versions.py` guarantees in CI that all 9 surfaces (including the README / docs/dev/setup.md install pins) agree and that stub < real
2. Merge the bump into `dev` via a normal PR
3. **dev→main release PR** — write the aggregated release notes (each PR's `### Changes` / `### Fixes`, per §Changelog convention) in the PR description, confirm CI is green, and merge. Dispatch `release.yml` from the `main` ref (the release artifact reflects main's content)
4. **Dry run on TestPyPI**: `gh workflow run release.yml --ref main -f target=testpypi -f mode=release` → confirm the run succeeds
5. **Verify the TestPyPI install**: in a fresh venv, `pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ "mordred-hermes==<version>"` (the extra-index is for resolving dependencies like `hermes-agent`) → confirm entry-point discovery 5/5 (`PluginManager.discover_and_load`) + `hermes-mordred --version`
6. **Production publish**: `gh workflow run release.yml --ref main -f target=pypi -f mode=release` → confirm it's live via the PyPI JSON / simple index. **Note**: while the `pypi` Environment has no required reviewers configured (a billing-plan constraint, the deviation noted in §Initial setup), dispatch ≈ immediate publication
7. **Verify the production install**: in a fresh venv, install with a pin → re-confirm discovery + CLI
8. **Tag + GitHub Release**: put an annotated tag `v<version>` on main's release merge commit → create a GitHub Release (use `--prerelease` for pre-release versions; copy the notes from the aggregation done in step 3)

> **Completed 2026-07-08 (first `mode=release`)**: `0.1.0a0` has been published — carried out in the order: dev→main merge (PR #12) → `target=testpypi` from the `main` ref (run `28942410646`) → fresh-venv install verification (entry-point discovery 5/5 + `hermes-mordred` CLI, hermes-agent 0.18.2) → `target=pypi` (run `28942564707`) → e2e install verification from production PyPI. Tag `v0.1.0a0`. No version bump only for this first release (since `0.1.0a0` hadn't been published yet). Note: while all releases remain pre-release, an unpinned `pip install mordred-hermes` depends on pip's all-prereleases fallback, so user-facing instructions recommend pinning `==0.1.0a0` (or `--pre`) (README §Install (PyPI)). The issue where a local `uv build` from a dirty checkout doesn't respect nested `.gitignore` and pulls the cargo `target/` directory into the sdist has been resolved by adding an explicit exclude to the sdist config (2026-07-09, pyproject `[tool.hatch.build.targets.sdist] exclude`).

## Changelog convention

Mordred **does not** have a dedicated `CHANGELOG.md` file. Change history is recorded **in each PR's description** (a cross-cutting operational convention shared with `PLAN.md` / `TODO.md`):

- Write **one entry per line** in each PR description under the `### Changes` (features added/changed) / `### Fixes` (bug fixes) headings
- For contributions from external contributors, append `Thanks @<author>`
- At release time, aggregate the `### Changes` / `### Fixes` entries from the PRs included in that release and transcribe them into the GitHub Release / tag-annotation release notes

**Don't edit the shared PR template**: `.github/PULL_REQUEST_TEMPLATE.md` at the repository root is owned by Hermes upstream and applies across the whole monorepo, so Mordred-specific headings are not injected into it (soft-fork discipline, `ROADMAP.md` "Forever out of scope"). This convention is followed manually by the author of each Mordred PR.

## Branching model (dev / main, introduced 2026-07-07)

- `dev` — the **default branch**. The integration branch for day-to-day development: feature branch → PR → `dev`
- `main` — the release/stable branch. Updated only via `dev` → `main` PRs (never a direct push, and never a direct target for feature PRs)
- `ci.yml`'s `push` trigger covers both `main` and `dev` (post-merge CI). The `pull_request` trigger has no branch filter, so it still runs as before on PRs targeting dev
- Schedule-based workflows (`upstream-check.yml`'s weekly cron) run using the workflow definition on the default branch (`dev`)
- Dispatch of `release.yml` is, in principle, done from the `main` ref (the release artifact reflects main's content)

## Branch protection (one-time setup)

> **Note (2026-07-07)**: under the current billing plan (private repo), branch protection / rulesets are unavailable (API 403). The settings below are planned to be enabled once the repo goes public or the plan is upgraded; until then, the operational convention in §Branching model substitutes for them. When enabled, apply equivalent protection to `dev` in addition to `main`.

After Phase 0 completes, enable the following on the `main` branch:

- Required status checks:
  - `CI / test (ubuntu-24.04, 3.12)`
  - `CI / test (macos-latest, 3.12)`
- Require strict mode (branches must be up to date)
- Allow force pushes from maintainers (for the rebase workflow)
- Linear history is **optional** (Mordred plugin development may permit merge commits)

## Auditing

Since the Mordred plugin repository doesn't have the large number of workflows that upstream OpenClaw does, the `workflow-allowlist-audit` job from the old version is unnecessary.

```sh
gh api -X GET /repos/InternetMaximalism/mordred-hermes/actions/workflows --paginate \
  --jq '.workflows[] | select(.state=="active") | .path' | sort
```

Expected output (as of 2026-07-06, all 5 Mordred-owned workflows restored under §Standalone-repo adaptations):

```
.github/workflows/ci.yml
.github/workflows/integration-vpn.yml
.github/workflows/labeler.yml
.github/workflows/release.yml
.github/workflows/upstream-check.yml
```

**On Hermes-upstream-origin workflows (monorepo-era note, no longer applicable)**: the paragraph below dates from when this repo was part of `Mordred-Hermes-monorepo` (the Hermes fork). This repo is now the post-split **Mordred-plugin-only standalone repo**, so no upstream-origin workflows exist here at all (`.github/workflows/` contains only the 3 Mordred-owned workflows above). Kept as a historical record: "this repo derives from a fork of Hermes (`NousResearch/hermes-agent`), so upstream-origin workflows (`tests.yml`, `osv-scanner.yml`, `nix.yml`, `docker-publish.yml`, `deploy-site.yml`, `docs-site-checks.yml`, `nix-lockfile-fix.yml`, `skills-index.yml`, `supply-chain-audit.yml`, `contributor-check.yml`) coexist in `.github/workflows/`. These were left untouched in the Mordred-Hermes v0.1.0-mvp.0 PR and will be individually evaluated for disable/archive in a follow-up cleanup PR."

## Future expansion

Workflows to consider adding when the need arises in the future:

- `docs.yml` — publish `docs/` via Sphinx / mkdocs
- `e2e.yml` — spin up a real Hermes environment in Docker for end-to-end testing

These will be prioritized as Phase 1 after the v1 release.
