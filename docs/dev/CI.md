# Mordred — CI Policy (Hermes-base)

> **Status**: current operational policy for this standalone repository. Workflow
> YAML is authoritative for mechanics; this document owns intent, release order,
> branching, and manual validation requirements.

## Why it got simpler

Mordred is a plugin package, not a Hermes fork. CI is responsible for Mordred's
source, package, native helpers, compatibility floor, and declared integration
boundaries. Hermes tests and releases remain upstream responsibilities.

## Standalone-repo adaptations (2026-07-01)

The standalone repository resolves `hermes-agent` from PyPI, ships its own five
workflows, and has no inherited upstream workflows. The initial repository-split
repair is complete; historical restoration details remain in Git.

## Active workflows

| Workflow | Purpose | Trigger |
|---|---|---|
| `ci.yml` | Test matrix, extras, wheel smoke, Tor/TPM, native helper builds | PR and pushes to `dev`/`main` |
| `upstream-check.yml` | Hermes hook-name and consumed-payload drift | Weekly and manual |
| `labeler.yml` | Path-based PR labels | `pull_request_target` |
| `integration-vpn.yml` | Live Mullvad validation | Manual only |
| `release.yml` | TestPyPI/PyPI build and publish | Manual only |

## `ci.yml` details

The workflow has nine job definitions:

1. **`test`** — Python/OS matrix; Ruff, shellcheck (one Linux cell), strict
   mypy, pytest, coverage, and the status-skill drift guard.
2. **`feature-extras`** — installs `ethereum`, `messaging`, and `tor-control`
   and runs their focused tests so optional coverage cannot disappear behind
   import skips.
3. **`package-smoke`** — builds sdist then wheel, installs outside the checkout,
   loads six plugin entry points plus the console script, and checks shipped
   native/offline/web/bootstrap assets.
4. **`hermes-floor`** — pins `hermes-agent==0.13.0`, verifies the resolver kept
   the pin, and runs the compatible default suite.
5. **`integration-tor`** — Docker-based Tor, SOCKS5h, and provider-transport
   integration tests. Tor bootstrap runs against the live Tor network; the
   harness waits up to 240s per attempt and recreates the container once
   before failing (`tests/integration/_docker.py`). A `BootstrapTimeout`
   that survives both attempts is a network flake — re-run the job rather
   than bypassing the CI gate.
6. **`sekey-helper`** — compiles the Secure Enclave Swift helper on macOS.
7. **`tpmkey-helper`** — checks the Rust crate, locked dependencies, MSRV, and
   `tss-esapi` build.
8. **`tpmkey-helper-tpm`** — runs the TPM backend against `swtpm` on Linux.
9. **`windows-private-fs`** — scoped native ACL/path/publication/process tests on
   Server 2022 with Python 3.11–3.13, plus an sdist-derived wheel smoke outside
   the checkout. This is foundation coverage, not whole-Windows product support.

Key policy:

- The test matrix covers Ubuntu and macOS with Python 3.11–3.13.
- CI installs `.[dev,keyvault,extension]`; macOS adds `macos`. Do not assume
  `ethereum` or `tor-control` imports are available in the main typing job.
- Run `mypy --strict src tools scripts/keyvault_offline_digest.py`; a narrower
  CLI target silently stops checking `tools/` or the shipped digest script.
- GitHub Actions use immutable commit SHAs. Cargo commands use `--locked`.
- The default pytest configuration excludes `integration` tests.
- Required branch checks are the Ubuntu and macOS Python 3.12 `test` cells;
  helper and integration jobs remain additional signals.
- Live LLM and Secure Enclave tests have no automated workflow. VPN is the only
  live-gated suite with a manual workflow.

## `integration-vpn.yml` details

This workflow requires the `MORDRED_MULLVAD_ACCOUNT` repository secret and a
manual `mullvad_version` input. It installs the official daemon, runs
`tests/integration/test_vpn.py` with `MORDRED_LIVE_VPN_TEST=1`, then always
disconnects and logs out in teardown. It never runs automatically because it
uses a paid account and mutates runner network state.

## Manual live-device validation log

- **2026-10-08 — Checked Windows audit sessions (C7a).**
  Shared implementation `b39a064379038bcce99fb021fe7418f326c1d105`, with the
  already-reviewed elevated-owner fixture correction at `b9332e64d`, passed
  ordinary-user Server 2025 source and isolated sdist-derived wheel suites:
  **356 passed, 54 skipped** each. Native checks include process serialization,
  hostile ACL/hardlink/junction refusal and case aliases. Wheel origin was
  verified inside a fresh test-only environment. Host all-extras regression:
  5,603 passed, 63 skipped, 35 deselected; independent reviewer focused run:
  165 passed, four native skips. Ruff/format, reduced-extras strict mypy and
  shellcheck passed; independent review found no actionable issues.
  An intentionally broader Windows diagnostic also selected legacy POSIX
  `test_log_rotation.py`: 373 passed, 54 skipped, one existing fchmod-path
  failure. Legacy audit APIs remain POSIX; C7a's new explicit session APIs do
  not migrate production consumers. That diagnostic exclusion is not a waiver
  for the later C5/C7b consumer and whole-product gates.
  Evidence: `~/.codex/artifacts/mordred-windows-completion-20261008/c7a-*`.
  Windows 11, encrypted-writer key leases, CLI and production caller adoption
  remain separate gates.

- **2026-10-08 — Windows confidential-file and coordinator identity capabilities.**
  Code `fc5db88455592badb638ca400507866b53328450` passed ordinary-user
  Windows Server 2025 source and isolated sdist-derived wheel runs: **279 passed,
  53 POSIX-only skips** each, including the explicitly enabled inherited-ACL
  live roundtrip. Wheel SHA-256: `d55a4ee4aba92a146387f5aedaf1b9fe0b227d0c59498db5d11e1e278eb5c648`. Module origin was checked inside the
  fresh wheel environment. The preceding `4f3f4377e` implementation also passed
  actual Hermes-created `config.yaml`/`.env` read and replacement with unchanged
  parent ACLs; replacements became exact-private. Local Python 3.13 all-extras
  regression at `4f3f4377e`: 5,493 passed, 59 skipped, 35 integration deselected;
  final identity-seam focused suite: 277 passed, 54 skipped, one live deselected.
  Strict reduced-extras mypy, Ruff and formatting passed. Independent original
  and identity-seam reviews found no actionable issues. Evidence is retained
  under `~/.codex/artifacts/mordred-windows-completion-20261008/` (C1b logs).
  These are shared-boundary checks; production caller migration, full product,
  Windows 11 and new reboot/TPM validation are not established by this entry.

- **2026-10-08 — Private filesystem review fixes on macOS.**
  Review reproduced inherited extended-ACL grants despite mode 0700/0600 and
  stale exception text after promotion to an uncertain commit. Before the fix,
  six native ACL regressions and one exception-message regression failed.
  Product revision `e6efd9dfc` checks macOS ACLs through validated descriptors,
  accepts only absent/empty/deny-only ACLs and refuses all allow/unknown entries
  or query failures without repairing permissions. Even owner-only, read-only
  and inherit-only allow entries are intentionally refused; the normal profile
  deny-delete ACL remains accepted. Exception `args` and text now follow the
  current `commit_state` while preserving the original exception.

  Native macOS tests cover inherited grants, existing directory/file/lock ACLs,
  ACL changes during a transaction and injected native-query/free failures with
  resource cleanup. The five filesystem test files produced **85 passed,
  34 platform skips**. The full default suite produced **5,250 passed, 49 skipped,
  34 integration deselected; 87.42% coverage**. Ruff/format, strict mypy (205
  files), shellcheck and an independent read-only review passed. Hosted Windows
  cleanup tests also assert that rendered errors match uncertain commit state;
  current-head CI results are tracked on PR #192. AWS was not started for these
  fixes, and Linux validation resources were untouched. The actual Windows
  wheel/restart evidence below predates these fixes and is not a fresh host run.
  Local evidence is retained under
  `~/.codex/artifacts/mordred-filesystem-review-fixes-20261008/`.

- **2026-10-08 — Shared private filesystem foundation (WF1–WF5).**
  Independent foundation PR #192 follows contract PR #191; neither includes the
  pending CNG helper implementation or migrates component callers. The product
  source at `cb266a5` was built as an sdist and then wheel, installed in a fresh
  out-of-checkout `wf-wheel-final\venv` under the credentialed ordinary `mordred`
  user on retained Server 2025 build 26100, fixed local NTFS. Python was 3.11.17
  AMD64; the imported module was under that venv's
  `Lib\site-packages\mordred_hermes`. Wheel SHA-256:
  `BFBC6419B245DE7026F43699CD623F70269F37B74E16F130313DC8069C12FEB4`.

  Running `python -m pytest -q` against the five `test_private_fs*.py` files
  produced **91 passed, 13 POSIX-only skips** from both source and installed
  wheel. Native checks cover create-time/existing ACLs, normal profile ancestors,
  junctions/hard links, >260-character paths, an actual 8.3 sidecar alias,
  concurrent process/thread transactions, crash release, interrupted writes and
  held-target refusal. Fault-injection tests separately cover short/zero writes,
  ambiguous publication, flush/close/unlock failures and uncertain commit state;
  they are not physical disk-failure tests. Independent review found two issues:
  case-sensitive POSIX reserved names and cleanup misclassifying completed
  publication. Both reproduced before fixes and passed afterward, including
  preservation of the original exception when cleanup also fails.

  With `MORDRED_WINDOWS_FS_LIVE=1`, a synthetic
  `MORDRED_WINDOWS_FS_TEST_ROOT` and provision/reopen phases,
  `python -m pytest -q -s -m integration tests/integration/test_private_fs_windows.py`
  passed under a non-administrator token. A separately credentialed disposable
  ordinary user was denied access to the wheel-created file. Only its temporary
  batch-logon right was granted; that right, account and scheduled task were
  removed after the assertion. Existing accounts, TPM fixtures and Linux
  validation resources were unchanged. No inbound network rules were added.

  Fresh-process, final-wheel Windows reboot and EC2 stop/start reopen each passed. Synthetic
  fixture SHA-256 remained
  `5aa341081d33ad1cfdbb608258d9f0a4078e54f7458a6133011837e96eef33de`.
  This is retention evidence, not sudden power-loss durability.

  On the clean dev-based foundation branch, the full default suite with coverage
  produced **5,235 passed, 49 skipped, 34 integration deselected; 87.38% coverage**.
  The earlier branch including pending helper changes passed 5,269 tests; the
  differing count reflects PR isolation, not removed foundation assertions.
  Ruff/format, shellcheck and reduced-extras strict mypy (204 source files) passed.
  Hosted CI gates are tracked on PR #192 (three Windows cells plus existing
  Linux/macOS checks); early failures and their resolutions follow. Final host
  state was independently verified **stopped** after acceptance. The retained
  development instance has one encrypted 50 GiB gp3 volume
  (`vol-08b0b74e57e899ad0`), existing TPM fixtures and synthetic filesystem evidence.
  Storage remains billable; no new volume, snapshot or instance was created. The initial hosted native run passed 90 checks and failed
  only the independent Get-Acl subprocess: inherited PowerShell 7 module paths
  prevented Windows PowerShell from loading its security module. The test child
  now reconstructs the default PSModulePath without weakening ACL assertions.
  The next hosted run passed all native tests but correctly refused the broadly
  writable ancestor on the RUNNER_TEMP data volume. The out-of-checkout wheel
  smoke now uses the runner's ordinary profile; the product trust policy and
  system ACLs are unchanged.
  Sanitized run evidence is retained privately under
  `~/.codex/artifacts/mordred-windows-filesystem-20261008/`.

- **2026-10-07 — Real Telegram login, sync, and questions on EC2 NitroTPM.**
  Installed the wheel built from `52e69d7fc` in the actual Hermes Desktop
  interpreter on the isolated Ubuntu 24.04 EC2 NitroTPM host. The CLI login
  completed against the user's real Telegram account with exit code 0.
  A separate process successfully unsealed the saved session through the TPM;
  metadata reported `logged_in=true` and `api_configured=true`, the sealed
  file had the `MTC1` header and mode `0600`, and memory encryption was active.
  Credential values and the decrypted session were not included in evidence.
  Subsequent operator-authorized sync imported three messages across two
  dialogs; a later incremental sync imported one new message into a third
  dialog, while an unchanged sync imported zero duplicates. With a
  TPM-sealed Venice key, `deepseek-v4-flash` passed the live private-model
  catalog check and answered questions through the production service path.
  The final period query considered all four imported messages without
  truncation. No message content, account identifiers, or model answers are
  recorded here. This validates the CLI/service path, not a live Hermes agent
  conversation or the Desktop question UI. Live-account cancellation and
  logout remain untested; the operator retained the encrypted session.
  Login evidence:
  `mordred-linux-telegram-20261007/live-login-success.png` and
  `mordred-linux-telegram-20261007/live-login-verification.json`.

- **2026-10-07 — Follow-up review and Linux TPM custody fixes.**
  Tested commit `1e64c8d85` on the same isolated Ubuntu 24.04 EC2 NitroTPM
  environment. An independent review reproduced two data-loss paths: keyvault
  reset recursively deleting the native memory key, and inaccessible memory
  directories being mistaken for empty during purge. The reset bug was also
  reproduced against the prior code on actual NitroTPM using a disposable
  profile; the new integration assertion failed before the fix (reset returned
  success), then passed after it. The actual-device suite passed **2 tests in
  8.29s**, including reset refusal, failed-scan key/ciphertext retention and
  subsequent successful reads, plus synthetic Telegram sync/list/ask/cancel.
  Added regression coverage for inaccessible directories and individual files,
  concurrent provisioning/reset, uninstall purge ordering, ordinary Linux
  plaintext reads/writes, and malformed ambient keys during re-enable.
  Linux full suite: **5,118 passed, 21 skipped, 0 failures/errors** (172.375s).
  macOS full suite: **5,212 passed, 5 skipped, 0 failures/errors** (160.681s).
  A macOS symlink-handling regression found during remediation was fixed by
  selecting the strict scanner only for Linux/TPM custody; its existing test
  and the final full suite passed. Metadata-only Linux status now refuses
  unreadable memory trees instead of reporting them ready. Ruff, format,
  shellcheck, JavaScript syntax, and strict mypy passed; reduced-extras Linux
  mypy checked 195 files. Coverage and the full CI interpreter matrix were not
  repeated for this follow-up. Evidence: `mordred-linux-telegram-20261007/review-*`.
  All three validation instances were verified stopped after this run; existing
  EBS/AMI/snapshot resources were retained. No live account/model was used;
  that acceptance gate remains pending.

- **2026-10-07 — Linux Private Telegram implemented and validated on EC2.**
  Tested feature code through commit `8b37984d3` on the existing Ubuntu
  24.04.5 x86_64 `t3.medium` NitroTPM instance in `ap-southeast-1`, using isolated
  source, memory, and Desktop homes. Python 3.12.3; production helper and
  `/dev/tpmrm0`; no `TCTI` or native-test override for actual-device acceptance.
  The explicit `MORDRED_LINUX_TELEGRAM_TEST=1` suite passed **2 tests** against
  real NitroTPM (7.95s). It exercised fresh Hermes startup hooks, sealed memory
  read/write, corrupt wrapped-key and unavailable-device refusal without ambient
  key fallback, ciphertext preservation, disable/re-enable with the same key,
  and purge. A synthetic Telegram client and local model drove real
  `TelegramService` sync/list/ask/cancel, encrypted archive storage and fresh
  process credential access through the real TPM. A separate swtpm run passed
  the same **2 tests** (44.88s); it is recorded separately from hardware proof.
  The complete Linux suite passed **5,103 tests, 21 skipped, 0 failures/errors**,
  with **87.99% coverage**. macOS/Python 3.14.7 regression passed **5,197 tests,
  5 skipped, 0 failures/errors**. Ruff, format, shellcheck, JavaScript syntax,
  documentation links, and strict mypy passed; Linux mypy used a fresh venv
  with only `dev,keyvault,extension` extras (195 files). The full CI Python
  matrix was not rerun locally. The four post-review regression tests first
  failed, then passed: runtime write/purge serialization, stale-profile path
  refusal, re-enable authentication of existing seals, and old Desktop client
  rejection. No Secure Enclave helper behavior changed; its live-device gate
  was not rerun.
  Installed the final wheel into the actual Python interpreter used by packaged
  Hermes Desktop `v2026.9.24` (Agent 0.21.5 / Desktop 0.17.6 / Electron 40.10.2),
  verified installed source/asset SHA-256 hashes against this checkout, and
  observed the TPM 2.0 label, absence of per-use presence/recovery promises,
  and successful memory enable through the page. The actual Desktop API
  hardware build/probe and idempotent memory enable also passed. Screenshots
  and sanitized logs are in `mordred-linux-telegram-20261007`.
  Stopped and started the instance, verified the pinned SSH host key at its
  new IP, and read the same sealed memory using Desktop's actual interpreter
  through the Hermes startup path. Wrapped-key and ciphertext SHA-256 hashes
  were unchanged. All three validation instances were stopped after testing;
  prior encrypted EBS volumes, the private AMI, and snapshots remain retained.
  **Limits:** no real Telegram login, live MTProto server, or live model was
  exercised; operator-assisted login/sync/question/cancel/logout remains pending.
  Linux memory is bound to its original TPM and has no portable recovery key.
  The unchanged baseline's cross-instance rejection remains separate evidence.

- **2026-10-07 — Current TPM implementation validated on actual EC2 NitroTPM.**
  Tested unchanged Mordred commit `f3211c6fb20b42d610feb00cfd6ed8d20681c888`
  on two `t3.medium` instances in `ap-southeast-1`, using a private,
  NitroTPM-enabled UEFI AMI cloned from the previous stopped Ubuntu validation
  disk. Ubuntu 24.04.5 x86_64, kernel `7.0.0-1014-aws`, Python 3.12.3,
  Rust/Cargo 1.85.0. AWS reported `TpmSupport=v2.0`; `/dev/tpmrm0` reported
  manufacturer `AMZN`, vendor `NitroTPM`, TPM 2.0, and NIST P-256 support.
  No TPM emulator was running. Used separate source and `HERMES_HOME` paths;
  the original validation instance remained stopped.
  Native tests ran with `MORDRED_TPM_TEST=1` and
  `TCTI=device:/dev/tpmrm0`: **64 passed, 0 failed, 0 ignored**, including
  actual key creation, ECDH parity, encrypted-session attributes, substitution
  rejection, and deletion. The existing focused Python suites passed
  **172 tests**. Built and installed the release helper, then separately
  verified production Python `wrap_dek`/`unwrap_dek` and `TeeSecretStore`
  using synthetic secrets, with `TCTI` and `MORDRED_TPM_TEST` unset.
  Verified fresh-process access, mode-`0600` key/ciphertext files, corrupt wrap
  and credential rejection, wrong-profile refusal, unavailable-device refusal
  without software fallback, and preservation of valid ciphertext after errors.
  Copied both opaque native key blobs to the second NitroTPM instance: its
  helper probe succeeded, but both copied blobs were rejected by that TPM.
  Stopped and started the original test instance, verified its pinned SSH host
  key at its new IP, and successfully unwrapped the original data and Telegram
  credentials without regenerating keys. The actual `keyvault enable-tpm`
  CLI also built, installed, and passed its hardware probe; original keys still
  worked after installation. Finally verified idempotent key deletion and
  refusal to unseal credentials after deletion of the synthetic test key.
  Evidence bundle: `mordred-nitrotpm-validation-20261007` (source/helper hashes,
  device properties, native/Python logs, and per-case results).
  **Scope:** this validates the existing TPM backend and credential custody,
  not Linux private Telegram as a complete feature. `telegram doctor` confirmed
  the hardware check passed while agent-memory encryption remained inactive.
  No real Telegram account, live model, memory-encryption implementation, or
  full Telegram/Desktop workflow was exercised in this run.
- **2026-10-07 — Packaged Hermes Desktop validated on Ubuntu EC2.**
  Built the official Hermes release `v2026.9.24` (`f97608f178d1`, Agent
  0.21.5 / Desktop 0.17.6 / Electron 40.10.2) with `hermes desktop
  --build-only` on the same Ubuntu 24.04.5 x86_64 instance. Installed Mordred
  commit `2c7073576` into the Python environment used by Desktop, with a
  separate `HERMES_HOME` and Desktop user-data directory. Ran the packaged
  Electron application under Xvfb/Openbox and inspected it through VNC over
  an SSH tunnel. The app mounted `/api/plugins/mordred/`, loaded the Mordred
  sidebar page, and displayed "Private Telegram requires macOS" without
  Secure Enclave or memory-encryption setup buttons or an Xcode error.
  The same page and platform guard remained visible after restarting the app
  and its backend. The installed page's SHA-256 matched the source asset.
  The virtual display produced a GPU command-buffer error during initial startup; the test used
  `desktop.electron_flags: ["--disable-gpu"]` for software rendering.
  No model credentials, Telegram login, or hardware-key operations were used.
- **2026-10-07 — Desktop Telegram platform guard validated on Ubuntu EC2.**
  Ubuntu 24.04.5 x86_64, Python 3.12.3, in `ap-southeast-1`, with an isolated
  `HERMES_HOME`. Before the fix, `/enclave/build` returned a job that failed
  with `enclave_build_failed`; the native command rejected Linux before
  checking the build tools. The actual Desktop plugin rendered in a temporary
  React/SDK harness against the EC2 API reproduced the misleading Xcode toast.
  After the fix, `/status` reported `platform=linux` and
  `telegram_supported=false`; the page displayed the macOS requirement with
  no Secure Enclave or memory-encryption setup buttons. Direct HTTP requests
  to both setup endpoints returned `telegram_platform_unsupported` without
  starting a job. The 12 platform tests had 10 expected failures before the
  fix; all 115 platform, Desktop API, and native-helper CLI tests passed after
  it. The full unit suite passed on Ubuntu (5,079 passed, 21 skipped) and
  macOS (5,173 passed, 5 skipped), with 31 integration tests deselected on
  each. Ruff, formatting, strict mypy with the Linux extras, and shellcheck
  passed. This checks the Ubuntu runtime and plugin UI, not a full Hermes
  Desktop installation, a live Telegram account, or TPM hardware operations.
- **2026-05-25 — passed on real devices**:
  - `MORDRED_KEYVAULT_LIVE=1 pytest -m integration tests/integration/test_keyvault_macos.py -v`
  - `MORDRED_LIVE_VPN_TEST=1 MORDRED_MULLVAD_ACCOUNT=... pytest -m integration tests/integration/test_vpn.py -v`
- **2026-08-21 — Slack E2E outbound channel-key binding passed on live Slack.**
  In an externally shared channel with a bound `K_chan`, an encrypted command
  reached the gateway, was released as `/version`, and received an encrypted
  reply that the browser extension rendered as the Hermes version with no
  decrypt failure. An agent-initiated top-level send also arrived as `ENC:v3`
  and decrypted, a plaintext post received the readable needs-key notice, and
  an unbound channel remained unchanged. The same end-user round-trip passed
  when the sender was an external Slack Connect member. The successful
  `app_mention` was stamped with the installing workspace; an earlier generic
  message supplied the external workspace scope and reproduced
  `key_not_bound_to_channel`. The captured generic-event shape now has strict
  regression coverage for the authenticated installing-team fallback,
  including stale-scope and forged-raw-team rejection.
- **2026-08-21 — isolated Slack `/hermes` slash-command dispatch passed on live
  Slack.** The app-level token was rotated to stop the competing Socket Mode
  client, and a fresh foreground gateway then received a Slack hello reporting
  one connection. In the installing workspace, `/hermes` carried a bare
  `ENC:v3` argument: the plaintext `/version`, Unicode lock, and Slack `:lock:`
  alias were absent from the wire value. The foreground gateway authenticated
  and released `/version`, and the bot posted a top-level encrypted reply. A
  Web API read confirmed that the reply was from the bot, decrypted under the
  bound channel key to `Hermes Agent v0.19.0`, and did not expose the version in
  plaintext. The gateway recorded no invalid-envelope, replay, encrypted-send,
  or Slack-send failure for the round trip.
- **2026-08-20 — agent-memory encryption passed on Apple Silicon with a running
  gateway.** Enabling memory encryption sealed the existing memory file and
  emitted the restart warning. After restarting the gateway, the Hermes memory
  seam read both existing entries, added and reloaded a temporary fact, and
  removed it again while the on-disk file remained mode `0600` with the
  `HERMES-MEMORY-ENC-v1` header; `encryption status` reported `memory [on]`.
  Disabling memory encryption restored the whole file to plaintext, the same
  two entries remained readable through Hermes, and the temporary fact was
  absent. The pre-test gateway and encryption states were restored afterward.

After changing a live-gated path, rerun the relevant command and append a dated
result here. Do not replace the previous result without recording the new date.
Tor and TPM use hermetic CI coverage and do not belong in this manual log.

## `upstream-check.yml` details

- Runs Monday at 03:00 UTC and by manual dispatch.
- Checks both the latest PyPI `hermes-agent` and a shallow clone of upstream
  `main`.
- `tools/check_hook_payload_drift.py` statically verifies `VALID_HOOKS` and the
  fields in literal `invoke_hook(...)` dispatches against
  `tools/hook_payload_contract.json`.
- A mismatch opens or updates an `actionable` + `upstream-drift` issue. It never
  patches Hermes or opens an upstream PR.
- `tests/test_hook_payload_drift.py` runs the same contract against the locally
  installed package and ensures contract keys match Mordred registrations.

## `labeler.yml` details

`.github/labeler.yml` maps repository paths to labels; the workflow applies
them with `contents: read` and `pull-requests: write`. Because it uses
`pull_request_target`, it must never check out or execute the PR head.

Required labels:

- `plugins/mordred-network`
- `plugins/mordred-privacy-check`
- `plugins/mordred-llm-guard`
- `plugins/mordred-keyvault`
- `plugins/mordred-wizard`
- `plugins/mordred-extension`
- `actionable`, `upstream-drift`, `docs`, and `ci`

## `dependabot.yml` details

`.github/dependabot.yml` keeps the SHA-pinned GitHub Actions current: weekly,
with all action bumps grouped into one `ci`-labelled PR against `dev`. Scope is
deliberately actions-only — Python dependencies are governed by
`pyproject.toml` floors plus `uv.lock` and the `hermes-floor` job, so pip/uv
update PRs would add review noise without a matching safety gain. It is not a
workflow, so the expected-path list in [Auditing](#auditing) is unchanged.

## `release.yml` details

Publishing is `workflow_dispatch` only and uses PyPI Trusted Publishing (OIDC),
not stored API tokens.

- `target`: `testpypi` or `pypi`.
- `mode=reserve`: the already-published permanent `mordred-hermes==0.0.0.dev0`
  name-reservation stub.
- `mode=reserve-rename`: the separate permanent
  `hermes-mordred==0.0.0.dev0` reservation required before the distribution
  rename.
- `mode=release`: the real package.
- `mode=compat`: the metadata-only legacy-name shim. The workflow refuses this
  mode unless the matching `hermes-mordred` version already exists on the
  selected index.
- `expected-version`: exact PEP 440 version required in source, wheel metadata,
  and sdist metadata.
- Production publishing accepts only `main` and never permits a CI-gate bypass.
- The build must produce exactly one wheel and one sdist with matching name and
  version.

### Initial setup (one-time, manual by the operator)

Completed 2026-07-07: TestPyPI/PyPI trusted publishers, GitHub environments,
and the `0.0.0.dev0` reservation are in place. The current private-repository
billing plan does not permit required reviewers on the `pypi` environment;
manual dispatch plus the production branch/CI gates are the compensating
controls until that setting becomes available.

Completed 2026-08-12 for the `hermes-mordred` rename: pending publishers were
created on both indexes with owner `InternetMaximalism`, repository
`mordred-hermes`, workflow `release.yml`, and environments `testpypi` / `pypi`.
`reserve-rename` published `0.0.0.dev0` from main SHA `504e1b7ab` after exact-SHA
CI succeeded. Fresh installs from both indexes confirmed a dependency-free,
entry-point-free reservation with no `mordred_hermes` runtime package. The
historical `reserve` mode remains immutable and must not be dispatched again.

On 2026-08-12, after both `0.1.0a16` projects passed TestPyPI and production
verification, the repository was renamed to `mordredagent/hermes-mordred`.
All four publisher claims (two projects on both indexes) were replaced
add-first with the new repository claim while preserving `release.yml` and the
`testpypi` / `pypi` environments.

### Normal release (runbook)

1. Run `python tools/bump_version.py <version>`; never reuse a published PyPI
   version or edit version surfaces separately.
2. Run the full local checks and merge the version bump to `dev` through a PR.
3. Open the release PR from `dev` to `main`, aggregate the included PRs'
   Changes/Fixes entries, confirm CI, and merge.
4. Dispatch TestPyPI from `main` with `mode=release` and the exact expected
   version.
5. In a fresh venv, install `hermes-mordred` from TestPyPI (using PyPI as the
   dependency index) and verify the single `mordred` plugin entry point plus
   `hermes-mordred --version`.
6. Dispatch TestPyPI with `mode=compat`; install `mordred-hermes` in another
   fresh venv, verify that it resolves the matching canonical package, then
   uninstall only the shim and confirm the runtime package and CLI remain.
7. Repeat steps 4–6 against production PyPI, preserving the same canonical-first
   order.
8. After the production compatibility upload succeeds, `release.yml` creates
   annotated tag `v<version>` on that run's exact release commit and publishes
   the GitHub Release. Its notes and tag annotation come from the matching
   merged `dev` → `main` PR; include nonempty `### Changes` and/or `### Fixes`
   entries before publishing. Alpha, beta, RC, and development versions are
   automatically marked as prereleases. Confirm the `github-release` job is
   green and inspect the resulting Release.

The finalizer runs only after a successful production `compat` publish, never
for TestPyPI or reservation modes. Only this job receives `contents: write`
and `pull-requests: read`; package publication retains its OIDC-only grant.
It checks that both distributions have an unyanked wheel and sdist on PyPI.
For all four files, PyPI's HTTPS Integrity API must report publishing
provenance for this repository's `release.yml` on `main`, the production
environment, the matching file digest, and the exact release SHA. This trusts
PyPI's validated attestations; it is not independent offline signature
verification. If `main` advances between the canonical and compatibility
publishes, mismatched provenance stops tag creation even if versions match.
Existing tags must resolve to the exact release SHA; they are never moved.
Existing published Releases with the correct prerelease status are preserved,
including any human edits to their notes.

If finalization fails after upload (for example, an API outage), fix the cause
and **re-run failed jobs** on the same workflow run. Do not dispatch a new
publish or re-run all jobs: PyPI versions cannot be uploaded twice. A tag
created before a Release API failure is reused safely. A mismatched tag,
draft Release, or incorrect prerelease flag requires operator investigation;
the finalizer fails rather than overwriting it. For read-only diagnosis, run
`uv run python tools/finalize_release.py --repo mordredagent/hermes-mordred
--sha <release-merge-sha> --version <version> --dry-run` from the matching
version checkout with `GH_TOKEN` set. This verifies PyPI and GitHub state
without creating tags or Releases.

## Changelog convention

There is no `CHANGELOG.md`. Every PR description carries one entry per line
under `### Changes` and/or `### Fixes`; external contributions append
`Thanks @<author>`. A release PR aggregates those lines into its description,
tag annotation, and GitHub Release notes.

There is currently no PR template, so authors add the headings manually.

## Branching model (dev / main, introduced 2026-07-07)

- `dev` is the default integration branch. Feature PRs target `dev`.
- `main` is release-only and changes through `dev` → `main` PRs.
- CI runs for PRs and post-merge pushes to both branches.
- Scheduled workflows use the definition on the default `dev` branch.
- Release dispatches use the `main` ref.

## Branch protection (one-time setup)

The current private-repository billing plan does not expose branch protection
or rulesets. When available, protect both `dev` and `main`, require the Ubuntu
and macOS Python 3.12 test cells, require branches to be current, and keep
direct pushes to `main` disabled. Until then, the branching convention above is
the operational control.

## Auditing

List active workflows with:

```sh
gh api -X GET /repos/mordredagent/hermes-mordred/actions/workflows \
  --paginate --jq '.workflows[] | select(.state=="active") | .path' | sort
```

Expected paths are the five workflows in [Active workflows](#active-workflows).
Any additional workflow requires an explicit policy update and review.

## Future expansion

Add a documentation publishing workflow only when the project has a hosted docs
site. Add broader E2E automation only when it can run without production
credentials or state. Until then, keep the current workflows small and
purpose-specific.

### C1a lifecycle validation (2026-10-08)

The checked lifecycle slice extends the scoped `windows-private-fs` invocation
with `tests/test_private_fs_lifecycle.py` and
`tests/test_private_fs_lifecycle_faults.py`. Existing native Windows tests now
also cover lifecycle ACL/junction refusal and exclusive-handle sharing failures;
process tests include concurrent checked append with every record retained.

Local macOS Python 3.13.12 validation: the focused shared-filesystem suite has
**184 passed, 47 platform-specific skips**. Ruff check/format passed. Strict mypy
passed for 205 source files in a separate `.venv-ci` installed with only
`dev,keyvault,extension,macos` extras. Native Windows execution belongs to the
controller's final-commit acceptance run, not these local results.

Regression development observed 43 lifecycle cases fail on missing APIs, then
13 portable Windows cases fail on missing backend methods. Three native ABI
cases failed before adding time/seek/truncation/enumeration bindings. Subsequent
RED/GREEN cases caught prevalidation metadata access, unbounded reserved staging
scans and replaced exceptions after Windows publication. Fault seams exercise
partial append/rollback, partial POSIX rename, native deletion/rename ambiguity,
close/unlock/directory cleanup and original-error preservation. These are
injected failures, not physical disk-failure or power-loss durability evidence.

The full default `uv run pytest -q` run exited 0: **5,425 passed, 52 skipped,
34 integration deselected** (counts from progress output and collection).
Twelve final cleanup regressions added while that run was active were verified
by the subsequent focused run above; product code was unchanged. Warnings were
upstream Starlette/httpx deprecation, an installed Hermes invalid-escape warning,
and existing Python multi-threaded-fork deprecations. No test failed.

C1a review follow-up: ordinary `OSError` bodies after successful deletion exposed
uncertainty loss when POSIX unlock or lock-close also failed. Regression RED was
**2 failed, 4 passed**; retaining the transaction mutation state during error
classification gave **6 passed**. The analogous directory-close case already
preserved uncertainty and remains covered. Final focused suite: **190 passed,
47 skipped**; Ruff check/format and reduced-extras strict mypy (205 files) passed.
The full suite was not repeated for this bounded review fix.
