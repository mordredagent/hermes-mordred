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

The workflow has eight jobs:

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

- **2026-10-07 — Windows CNG helper implementation (W1–W4).**
  The dedicated Phase 0 Windows Server 2025/NitroTPM host was reused under the
  ordinary `mordred` account with password-authenticated SSH through SSM. MSVC
  Build Tools `17.14.37710.0`, toolset `14.44.35207`, Windows SDK 26100, Rust
  `1.99.0` and MSRV `1.85.0` built the actual executable. The Rust protocol/unit
  suite passed **12 tests**; the separately gated real CNG suite passed **3 tests**.
  It verified P-256 ECDH against an independent implementation, a leading-zero
  secret, duplicate preservation, malformed-point refusal, private-export
  rejection with export policy zero, deletion, and concurrent probe cleanup.

  **Actual-device corrections:** the provider rejected the silent flag on
  deletion (`0x80090009`), while zero flags succeeded. Two parallel native
  create/finalize operations returned distinct successful keys for one name
  despite no overwrite flag; a user-SID/key-scoped Global Windows mutex now
  serializes helper operations across processes and sessions. The same live
  concurrency regression then passed. Public-key-only SSH still correctly
  refused the compiled helper's probe with `AUTH_DENIED` (`0x80090010`). No
  password capture, impersonation or software provider exists in the product.

  **Python/build boundary:** actual Windows production MRKW wrap/unwrap through
  the compiled helper passed, including a Unicode/space-containing installation
  path, duplicate refusal, wrong-profile/corrupt-ciphertext rejection, missing
  helper, valid-data retention and refusal after deletion. The installer passed
  **4 actual Windows tests** covering replacement, failed-build retention,
  an in-use executable and a Japanese default home under a cp1252 Python pipe.
  ASCII JSON transports the default path without code-page corruption. Windows PowerShell 5.1 requires `[NullString]::Value`
  for the nullable `File.Replace` backup argument. A real sdist-to-wheel build
  passed **6 packaging checks**. The wheel installed outside the checkout;
  `build.ps1` compiled bundled sources under `site-packages` and installed into
  the selected Hermes home's `bin`. The resulting executable SHA256 was
  `c3da84b5ab0a2e2171ce0f9663af2322fb811bc19b781418cb8c25a3f02e6255`
  after the review corrections.

  **Persistence:** a retained synthetic MRKW fixture (SHA256
  `e80184560cc28a8342e745c34c43c90c8f673e072b8ff89eda9ee88f12404e81`) reopened
  through the installed wheel/helper in a fresh process, after Windows reboot,
  and after actual EC2 stop/start. Each check verified the same public key and
  plaintext digest; SID, fixture, executable and PCP key-file hashes were
  retained. The final helper also reopened this unchanged fixture after upgrade and a
  second Windows reboot.
  The same final executable on a cloned disk refused the retained key on the
  second TPM, while fresh production MRKW operations worked. Both clone
  integration tests passed; SID, credential-file and retained PCP-file hashes
  matched the source host.

  **Review/regressions:** one independent whole-branch review identified
  malformed helper acknowledgement/status handling and a possible false-success
  deletion of a retained inaccessible key. The bridge regression failed in 18
  cases before correction; the focused local suite then passed **218 tests**,
  and Windows passed **101 tests** with one explicitly clone-gated skip. The
  inaccessible-key deletion regression failed on the real clone before the fix,
  then passed with the final executable. A new-key probe succeeded and CNG
  enumeration omitted the inaccessible retained key, so neither proved absence.
  Windows deletion now refuses an unopenable keyset with the original status
  and `UNAVAILABLE`, including repeat deletion; exact-key deletion still passes.
  After the review fixes, the full local suite passed **5,158 tests**, with
  **88.62% coverage**. Reduced-extras strict mypy, Ruff and
  ShellCheck passed. A scoped Windows helper CI job is added; hosted runners do
  not substitute for hardware acceptance. Full Windows private filesystem,
  runtime, wizard, network, Desktop and Windows 11 acceptance remain separate
  dependent plans. Final resource states are recorded below.

- **2026-10-07 — Windows native feasibility on actual EC2 NitroTPM (Phase 0).**
  Unchanged Mordred `f14c1edce23f88c4a2cb6f8bfd3c1454ed0a59ce` / `0.2.0a1`,
  installed as a locally built wheel with `keyvault,extension` extras, was tested
  on Windows Server 2025 build 26100, x86_64, `t3.large` in `ap-southeast-1`.
  The TPM-enabled image was `ami-05171b2d13ab22cba` (2026-09-17); primary
  instance `i-00f4db5c3a204906b`, encrypted 50 GiB gp3, UEFI/NitroTPM 2.0.
  The older Linux validation instance remained stopped and untouched.

  **Host baseline:** pinned upstream Hermes `v2026.9.24`, commit
  `f97608f178d1ffeca59860195ab7da295f7c8e5f`; Agent `0.21.5`, Desktop `0.17.6`,
  Electron `40.10.2`, Python `3.11.17`, Node `22.23.3` / npm `10.9.9`.
  The plugin loaded from the wheel in
  `C:\Users\mordred.000\hermes-source\venv\Lib\site-packages`, not the checkout.
  `hermes --help`, `hermes-mordred --help`, and isolated
  `hermes-mordred status --json` exited zero. `hermes desktop --build-only`
  produced the real `win-unpacked/Hermes.exe`. Playwright launched that binary
  under the ordinary user and captured screenshots: with Mordred disabled in
  a separate baseline home, Desktop reached provider onboarding; with Mordred
  enabled, backend startup refused at `_audit_io.py`'s unavailable `os.fchmod`
  during the network plugin's audit initialization. No security checks were
  bypassed and no upstream application source was patched. No model provider
  or messaging account was configured, so onboarding is not a chat/E2E pass.

  The upstream installer needed a clean checkout of its exact release in the
  disposable source directory (initial checkout refused generated/line-ending
  changes), then its official individual dependency stages after an existing-
  venv cleanup failed under the ordinary user. npm completed, though the wrapper
  emitted empty-exit-code failures; Desktop used the official CLI build. These
  workarounds do not establish one-command Windows installation support.
  An initial gateway harness timed out while collecting inherited output pipes.
  A repeat with file output reached the Gateway Starting banner and remained
  alive at 20 seconds; ordinary-user `taskkill /T /F` returned Access denied,
  and the harness also hit cp1252 output encoding. Thus clean shutdown, channel
  readiness and scheduled gateway support are not established; the later SYSTEM
  cleanup found that PID already gone.

  **Unmodified test baseline:**
  `python -m pytest -q -o addopts= --tb=short tests/test_keyvault_wrap.py tests/test_file_lock.py`
  returned **71 passed, 6 skipped, 12 failed**. All failures were in the file-lock
  suite: both POSIX-mode assumptions and Windows-path regex assumptions occur.
  These are recorded failures, not a passing Windows suite. The independent
  wire probe used Python `3.12.15` / cryptography `50.0.2` and the unchanged
  production `wrap.py` (SHA-256
  `a043eb7dbc1c04ad0d80f849a588748ca50fb1b7d3b536b7b4fb4c097c2dfe6c`).

  **Hardware custody:** `Get-Tpm` reported present/ready, manufacturer `AMZN`.
  The explicit Microsoft Platform Crypto Provider reported implementation flag
  `1` (hardware). Direct CNG user-scoped persisted `ECDH_P256` worked without
  setting KeyAgreement usage; explicitly setting that property returned
  `0x80090029`. `NCryptSecretAgreement` and `NCryptDeriveKey(TRUNCATE)` yielded
  32 little-endian bytes, reversed for Mordred. Nine comparisons with independent
  Python/OpenSSL ECDH passed, including leading-zero scalar `189`. The unchanged
  127-byte MRKW wrapper round-tripped. Corrupt ciphertext, wrong profile,
  malformed points and an invalid native peer were refused; valid ciphertext
  remained usable. Private export failed with `0x8009000A`.

  The same proof passed in a separate password-authenticated non-administrator
  SSH process, without impersonation. Public-key-only SSH could not access the
  persisted key (`0x80090016`); this token distinction must be diagnosed by the
  actual product process. SYSTEM-only or impersonated results are not presented
  as desktop/service identity proof. No Windows password capture or impersonation
  is proposed for the product helper. Fresh-process reopen, Windows reboot and EC2 stop/start
  retained public-key fingerprint
  `7a573e66759b1ae7a4fa2715985d2ffa4d597eeab63978581170b0fe9c7f8e27`
  and the valid synthetic wrapped DEK. The reboot repeat used a credentialed
  user token from the SSM harness. The stop/start repeat also passed under the
  actual password-authenticated ordinary-user SSH process. A separate disposable
  key was created/reopened/deleted, and its subsequent open returned
  `0x80090016`; the retained original fixture still decrypted afterward.
  Scheduled gateway acceptance remains open.

  **Device binding:** a cleanly stopped disk was imaged and launched on
  second NitroTPM instance `i-08c6ec3e52adac82a`. Local SID, encrypted DPAPI test
  credential, PCP key metadata and wrapped-fixture hashes matched the source.
  DPAPI unprotect and credentialed logon succeeded, but the copied persisted key
  could not open (`0x80090016`). A new, uniquely named key under the same user on
  the second TPM completed ECDH with independent software parity and refused
  private export; it was deleted afterward. This controls for unavailable TPM,
  wrong SID and inability to authenticate. The test used synthetic data only.

  **Phase 0 resources:** primary Windows and prior Linux instances were verified
  stopped at the investigation boundary. Clone `i-08c6ec3e52adac82a` was
  terminated; AMI `ami-021065c89d82a9745` was deregistered and snapshot
  `snap-0b8b5d7ed23d25d0d` deleted. The task's TCP/22 ingress was revoked; all
  working access uses SSM. The dedicated SSM role/profile and primary encrypted
  50 GiB gp3 volume remain for implementation ($4.80/month storage at the
  queried regional rate). The primary was then resumed for the approved helper
  implementation with a new bounded shutdown deadline. Windows instance rate
  was $0.1332/hour, excluding IPv4, surplus CPU credits and other usage.

  **Scope and evidence:** disposable scripts, JSON results, baseline failure
  logs, build logs and actual application screenshots are retained privately at
  `~/.codex/artifacts/mordred-windows-validation-20261007/`; do not publish its
  test credentials or private SSH key. The checked-in change is documentation
  only. It proves feasibility of this device's CNG/wire boundary, not a shipped
  helper, secure Windows file storage, Windows 11/MSIX, consumer TPMs, scheduled
  gateway custody, Private Telegram or full Windows support. See
  [Windows feasibility](WINDOWS_FEASIBILITY.md) and the Windows sections of
  [SPEC](SPEC.md#windows-native-support-proposal-2026-10-07) and
  [PLAN](PLAN.md#windows-cng-helper-implementation-plan).


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
8. Add annotated tag `v<version>` on the release merge and create the GitHub
   Release; mark pre-releases accordingly.

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
