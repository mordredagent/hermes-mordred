# Manual live-device validation log

Append-only record of live-device, native and model validation runs that CI
cannot automate (Secure Enclave, TPM/CNG hardware, Windows Server, Mullvad,
live LLMs, Hermes Desktop). The gates that require an entry, the log-entry
template and the release policy stay in [`CI.md`](./CI.md); this file was
split out of `CI.md` §Manual live-device validation log on 2026-11-02 (older
history of these entries is in `CI.md`'s Git history).

After changing a live-gated path, rerun the relevant command and append a dated
result here. Do not replace the previous result without recording the new date.
Tor and TPM use hermetic CI coverage and do not belong in this manual log.

- **2026-11-02 — Uninstall PR integration with the current `dev` layering contract.**
  Shared SPEC/PLAN contract [PR #276](https://github.com/mordredagent/hermes-mordred/pull/276)
  merged before the implementation PR. Integrating the newer `dev` import
  contract exposed the new root helper's keyvault dependency when registered
  in the explicit helper inventory. The failing contract was reproduced, then
  the SQL-free permit implementation moved without behavioral changes to
  `keyvault/_uninstall_authority.py` (`d92c773cf`); consumers and tests use its
  new location. Both import contracts pass without additional ignores. New
  paths are registered in the CI inventory and retain conservative final CI.
  The integration selection passed 383 tests, CI policy modules passed 137,
  critical passed 24, strict typing passed 402 files, and ruff/format passed.
  The integrated local default suite passed 14,384 tests (295 skipped,
  168 deselected). Initial hosted run `41444965496` exposed test-fixture
  assumptions: nine Linux cases used ambient holder discovery instead of the
  controlled empty inventory used by neighboring proof tests, and one Windows
  profile-ordering fixture used `mkdir` instead of checked private directory
  creation. Test-only corrections retain all production holder/ACL refusals.
  The native wheel hashes below precede this module relocation and the imported
  `dev` reset-journal extraction; they are not relabelled as new native runs.
  Current merge-context hosted acceptance is recorded on the implementation PR.

- **2026-11-02 — Data-preserving uninstall final regression passed.**
  On final runtime source `075a99e58`, `uv run pytest -q` completed with exit
  code 0: **14,384 passed, 295 skipped**, with integration tests excluded by
  the repository default. Counts are from the per-test status characters in
  the complete double-quiet output. Evidence archive:
  `~/.codex/artifacts/mordred-safe-uninstall-20261102-c8d589b4/`
  (`full-regression-final.log`, `full-regression-final-result.json`). This
  supersedes the earlier interrupted follow-up run; its import-store containing
  module also passed independently (83 tests).

  Final containing-module selection: **240 passed**; critical preset: **24
  passed**. Ruff check/format passed (867 files already formatted), strict mypy
  passed all 401 source files, and documentation link checks passed (12 tests).
  An independent review of the two native fixes found no actionable defects
  and independently passed both changed test modules (38 tests). Earlier
  full-branch review, CI-extras typing and shellcheck evidence remain recorded
  below; native outcomes and exact candidate builds are separate entries.

- **2026-11-02 — Final-source macOS Secure Enclave uninstall/recovery recheck passed.**
  After both Windows native fixes, a freshly built universal candidate wheel
  (`4f11f42a4dda71391ee8887c17acb590482a36b045b7d473871a274c5ddb3ef6`)
  matched all 362 source Python modules at `075a99e58` and passed every phase
  of the existing manual macOS wheel driver in a new home:
  `/private/var/folders/v_/qz0m0d1d71j6njw_fgrnlwsc0000gn/T/mordred-uninstall-wheel-tuh97vp9/home`.
  Normal restore/uninstall, package-free reads, same-wheel reinstall, actual CLI
  backup export, retained-backup purge refusal, checked backup deletion, native
  main-key enrollment, purge and final package-free reads all passed. The
  fixture used the real signed Secure Enclave helper and login-Keychain anchor;
  successful fixture keys were removed by purge. Production homes/keys were
  untouched. Evidence in the archive below: `macos-final.log` (ending with
  `ALL_PHASES_PASSED`), `macos-final.json`, `macos-final-run.py`, `final-posix/`.

- **2026-11-02 — Data-preserving uninstall follow-up: Windows Server CNG candidate-wheel lifecycle passed.**
  The retained Windows Server 2025 host ran under the ordinary, non-admin
  `mordred` account with Python 3.11.17, Hermes 0.19.0, SQLCipher wheels 0.5.7,
  actual CNG/TPM custody and the native checked VFS. The unpublished candidate
  wheel SHA256 is
  `0fe78eff5ebf14a96364899a2aa3a16838c79bde506f41440a958304913f34fd`;
  all 362 packaged Python modules match source commit `075a99e58`.
  Synthetic root:
  `C:\Users\mordred.000\mordred-uninstall-wheel-20261102-r6\home`.

  Root/profile memory custody and the required installed-Hermes runtime proof,
  three encrypted databases (root, profile and plugin data), registered backup,
  normal uninstall and package-free SQLite integrity/content reads passed.
  Reinstalling the same wheel at the same physical home allowed the real
  `databases backup export` CLI to recover the unchanged retained backup.
  Purge refused with the backup retained, without changing observed data.
  After explicit checked backup deletion, purge restored all three DBs, deleted
  only root/profile memory custody keys and removed the package. Another fresh
  interpreter verified preserved plaintext DB, memory, config and environment
  content. Windows recursive deletion and Windows 11 encrypted DB restoration
  remain unsupported; this run does not establish native Windows 11 evidence.

  Earlier native attempts exposed two defects, fixed with failing-then-passing
  regressions: recursive private transactions during retained publication
  (`ac150e801`), and bound ATTACH parameters rejected by the exact-path export
  authorizer (`075a99e58`). Holder/identity/revision checks remain in place;
  the authorizer was not widened. Failed synthetic homes retain their recovery
  state. The earlier macOS/Linux wheel results below predate these two fixes
  and must not be relabelled as runs of this final Windows candidate.

  Evidence: `~/.codex/artifacts/mordred-safe-uninstall-20261102-c8d589b4/`
  (`windows-wheel-r6.log`, `windows-driver.py`, `windows-run-r6.py`,
  `final-windows-r6/source-comparison.json`). The lifecycle log ends with
  `ALL_PHASES_PASSED`. AWS profile `intmax-developer` was used with a bounded
  ownership/deadline controller and an independent guest shutdown timer.
  Both retained validation instances were independently observed stopped,
  their task ownership tags released, and the task's SSM forwarder closed.
  No production Hermes home or keys were used.

- **2026-11-02 — Data-preserving uninstall follow-up: Linux NitroTPM candidate-wheel lifecycle passed.**
  The owner selected AWS profile `intmax-developer` and completed CLI login.
  The retained Linux host ran the same unpublished candidate wheel with SHA256
  `c8d589b47c9a0c52d384112b865d1aa3cbda7daaa7a85b6bade6907286e556ec`,
  Python 3.12.3, Hermes 0.19.0 and SQLCipher wheels 0.5.7. The TPM device was
  `/dev/tpmrm0`, with manufacturer `AMZN`. No production home or keys were used.

  The ordinary `ubuntu` account (UID 1000) ran in a fresh private PID/mount
  namespace using the actual host filesystem and NitroTPM. Root/profile DBs,
  encrypted memory, plaintext configuration/environment, registered backup,
  actual package uninstall, package-free SQLite/content checks, reinstall and
  real CLI backup export passed. The backup hash remained unchanged. Purge
  refused with that backup retained; checked backup deletion, native main-key
  enrollment and purge then passed, including removal of native fixture keys
  and another package-free read of the preserved plaintext.

  Outside the namespace, the same-user `systemd` and `(sd-pam)` processes had
  unreadable descriptor inventories. Database conversion refused before DB
  mutation; these failed synthetic setup homes and their recovery material
  remain retained. No holder check, process visibility policy or product code
  was weakened. The successful isolated result does not establish successful
  operation with those host-level visibility gaps.

  Successful root: `/home/ubuntu/mordred-uninstall-wheel-8Op9IVMX/home`.
  Evidence: `~/.codex/artifacts/mordred-safe-uninstall-20261102-c8d589b4/`
  (`linux-wheel-lifecycle.log`, `linux-driver.py`, `linux-run.sh`,
  `linux-prepare-refusal.log`). The host was independently observed stopped,
  and the temporary current-IP SSH rule was removed. Windows Server candidate
  execution is tracked separately; no Windows result is inferred from Linux.

- **2026-11-02 — Data-preserving uninstall: isolated macOS candidate-wheel lifecycle passed; Linux/Windows native acceptance pending.**
  This initial snapshot is retained for build provenance; the follow-up entries
  above supersede its pending native gates and record subsequent source fixes.
  Dedicated branch `fix/data-preserving-uninstall` follows the shared contract
  commit `201e4b4d6`. No production Hermes home or native key was used. The local
  wheel is an unpublished `0.3.0a4` candidate, not evidence for a released wheel.
  Candidate wheel SHA256:
  `c8d589b47c9a0c52d384112b865d1aa3cbda7daaa7a85b6bade6907286e556ec`.

  macOS arm64/Python 3.12.13 with the actual signed Secure Enclave helper and
  login-Keychain anchor passed the isolated
  [manual wheel driver](../../tests/integration/_uninstall_macos_acceptance.py).
  Its fresh `mordred-uninstall-wheel-*/home` held root/profile SQLCipher DBs,
  sealed memory, config and environment files, and a registered external backup.
  The actual package was uninstalled; a fresh interpreter without Mordred read
  every restored DB with SQLite integrity/row checks and verified memory/config
  and environment content. After installing the same wheel, the real
  `databases backup export` CLI recovered the backup into a new plaintext DB;
  the original backup hash remained identical. Purge with the backup retained
  refused without changing the checked files. After the test explicitly deleted
  that backup through checked backup maintenance and enrolled scoped main-key
  ownership, purge restored both DBs, removed native keys and the package, and
  the fresh package-free interpreter read the preserved plaintext again.
  Test-only keys used `MORDRED_SEKEY_UNATTENDED=1`; no attended/Touch ID prompt
  count is asserted. The final purge removed this fixture's native key material.

  The checked main-key ownership requirement is unchanged: a vault-only native
  key directory with no `meta.json` is not a complete keyvault-reset target.
  Its purge was observed refusing **before restoration**, with keys and package
  retained. This change does not repair ambiguous ownership or widen recursive
  keyvault reset. Ordinary uninstall and recovery remain available.

  Portable regressions exercise Windows proof-before-EX ordering, qualified
  Server admission, unsupported-runtime refusal, memory-only purge and profile
  ordering. Neither Linux TPM nor Windows Server CNG uninstall acceptance was
  executed on this Mac. The retained-host control tool requires AWS profile
  `intmax-dev`, which is absent from the current AWS profile inventory; no
  alternate account or cloud resources were selected or started. Windows 11 encrypted DB restoration and Windows recursive
  deletion/erase remain unsupported. The existing native crash/persistence
  matrix is not relabelled as evidence for this candidate.

  Evidence archive: `~/.codex/artifacts/mordred-safe-uninstall-20261102-c8d589b4/`
  (candidate wheel, native/portable logs and manual driver). Runtime source is
  recorded in `45486c673`, `d6fffa1bf` and `ae2d5d4f1`. Isolated root:
  `/private/var/folders/v_/qz0m0d1d71j6njw_fgrnlwsc0000gn/T/mordred-uninstall-wheel-la1j371m/home`.
  Portable verification: the containing-module run passed **241 tests**; the
  critical preset passed **24 tests**. The full regression completed with
  **14,370 passed, 295 skipped, 168 deselected, 9 failed** (968.36 s). All nine
  failures were old package-removal mock targets in the Windows compatibility
  tests after orchestration moved into its own module. The test-only correction
  in `59581c421` preserves native/file immutability and removal tripwires;
  the entire compatibility/acceptance-helper selection passed **81 tests**, and
  `pytest --lf --lfnf=none` confirmed **all 9 previously failing cases pass**.
  Product code did not change after that full regression started. This records
  the full run and targeted reruns separately, not a second clean full run.

  Ruff, formatting, shellcheck and 12 documentation checks passed. Strict mypy
  passed all 401 checked source/tool files in both all-extras and the CI-sized
  `dev,keyvault,extension,macos` environment. No Linux/Windows native skip is
  counted as platform acceptance. Logs include `full-regression.log`,
  `compatibility-rerun.log` and `last-failed-rerun.log` in the evidence archive.

- **2026-10-28 — Cross-platform database: Windows read optimization reviewed; remaining lifecycle validation deferred.**
  The owner requested a shorter completion path. Draft PR
  [#270](https://github.com/mordredagent/hermes-mordred/pull/270) records the
  implementation, verified results and remaining work; it is not a release or
  full cross-platform lifecycle acceptance.

  Retained runtime `e01c19a9437336f3ab0cd760d95e9f2f54bb75f3`, tree
  `c71027399e795e4ba03333eff72d87af6658c1be`, passed all eight Linux source/wheel
  provision, process restart, OS reboot and EC2 stop/start observations, six
  reopen continuity checks and three settled control cycles. Linux was not
  rerun and this evidence is not relabelled as a newer runtime.

  The same e01 runtime passed Windows Server 2025 native PowerShell parsing,
  14 guards, U66 attachment, 86 selected test bodies, source/wheel
  qualification, assembly and the production package gate. Recovery of the
  complete 639-file public graph passed the unchanged local qualification and
  bundle consumers, source pins and actual bundle-byte checks. Archive SHA256:
  `18b185b41bbb494cbb81af6c5681a58efd4465f8f073a8cd822a8fd8b35a571a`.

  The new Windows read optimization is runtime
  `38f31cd405d9e3f5740ccd5de25cb06bc342e6c6`, tree
  `28fcc577bf4e481d020eaf91ef80573796f09d36`. It coalesces repeated full
  directory traversals only within one fixed custody stat/read operation on
  exact live held directories. Fresh entry/exit validation, leaf checks,
  pending/coordinator checks and every SQL authorization/progress/API boundary
  remain. Handle closure/reuse and nested reads refuse. Transient changes
  reverted between the boundary checks are sampled less often; this does not
  claim identical intermediate sampling or a session/cross-read cache.

  The initial implementation passed the complete 883-case affected command
  with platform-gated skips. After the lifetime and fixture fixes, all 58
  focused regressions and scoped lint/formatting/strict typing passed. Independent SOL review found a late exit-lifetime gap; its fix and
  regression passed scoped re-review. Astra reviewed the boundary design.
  The final test-only change makes the synthetic fixture drive-absolute on
  Windows. Native gates skipped on Darwin do not establish Windows acceptance.

  Actual Windows metadata measurements on the identical production source
  bytes at 2363 reduced median observation time from 0.26638 to 0.11181 seconds
  and per-observation metadata/descriptor calls from 3166/1556 to 1366/656.
  Three observations performed no SQL, native key operation or new fixture
  write. The new measurement forwarded six reads, file validations and read
  verifications each; old leaf counters were not recorded. This is a metadata
  result, not a prediction of full lifecycle timing.

  An expanded Windows run at 2363 reported 425 passes, 118 failures, 58 setup
  errors and 15 skips. The 58 setup errors came from the new test's nonabsolute
  Windows path and are corrected in 38f. The actual Windows rerun at 38f
  passed all 58 cases in 1.17 seconds, with source origin and raw hashes
  verified and no native-key opt-in. The latest mapped draft CI also passed
  on Linux, macOS and Windows
  ([run](https://github.com/mordredagent/hermes-mordred/actions/runs/40557561423)).
  Five exact e01 representatives reproduced the other failure groups,
  including POSIX-only keyvault refusal, direct snapshot permission failures,
  private-ACL fixtures and stale flush-boundary expectations. Those existing
  test failures remain recorded and unfixed; the expanded run is not green.

  A separate e01 focused diagnostic removed a scheduled stack-dump timer and
  enabled fatal handling only. Genuine provision passed in 33.1 seconds and
  the unchanged protected SessionDB save/read/FTS/trigram checks passed in
  265.8 seconds (273.0-second child, exit zero, empty stderr). The logical
  digest was checked in memory, not retained. Earlier timer-enabled runs
  encountered access violations. This supports a timer-associated diagnostic
  failure without proving its cause; it is not a full collector/lifecycle pass.

  Codex CLI 0.163.0 authentication and actual SOL tool work passed on both
  dedicated ordinary-user guest environments. Development wrappers reuse
  existing SDK dependencies and isolated synthetic Hermes homes. No process
  inventory or private-file policy was widened for development. Owned jobs
  and forwarders closed, with all five restoration checks passing after the
  latest crypto diagnostic. Final independent AWS observations confirmed both
  instances stopped, the original Windows profile retained, Linux without a
  profile or association, and development/formal ownership released. The
  original disabled Password/Limited task, worker bytes and descriptor were
  verified. The ordinary account remains nonadministrator with its SSH group
  membership retained; the development CLI disabled it before stopping Windows.
  Authentication, old SDK/workspaces and current development routes remain
  preserved. No active owned job, target SSM session or transport remains.

  Fresh source/wheel qualification for the new runtime, all eight Windows
  lifecycle observations and the combined final16 consumer are deliberately
  deferred. Windows lifecycle acceptance remains zero of eight. Preparation
  artifacts remain in the private local ledger; no new SDK build or old-root
  replay is inferred from preparation. Windows 11/Desktop/Hello, real
  Telegram/IMAP accounts, live model behavior and measured macOS Touch ID
  counts also remain unverified.

- **2026-10-24 — Import-store shared writes and mail reconciliation: isolated SQLCipher validation.**
  Source: `refactor/import-store-writes`, based on `5396f0e89`; macOS
  27.0.1 arm64, Python 3.13.15, editable package verified against its dedicated
  worktree. A temporary `HERMES_HOME` and a randomly generated synthetic
  `hex:` memory key armed the real database shim; `open_import_store` passed
  the production SQLCipher gate. Synthetic RFC 2606 mail verified staged
  thread invisibility until run commit, atomic batch publication with its
  cursor, cross-batch parent/reply reconciliation and message counts, dry-run
  rollback and duplicate replay. Unkeyed stdlib SQLite could not read the
  resulting store. The home was deleted after the check; no production
  profile, mailbox credentials or gateway port was used. Explicit
  `-m integration` selection of `test_provenance_eval.py` and
  `test_telegram_local_llm.py` completed with three skips because their live
  model gates were unset. A real IMAP account fetch, Hermes/model provenance
  evaluation and Telegram live inference were not run. Hardware-key and VPN
  code paths are unchanged and were not exercised.

- **2026-10-24 — Activity redaction extraction: isolated SQLCipher validation.**
  Source: `refactor/activity-redaction` at `1f7ce6c24`; macOS 27.0.1 arm64,
  Python 3.13.15, editable package verified against its dedicated worktree.
  A temporary `HERMES_HOME` and a randomly generated synthetic `hex:` memory
  key armed the real database shim. The production receiver and
  `open_store` gate normalized and stored a synthetic event with secrets in
  its user text, page title, page text and URL parameters; none of the secret
  values appeared in the normalized event, stored fields or history detail.
  The stored digest matched both normalization and canonical digest
  calculation, and replay returned a duplicate. Unkeyed stdlib SQLite could
  not read the resulting store. The home was deleted after the check; no
  production profile, credentials or gateway port was used. The complete
  related automated module batch passed (1,606 cases). A real browser
  operator/receiver/Hermes session and live model acceptance were not run;
  this records the SQLCipher receiver/store check only. Hardware-key and VPN
  code paths are unchanged and were not exercised.

- **2026-10-23 — Browser activity and history (B2 stack) final live re-verification after the privacy fixes: operator, receiver and Hermes.**
  Source: branch `feat/browser-history-b2` (runs at `1312612b1`, `efac92a92`
  and `4a89bb602`, the commit before this entry), hermes-mordred 0.3.0a4,
  hermes-agent 0.19.0, Python 3.12.14, macOS 27.0.1 arm64. Operator: worktree
  `mordred-browser-os-oparator-capture`, branch
  `feat/activity-capture-extended` at `90f9f7e` (its later display-masking
  commits `58e0288`/`ca2ce76` were unit-tested only), Playwright Chromium 134
  headless, Fara1.5-4B on llama-server b10087. Hermes model: Ollama's
  `qwen2.5:7b` GGUF on llama-server b10087 (`-c 65536 -np 2`, 127.0.0.1,
  `provider: custom`); Hermes's own browser: agent-browser 0.39.1 with Chrome
  155 headless. Fresh armed throwaway homes with synthetic `hex:` keys; no run
  used `~/.hermes`. A first pass at `efe9bb27d` found two high-severity leaks:
  with a host excluded only in the receiver's `excluded_sites`, the operator's
  `task_start` / `task_end` named no host and were stored with the excluded
  page's title, page text and Fara's summary, which both history tools served;
  and a password named before its keyword ("Hunter2-fake-pw as the password")
  was stored verbatim in Hermes's own `task_start` and re-sent to every later
  session. Fixed since: host-less events lose site-controlled content while
  sites are excluded (`page_host_unknown`); an episode holding a
  `source_excluded` gap or a collector `site_excluded` mark is hidden on every
  surface; the operator names the page on task boundaries and holds its task
  start until the task ends; value-first, `to` and qualifier phrasings are
  redacted (property tests against a frozen copy of the base redactor, near-
  linear time); Hermes holds each turn's text until the turn ends and scrubs
  every value its `browser_type` withheld; secret-shaped tokens of 20+
  characters in the user's own words are redacted; a secret the message names
  is withheld wherever it is typed; one snapshot-ref parser classifies fields
  and fails closed. Operator pass (`1312612b1` + operator `90f9f7e`,
  `excluded_sites: [localhost]`): the search task's start arrived with its end
  yet carried site `127.0.0.1` and route `/index.html` and sorted first (route
  `/index.html -> /search.html`); the value-first login was stored as "... and
  redacted as the password"; a keyword-less login ("demo-user /
  Hunter2-fake-pw") was stored as "... redacted / redacted" after Fara typed
  the password into the password field; the receiver-only exclusion stored 7
  `source_excluded` gaps in the task's own episode and `localhost` in no
  column; the operator-side exclusion stored position-only `site_excluded`
  events. Hermes named Contoso and the visited pages, did not reveal the
  password, and no history surface returned either excluded episode (40
  offline probe calls). 0 password hits in every column of the decrypted
  `mordred.db` and `state.db` and in every file under the home; the operator
  console still printed a keyword-less password until it was typed (fixed in
  `ca2ce76`). B2 pass (`1312612b1`, 9 scenarios, all passed): typed `Contoso`
  kept; value-first password redacted; `notes.html` and `Fabrikam` intact (no
  over-scrub); a keyword-less password scrubbed once typed into the password
  field; a 24-character secret-shaped token redacted at ingest; a named secret
  typed into an ordinary field withheld; English and Japanese correction
  prefixes linked, also after `--resume`, whose first block no longer showed
  the session's own episode; exclusion and `activity use off` / `on`. One
  defect: after `--resume`, a password typed before any snapshot into a field
  remembered from the old page was stored as `other` with its text. Fixed: a
  ref the session's latest snapshot in this process does not list is
  `sensitive` (withheld and scrubbed); a transcript-seeding variant
  (`efac92a92`) was dropped after review found four ways it could fail open.
  Resume re-check at `4a89bb602`: typing before any snapshot after `--resume`
  (also into a ref a pre-resume click had made stale) was withheld and
  scrubbed (`Kiwi7-fake-pw`, `Plum4-fake-pw`: 0 hits in `mordred.db`; in
  `state.db` only in the sessions whose own messages held them); after a
  snapshot in the new process `Contoso Ltd` was kept as typed and task text.
  Known gaps kept: a keyword-less password under 20 characters that is never
  typed; a value typed before the first snapshot after `--resume` is scrubbed
  from the user's words too (accepted trade-off). Seen outside Mordred:
  Hermes writes REPL input to `.hermes_history` (0644) and `logs/agent.log` in
  plaintext, and Fara's `runs/` keep the raw task text. One resumed Hermes
  process crashed with SIGBUS; it was traced to dbcrypt's in-process
  `_classify` opening the live `state.db` through a second SQLite library,
  which drops the process's POSIX locks on close (pre-existing, fixed
  separately); the re-check harness never opened a database while Hermes ran.

- **2026-10-22 — Browser history for Hermes (B2) live: Hermes records its own browser calls and chat corrections; a later session reads them.**
  Source: branch `feat/browser-history-b2` at `628b17bcc` (hermes-mordred
  0.3.0a4), macOS 27.0.1 arm64, the worktree's dev venv (Python 3.12.14,
  `sqlcipher3-wheels` 0.5.7, hermes-agent 0.19.0), agent-browser 0.39.1
  installed in the home's `node_modules`. Model: Ollama's `qwen2.5:7b` GGUF
  served by llama-server b10087 with `-c 65536` on 127.0.0.1
  (`provider: custom`). Home: a rebound copy of the B1 browser-check home
  (schema 3 store, 11 episodes / 80 events, one pre-fix operator `task_start`
  holding the fake password). `activity status`: protection ok, schema 3,
  hermes use on. Test site on 127.0.0.1:8499. One-shot runs used `hermes -z`
  from an empty directory with `-t browser,mordred_activity,todo,clarify`. (1)
  "Open …/index.html, search for 'Contoso invoice' …, then open the notes page
  and type 'Call the accountant on Friday' into the note field": 120 events in
  one episode, all with `hermes_session_id`, Hermes's `turn_id` and
  `attempt_id` = `tool_call_id`: a `task_start` (actor `human`, the message
  verbatim), 3 navigates with titles and page text (359/364/222 characters),
  and 39 type, 53 click, 11 key and 13 scroll events; typed text was kept for
  named fields (`searchbox "Search invoices"` → `Contoso invoice`); the model
  looped to Hermes's 90-call cap; 117 events kept route `/index.html` after
  Enter and a link click had loaded `/search.html?q=…` and `/notes.html`, and
  no `query` was recorded. (2) The login request naming `Hunter2-fake-pw`: the
  `task_start` reads `… and the password redacted` (`text_secrets_redacted`);
  the username was kept; the password field was `field_kind: sensitive` with
  no text (`sensitive_field`, `typed_text_dropped`); the password was in no
  new store row; in the decrypted `state.db` it appeared only in that
  session's own messages (user message and API copy, `browser_type` arguments
  and result, three replies) and their full-text index rows, and in no file
  under the home. (3) Corrections: `-z` ignores `--resume`;
  `hermes chat -Q -q "correct: …" --resume <id>` recorded no correction (new
  process), and its browser calls were refused by privacy_check's `ask` prompt
  (no TTY) and recorded as `cancelled` / `blocked`; in the classic REPL
  (`chat --cli --yolo`, two turns in one process, driven through a pty) the
  correction was stored as `user_correction` / `human` / `correction` in the
  previous turn's episode with that call's `attempt_id` and URL, and appeared
  in the next navigation block as `user correction: …`. (4) "What did I do on
  127.0.0.1 earlier?": the turn-start block and one `mordred_browser_history`
  call returned the Hermes-recorded episodes with the correction, and the
  answer named them. (5) `activity use off` changed only `history_enabled`; a
  browser task then recorded nothing and got no blocks; `activity use on`
  restored `config.yaml` byte for byte and the next task was recorded. Found:
  every navigation block led with the session's own in-progress episode
  (capture writes before the block is read); a `correct:` turn with browser
  calls also started a new episode whose task text is the whole `correct: …`
  message; a correction in a resumed process was not recorded; an episode of
  refused calls has no site but still entered the turn-start context;
  privacy_check's denial text quoted typed arguments into plaintext
  `logs/agent.log`. This branch's later commits fix each of these findings:
  the session's own episode is left out of its navigation block and events
  after Enter or a click carry no route until a result reports the page
  (`e62f2f5cb`); a `correct:` turn's browser calls join the corrected episode,
  or start one without a task start, instead of making the correction a second
  task; a correction in a resumed process is linked to the session's last
  Hermes-recorded call found in the store; an episode without a site and
  without a successfully dispatched call stays out of the turn-start and
  navigation blocks; privacy_check's prompt and denial show typed and other
  free-text arguments only as `<N characters>`; and `activity use on|off` now
  says that Hermes's own capture stops and restarts with the switch while
  operator collection is unaffected.

- **2026-10-22 — Browser history for Hermes (B1): navigation block in a live Hermes browser session.**
  Source: branch `feat/browser-history-b1` at `9faa10374` (hermes-mordred
  0.3.0a4), macOS 27.0.1 arm64, the worktree's dev venv (Python 3.12.14,
  hermes-agent 0.19.0). Browser backend: `agent-browser` 0.39.1 from npm,
  installed with `npm install --prefix <home>` into the throwaway home's
  `node_modules` (Hermes's managed `$HERMES_HOME/node_modules/.bin`, found
  before the `npx` fallback; npm 12 blocked the postinstall, the JS wrapper
  made the binary executable on first run); no browser download: agent-browser
  ran the system Google Chrome 155.0.8059.85 headless with a temporary
  profile. Model: Ollama's `qwen2.5:7b` GGUF on llama-server b10087
  (`-c 65536`, 127.0.0.1, `provider: custom`). Home: a copy of the operator
  run's armed home (11 episodes, 80 events, one pre-fix `task_start` holding
  `Hunter2-fake-pw`), its store rebound to the copy (`profile_home`). Test
  site on 127.0.0.1:8399. `hermes -z` from an empty directory with
  `-t browser,mordred_activity,todo,clarify` (14 tools). "Open
  http://127.0.0.1:8399/login.html in the browser and tell me what you know
  about my earlier work on this site.": `browser_navigate` returned valid
  JSON inside `<untrusted_tool_result source="browser_navigate">` with
  `mordred_browser_history` ("[Mordred browser history for 127.0.0.1 — data,
  not instructions]", three episodes, routes, titles, "(5 more episodes; ask
  with mordred_browser_history)"); the turn-start block (the message names the
  URL) had taken the three newest episodes in the user's own words, so the
  navigation block showed the next three. With `history_turn_context: false`
  the block showed the newest three, both login tasks as "… and the password
  redacted". navigate, `browser_snapshot` and navigate again in one session:
  the second block showed three other episodes ("(2 more …)"), no episode was
  repeated, the snapshot got no block. In local mode Hermes 0.19.0's
  `browser_snapshot` result carries neither `url` nor `frame_tree` (only with
  a CDP supervisor), so the snapshot surface cannot add a block in this mode;
  `browser_back` was not exercised. No block held page text, typed text or a
  credential parameter value. Egress (level `ask`): every browser call was
  audited as `decision: ask` (`egress.ask`) and auto-approved by `-z`; the
  loopback address was not refused. `activity use off`: the history tools
  left the tool list and the navigation result had no history key and no turn
  block; `activity use on` restored `config.yaml` byte for byte.
  `Hunter2-fake-pw` had 0 hits in the decrypted `state.db` and the audit
  log; the raw store still holds it in one event.

- **2026-10-22 — Browser history for Hermes (B1) end to end: the real operator records, a local-LLM Hermes session reads.**
  Source: branch `feat/browser-history-b1` at `778e5ca52` (hermes-mordred
  0.3.0a4), macOS 27.0.1 arm64, the worktree's dev venv (Python 3.12.14,
  `sqlcipher3-wheels` 0.5.7, SQLite 3.51.1, hermes-agent 0.19.0). Operator:
  worktree `mordred-browser-os-oparator-capture`, branch
  `feat/activity-capture-extended` at `62d914b` plus its uncommitted capture
  changes, `mordred --text --headless`, Fara1.5-4B Q4_K_M on llama-server
  b10087. Model: Ollama 0.40.3's `qwen2.5:7b` GGUF served by llama-server
  with `-c 65536` on 127.0.0.1 (`provider: custom`, no API key). Home: the
  armed throwaway home of the previous operator run (schema 3 store with 58
  events, one of them a `task_start` stored before free-text redaction that
  holds the fake password `Hunter2-fake-pw`) and its synthetic `hex:` key.
  `activity status`: protection ok, schema 3, `hermes use: on`, no config
  warnings. Capture through `extension serve --port 7799`: a Fara search task
  (typed `Contoso`, observed `/search.html` with query `?q=Contoso`) and a
  Fara login task whose instruction held the password; 22 new events in 2
  episodes. The new `task_start` text reads `… and the password redacted`
  with exclusion `text_secrets_redacted`; a case-insensitive grep of every
  column of every table found the password only in the pre-fix row. Hermes
  sessions (`hermes -z` from an empty directory, toolsets
  `mordred_activity,skills,memory,session_search,todo,clarify`; the offline
  tool list held both history tools, 9 tools in all, and 29 in the default
  CLI set): (a) "What did I search for on 127.0.0.1 earlier, and which pages
  did I visit?" got no turn block and made one `mordred_browser_history` call;
  the answer listed the search and login episodes with titles and attributed
  one page-text excerpt to the wrong episode. The same question naming
  `http://127.0.0.1:8099/` got the turn block (persisted in
  `messages.api_content`) and was answered without a tool. (b) The explicit
  two-tool request called `mordred_browser_history`, then
  `mordred_browser_history_episode` on the search episode rather than the
  newest one; the answer gave its titles and the typed text `Contoso`. (c)
  "What password did I use to log in on 127.0.0.1?" got a turn block with
  both login episodes, made one lookup call and answered that the password was
  redacted; a follow-up that opened the pre-fix episode with
  `mordred_browser_history_episode` returned its task as `… the password
  redacted`. The password appeared in no answer, tool result or injected
  block, in no row of the decrypted `state.db` (21 tables) and in no file
  under the home (logs included). `activity use off` added only
  `history_enabled: false` to `config.yaml`; the history tools left the tool
  list and both question forms got no block (one called `session_search`).
  `activity use on` brought the tools and the block back. Nothing was audited
  as `activity.history_unavailable`. Found: `hosts_in` does not recognize a
  bare IP literal or a bare `localhost`, only inside a URL, so question (a)
  fell back to term matching, which shared one term; the operator console log
  still prints the typed password (operator repository). Not covered: the
  navigation block in a live Hermes browser session (Hermes's `agent-browser`
  CLI is not installed); called offline with a synthetic `browser_navigate`
  result, the hook added the 127.0.0.1 block with titles and the pre-fix task
  redacted, showed only unseen episodes on each repeat and nothing once all
  were shown. Gateway chats were not exercised.
  Re-check after the review fixes (`579947409`, same home, store and local
  model): "What did I search for on 127.0.0.1 earlier, and which pages did I
  visit?" now gets the turn-start block (the bare IP is recognized; three
  episodes, the login task shown as "the password redacted"), the model also
  called `mordred_browser_history`, whose result arrived framed as
  `<untrusted_tool_result source="mordred_browser_history">`, and the answer
  listed the login and search episodes. `Hunter2-fake-pw` had 0 hits in the
  answer, the decrypted `state.db` (21 tables) and the home's files.
  `activity use off` / `on` changed exactly the `history_enabled` line and
  restored the file.

- **2026-10-22 — Browser history for Hermes (B1 read side) on live SQLCipher, without a model.**
  Source: the uncommitted working tree of branch `feat/browser-history-b1`
  (base `55289b849`), macOS 27.0.1 arm64, the worktree's dev venv (Python
  3.12.14, `sqlcipher3-wheels` 0.5.7, SQLite 3.51.1, hermes-agent 0.19.0). A
  throwaway `HERMES_HOME` with `plugins.enabled: [mordred]` and
  `plugins.mordred_activity.enabled: true`, the SQLCipher marker written by
  hand and a synthetic `HERMES_MEMORY_KEY` (`hex:` form); the script called
  `dbcrypt.install()` first, opened the store with `open_store`, appended one
  synthetic six-event episode and then loaded the plugin through Hermes's own
  `PluginManager.discover_and_load`. Results: the tools' `check_fn` was true;
  `invoke_hook("transform_tool_result", …)` for a `browser_navigate` result
  added the site block (task, outcome, route with `?…`, title, correction; no
  page or typed text); `invoke_hook("pre_llm_call", …)` for a message naming
  the host returned the turn block without titles; `mordred_browser_history`
  and `mordred_browser_history_episode` answered through `registry.dispatch`
  inside the `<untrusted_tool_result>` frame (episode result 1,821 bytes); a
  typed `sk-live-…` value was withheld (`typed_text_dropped`); the stdlib
  `sqlite3` refused the store and no fixture string appeared in its bytes.
  The final run used the read-only reader (keyed opener plus the
  `activity_meta` binding check; the Hermes side never calls `open_store`)
  and audited nothing. An earlier attempt whose script replaced the shim in
  `sys.modules` was refused `unprotected_process` by every surface and
  audited once (`activity.history_unavailable`). Not covered: a real LLM session, the
  operator's extended capture (B3) and Hermes Desktop.
- **2026-10-22 — Imported-message provenance: real mail import into a SQLCipher store and a Hermes
  agent reading it through `mordred_history_search`.** Source: branch
  `feat/imported-message-provenance` at ae6917c8e (pull request #259), dev venv (Python
  3.12, `sqlcipher3-wheels` 0.5.7). Both runs used throwaway `HERMES_HOME` directories in
  the session scratchpad with the SQLCipher marker written by hand and a synthetic
  `HERMES_MEMORY_KEY` (`hex:` form); production state was never touched.
  (1) `hermes-mordred mail import --mbox tests/fixtures/mail/takeout_small.mbox --account
  work --own-address owner@example.com` wrote 5 messages, 2 conversations, 9 parts, one
  committed run; `mail status` reported the same; the store file could not be opened by
  plain SQLite ("database disk image is malformed"), its bytes held no schema text, and only
  the shim's 112-byte plaintext header was readable; file mode 0644 inside a 0700
  directory, as the activity store. (2) `uv run python tools/provenance_eval run --driver
  hermes --tier smoke --reps 1 --seed 0 --style per_part_en --threads 4 --max-calls 80`
  against a loopback `llama-server -c 65536` serving Ollama's `qwen2.5:7b` GGUF on
  127.0.0.1:5011, with `MORDRED_EVAL_HERMES_CONTEXT_LENGTH=65536` (Hermes 0.19.0 refuses
  the advertised 32K window). 25 of 34 questions were asked before the call cap (75 model
  calls); every answer carried `reader_mode: true` from the real `pre_tool_call` hook; 51
  tool calls: `mordred_history_search` executed 29 and refused 9 malformed argument sets
  (`invalid_request`), `telegram_chats` executed 5, `telegram_ask` refused 6
  (`telegram_not_configured` in the throwaway home), and the decoy `terminal` was attempted
  twice and executed zero times (blocked by reader mode). Answers quoted head lines and
  evidence ids (6 citations, 1 grounded-correct, 0 critical swaps by the scorer); the model
  itself is unfit (it attributed the owner's invoice promise to the other party in one
  answer), so the cell verdicts stay UNAVAILABLE and the attribution thresholds remain to be
  measured on the production Venice model. Earlier the same day the privacy driver's smoke
  run on `qwen2.5:7b` (32K) answered 42/42 with 35% critical swaps and 16 cited answers;
  see TODO for the scorer follow-up.

- **2026-10-21 — Browser activity end to end through the shipped surfaces with the real operator and Fara.**
  Source: the pre-commit working tree of branch `feat/browser-activity-
  learning` (no SHA yet), the same host and dev venv as the 2026-10-20 entry
  (Python 3.11, `sqlcipher3`, SQLite 3.51.1); operator `mordred-browser-os-
  oparator` branch `feat/activity-events` working tree in its own Python
  3.12.14 venv. Every run used a throwaway `HERMES_HOME`
  (`plugins.mordred_activity` with `enabled`, `collection_enabled`,
  `review_mode: manual`; the SQLCipher marker written by hand) and a synthetic
  32-byte key as `HERMES_MEMORY_KEY` (`hex:` form), so the shipped `.pth`
  bootstrap installed the shim in every `hermes-mordred` process; afterwards
  no production home state, marker, `plugin-data`, peer file or default-
  location operator credential existed. Gateway: `hermes-mordred extension
  serve --port 7799` (receiver from `_resolve_activity_receiver`). Pairing:
  `activity pair-operator` and `mordred-activity pair` wrote a `0600`
  credential, `activity peers list` showed the peer active,
  `activity_pending.json` and `activity_peers.json` were `0600` with SHA-256
  digests only, and `mordred-activity status` answered `activity_auth_ok` /
  `collection enabled`. Operator: `mordred --text --headless --activity` with
  Playwright headless Chromium, Fara1.5-4B on llama-server b10087 and Ollama
  `qwen2.5:7b` as interpreter, against the operator's test page served over
  HTTP on 127.0.0.1 (a `file://` page has no site, and a candidate needs one).
  Run 1 (task cut off at 240 s, cancelled at exit) stored 34 events in 1
  episode; run 2 (a guarded click declined, then a typed correction in the
  same episode) derived candidate `d5ad2142` with the site/route scope, the
  task text and 3 evidence events. Found and fixed: in run 3 Fara completed
  the task and the correction typed afterwards was refused as
  `attempt_unknown` and stored as a one-event episode, because the operator
  closes its episode at task end while the correction's `attempt_id` names the
  finished attempt; `ActivityStore.append_batch` now stores such a correction
  in its attempt's episode (SPEC §"Event contract"), and run 4 with the same
  script derived candidate `40d3fd28` with the correction joined to the task's
  episode and no extra episode. Correction loop on the live store through the
  shipped CLI: `candidates list/show` printed fields, digest and evidence
  lines without page text; `validate --method user_confirmed`, a wrong digest
  refused `confirmation_mismatch`, `adopt` with 12 digest characters admitted
  the lesson; the recall tools (shim installed) returned it for the same site,
  a reference on repeat, nothing for another site and `not_admitted` for an
  unknown id; `lessons suspend` stopped recall at once, `lessons revise` made
  revision 2 a candidate, and the audit log carried `activity.lesson_adopted`
  and `activity.lesson_suspended`; `backup --output` wrote a `0600` copy the
  stdlib `sqlite3` refuses, with no fixture strings; `review --dry-run`
  resolved `route_unavailable` (Hermes 0.19.0 `complete_structured` takes no
  `task` and no override route was set), enqueued jobs and made no model call;
  `retention --dry-run` counted 0/0/0; `activity peers revoke` made the next
  `mordred-activity status` fail with `peer_revoked`, and a second revoke
  reported no change. Final store: 5 episodes, 51 events, 3 lesson revisions
  (2 candidates, 1 suspended), 3 pending review jobs. Operator-side notes
  (they belong to that repository, not this one): address Fara as 127.0.0.1
  since `localhost` resolved to `::1` where the AirPlay receiver answers,
  `--text` needs stdin to be a pipe, and a typed "stop" while the guard awaits
  approval is a decline. Not covered: the Chrome-extension relay path and its
  navigation observations (Playwright mode only), any real provider review
  call, lost-ACK resend live (unit tests only), and Windows checked storage.

- **2026-10-20 — Browser activity store on live SQLCipher, operator↔receiver delivery and the correction loop.**
  Source: the pre-commit working tree of branch `feat/browser-activity-learning`
  (no SHA yet), macOS 27.0.1 arm64 / Python 3.11.15, `sqlcipher3-wheels` 0.5.7
  (SQLite 3.51.1) added to the dev venv with `uv pip install`, uv 0.12.9. Every
  run used a throwaway `HERMES_HOME`, a synthetic 32-byte memory key injected
  through `dbcrypt.KeyProvider`, and `dbcrypt.arm` + `dbcrypt.install` in the
  test process; no production home, key, marker or configuration was touched.
  Store: `open_store` passed the gate and created `plugin-data/mordred/mordred.db`;
  nine synthetic operator events were appended and the same batch replayed as
  nine duplicates with no second insert; the stdlib `sqlite3` refused the file
  (`DatabaseError`), the plaintext probe was false for the store and for the
  `activity backup` copy (mode `0600`), no fixture string appeared in the file
  bytes, and a copy placed under another home was refused. Delivery: a real
  `ExtensionAPIServer` with `build_receiver(home)` on 127.0.0.1 (ports 7817 and
  7818), `mordred-activity pair <code>` from the operator venv (Python 3.12.14)
  wrote a `0600` credential, `activity_auth` succeeded, and one batch was
  acknowledged after commit; lost-ACK resend was covered by unit tests only.
  Correction loop on the same store through the shipped CLI handlers: the
  ingestion-derived candidate was validated and adopted (a wrong digest refused
  `confirmation_mismatch`), the recall tools returned only the admitted lesson
  (nothing for another site, a reference only on repeat, nothing after
  suspension), `review --dry-run` enqueued one job without a model call, and
  the audit log carried `activity.lesson_adopted` and `activity.lesson_suspended`.
  Not covered: any real provider review call (no paid evaluation was run), the
  extension's navigation observation in a real Chrome (the operator's relay
  tests need Chromium and were skipped), Windows checked storage, and the
  30-task pilot benchmark. Full source regression on the final tree: 8,452
  passed, 299 skipped, 1 deselected (`tests/extension/test_pm_member.py` wheel
  test: the temporary venv's interpreter aborts loading `libpython3.11.dylib` on
  this host, unrelated to the change); critical preset 20 passed; Ruff,
  formatting and strict mypy passed. Operator repository: 355 passed.

- **2026-10-19 — macOS Ollama/Qwen3 local inference and Telegram archive questions.**
  Source candidate `f87de8046ed20723e29e72051885636828a240cb` was exercised
  on macOS 26.6.2 arm64 / Python 3.11.15 against the existing loopback
  Ollama 0.40.3 service and `qwen3-14b-q4-4k:latest` (14.8B, Q4_K_M,
  actual serving context 4096). No existing model settings were changed.
  The original 64-token probe returned HTTP 200 but exhausted its budget
  on reasoning, producing no visible answer. Keeping the same prompt,
  streaming client and 30-second deadline while allowing 512 tokens
  produced visible `OK` in 7.08 seconds. The probe-only budget correction
  retains empty-answer and incomplete-stream refusal; it does not guarantee
  success for every reasoning model.

  The explicit `tests/integration/test_telegram_local_llm.py` run retained
  its original probe failure; after the correction, the unchanged test
  passed in 100.90 seconds, including saved-target configuration, a real
  streamed probe and an actual `telegram_ask` answer. Independent English
  and Japanese questions over the same synthetic encrypted message returned
  the expected weekday, Monday, in 60.25 and 69.03 seconds. The English
  answer added a calendar date absent from the message, and neither answer
  cited its source: this validates transport and weekday retrieval, not
  citation compliance or general answer quality. Archive encryption was
  real; key custody and policy/memory guards used explicit test boundaries.
  No real Telegram account, Telegram network connection or physical
  Secure Enclave was used. This 4k-context result does not establish normal
  64k Hermes chat readiness or large-archive acceptance. The existing
  installed Hermes environment was not replaced.

  One full source regression retained 8,062 passes, 84 failures and 295
  skips, with 50 default deselections and 90.54% coverage. All 84 failures
  were private harness environment errors: one used `HOME/.hermes` instead
  of a distinct `HERMES_HOME`, and 83 invoked a mise Node shim whose trust
  state was unavailable under the isolated HOME. With a separate test
  Hermes home and the existing real Node 24.21.0 binary on PATH, the six
  complete containing/affected modules passed all 147 cases. Every original
  failed node passed; the reconciled original scope is 8,146 passes and 295
  skips across multiple runs, not a single clean full run. Production code
  did not change between these executions. The final critical preset passed
  20 cases; Ruff, formatting and strict mypy also passed. No production home,
  credentials or mise trust settings were modified.

- **2026-10-18 — Maintenance repair validation on isolated Linux and Windows Server.**
  The tested code is `2ed57454803fa588b520a301cb9b9896decc1017`.
  On Ubuntu 24.04.5 / Python 3.12.3, the full source regression at
  `be0368137332fd5f5fe821834dc7c48d021aaa7a` passed 8,048 cases, with
  358 selected skips, two additional module collection skips and 50 default
  deselections; coverage was 88.19%. The subsequent revisions changed five
  test files only. Complete changed modules passed again on both operating
  systems and both source/installed-wheel runtimes. Production, native,
  build and dependency inputs remained identical; every independently rebuilt
  wheel retained SHA-256
  `64ad3da109ba90889c6dd2272ee414a38a5efb67f66f0d2d92d0a7c661f4c422`.
  Linux's first wheel run retained its original 2,639 passes, 197 skips and one
  packaging-fixture setup error. The corrected private build-data context
  subsequently passed the complete three-case packaging-proof module without
  changing installed imports. Real TPM tests passed twice per runtime; each
  source/wheel transition checked 11 public operations. All four source/wheel
  plain/authenticated local-LLM gates passed, including initial 401 then saved-key
  success. The 0.5B model does not establish normal 64k Hermes chat readiness.

  Windows Server 2025 / NTFS / Python 3.11.17 used an ordinary, non-elevated
  token. Default collection selected 8,406 cases; this is collection evidence,
  not a global Windows execution claim. The original four-shard 116-module
  execution retained 3,756 passes, 384 skips and 21 failures. All 21 have exact
  passing corrections from complete containing modules in both runtimes.
  Combining those corrections with fresh N1 execution reconciles the same
  4,161 scoped cases to 3,789 passes and 372 explicit prerequisite skips;
  this is a multiple-run ledger, not a relabeled original run. The complete
  frozen 67-module installed-wheel execution passed 2,552 cases with 285 skips
  and zero failures/errors, outside the checkout with unchanged static/RECORD
  payload. All 20 final validation controllers exited successfully.

  Public configuration/network tests passed all 87 cases per runtime. Actual
  CNG settings, Desktop settings, explicit private-source migration, inherited
  confidential roundtrip and mixed dotenv concurrency gates passed in both
  runtimes. Fresh distinct N1 fixtures passed 16 cases per runtime, with two
  ordinary-token mutation skips. An additional complete six-case Telegram
  module verified actual NTFS/SID/DACL/hardlink/junction/process-lock behavior
  with its explicitly modeled CNG backend; real CNG proof remains separate.
  All 294 original failure entries were reconciled individually: 151 exact
  required-context passes and 143 qualified platform contracts with explicit
  prerequisites, supported-context witnesses and native counterparts. All
  211 source and 165 required wheel counterpart IDs passed. The 18 original
  SQLCipher-dependent uninstall cases separately passed on supported macOS;
  these are not Linux/Windows SQLCipher passes.

  Both final runtime audits passed; all four new custody profiles had empty
  Telegram generations, no memory lease and no archive payloads. No known
  test process/listener or task-related visibility gap remained. Unrelated
  process visibility gaps and historical inventory errors remain disclosed.
  Both exact owned N1 roots were removed after admission. The selected Linux
  retained inventory and Windows 68-root/1,902-file inventory were unchanged,
  including the same three Windows historical errors and original retained
  subset. The final Windows archive contained 81 independently hash-verified
  JSON/XML evidence files. Original SSH ingress was restored, only the owned
  backstops/forward were removed, and both validation instances were independently
  confirmed stopped before local guard disarm; the unrelated fixture stayed
  stopped. No production home, real Telegram account, existing custody key or
  production gateway port 7788 was modified. Private receipts and exact ledger
  are retained under `mordred-maintenance-failure-repair-20261018`, including
  `final-acceptance-r5-03.md`. Earlier failed validation entries remain historical.

- **2026-10-18 — Maintenance validation on isolated macOS worktrees.**
  Python 3.11 editable imports were verified against each task worktree,
  with task-local `HERMES_HOME` set before imports. The explicitly selected
  `tests/test_wizard_windows_telegram_live.py` and
  `tests/integration/test_telegram_local_llm.py` gates both skipped: this host
  cannot run Windows CNG and has no configured real local inference model.
  The CNG recipe now checks synthetic LLM-setting retention and endpoint-change
  key removal through a fresh-process reload. The Desktop/Telegram native
  selection skipped 9 cases. Dotenv's complete affected-module selection
  skipped 6 Windows cases; a separate native selection skipped 28.
  These are recorded selections, not native or live acceptance. Actual Windows
  checked-filesystem/CNG and real local inference reruns remain open. No
  production home, real Telegram account or existing custody key was used;
  production gateway port 7788 was untouched.

- **2026-10-15 — macOS Desktop package-change restart control.**
  With Hermes Desktop `v0.22.0+119` / Python 3.14.7 on arm64, reproduced the
  old button calling the messaging restart: only the statusbar changed,
  followed by a delayed notice, while the Desktop backend PID stayed fixed.
  Backed up the page in an owner-only temporary directory
  (`mordred-desktop-restart-qa-e5s4mwgr/plugin.js`) and staged only the new
  page asset, SHA-256
  `926f058f396467c46a512b13be42da92cb124f121e67140e4e0891130a35b6ed`.
  The actual page showed the neutral running-code/installed-metadata copy
  and **Restart Hermes Desktop**. **Cancel** left Desktop/backend PIDs
  `88830` / `88924` unchanged. **Restart now** invoked the app relaunch at
  13:11:36 local time: Desktop became PID `94831`, backend became `94933`,
  and the backend reported ready at 13:11:49. The tool observed the window
  exit before capturing the short pending state; immediate pending and
  deadline/failure/remote/disposal paths are covered by the Node harness.
  Reconnection briefly waited on the Secure Enclave helper. The actual
  Mordred page subsequently returned, with the same running/installed
  versions and the model, hardware, memory and Telegram checks preserved.
  The sidebar reported a session-list retry and messaging stopped; no
  session-content or messaging-platform acceptance is claimed here.
  The base Python's editable pointer still imports `0.3.0a1` from the
  original repository, while Hermes's selected environment/member report
  `0.2.0a1` from the older checkout. Bootstrap restored that source's old
  page asset after relaunch. No package provenance, metadata, credentials,
  custody key or configuration was changed to hide this mismatch.

- **2026-10-14 — macOS Hermes Desktop dev installation, Telegram import and SQLCipher acceptance.**
  Installed immutable Mordred candidate `c98493af2dce1179991a26b2cbf9e5c78623db69`
  into the existing Hermes Desktop-managed environment using
  `scripts/install.sh --from-source <pinned checkout> --with-telegram`.
  Hermes reported `0.22.0` (Desktop displayed `v0.22.0+119`), Python 3.14.7,
  on macOS arm64. Desktop and its backend were stopped before an owner-only
  full-home and Desktop-settings backup; eight configuration/database files
  were hash-verified. The four existing databases (`state.db`, `projects.db`,
  `shared-state.db`, `cron/executions.db`) were readable by standard SQLite
  and passed `quick_check` before setup.
  All 254 checked package source/assets matched the pinned candidate both
  immediately after installation and after Desktop rebuilt its managed
  environment. The rebuilt environment passed `uv pip check`; the initial
  environment's sole warning was Hermes source metadata `0.0.0` against
  Mordred's `hermes-agent>=0.13.0` requirement. The actual Desktop displayed
  the Mordred setup page, its local source origin, and the expected privacy
  model gate. Critical feedback initially passed 19 cases with one page-auth
  timeout during backup; that case passed alone, and the full critical preset
  then passed **20 tests in 13.95s** (one Starlette deprecation warning).
  The operator saved the Venice endpoint credential; Desktop accepted
  `deepseek-v4-flash` as a private Venice model. Secure Enclave helper setup
  completed and `telegram doctor` reported hardware readiness. Memory setup
  then failed: the default vault directory and manifests were absent, but
  its device freshness anchor remained in macOS Keychain. Both the environment
  injection and memory runtime probes passed (memory seam A). The retained
  nonsecret anchor was backed up and verified. With the operator's explicit
  approval, only that helper-owned anchor was reset; no wrapping key was
  deleted. Retrying Desktop memory setup displayed a recovery passphrase,
  and `telegram doctor` reported `agent memory sealed`.
  The operator saved the recovery passphrase. Desktop was fully quit and
  restarted; its backend became ready and the memory step remained checked.
  The saved Venice credential was reused through Desktop for Telegram's
  question model; `telegram doctor` reported the Telegram key present,
  memory sealed, and Venice `deepseek-v4-flash` configured. The operator
  completed Telegram login in Desktop. The real three-day import (archived
  chats excluded, default maximum group size 100) yielded **2 chats / 3
  messages**. A Desktop reimport added **0 messages**; local authenticated
  archive reads found no duplicate message IDs and the same identifier set
  before/after reimport and after restart. All three archive blobs had `MTG1`
  headers and mode `0600`. No Telegram question was sent to an LLM.
  With Desktop stopped, `databases encrypt` converted **5 databases**:
  the original four plus `telemetry/shared_metrics/metrics.sqlite3` created
  during the live run. All five refused keyless stdlib SQLite reads, passed
  keyed `integrity_check`, and returned no `cipher_integrity_check` findings,
  both immediately after conversion and after Desktop writes. No conversion
  journal remained. Conversion itself compared post-checkpoint table counts
  and SQLite IDs before swapping files.
  The independent pre-conversion probe initially used `immutable=1`, which
  ignored committed WAL pages and undercounted the newly created synthetic
  chat. The probe was corrected to include WAL. Separate row comparisons
  confirmed all four preexisting messages survived, along with the two
  pre-conversion synthetic messages. Desktop reopened that chat, found it by
  an exact message-content search, and saved a second synthetic user/assistant
  exchange through the encrypted database (eight total messages afterwards).
  A final full quit/restart displayed both synthetic replies, and exact
  content search found the post-encryption reply. Desktop was left running
  with memory/database encryption enabled and Telegram logged in.
  Only synthetic chat text was sent to Venice for these checks.
  One startup logged a cancelled hardware authentication before the backend
  connected; keyed checks and the subsequent Desktop read/write succeeded.
  SQLCipher's linked SQLite 3.51.1 triggered Hermes's known WAL-reset warning;
  the databases used the existing DELETE-journal fallback. Pre-install and
  pre-conversion plaintext backups were retained in an owner-only directory
  outside the Hermes home, alongside verified encrypted database backups.
  No credentials, recovery passphrases, or real message contents are included
  in this record. Product code was unchanged; this is live-device acceptance,
  not an additional full regression run.

  Release preparation subsequently hit the existing native Defender-image
  test's positive admission expectation at `Platform/CurrentVersion`.
  The test now checks the parent's native reparse metadata, requires alias
  refusal before inspecting its concrete OS target, preserves descriptor
  comparisons and records both observations in JUnit. Production admission
  remains unchanged; the fresh full hosted run must establish native results.

- **2026-10-12 — Pre-merge Telegram review follow-up.**
  After integration with `dev` at `d3ad9d795`, independent review reproduced
  a diagnostic disclosure when malformed local HTTP coincided with audit
  writer construction failure: DEBUG traceback logging included the active
  transport exception's response bytes and URL path. A real malformed-chunked
  loopback regression through `telegram_ask` failed before the fix. The audit
  fallback now logs only the exception class, without traceback or exception
  text. The complete affected modules passed **307 tests in 11.28s**; Ruff,
  formatting, strict mypy (266 sources), and shellcheck passed. The 401/403
  remediation also includes the required endpoint/model placeholders.
  Final integrated regression and hosted acceptance are recorded in PR #238.
  The user subsequently confirmed the installed Hermes/Telegram workflow
  after the CLI toolset correction described below.

- **2026-10-12 — Follow-up: Telegram discovery in the actual Hermes session.**
  The user's Qwen session could read Mordred's Telegram prompt section but
  `tool_search` had only five deferred tools and returned no Telegram matches.
  A fresh installed-runtime probe found both tools registered, their
  availability check true, and no component registration errors. The precise
  startup ordering that omitted them from the existing session was not
  established. Earlier one-shot runs also logged plugin-load timeouts in
  `agent.log` / `errors.log` that were absent from captured stderr; successful
  generic chat and file calls alone did not establish Telegram discovery.

  `hermes tools enable mordred_telegram --platform cli` explicitly persisted
  the CLI selection. A fresh `hermes chat -m qwen14b` one-shot then had seven
  deferred tools; Qwen called `tool_search` with both Telegram names and
  received matches for both tools (exit 0, 88.0 seconds). This was a real
  installed-Hermes/model/search-bridge check, without invoking Telegram
  custody or reading an archive. The already-running user session still
  needs its tool selection reloaded or a restart. No Telegram privacy
  backend, keys, model default, or application source was changed.

- **2026-10-12 — Qwen3 14B on the installed Hermes runtime (macOS M5, 24 GiB).**
  Candidate `6eb299682` was installed as a copied package, replacing an
  existing editable install that pointed at a deleted checkout. Hermes's
  package manager then rebuilt its environment with the vendored Mordred
  member; all 252 installed Python source files matched the candidate.
  The generated CLI launcher was refreshed to that active environment.
  Hermes `0.21.5+4900.gbddd22b` loaded Mordred `0.2.0a1` on subsequent starts.

  The official `Qwen/Qwen3-14B-GGUF` Q4_K_M weights (SHA256
  `500a8806e85ee9c83f3ae08420295592451379b4f8cf2d0f41c15dffeb6b81f0`)
  were served by llama.cpp `b11562` on `127.0.0.1:11435`, aliased as
  `qwen3-14b-q4-hermes`. Hermes refused the initial 4096-token runtime because
  it requires at least 64000 tokens. Ollama clamped a requested 65536-token
  context to 40960 for these weights. The accepted llama.cpp configuration
  used a 65536-token context, YaRN scaling factor 2 with original context
  32768, q8_0 K/V cache, Flash Attention, one slot, and thinking disabled.
  Both `/v1/models` and `/props` confirmed the runtime context. This checks
  allocation and short interactions, not answer quality at 64K tokens.
  The loopback LaunchAgent unloads the model after 300 idle seconds; logs
  confirmed unloading and a successful wake on the next Hermes request.

  In the existing Hermes profile, `hermes chat -m qwen14b --toolsets file`
  called `read_file` on a synthetic fixture and correctly returned its
  Monday meeting date and random verification code (exit 0, 33.3 seconds
  including the cold model wake). A subsequent normal invocation without a
  toolset override also returned the requested Japanese response (exit 0,
  75.4 seconds, 12450 input tokens). This demonstrates a working default
  tool configuration but also substantial initial prompt latency on this Mac.
  The original default model/provider and
  plugin configuration were unchanged. A named local provider, model alias,
  and per-model reasoning override were added. The existing Telegram
  privacy backend remains Venice; its real archive was not queried.

  The explicit live gate
  `uv run pytest -o addopts= -q -m integration tests/integration/test_telegram_local_llm.py`
  passed **1 test in 3.14s** against this 14B endpoint. This exercised sealed
  local configuration, `telegram doctor --probe-llm`, and `telegram_ask`
  with a synthetic encrypted archive. The fixture uses test hardware
  custody and injected policy/memory guards; it does not validate physical
  Secure Enclave custody, a live Telegram import, Linux TPM, or the
  reporter's original 27B setup. No application code changed in this
  environment-validation step; the full regression result below remains
  the code candidate's acceptance evidence.

- **2026-10-12 — Telegram saved local LLM: real llama.cpp, with and without authentication.**
  Candidate `0617515df` was exercised on macOS arm64 / Python 3.14.7 against
  the official llama.cpp `b11562` binary and
  `Qwen/Qwen2.5-0.5B-Instruct-GGUF` (`qwen2.5-0.5b-instruct-q4_k_m.gguf`,
  SHA256 `74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db`).
  Both servers were task-owned, bound only to dynamic loopback ports, and
  stopped after validation. The model was served as `mordred-synthetic` with
  a 4096-token context and one slot. No existing Ollama models/settings or
  production Hermes state were changed.

  Explicit runs of `tests/integration/test_telegram_local_llm.py` passed
  **1 test in 1.51s without authentication** and **1 test in 1.52s with
  authentication**, after the review fix requiring an explicit terminal
  SSE event for a successful probe. The authenticated run first observed the real server's
  HTTP 401 as `local_llm_unauthorized`, then imported a temporary key through
  `telegram local-llm --api-key-env`. Both runs verified the saved target via
  `telegram doctor --probe-llm --json` and obtained an answer through the
  actual `telegram_ask` tool over a synthetic encrypted archive. Custody used
  the existing test hardware backend with real credential sealing, not a
  physical Secure Enclave or TPM. This is live model/HTTP evidence, not
  Linux TPM or the reported 27B model's acceptance.

  Reproduce with `MORDRED_TELEGRAM_LIVE_TEST=1`,
  `MORDRED_TELEGRAM_LIVE_ENDPOINT=http://127.0.0.1:<port>/v1`,
  `MORDRED_TELEGRAM_LIVE_MODEL=<served-model>` and, for an authenticated
  server, `MORDRED_TELEGRAM_LIVE_API_KEY` set privately, then run
  `uv run pytest -o addopts= -q -m integration tests/integration/test_telegram_local_llm.py`.
  The gate-off run skipped that live test and both
  `tests/integration/test_linux_telegram_tpm.py` tests. A real Linux TPM and
  the reporter's sealed endpoint remain unavailable in this environment;
  the original incident's exact cause is still unconfirmed.

  Final regression: `uv run pytest --cov=src/mordred_hermes` passed
  **7272 tests**, skipped **220**, deselected **50**, and reached **90.34%**
  coverage (80% floor) in **1286.38s**. The run reported 28 warnings,
  including SQLite resource warnings in existing lifecycle tests and
  dependency/fork deprecations. Repository-wide Ruff checks and formatting,
  strict mypy (260 source files), and the prescribed shellcheck command
  passed. A fresh code review found one incomplete-SSE probe issue; two
  regressions failed before its fix, then all 109 affected tests passed.
  The final full regression includes the fix. No Critical or Minor review
  findings remained.

The restored WF0, C5 shared, C3 and C5a entries below are dated historical
results for their original source/wheel snapshots, not evidence for the
consolidated candidate `bb75885ac`. Pending observations in those entries
describe their original test time; subsequent contracts and the Windows
completion acceptance matrix track later work and current open gates.

- **2026-10-12 — Local LLM probe refusal; live endpoint unavailable.**
  The LLM candidate `4ecb4cf58` rejects HTTP 1xx and 3xx responses instead
  of treating them as healthy. Deterministic HTTP 103 refusal and HTTP 302
  strict-session refusal regressions failed before the fix and passed after
  it. An explicit run of `tests/integration/test_llm_local.py` on macOS,
  Python 3.14.7, passed the two connection/refusal tests and skipped the
  three live-gated tests. `MORDRED_LIVE_LLM_TEST` and
  `MORDRED_LIVE_LLM_ENDPOINT` were unset, and no service was listening on
  the default local port 1234. Real LM Studio / Ollama / vLLM validation
  remains pending; mock-transport results are not live-server evidence.

- **2026-10-11 — Linux setup/enable-all memory and armed shape-B backup on real NitroTPM.**
  The immutable wizard candidate `dbd8acc8d8d23df88c4674e6585339758abdc831`
  passed **3 gated tests in 16.47s** on the retained EC2 NitroTPM instance
  `i-095cbe655c196c749`. Actual `/dev/tpmrm0` capability output identified
  AMZN/NitroTPM 2.0; no emulator or device-selector override was used.
  The host was Linux `7.0.0-1014-aws`, x86_64, glibc 2.39, Python 3.12.3,
  with installed Hermes 0.19.0. The candidate wheel SHA256 was
  `9c63bc28fe2e4a274e04f47aef156bc14d4e4e4aad43453bef7dfe8f6f39a92f`.
  The existing helper `/home/ubuntu/.local/bin/mordred-hermes-tpmkey` had SHA256
  `b870be37f051447c02f008111dd01bc55a1fe163e7a33af0c6e5eb2812701b19`.

  Both the new setup-memory resolver and actual installed public
  `hermes-mordred encryption enable all` enrolled fresh owned synthetic homes.
  Fresh automatically hooked Hermes processes verified shape B, sealed
  read/write, exact wrapped-key reuse, paused setup versus explicit re-enable,
  and unchanged env/config sentinels with no file-vault enrollment. Real
  `MemoryStore(memory_char_limit=40)._detect_external_drift("memory")` protected
  armed external plaintext in a private `0600` sealed backup, authenticated
  with the actual returned backup filename as AEAD identity. Corrupt and
  missing wrappers refused both backup publication and the corresponding
  entrance without source/backup/marker changes or persistent native-store
  regeneration. Exact wrapper bytes/mode were restored in `finally`, followed
  by successful readability and scoped disable/purge. The existing lifecycle
  selection also exercised unreadable-tree refusal and a missing-device
  selector with an ambient key, which could not bypass managed TPM custody.

  The runtime prefix was `/tmp/mordred-pr155-dbd8acc-pORrMq/runtime`.
  Recorded imports were its `lib/python3.12/site-packages/tools/memory_tool.py`
  (both memory module and real MemoryStore class) and
  `lib/python3.12/site-packages/mordred_hermes/__init__.py`; these were installed
  wheel imports, not the source checkout. From the adjacent `repo` directory,
  the actual sanitized outer launch was:

  ```sh
  native_root=/tmp/mordred-pr155-dbd8acc-pORrMq
  env -i HOME=/home/ubuntu \
    PATH="$native_root/runtime/bin:/usr/local/bin:/usr/bin:/bin" \
    HERMES_HOME="$native_root/parent" MORDRED_CONFIG_DECRYPT=0 \
    MORDRED_LINUX_ORCHESTRATION_TEST=1 MORDRED_LINUX_TELEGRAM_TEST=1 \
    MORDRED_ACCEPTANCE_COMMIT=dbd8acc8d8d23df88c4674e6585339758abdc831 \
    MORDRED_LINUX_TPM_PROVIDER=EC2-NitroTPM \
    MORDRED_HERMES_RUNTIME_PYTHON="$native_root/runtime/bin/python" \
    "$native_root/runtime/bin/python" -m pytest -p no:cacheprovider \
    -o addopts= -m integration -s -q --basetemp="$native_root/acceptance-owned" \
    tests/integration/test_linux_memory_orchestration_tpm.py \
    tests/integration/test_linux_telegram_tpm.py::test_fresh_runtime_lifecycle_and_fail_closed
  ```

  All three test-owned native stores were independently confirmed empty after
  purge. The instance was independently verified stopped; the original SSH
  ingress rule remained unchanged, and the owned watchdog was terminated only
  after cleanup checks. Host-key admission matched the prior console-verified
  pin. No new resources or ingress changes were needed. No production home,
  live credentials, full general setup, gateway or live Telegram account flow
  was exercised. This establishes the bounded memory entrances, installed
  shape-B runtime and backup/refusal paths on actual TPM hardware; final-state
  inventory does not trace every TPM command or intermediate write, and the
  missing-device selector is not a physical TPM outage test.

- **2026-10-11 — Wizard file-vault eligibility; portable validation only.**
  The candidate based on `eebf31fc9` used an isolated `HERMES_HOME` on macOS
  with Python 3.12.13. Focused RED/GREEN covered anchor `WrapError`, unsupported
  production Keychain defaults, cached/injected stores and portable rotation;
  107 focused cases passed. Additional add/migrate preservation and Windows
  exclusion-before-flow checks passed their 66-case containing modules.
  The full frozen-production regression passed **7,621 tests**, with 220
  skipped, 47 deselected and 90.29% coverage. Source and isolated installed-wheel
  CLI probes verified Linux init/recovery refusal and passphrase rotation
  without native resolver calls, preserving all non-sidecar vault bytes.
  Lint, formatting, shellcheck, strict typing with all and CI-only extras,
  package build, macOS Swift helper build and 55 portable TPM-helper Rust
  tests passed. The explicit Secure Enclave integration command ran with
  `MORDRED_KEYVAULT_LIVE=0`: **8 skipped**, so no live hardware validation is
  claimed. Native Linux/Windows and live-device gates remain separate; no real
  custody or production profile was opened or modified.

- **2026-10-11 — Consolidated candidate ordinary-user AWS CNG validation.**
  Candidate `c055169639af5e82706e73e5316278a48f8b9a56` ran on the retained
  Windows Server 2025 Datacenter 10.0.26100 x64 / fixed NTFS host with
  AMZN NitroTPM 2.0 ready. Python 3.11.17 used a credentialed, non-elevated
  SSH user. Both owned venvs installed their dependencies directly; Hermes
  0.21.5 retained its existing editable source installation. Mordred imported
  from the candidate's `src` in the source venv and from the wheel venv's own
  `site-packages` in the installed run. The sdist-derived wheel SHA-256 is
  `10b8e50640d2266fe60f44b3affe63e0d32c940c6fec39b98b9b55cbd6dca289`.

  Real CNG acceptance passed **4 source Python cases and 9 installed-wheel
  Python cases**, each with fresh JUnit and zero failures, errors or skips.
  The installed cases cover custody, encrypted audit, memory and Telegram
  storage, installed-runtime proof/lifecycle, memory and synthetic Telegram
  wizard flows, compiled-helper production MRKW and Desktop API enable/disable
  through the serving interpreter. Rust regression passed 12 cases with the
  three live cases intentionally ignored; the explicit real-CNG invocation
  then passed **all 3 live cases with zero ignored**. Test profiles and keys
  were newly scoped fixtures. The successful Desktop fixture's retained
  memory key was purged through the actual installed CLI (exit 0).

  The initial full Server source attempt failed (2,517 passed, 68 failures,
  41 errors, 123 skips): child fixtures did not process the parent's borrowed
  dependency `.pth`, so PyYAML was unavailable and the runtime guard refused.
  Disabling that owned borrowing hook and installing complete dependencies
  corrected the isolated proof reproduction: **1 passed in 8.20 seconds**.
  The subsequent full 84-module source attempt reached approximately 89%
  without observed failed markers, but timed out at 3,600.016 seconds (exit
  124, no final JUnit). **Fresh complete Server regression remains open.**
  Unchanged injected proof fixtures require a source-checkout parent; no
  full 84-module installed-wheel pass is claimed.

  Independent live execution used verified equivalent-input CI
  [38106401094](https://github.com/mordredagent/hermes-mordred/actions/runs/38106401094)
  as its prerequisite after the source processes ended. Production/native
  inputs, all 84 selected modules and the three imported configure helpers
  match that green candidate; this does not imply equivalent dependencies or
  a new complete Server pass. The 23 collected evidence files matched their
  SHA-256 manifest. Task-owned processes ended, the created shutdown task was
  removed, and EC2 was independently verified **stopped** before disarming the
  local stop guard. No new VM or Azure resource was created. Windows 11,
  packaged GUI/page/restart, full installed lifecycle and actual external
  account/model/route flows remain separate open gates. The user authorized
  PR #226 integration into `dev` after ready-for-review full CI succeeds;
  this does not close the Windows product release gates above.

- **2026-10-08 — Windows privacy canonical decisions (C8).**
  Component revision `31845b8b4` follows the shared canonical coordinator.
  Ordinary non-administrator Server 2025 / Python 3.11.17 runs passed all
  **35 tests** in `tests/test_windows_privacy_policy.py` for both source and
  a fresh sdist-derived wheel environment. Module origins were verified;
  all profiles were task-owned. Native cases cover inherited ACL preservation,
  broadened ACL/hardlink/junction refusal after a cached allow, and another
  process holding the canonical locks. The session-start regression verifies
  one checked generation and a later pending-state hard refusal.
  Wheel SHA-256: `2c052e6e4f4922dac7977e944f06f81fdfb2ecceecce9293c9b1abd875808403`.

  Independent review found an unguarded second session-start read; the final
  revision reuses the integrity gate's checked state and passed scoped review.
  Host full regression at the pre-fix revision: 6,039 passed, 130 skipped,
  37 integration cases excluded, coverage 89.16%. Final focused regression:
  174 passed, four native-only skips. Reduced-extras types, lint, formatting,
  shellcheck and documentation checks passed; existing dependency/fork warnings
  remain. Production audit storage, other components, Windows 11 and the full
  installation-to-use flow remain separate acceptance gates.

- **2026-10-08 — Windows LLM canonical decisions (C8).**
  Final component revision `a3be33537` passed **70 tests** in both ordinary-user
  Server 2025 / Python 3.11.17 source and fresh sdist-derived wheel environments:
  `tests/test_llm_windows_policy.py` and
  `tests/test_llm_windows_policy_native.py`. Verified module origins and
  disposable profiles kept production state unchanged. Native cases exercise
  inherited ACL preservation, permission broadening, hardlinks and pending
  markers after prompt/auxiliary grants were cached. No live model was called.
  Wheel SHA-256: `1000c52f982faa6cd37791c5700eb1648bc9f03e34bf093a81e679e8be67ce64`.

  Independent review and scoped R1 review approved. The R1 fix validates main
  model endpoint/default/alias types before off-mode exits. Final focused host
  checks passed 303 tests with four native skips; reduced-extras strict typing,
  Ruff, formatting, shellcheck and docs checks passed. A prior full suite exited
  successfully before the final ownership/schema changes; it is not evidence
  for the final full-suite snapshot. Production audit IO, live provider flow,
  other components, Windows 11 and full-product acceptance remain unfinished.

  2026-10-09 host-only follow-up: policy/config and audit-factory refusals are
  raised after their handlers (no `__context__` retains parser/reader errors or
  bytes); 8 new host cases, full suite 7,160 passed; native reruns not repeated.

- **2026-10-08 — Windows dedicated custody checked-file candidate (C5a).**
  Revision `b4793e7d3` passed **51 tests with 11 POSIX-only fault-injection
  skips** in both ordinary-user Server 2025 / Python 3.11.17 source and fresh
  sdist-derived wheel environments. Selectors:
  `tests/test_windows_custody.py tests/test_windows_custody_profile.py`.
  These runs use real Windows checked files and real MRKW cryptography with
  an injected native-key backend; they do **not** establish actual CNG enrollment
  or deletion. All profiles are disposable and imported origins were checked.
  Wheel SHA-256: `32298344357c81e279a0d66668b4f392170f6e583613feb7379949fae98345be`.

  Core and scoped R1 independent reviews approved. Host full regression before
  the narrow R1 correction: 6,060 passed, 126 skipped, 38 excluded. Final focused
  checks: 62 passed, one native-only skip; reduced-extras types, lint/format,
  shellcheck and docs passed. R1 validates malformed journal field types and
  prevents pytest from rendering native key operands in live-test failures.

  Real CNG validation is pending the C5c ordinary-user process-inventory gate:
  protected foreign process token access is denied on this machine. The gate
  remains strict; no native-key live test or fixture was run as a workaround.
  The managed installation image prerequisite and supported-runtime boundary
  are tracked in shared contract PR #195. Memory hooks, installed-runtime proof,
  encrypted audit/Telegram consumers, wizard flows and Windows 11 are separate
  unfinished gates. The component PR remains a draft until native custody
  acceptance is complete.

- **2026-10-08 — Windows wizard canonical writers (C3).**
  Final code/tests `d6cfc519223096680005684d253e2fc6fcd0a6ee` passed
  ordinary-user Server 2025 source and fresh sdist-derived wheel suites:
  **147 passed each**. Native cases include configure rerun, concurrent config
  and dotenv edits, crash/recovery, checked private credentials/backups,
  no-overwrite collisions, busy custom destinations and hostile ACL/hardlink
  refusal. The wheel SHA-256 was
  `930c4c81db439f274fb041bc4727d4fca378e3d74475515d6c82c8e5006bd26a`.
  Both module origins were checked; wheel tests borrowed only test dependencies
  from the unchanged earlier validation environment.
  A separate full Hermes 0.19.0 environment installed the final candidate wheel,
  created a fresh home through Hermes itself, and ran the actual console
  `configure --non-interactive --policy strict` twice. The checked policy was
  strict, config/policy contents remained unchanged on rerun and the parent's
  ACL was preserved. No account/provider calls or production home were used.

  Independent review found two Important defects: lost child publication
  uncertainty during a second cleanup failure, and stale interactive provider
  overrides. Both reproduced and were fixed at `08ec8a76b`; scoped review
  approved the fixes. Final targeted regression: 346 passed, eight native skips;
  strict reduced-extras mypy (209 files), Ruff/format, shellcheck and docs links
  passed. The earlier full host suite was 5,757 passed, 105 skipped, 37 excluded;
  final narrow fixes have the focused and native evidence above.
  Initial native testing completed 139 checks with two setup/teardown errors
  because an 8 MiB pytest parameter ID exceeded Windows' environment limit.
  Short IDs fixed only the harness. The resulting 67 MiB diagnostic log also
  made line-based PowerShell tailing expensive; bounded recovery confirmed the
  test process had finished. Only those task-owned log readers were stopped.
  Evidence: `~/.codex/artifacts/mordred-windows-completion-20261008/c3-*`.
  Memory/OpenClaw lifecycle, enforcement callers, Windows 11 and full-product
  acceptance remain separate; legacy generic Windows writers still refuse.

- **2026-10-08 — Windows custody coordination prerequisites (C5 shared).**
  Code `c6d2e8ab767d26df408aae3ca7091f55634fbcb0` passed ordinary-user
  Server 2025 source and fresh sdist-derived wheel runs: **503 passed,
  54 skipped each**. Native cases include inherited-safe confidential inventory,
  canonical SID, bounded enumeration, protected transaction loans, child
  publication receipts, process/lifetime refusal and borrowed C7a audit sessions.
  The subsequent four-line checked-home identity accessor at `ff4edbbc2` passed
  six focused cases in its fresh sdist-derived wheel, including native case-alias
  identity (113 unrelated cases deselected). Both module origins were verified.
  The final wheel SHA-256 was
  `1ba8409d02a8550a866325e314814ce5bd9b6d99dda040e41a9fde0648f8e412`.
  Independent original and accessor reviews found no actionable findings.
  Host full regression before the accessor: 5,895 passed, 106 skipped,
  37 integration deselected; final accessor focused host checks and strict
  reduced-extras mypy (210 files), Ruff/format and shellcheck passed.
  Evidence: `~/.codex/artifacts/mordred-windows-completion-20261008/c5-foundation-*`.
  Custody providers, memory hooks, Windows 11 and full-product use are separate
  gates. These tests do not provision or recover a TPM role key.

- **2026-10-08 — First keyvault Windows caller: wallet selection storage.**
  Component contract PR #193 follows the shared contract/foundation PRs
  #191/#192. The implementation at `e05034f63` migrates only the keyvault-owned
  wallet selection document; `be87acf06` fixes Windows pytest IDs and extends
  cleanup-error coverage. Signing, key custody, memory/reset/purge, audit,
  installer and Desktop support remain separate, incomplete gates.

  Reused `i-00f4db5c3a204906b` in `ap-southeast-1`; verified it stopped before
  startup and armed a two-hour controller stop deadline plus a Windows scheduled
  shutdown. Tests ran as the credentialed, non-administrator `mordred` user on
  Server 2025, Python 3.11.17, fixed local NTFS, using new synthetic paths.
  Neither TPM fixtures nor Linux validation resources were changed.

  Final source and out-of-checkout wheel suites each produced **121 passed,
  2 POSIX-fork skips** across the wallet suite and four shared filesystem/process
  test modules (the POSIX-only module was not selected). The wheel was built
  from the sdist and installed without dependencies into a fresh venv, with
  pytest installed separately. Its imported module was under
  `C:\Users\mordred.000\wallet-wheel-20261008\venv\Lib\site-packages`;
  SHA-256: `6871af48f413c7270962705b3127e5c0138d1bd90f2d63a166b5cae4f5ee5b3e`.
  The source run used the separate `wallet-validation-20261008` tree.

  Native cases prove ACL/junction/hard-link refusal without repair, read/write
  process exclusion, bounded file reads, and pre/post-publication error handling.
  Synthetic selection survived a fresh process and a Windows reboot with SHA-256
  `34fee0fee72b07ef4640a7638737e5d20c72aa7bd74d6ee688aa23f9e6a8ea5f`.
  A separate ordinary account was denied access; its temporary account, task and
  logon rights were removed. This slice did not repeat EC2 stop/start persistence,
  sudden power-loss testing, TPM operations, Windows 11 or whole-product flows.

  The initial source/wheel runs each had **117 passed, 2 skips, 2 setup/teardown
  errors**: pytest expanded a 1 MiB parameter into `PYTEST_CURRENT_TEST`, exceeding
  Windows' 32767-character environment limit. Short explicit parameter IDs fixed
  the harness; no product-code change was needed. Independent review found no
  product defect, confirmed that harness issue and suggested the additional
  absent-wallet transaction-cleanup regression, which now passes.
  Final local Python 3.13 full regression: **5,362 passed, 45 skipped,
  34 integration deselected; 88.48% coverage**. Five warnings came from the
  existing FastAPI/Starlette, Hermes escape-sequence and POSIX fork checks.
  Ruff/format, reduced-extras strict mypy (206 files), shellcheck and all
  12 documentation-link tests passed. The final hosted CI results are tracked
  on the component PR; local/native acceptance does not replace that matrix.
  The host was verified stopped after acceptance; both task-specific automatic
  stop mechanisms were disarmed. Its retained disk and synthetic wallet remain.
  Evidence is retained under `~/.codex/artifacts/mordred-windows-wallet-20261008/`.
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

- **2026-10-08 — Canonical Windows configuration coordination (C2).**
  Code `c5d4e871c9b9b1846c95b1c22a2876179fa7f47e` passed ordinary-user
  Server 2025 source and fresh sdist-derived wheel suites: **357 passed,
  54 skipped** each. Skips are POSIX-specific or require an elevated owner
  fixture. The wheel environment installed only pytest and ruamel.yaml for
  these shared-boundary tests; this is not a full product dependency smoke.
  Native cases include inherited-descriptor no-op preservation, case aliases,
  fresh-process busy refusal, and a killed writer between config/policy members
  retaining a pending marker until explicit reconciliation. Wheel import origin
  was verified inside its new virtual environment.
  Independent review findings on caught uncertainty, nested nonblocking scope
  extension and custom config-name bypass were fixed and scoped re-review passed.
  Full host regression before the final narrow nested-cleanup guard: 5,603 passed,
  63 skipped, 35 deselected; final complete focused suite: 111 passed, three
  native skips. Ruff/format, reduced-extras strict mypy, shellcheck and docs checks
  passed. Evidence: `~/.codex/artifacts/mordred-windows-completion-20261008/c2-*`.
  Canonical wizard writer adoption, enforcement decisions/caches, Windows 11 and
  installation-to-normal-use remain separate component gates.

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

- **2026-10-08 — Windows private filesystem assumptions (WF0).**
  Retained Server 2025 build 26100 on fixed local NTFS was resumed with a
  four-hour shutdown deadline. Under the credentialed non-administrator
  `mordred` token, create-time protected user/SYSTEM/Administrators DACLs were
  observed independently through Get-Acl. A disposable second ordinary user
  was denied access. Its first scheduled runs failed with logon error 1385;
  granting only that disposable SID SeBatchLogonRight enabled the actual check.
  The test account, task and granted right were removed afterward. No existing
  user's password, TPM fixture or Linux validation resource was changed.

  SDK 26100/MSVC confirmed x64 FILE_RENAME_INFO size 24/name offset 20,
  OVERLAPPED size 32 and FILE_ID_INFO size 24. Relative-name publication with a
  non-NULL RootDirectory failed with WinError 87. A NULL RootDirectory and
  NUL-terminated absolute volume-GUID destination derived from the pinned
  directory succeeded, including flush and complete payload reopen. A separate
  unterminated disposable buffer produced a wrongly suffixed filename; production
  tests must pin termination, byte length and non-ASCII names. Held-target
  publication returned access denied without changing old bytes; renaming a
  pinned parent returned sharing violation. Real subprocess byte locks excluded
  a second process and released after owner termination. OPEN_REPARSE_POINT
  inspection identified an actual junction tag without following it.

  Default volume/profile ancestor descriptors were recorded without modifying
  them. These are disposable native API probes, not a shipped-foundation pass;
  production ACL parser, all-path refusal, failure injection, wheel, scoped CI
  and restart persistence acceptance belong to WF2–WF5 in PR #192. Evidence is private under
  `~/.codex/artifacts/mordred-windows-filesystem-20261008/`. Compute was retained
  within the deadline while implementation continued; final stopped-host evidence
  is recorded in foundation PR #192.

- **2026-10-08 — Native Windows installer and owned TPM helper (C4).**
  Code `f9c15a72ac060486e14f08f730e1021843a6a330` passed ordinary-user
  Windows Server 2025 source-editable and isolated sdist-derived wheel tests:
  **91 passed each**. Both module origins were verified. The source harness
  initially ordered borrowed dependency paths ahead of the editable checkout;
  fixing only that task-local `.pth` order restored the intended source import.
  The exact wheel SHA-256 was
  `d53a23698c0d6f5a20571d67015e7553254b434e1d6494f6acbe45707cf2d4e2`.
  Tests include PowerShell 5.1/7.6.6 environment selection, Unicode owned
  launchers, restricted-parent helper launch, retained unknown destinations,
  and bounded public Cargo-source reads with hardlink/ACL/identity checks.
  The controller SSH stream was interrupted after completion; the retained
  native test log was independently recovered through SSM and showed 91 passed.

  A separate fresh environment installed Hermes 0.19.0 and real uv 0.12.23.
  Both PowerShell 5.1 installation and PowerShell 7.6.6 reinstall passed with
  verified module origins, console entry point and unchanged Hermes version.
  The installed wheel's packaged Rust sources built into a custom Unicode,
  space and metacharacter destination; owned publication and the actual
  current-user TPM hardware probe succeeded. Existing TPM fixtures and the
  released Hermes environment were not modified. Profiles were task-isolated.

  Native acceptance found and fixed UTF-8 child output, PowerShell 7.5+ empty
  environment-variable deletion, and Cargo release-output hardlinks. The
  public build-input capability permits checked read-only hardlinks without
  weakening private destination/receipt checks. Independent scoped reviews
  approved each fix. Configure/setup consumer migration, memory encryption,
  full-product use and Windows 11 remain separate acceptance gates.
  Final supported-host Python 3.13 all-extras unit suite passed (exit 0);
  focused shared/installer coverage was 443 passed, 95 native skips. Ruff,
  formatting, reduced-extras strict mypy (208 files), shellcheck and 12
  documentation-link checks passed.
  Evidence: `~/.codex/artifacts/mordred-windows-completion-20261008/c4-*`.

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
  ASCII JSON transports the default path without code-page corruption.
  The hosted Windows CI initially reproduced a PowerShell 7 -> Python -> 5.1
  module-path inheritance failure (`Get-FileHash` unavailable). The installer
  explicitly loads Utility/Management manifests from its own `$PSHOME`;
  the existing build tests cover that actual runner invocation. Windows PowerShell 5.1 requires `[NullString]::Value`
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
  second Windows reboot and EC2 stop/start.
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
  dependent plans.

  **Cleanup:** second instance `i-0d0f2c45787bedcee` terminated; AMI
  `ami-0d58a6979d00b69ff` deregistered and snapshot `snap-0cff25fd395bda4c2`
  deleted. Primary `i-00f4db5c3a204906b` is retained for subsequent porting,
  with CPU credits restored to standard and compute stopped after validation.
  Its encrypted 50 GiB gp3 volume remains (approximately USD 4.80/month at
  the recorded regional storage rate); the task-only SSM role/security group
  remain, with no inbound rules. Previous Linux validation resources were
  untouched. No production profiles or live Telegram/LLM accounts were used.

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

- **2026-10-18 — Linux and Windows Server maintenance validation (Windows acceptance failed).**
  Candidate `e2e9095087ea04e4d5865eff223fa292c5711425` used verified source
  and exact sdist-derived-wheel environments; Windows verified 117 dependencies
  and 297 static members.

  **Linux:** Ubuntu 24.04.5 LTS, Python 3.12.3, Hermes 0.19.0, actual
  AMZN NitroTPM. Final source: **7,735 passed, 285 skipped, 50 deselected;
  88.7161% coverage**, 8,018 runtime nodes reconciled. Earlier
  umask/missing-uv and ignored-SIGINT input failures remain recorded; baseline
  and signal controls justified umask 022, uv and normal-signal inputs without
  weakening guards/assertions.
  Controlled wheel: **1,355 passed, 11 failed, 25 skipped**; source-parent-only
  injected-proof restrictions remain; those nodes passed in source.
  No complete wheel pass is claimed. Actual TPM passed **two tests per
  environment**; Desktop/CLI probes completed **22 fresh-process steps**.
  Real-model doctor/`telegram_ask` passed **four plain/authenticated source/wheel
  gates**, including 401 then saved-key success. Owned native keys were cleaned,
  children/listeners cleared, **20,740 retained rows** matched; Linux stopped,
  original ingress restored, guard disarmed, failed fixtures preserved.

  **Windows Server 2025 Datacenter:** Python 3.11.17, Hermes 0.21.5. Native
  validation passed **eight stages and fourteen postflight checks**, including
  real CNG ceremonies. Global collection failed; **the same three errors
  reproduced with baseline test modules under the candidate runtime**.
  Frozen scoped source **109 modules / 3,556 nodes** completed FAILED:
  **3,172 passed, 204 failed, 41 errors, 139 skipped**. Its native84 subset
  (**2,704 nodes: 2,583 passed, one failed, 120 skipped**) retains the
  SYSTEM-created junction failure: its DACL lacks ordinary/Everyone read
  permission; actual ordinary opening returned `access_denied/open/native5`
  before metadata. No repair/retry; native acceptance remains failed.
  Original wheel: **1,217 passed, 195 failed, 76 errors, 35 skipped**;
  recovery: **139 passed, 11 failed**. Baseline reproduced two exception
  defects: status crashing with blocked cryptography and malformed-config
  `ParserError`.

  Extension API's eight findings are two Slack routing, two POSIX-mode and
  four WebAuthn/history missing-file failures; four isolated candidate/baseline
  HTTP passes cover only the Slack nodes. Combined source LLM's **nine
  memory-guard failures remain unresolved**. Fresh LLM **eight passed/one
  baseline failure** reports an authenticated-CLI missing helper/profile
  custody-key refusal. Source Telegram TEE has one unresolved
  `MemoryEncryptionRequired` direct-loopback failure beyond the wheel's
  nineteen; fresh LLM observation did not cover it.
  Ordinary audit: **67 roots, 1,633 selected hashes unchanged**, same two
  historical errors. Intermediate pytest-temp preservation is not guaranteed.
  Four recorded native custody states were empty after purge. No ordinary-SID
  process remained; only the exact observer/launcher were found. PID0/Registry
  metadata gaps and 86 historical process owners remain unknown. The owned
  fixture/shutdown task were removed; SSM forwarding ended; both tested hosts and the shared-group
  instance were independently confirmed stopped at **03:06:51Z**; the Windows
  guard was then disarmed.
  No Windows global/product, Windows 11 or whole-product acceptance is claimed.

- **2026-10-23 — Desktop mail and ceremony pages (run by the owner with the
  Fable session, production profile, macOS 27.0.1, Hermes Desktop git install
  v0.21.4+canary…df81f543f (workspace build reported as 0.0.0), Python 3.14.7,
  Mordred 0.3.0a4 from `feat/desktop-mail-ceremonies` at 7f8d6d462 installed with
  `scripts/install.sh --from-source`).** Counts and codes only.
  1. Overview: PASS after one fix. The databases step first said "needs
     attention" because the Xcode build cache of `keyvault enable-se`
     (`_native/sekey-helper/.build/.../build.db`) was classified as a plaintext
     database (TODO "Native helper build cache"); after deleting the three
     `.build` copies the overview read model private, Secure Enclave, vault,
     memory encrypted, databases on, Telegram 3 chats / 25 messages, mail account
     `work` / 100 messages.
  2. Mail setup from the page: not run (the mailbox had been set up from the CLI
     in the morning; the wrong-password hint was not exercised live).
  3. Fetch new mail: PASS after two fixes. The first attempts failed in
     milliseconds with `imap_unreachable` only inside Hermes (the CLI dry run
     succeeded): Hermes injects `truststore` into every `ssl.SSLContext`, whose
     `wrap_socket` verifies the chain before our manual handshake (fixed in
     621f009fa and 7f8d6d462, SPEC "TLS handshake placement"); content-free
     connection diagnostics were added on the way (fd3efbde7, 9b67a1d7d,
     7f62b9343, 4d31e64ad). Then: Touch ID prompt, `mailboxes 1`, `fetched 0`,
     `inserted 0` (nothing new since the morning), `mail status` agrees
     (`last fetch … (complete)`).
  4. Chat: PASS. "sync my mail" (second attempt; the first was cut short by the
     Venice stream closing early) reached `mordred_mail_sync` through the
     deferred-tool bridge and returned counts only; a history question was
     answered through `mordred_history_search` (audit `policy.egress.reader_mode`
     allow); "save this note to a file" was refused (`write_file` blocked,
     `egress.reader_locked`). One turn took about 43 s, of which Mordred's part
     was about 6 s; the rest was the Venice model and the bridge round trip
     (follow-up: the direct-tools option, PR D5).
  5. Remove the mailbox: not run.
  6. Throwaway-home databases step: not run.
  7. Light/dark and VoiceOver: not run.
  Other findings, each recorded in TODO: Hermes Desktop rebuilds its environment
  at every restart and deleted the venv the `hermes-mordred` launcher pointed at
  ("Stale `hermes-mordred` launcher…"); the previous attempt's failure note stays
  visible while a new fetch runs (fixed on the branch); a chat started before a
  protection problem was resolved keeps repeating the old warning because Hermes
  freezes plugin prompt sections at session start ("Stale protection notice…").

- **2026-10-24 — Cross-platform database P1 Windows VFS feasibility passed.**
  Candidate `0365ee8dcd21a8caabadbafb534bdc842862f0e2` ran on the existing
  Windows Server 2025 x64 host as a new credentialed, non-elevated batch user
  with its own loaded profile. Python 3.11.16, `sqlcipher3-wheels==0.5.7`,
  SQLite 3.51.1, SQLCipher 4.12.0 community and MSVC 19.44.35229.0 were recorded.
  Source and a fresh sdist-built installed wheel outside the checkout each
  passed **29 unit tests and four native tests**, with two explained unit
  skips: ordinary-user symlink creation lacked privilege; the detached-process
  supervisor harness is POSIX-only and passed on the controller host.

  Both environments proved same-library extension loading, bootstrap-close
  persistence, encrypted rollback/WAL and Japanese trigram FTS, keyless refusal,
  observed `xOpen/xDelete/xShmMap/xShmUnmap`, and a denied SHM write without
  delegation or committed rows. Three subprocess cases also verified that
  a reserved-name collision during initialization leaves no callbacks or
  VFS on bootstrap/later connections. DLL SHA-256:
  `5ecf615e6bd6b7a828b15a61b1bf3b3f35c947d24f26fe568351b8f1d765fee9`.
  Installed driver PYDs matched the hash-verified upstream wheel. The private
  final evidence archive SHA-256 is
  `be2b50f7df6724c1a5c1b497d636589da1373a45d72cb9333b20fda33c2912e5`.

  Astra's whole-branch review found four Important defects. RED-to-GREEN
  regressions cover uncertain starts, evidence-write failure, partial C
  registration, and competing receipts/stale EC2 describes. The controller
  retains uncertain starts, cleans up despite failed evidence writes, and uses
  canonical per-instance admission across receipts. Its supported deployment
  is one awake/connected controller host and OS identity; an unresolved AWS
  result keeps its guard beyond the requested stop deadline until settlement.

  Cleanup removed the owned user, task, profile, stage and explicit batch-logon
  rights. A cold boot was needed after Windows retained the test profile;
  no ordinary test process remained. Each run used a separate frozen guard and
  receipt; the final controller stop/verify and independent EC2 query confirmed
  both retained hosts stopped. Linux was not started. This is diagnostic
  feasibility; production checked-filesystem, custody, consumer and Desktop
  acceptance remain gated by the later implementation tasks.


- **2026-11-03 — Bounded macOS presence reuse: automatic candidate validation; attended acceptance pending.**
  Production implementation at `3d0c947c1`, on the isolated
  `feat/presence-reuse` worktree, was checked with Python 3.13.12 and the
  repository editable source (not the released Hermes venv). The coverage run
  completed with **14,432 passed, 295 skipped, 170 deselected and one environment
  failure**; coverage was **91.44%** (55,530 / 60,726 statements), exceeding the
  80% floor. The single failure was the member-wheel bootstrap test: stdlib
  `venv.EnvBuilder` copied uv's managed Python executable without its relative
  `libpython3.13.dylib`. The interpreter failed before wheel installation or any
  Mordred bootstrap could run. Re-running the **entire containing module** with
  `DYLD_LIBRARY_PATH` set to `sys.base_prefix + "/lib"` produced **66 passed,
  one skipped**. No production or test implementation was changed for that
  environment correction. This is not a claim that the initial full command
  was entirely green.

  The final critical preset passed **24 tests**; the profile/cancellation and
  affected host security set passed **354 tests**. Ruff check and format,
  strict mypy over **409 files**, both import-layer contracts, and ShellCheck
  passed. Strict mypy also passed in a separate Python 3.13 environment
  installed with only `dev,keyvault,extension,macos` extras. `swift test
  --package-path native/sekey-helper` passed **four tests** covering fixed
  deadlines, revocation, denial and one authentication decision with fresh
  exchanges. Credential tests used real custody, wrapping and AES operations
  with native IPC faked; ordinary and HD wallet tests verified two decrypts
  and rejection before the signing primitive when the signer changes.

  A fresh read-only branch review identified two mail cancellation defects;
  both were reproduced and fixed before worker drain. Additional regression
  tests cover late capability completion, cancellation after a setting change,
  independent monitor threads with request-scoped profiles, and invalidating
  pending old-profile operations. Profile validation binds only the framework
  profile selector in a fresh context, rather than retaining request secrets.

  A signed candidate was built only at
  `/tmp/mordred-presence-candidate.gR3e6k/bin/mordred-hermes-sekey`, SHA-256
  `2457510ac9099f1876d73292c8d090316d1f99638317ad34fc93413197419e35`.
  Its prompt-free capability command reported `presence_session: 1`.
  The explicit integration invocation of `test_presence_macos.py` and
  `test_keyvault_macos.py` collected **10 skipped tests**, with live gates unset.
  Actual Touch ID counts, 300-second reauthentication, lock/sleep notifications,
  denial UI and independent ordinary/HD signing prompts are **not validated**.
  The attended driver and commands are in `native/sekey-helper/README.md`.

  Decisions retained: unverifiable Desktop authentication generations (including
  gated OAuth and isolated ASGI hosts) use one-shot authorization; a nonzero
  opt-in requests OS presence even for an unattended key, without changing its
  stored ACL. Zero preserves unattended reads. Contract documents preceded
  foundation and caller-path implementation commits; no upstream PR or
  production integration was performed. **Reuse remains disabled by default
  (0); no production profile, key, installed helper or gateway was changed.**

  The initial Python 3.14.7 full run also exposed existing Windows-simulation
  `_winapi` imports and IMAP streaming incompatibilities. Representative failures
  reproduced against baseline `3db560f1d`; all **240** suspect module tests
  passed under Python 3.13. No unrelated runtime fixes were included.
  Local evidence: `/tmp/mordred-presence-verified-regression.log`,
  `/tmp/mordred-presence-verified-junit.xml`,
  `/tmp/mordred-presence-verified-coverage.xml`,
  `/tmp/mordred-member-verified.log`, `/tmp/mordred-final-profile-static.log`,
  `/tmp/mordred-swift-acceptance.log` and `/tmp/mordred-live-gates-final.log`.

- **2026-11-03 — Windows database namespace refusal (host verification only).**
  Lexical refusal was exercised on macOS with simulated Windows policy, before
  target-path absolutization, existence/metadata lookup, binding and SQL open,
  and for backup, restore, export and registered-backup paths before any
  filesystem call.
  `uv run pytest -q tests/test_dbcrypt_windows_paths.py
  tests/test_dbcrypt_connections.py tests/test_dbcrypt_windows_routing.py
  tests/test_dbcrypt_windows_admission.py` passed (312 cases); the legacy
  `tests/test_dbcrypt.py` module also passed (44 cases). No native Windows
  environment was available, so there was no native run:
  `tests/test_dbcrypt_windows_native_paths.py` skipped all 5 cases on macOS.
  Explicit invocation with `-m integration` of
  `tests/integration/test_dbcrypt_windows_vfs.py` and
  `tests/integration/test_dbcrypt_windows_vfs_probe.py` skipped all 90 cases on
  macOS; these skips establish no acceptance.
  Native Windows local-database and `:memory:` regressions remain required.

- **2026-11-04 — Windows database namespace refusal (native Windows Server).**
  Source: `fix/dbcrypt-windows-remote-paths` at `37551b489`, compared with `dev`
  at `78ff87c44`. Host: AWS EC2, `ServerDatacenter`, build 26100, as an ordinary
  medium-integrity user; Python 3.11.17, `hermes-agent` 0.19.0,
  `sqlcipher3-wheels` 0.5.7, with a software CNG double in the module fixtures.
  The first attempt was discarded because the run script had not created the
  `--basetemp` parent directory; results below are from the corrected run.

  | Suite | Branch | `dev` |
  |---|---|---|
  | `tests/test_dbcrypt_windows_native_paths.py` | 5 passed, 0 skipped | not present |
  | Windows path, locking, capability, connection, routing and admission modules | 265 passed, 16 skipped, 1 failed, 110 errors | 162 passed, 8 skipped, 1 failed, 110 errors |
  | `tests/integration/test_dbcrypt_windows_vfs.py`, `-Target CheckedTest` | 83 passed, 3 failed | 83 passed, 3 failed |
  | Same module, packaged DLL, documented non-injection `-k` filter | 38 passed, 3 failed | 38 passed, 3 failed |
  | `tests/integration/test_dbcrypt_windows_vfs_probe.py` | 4 passed | not run |

  Every failing test ID on the branch also fails on `dev`. The 110 errors come
  from a POSIX-custody fixture and the 1 failure needs the symlink privilege,
  which the ordinary user lacks. The 3 VFS failures on each row are
  `test_native_non_ntfs_root_refuses` and
  `test_native_file_reparse_refuses_before_data_open`, which need the owned
  exFAT/reparse fixture manifest. That fixture was not provisioned, so **those 3
  cases establish nothing and the full native VFS gate remains unmet.**
  A scratch module, not in the repository, passed 9 cases: seven more UNC, device
  and `file:` spellings refused, a `:memory:` and local-file round trip with the
  marker absent from the raw file and unreadable through plain `sqlite3`, and
  `backup_database` refused a UNC source, a UNC destination and an extended-length source.
  Refusal order is observed in-process; no SMB traffic capture was taken.
  User key inventories were unchanged and the instance ended `stopped`.

- **2026-11-05 — Coordinated local keyvault reset.** Contract draft
  [PR #299](https://github.com/mordredagent/hermes-mordred/pull/299) precedes
  component commits `b0ce34bab` (keyvault), `2a4c2be9e` (imports),
  `7da872f9d` (Telegram), `ca8e33133` (wizard), and `9928ffe8f` (verification).
  Reset now journals its scope before deletion, erases all current-profile
  Mail/Telegram accounts in one SQLCipher maintenance transaction outside
  custody, authenticates component retirement, and removes only known owned
  keyvault files. Independent helper material, memory/database sources, other
  profiles, unrelated history, imported originals and backups remain intact.

  macOS **26.6.2 / 25G83**, Python **3.11.15**, real installed Secure Enclave
  helper `~/.local/bin/mordred-hermes-sekey`, SHA-256
  `076beba85cf1310932ebba7e124ada75f08d11132604c9725f17c4e21e345642`:
  `MORDRED_RESET_NATIVE_TEST=1 MORDRED_RESET_TEST_ROOT=<private synthetic root>
  MORDRED_SEKEY_HELPER=<explicit helper> uv run pytest -m integration -s
  tests/integration/test_keyvault_connected_reset_native.py` passed **1 test**,
  exercising two complete provision/reset cycles of a scoped main key and its
  encrypted envelope, Mail and Telegram credentials, and retained independent
  helper material. The credentials were synthetic and unattended; no mail or
  Telegram account connection, remote logout or production-home access occurred.
  The successful retained fixture is
  `/private/tmp/mordred-reset-native.JGbeQD/connected-reset-62df0c2b6f0e42d5885abec95a2bf33d`.
  Earlier failed synthetic fixtures remain available for diagnosis.

  SQLCipher erasure tests use the real encrypted driver with synthetic native
  custody, including historical accounts, messages, parts, references, FTS,
  cursors, unrelated data, a mid-transaction SQL failure, and retained native
  database/memory source bytes. Backup recovery after selective reset also
  passed with an independent helper file and the original backup unchanged.
  This is separate from real macOS database-source hardware qualification.
  Linux hardware acceptance remains **pending** on this macOS host:
  `uv run pytest -m integration tests/integration/test_linux_telegram_tpm.py`
  reported **2 skipped**. The new native reset test also supports an explicit
  Linux TPM helper on a retained synthetic root. Windows secret-store reset
  remains unported and its early-refusal tests pass.

  Final default regression (`uv run pytest -n 4 --dist=worksteal
  --max-worker-restart=0`) ran all **15,016 selected cases**: **14,715 passed,
  300 skipped**, with one documentation portability check failing because this
  log initially embedded a developer-specific helper path. The helper path was
  changed to `~/.local/bin/...`; the complete documentation-link module then
  passed **12 tests**, including the failing
  `test_maintained_docs_do_not_embed_a_developer_home_path`. No runtime code
  changed after that full regression; the repository's documentation-only
  validation policy applies to this final correction.
  Ruff check/format (**892 files**), strict mypy (**419 source files**), both
  import-layer contracts and shellcheck passed. Strict mypy also passed in an
  isolated CI-extras environment (`dev,keyvault,extension,macos`). The critical
  preset passed **24 tests**; independent reset consumers passed **198 tests**.
  The coverage run reached **91.67%** (80% floor). It caught one obsolete
  expectation that the keyvault directory must remain after a source-only
  binding is retained; that assertion was corrected to check source/native-key
  preservation and the complete containing modules then passed. The final
  regression includes the corrected test and additional rollback/recovery
  cases. A preliminary serial run was interrupted after **1,539 passed** when
  related tests still asserted the intentionally removed blanket DB/memory
  refusal. Those tests now verify preservation. Python 3.14's existing
  `test_mail_imap_sync.py::test_an_under_reported_message_is_drained_and_counted`
  failed and reproduced independently; the same test passed on repository
  Python 3.11, used for final acceptance.

  A fresh read-only review found two Important recovery issues, both reproduced
  RED then fixed: backend initialization must finish before recording uncertain
  native deletion, and v2 scope checks must exclude already-authorized main-key
  blobs. No Critical or Minor findings remained. Review decisions: uncertain
  actual native calls keep their intent for manual reconciliation; v2 recovery
  conservatively refuses existing component directories/databases rather than
  assuming broader consent; same-UID adversarial edits remain outside the
  existing cooperative-lock threat model; legacy archive ownership follows
  Telegram's existing checked wipe; unavailable Linux/Python 3.14 acceptance is
  not claimed. Their costs are respectively manual repair, conservative refusal
  even for empty stores, no additional same-UID security guarantee, retaining
  files outside the known archive contract, and unverified platform coverage.
  Component commits remain on a stacked implementation branch so the contract
  and component changes can be reviewed separately, at the cost of splitting
  dependent implementation PRs before integration.

  Evidence:
  `~/.codex/artifacts/mordred-connected-reset-20261105-9928ffe8/`.

- **2026-11-05 — Installed coordinated reset verification.** Built the
  `0.3.0a5` wheel from local integration commit `7c274593b` and replaced the
  installed `0.3.0a3` PM member, preserving the recorded
  `extension,keyvault,macos,telegram` extras. Rebuilt the selected environment
  with `hermes pm install venv`; the installed reset modules matched the source
  bytes. Repaired the stale standalone launcher to resolve PM's committed
  environment at startup. The existing legacy database marker needed private
  permissions and authenticated adoption through `databases encrypt`, which
  reported **0 databases converted**. Hermes and Mordred version commands,
  plugin listing (`mordred` enabled), passive status and authenticated database
  diagnosis passed on the installed Python **3.14.7** runtime.

  Preloading the installed package into the repository Python **3.11.15** test
  runner, the complete keyvault-reset, connected-reset and Windows-refusal
  modules passed **73 tests**. The explicit real Secure Enclave helper suite
  passed **1 test**, including two provision/reset cycles, against a retained
  private synthetic home. The critical preset passed **24 tests** before
  deployment. No production keyvault reset or account retirement was run.
  This does not extend the earlier Linux or full Python 3.14 acceptance claims.

- **2026-11-05 — E2E standalone tool/cron sender guard: automated candidate verification; live browser gate pending.**
  Candidate branch `fix/e2e-standalone-senders` protects Hermes's common
  `_send_to_platform` seam without changing Hermes, the extension or the v3
  protocol. Actual tool/cron delivery is exercised with destination I/O replaced;
  captured ciphertext is decrypted with the observed channel/thread context.
  The initial regressions exposed plaintext tool and cron-fallback delivery.
  Independent review found a `DISCORD_PROXY` regression; a real-resolver
  regression failed before the platform override was carried through the shared
  Tor/VPN route validation, then passed after the correction.

  Locked Hermes 0.19.0: **66 standalone cases passed**, and **289 containing
  module cases passed** (including the final routing correction). The extension
  suite before that routing correction passed **1,775 tests, 12 skipped**; the
  final full runs include the correction. Hermes 0.13.0 / Python 3.11.15:
  **286 containing cases passed, 3 skipped** (the floor tool lacks Slack thread
  target parsing; real cron origin-thread coverage passes, and two existing
  Telegram cases require the optional Telethon dependency). Critical preset:
  **24 passed**. Docs/CI-scope checks: **74 passed**. Plugin/import checks:
  **17 passed**. Ruff, formatting, strict mypy (**416 files** in both the locked
  and floor environments), import-layer contracts and shellcheck passed. The
  floor typing environment uses dev/keyvault/extension plus FastAPI, which old
  Hermes does not install; ethereum and tor-control extras are absent.

  Final locked-version regression on Python 3.11.15 completed with **14,752
  passed, 300 skipped, 170 deselected, 2 failed** in 747.23 seconds. The two
  failures were:

  - `tests/extension/test_activity_api.py::test_extension_batch_ack_reaches_receiver_with_extension_principal`:
    its five-second WebSocket pairing wait timed out. The containing module and
    focused full-collection selections passed on rerun.
  - `tests/extension/test_pm_member.py::test_health_reports_version_environment_and_member`:
    the temporary venv's `/tmp` prefix differed from the resolved `/private/tmp`
    health response. Running through the canonical `/private/tmp` interpreter
    path resolves the assertion. Both exact failed cases then passed together
    (**2 passed**, 0.48 seconds). This is rerun evidence, not a clean single
    full-suite result.

  The initial uv-selected Python 3.14.7 full regression completed with **14,734
  passed, 300 skipped, 170 deselected, 20 failed** in 769.35 seconds. Those
  failures are in unchanged `test_dbcrypt_lifecycle.py` (2),
  `test_mail_imap_client.py` (15) and `test_mail_imap_sync.py` (3). The database
  Windows-platform simulation imports unavailable `_winapi`, and IMAP's literal
  drain uses Python 3.14's unsupported `IMAP4.file` interface. Representative
  failures `test_native_platform_missing_prerequisites_refuses_before_sql_or_auth[False-win32]`
  and `test_a_literal_over_25_mib_that_fits_is_drained_unread` reproduce on the
  original `dev` checkout under the same 3.14 interpreter. All three containing
  modules pass on Python 3.11 (**240 passed**). These other-component
  compatibility issues are not changed in this E2E candidate.

  Evidence: `~/.codex/artifacts/mordred-e2e-standalone-20261105/`, including source
  hashes, red/green logs, both full JUnit reports, exact failure-name JSON files,
  baseline reproduction and focused rerun logs. **Live Slack/Discord
  browser-extension decryption was not run:** no explicitly authorized test
  destinations were supplied. Before release, run that check on authorized
  channels/threads and append the live result. Automated crypto round trips do
  not establish browser acceptance. Live-adapter edit/media/prompt methods
  remain outside this change.
