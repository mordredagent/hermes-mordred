# Codex third-pass review: Desktop mail and ceremony pages (PR #262, 2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run by the Fable session against commit 3c7ad09d2 (integration branch feat/desktop-mail-ceremonies). Verdict REVISE (1 HIGH, 4 MEDIUM, 3 LOW); the API split, the Windows byte-identity and the Telegram read path passed. All earlier D2/D3/D4 findings are RESOLVED except D2 5/6 and D3 1 (PARTIAL, re-fixed on PR #262). Absolute links were flattened to `path:line` text.


Reviewed HEAD `3c7ad09d2`, including `acf6b0dc5...HEAD` and the requested earlier findings. **REVISE:** the split is sound, but credential retention, incomplete cleanup, WAL safety, and two page lifecycle issues remain.

## Earlier findings

“RESOLVED” refers to the original finding; separate remaining defects appear below.

| ID | Status | Evidence |
|---|---|---|
| D4 API 1 | **RESOLVED** | imports/store.py:1603 opens SQLCipher directly with captured, validated environment-derived key material, bypassing the shim’s provider. |
| D4 API 2 | **RESOLVED** | desktop/_vault.py:304 diagnoses a clean-directory stale anchor before entering the migratory wizard; a concurrent-creation false positive remains below. |
| D4 API 3 | **RESOLVED** | telegram/tee.py:344 reads flags through the non-creating path, including the store reached by `run_checks()`. |
| D4 API 4 | **RESOLVED** | desktop/_vault.py:195 preserves `unknown` when a legacy anchor accompanies an unreadable helper, suppressing the deletion remedy. |
| D4 API 5 | **RESOLVED** | desktop/_vault.py:344 checks vault existence, enrollment, injection and opt-out before returning `already`. |
| D4 API 6 | **RESOLVED** | SPEC.md:5211 now explicitly permits unknown effective policy, matching `_vault.facts()` returning `unattended: null`. |
| D2 1 | **RESOLVED** | mail/imap.py:191 severs exception chains, and `:1062` clears retained protocol buffers; a distinct traceback-local password defect remains below. |
| D2 2 | **RESOLVED** | dbcrypt/_monitor.py:90 escapes the plaintext-probe URI, and the final SQLCipher URI is escaped too. |
| D2 3 | **RESOLVED** | mail/setup_flow.py:564 reserves starts before probing, while registration and sealing check cancellation under the same mutex used by cancellation. |
| D2 4 | **RESOLVED** | imports/store.py:1656 derives the key once and retains a direct SQLCipher opener for subsequent connections. |
| D2 5 | **PARTIAL** | imports/store.py:1696 checks only missing `-shm` at admission; later connections bypass this check. |
| D2 6 | **PARTIAL** | mail/setup_flow.py:728 bases successful cleanup on `residue()`, which excludes staged credential files. |
| D3 1 | **PARTIAL** | The original secret-submit rendering paths are sanitized, but plugin.js:1347 still interpolates arbitrary lowercase error tokens in split-memory retry text. |
| D3 2 | **RESOLVED** | plugin.js:613 invokes disclosure cleanup; Telegram cancels/resets and Venice clears its key. |
| D3 3 | **RESOLVED** | plugin.js:1846 preserves status-derived `attention` before transient import state. |
| D3 4 | **RESOLVED** | plugin.js:686 renders operation failures independently of the completed-step body. |
| D3 5 | **RESOLVED** | plugin.js:1113 excludes new ARIA markup from legacy mode; 20 Windows rendering scenarios matched the original source, allowing the prescribed color substitution. |

## New findings

1. **HIGH — A retained setup exception still retains the plaintext app password.**

   setup_flow.py:508 raises the sanitized exception from `start()`, whose `app_password` argument remains in that frame. Clearing the previous traceback does not prevent Python from attaching this new frame.

   An in-memory probe of the current methods confirmed absent cause/context **and** the password in the exported traceback’s locals. This is retained-object exposure; normal HTTP/log disclosure was not demonstrated.

   **Fix:** clear sensitive boundary locals before raising, and apply the same treatment to `ImapSession.login`. Retain the exception during the lifetime regression: test_mail_setup_flow.py:408 currently checks release only after the caught exception has been discarded.

2. **MEDIUM — The WAL no-creation guarantee still has an ordinary reopen race.**

   store.py:1696 checks only `-shm`. Furthermore, admission closes its connection, and store.py:633 opens a fresh connection for each operation without another sidecar guard. A writer closing between admission and `status()` can remove sidecars, allowing the subsequent read to recreate them.

   **Fix:** enforce no creation at the SQLite/VFS boundary for every connection, or use a proven connection-and-lock lifecycle preventing sidecar disappearance. Another `lstat` alone leaves a race; `immutable=1` is unsuitable for concurrent writes. Cover writer-close/reopen and missing-`wal`/present-`shm` cases with SQLCipher.

3. **MEDIUM — Staged credentials can survive while cancellation reports “nothing was stored.”**

   secrets.py:451 suppresses staged-file unlink failures. `residue()` examines only final files, so setup_flow.py:728 skips `forget()` and restores `pre_seal` when only staging files remain.

   Interruption before the first rename plus failed cleanup therefore leaves encrypted credentials and their key while the CLI gives the false cancellation assurance.

   **Fix:** account for all staging artifacts and invoke cleanup after a failed store attempt. Keep `cleanup_failed` until their absence is verified. Add the staged-only failure case; existing final-file cleanup tests do not cover it.

4. **MEDIUM — A late mail-setup response escapes cancellation after page departure.**

   Cleanup cancels only an already-known flow at plugin.js:2195. After awaiting `/mail/setup/start`, plugin.js:2257 assigns the returned flow without checking mount state or attempt validity.

   A start → unmount → late folder response produced no cancellation request. Its password and sole setup slot remain pending until expiry, potentially blocking another setup for approximately ten minutes.

   **Fix:** invalidate attempts on unmount/block and immediately cancel late returned flows. Test delayed responses, not only cleanup of an existing flow.

5. **MEDIUM — Completed Telegram imports leave v4 counts and completion state stale.**

   plugin.js:1775 polls `/sync` without refreshing store status on completion. `SetupPage.onSync` only changes sync state, and periodic status refresh requires registry jobs; Telegram sync is outside that registry.

   A controlled completion with nine imported messages produced zero status refreshes: counts remained zero and the step remained `next`.

   **Fix:** refresh store status on sync completion and include active Telegram imports in bounded count refreshes. Test the transition through the page.

6. **LOW — Concurrent CLI creation can be misdiagnosed as a stale anchor.**

   The clean-directory snapshot at desktop/_vault.py:304 can precede CLI creation, while the subsequent anchor read observes the completed live vault. The code then returns `vault_anchor_stale` without revalidating that diagnosis. An in-memory interleaving reproduced this.

   **Fix:** coordinate diagnosis with the existing vault lock and revalidate recoverable state after anchor reads, releasing the lock before entering the wizard. This reproduced false refusal, not clobbering; the normal initialization protections remain intact.

7. **LOW — Split-memory retry text bypasses the fixed-message boundary.**

   plugin.js:1347 renders `safeCode(failure.code)`, but `safeCode` validates syntax rather than membership. A controlled `secret_canary` error appears verbatim.

   **Fix:** use fixed wording or an explicit allowlist. No live backend-secret disclosure was established.

8. **LOW — The new status tripwire can be swallowed.**

   test_desktop_status_e2e.py:43 raises `AssertionError`, which broad production handlers such as desktop/_status_v4.py:55 catch. A forbidden call in vault-facts collection can therefore return the same fallback shape without failing these tests.

   **Fix:** record calls and assert zero afterward, or use a test failure exception that the production handlers cannot swallow. The successful-count assertions meaningfully cover the provider path, but not every installed tripwire.

The **API split passes inspection**: no `from .api import` aliases, route helpers resolve module attributes at call time, and relocated tests patch the corresponding `_seams` or maintenance attributes. No stale references to the removed seam locations were found. Guarded loading registered all 30 routes; the merged lifespan ran its reaper and cancelled flows exactly once. No import cycle or filesystem/native initialization was observed.

The Windows acknowledgement module, custody implementation and inspected Windows handlers are byte-identical. Windows v4 status changes only its section-helper invocation. JavaScript parsed, linked and evaluated against synthetic modules exposing the unchanged baseline SDK/React exports; the actual installed Desktop runtime was not exercised.

The **Telegram read-path change passes inspection**: missing storage returns “not configured”; writes retain directory creation, `0700` permissions and git-ignore handling; Windows dispatch remains unchanged. Old helpers report `unknown` without legacy migration, and diagnosis uses the same identity function as the CLI. The normal wizard retains its fail-closed anchor checks and locked initialization guard.

## Verdict

**REVISE.** Fix findings **1–5** before merging PR #262 into its stacked base. The split itself introduces no demonstrated route-linking, Windows acknowledgement or lifecycle-ownership blocker.

Review completed offline and read-only using source comparison and guarded in-memory probes. No files changed, prohibited paths or databases read, or pytest suites run.