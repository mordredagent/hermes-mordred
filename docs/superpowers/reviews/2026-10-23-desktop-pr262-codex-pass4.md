# Codex fourth-pass review: Desktop mail and ceremony pages (PR #262, 2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run against commit bdf658a09. Verdict REVISE on two remaining MEDIUM items (WAL admission race, Telegram imports finishing between polls); no new regressions. Both are fixed on PR #262: the status path now reads rollback-journal stores only (mordred.db is never put in WAL mode by Mordred), and the page refreshes after any page-started import that reaches idle.


Reviewed `bdf658a09`, limited to `4542858e0..HEAD` and the requested earlier findings. Source paths below are relative to `src/mordred_hermes/`; test paths are repository-relative.

## Third-pass findings

| Finding | Status | Evidence |
|---|---|---|
| 1 — Retained credentials | **RESOLVED** | `imports/mail/setup_flow.py:514` and `imports/mail/imap.py:1030` remove sensitive arguments before raising; retained-exception probes found no password/address/host canaries and confirmed password-object release. |
| 2 — WAL reopen race | **PARTIAL** | `imports/store.py:1649` reuses the admitted connection, eliminating subsequent reopenings, but the sidecar check at `:1739` remains separate from opening at `:1710`. |
| 3 — Staged credentials survive cleanup | **RESOLVED** | `imports/mail/secrets.py:489` includes staging artifacts and `imports/mail/setup_flow.py:750` always attempts cleanup; memory-backed probes verified successful removal and persistent `cleanup_failed` when removal fails. |
| 4 — Late setup response | **RESOLVED** | `desktop/assets/desktop/plugin.js:2277` cancels abandoned returned flows; six harness cases verified cancellation after unmount, blocking, or completion. |
| 5 — Telegram completion leaves stale counts | **PARTIAL** | `desktop/assets/desktop/plugin.js:3528` refreshes observed busy→idle transitions, but an idle→idle completion probe left the status count at **0** while `/sync` reported **9** messages. |
| 6 — Concurrent CLI initialization | **RESOLVED** | `desktop/_vault.py:302` locks and rechecks diagnosis; the in-memory concurrency probe confirmed CLI lock acquisition waits during diagnosis and proceeds before the wizard runs. |
| 7 — Memory retry exposes unknown codes | **RESOLVED** | `desktop/assets/desktop/plugin.js:1354` uses membership-based `knownCode`; the rendering probe omitted `secret_canary`. |
| 8 — Swallowable status tripwire | **RESOLVED** | `tests/extension/test_desktop_status_e2e.py:56` records calls and raises a `BaseException` subclass; an injected trip escaped the actual status fallback. |
| D2 5 — Sidecar safety | **PARTIAL** | `imports/store.py:1755` now rejects either missing sidecar, but neither this check nor connection lifetime protects the initial check→open interval. |
| D2 6 — Cleanup completeness | **RESOLVED** | `imports/mail/setup_flow.py:750` requires successful key deletion and verified absence of residue before restoring `pre_seal`. |
| D3 1 — Fixed-message boundary | **RESOLVED** | `desktop/assets/desktop/plugin.js:846`, `:1354`, and `:2094` restrict retry/history/result codes to known tables; unknown-code rendering probes passed. |

## New findings

**No confirmed regressions introduced by these nine commits.** The two remaining defects below continue earlier findings.

The specifically requested boundary checks found:

- **Connection lifetime and concurrency:** two simultaneous threads completed 100 in-memory reads through one opener call; `close()` waited for an active reader, subsequent reads returned `store_unavailable`, and repeated closure was harmless (`imports/store.py:1646`, `:1652`).
- **Write methods remain callable:** the subclass inherits `set_meta`, `delete_source`, `initialize`, and other mutators. Production protection still comes from `mode=ro` (`imports/store.py:1566`, `:1613`). This API exposure predates these commits—the previous factory returned `ImportStore`—so it is not a newly introduced regression. The in-memory write-refusal probe used `query_only`, not a production database.
- **Staged-only recovery remains available:** leftovers block setup, but status reports `credentials_left`, the page offers removal, and CLI status displays `hermes-mordred mail forget --yes` (`desktop/_projections.py:295`, `desktop/assets/desktop/plugin.js:2508`, `wizard/mail_sync_cli.py:367`). The memory-backed probe removed staging files and the key without an account or database access.
- **Vault locking:** no lock-order inversion was found; the existing lifecycle lock is reentrant, and diagnosis exits before wizard initialization (`keyvault/_storage.py:76`, `:867`; `desktop/_vault.py:330`). The directory-creation probe recorded **0700** for `<home>/mordred` (`desktop/_vault.py:301`).
- **Status closure:** success, store refusal after opening, and mail-status failure each closed the opened store once (`desktop/_status_v4.py:106`).

## Verdict

**REVISE — two existing MEDIUM findings still block merging #262 into its stacked base.**

1. **MEDIUM — Initial WAL admission still permits sidecar creation.**  
   A writer can close after `_wal_without_reader_sidecar()` succeeds but before the first SQLCipher connection acquires its locks. The deterministic in-memory interleaving reached the opener with both sidecars absent (`imports/store.py:1739`, `:1710`). Keeping that connection afterward fixes the post-admission race only.

   **Fix:** protect admission through SQLite lock acquisition using coordination shared with all relevant writers, or enforce sidecar non-creation at the VFS boundary. Another existence check is insufficient. Add a real SQLCipher regression that closes the last writer between validation and opening.

2. **MEDIUM — Fast Telegram imports can evade completion refresh.**  
   If an import completes before any poll observes `syncing: true`, the new predicate never refreshes status. The harness reproduced unchanged status-read count **1→1**, displayed store count **0**, and sync count **9** (`desktop/assets/desktop/plugin.js:3528`). Starting the import does not mark a pending completion in the parent (`:1808`).

   **Fix:** track page-initiated imports until an idle answer and refresh on changed idle completion/count information; add an idle→idle completion case alongside the passing busy→idle test.

Review remained offline and read-only. No prohibited paths or database files were read, and the worktree remained clean. Physical WAL sidecar behavior was not exercised; the WAL conclusion combines source inspection with an in-memory admission-order probe.