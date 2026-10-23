# Codex sixth-pass review: Desktop mail and ceremony pages (PR #262, 2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run against commit 655ce5d00. WAL item and the late-POST LOW RESOLVED; one polling interleaving (busy, then an older idle answer) left PARTIAL and fixed afterwards on PR #262. Absolute links were flattened to `path:line` text.


Reviewed `655ce5d00` offline using Node component probes and real SQLCipher with an entirely in-memory VFS. No files changed or prohibited files read.

## Fifth-pass items

| Item | Status | Evidence |
|---|---|---|
| MEDIUM — WAL admission race and orphan sidecars | **RESOLVED** | Injected WAL restore between admission and opening now refuses with `backup_wal_unsupported`. All three orphan sidecars refuse before connection. A rollback journal appearing afterward caused no reader mutations: an active writer permitted reads; a hot journal returned `SQLITE_READONLY`. The reader neither created sidecars nor recovered/deleted the journal. See restore gate and admission. |
| MEDIUM — Stale poll loses import completion | **PARTIAL** | Original stale-first reproduction passes; remount preserves sequence **1→2→3**. However, post-start **busy** clears the pending mark, then an older pre-start **idle** still overwrites `syncWas` and refreshes prematurely. Actual completion sees idle→idle and never refreshes. Probe: status reads **1→2→2**, displayed messages **0**, imported **9**. Affected logic. |
| LOW — Late POST success after unmount | **RESOLVED** | Delayed success produced zero additional polls and no pending mark; a subsequent idle response triggered no status refresh. |

## New findings

No additional regressions found. Encrypted backup/self-check, rollback preview without mutation, and restore with preserved rows and renewed generation passed. `journal_mode=DELETE` retained encryption and normalized copies of existing WAL stores; restoring a rollback copy onto a WAL store also normalized it.

Compatibility change: existing WAL-mode backups now refuse both preview and restore. Existing rollback backups remain usable.

## Verdict

**REVISE.** The remaining polling race blocks merging into the stacked base. Reject out-of-order responses before updating completion state, and add the **new busy → stale idle → completed idle** regression case.