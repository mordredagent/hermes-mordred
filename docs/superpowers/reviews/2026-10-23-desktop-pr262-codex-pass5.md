# Codex fifth-pass review: Desktop mail and ceremony pages (PR #262, 2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run against commit a71322c7c. Verdict REVISE: both fourth-pass items PARTIAL (activity restore can switch mordred.db to WAL, orphan sidecars; a stale in-flight idle poll consumes the import flag) plus one LOW. Fixed on PR #262 afterwards. Absolute links were flattened to `path:line` text.


Reviewed `a71322c7c` offline using Node component probes and real SQLCipher with an entirely in-memory VFS. No files changed or prohibited paths read.

## Fourth-pass items

| Item | Status | Evidence |
|---|---|---|
| MEDIUM — WAL admission race | **PARTIAL** | Existing WAL headers are refused before connection. However, ActivityStore.restore() copies an encrypted WAL backup onto a rollback store, changing header bytes `[1,1]→[2,2]`. Injecting that restore between admission and opening left no sidecars, then the status reader requested WAL creation and shared-memory mapping. The race remains reachable through Mordred. |
| MEDIUM — Fast Telegram completion | **PARTIAL** | The pending flag accepts an idle GET already outstanding before POST succeeds. That stale response consumes the flag and refreshes prematurely. Reproduction: status reads **1→2→2**, displayed messages **0**, completed import **9**; later idle polls never repair it. Ordinary idle→idle, busy→idle, failed POST, two quick imports, and refresh coalescing passed. |

Normal import/activity writes and `dbcrypt` conversion—including `databases encrypt`—preserve rollback mode. Clean rollback readers created no sidecars; hot journals were refused without writes. **Header `[1,1]` alone is nevertheless insufficient:** an orphan `-wal` also triggered shared-memory mapping and deletion of that orphan in the SQLCipher probe.

## New findings

**LOW — Late start success re-arms pending after unmount.** Cleanup clears an existing flag, but the delayed POST continuation sets it again and launches a poll. HEAD performs an additional post-unmount status read; the base does not. No other confirmed regressions.

## Verdict

**REVISE.** Both MEDIUM findings still block merging #262 into its stacked base. Admission must cover restore-induced mode changes; completion tracking must reject polls originating before the successful start.