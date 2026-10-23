# Codex third-pass review: mail IMAP sync (2026-10-22)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run by the Fable session against commit dddbb8378. Verdict: do not ship; the closing commit follows this record. Links were rewritten from absolute paths to repository-relative text.

Reviewed `dddbb8378`. **Four items remain PARTIAL; the unbounded cancellation wait is FIXED.**

1. **PARTIAL — Connection-phase deadline.** DNS, SOCKS and TLS deadline probes passed. However, `src/mordred_hermes/imports/mail/imap.py:566` (imap.py:566) calls `route_resolver` synchronously. A stalled route lookup remained blocked beyond a 0.1-second hard deadline until explicitly released; the watchdog cannot interrupt that call.

2. **PARTIAL — Cancellation/join.** Early socket hooks fix the original SOCKS stall (`src/mordred_hermes/imports/mail/imap.py:313` (imap.py:313)). But cancellation cannot interrupt the route lookup above. The bounded join eventually abandons that worker (`src/mordred_hermes/extension/telegram/mail_tool.py:195` (mail_tool.py:195)); it can retain the fetch lock and block subsequent syncs. The handler is bounded, but worker termination is not guaranteed.

3. **PARTIAL — Late-parent reconciliation.** New v2 ingestion passes all six A/B/C arrival permutations, with transactional merging at `src/mordred_hermes/imports/store.py:742` (store.py:742). However, `src/mordred_hermes/imports/_schema.py:179` (the v1 migration) creates an empty reference table. Reproduced: store C→B under v1, upgrade, fetch B→A then A; conversations still contain **2 and 1 messages**.

4. **PARTIAL — Unconditional forget.** Cleanup now runs regardless of metadata (`src/mordred_hermes/wizard/mail_sync_cli.py:562` (mail_sync_cli.py:562)). However, `src/mordred_hermes/wizard/mail_sync_cli.py:612` (line 612) reports key-deletion failure only when credential files existed. Reproduced: first deletion removes files but fails to delete the key; a second failed attempt exits **0**, leaving the key.

5. **FIXED — Unbounded cancellation wait.** `src/mordred_hermes/extension/telegram/mail_tool.py:155` (mail_tool.py:155) enforces a monotonic deadline despite repeated cancellation. A scaled-budget probe completed in 0.202 seconds with the worker deliberately stalled.

New defects, ranked:

1. **MEDIUM — Rejected copies can merge unrelated conversations.** `src/mordred_hermes/imports/store.py:787` (store.py:787) stores references even when the incoming message is rejected as a weaker duplicate. Reproduced: authoritative Sent M1 and unrelated M2 become one conversation after a rejected inbox copy of M1 supplies `References: M2`; the result reports `duplicates=1`.

2. **MEDIUM — TCP address fallback loses its per-attempt timeout.** `src/mordred_hermes/imports/mail/imap.py:450` (imap.py:450) waits against the session deadline, ignoring `op_timeout`. A stalled first address consumed the entire budget; a reachable second address was never attempted.

Verification: **268 tests passed; 13 listener tests were sandbox-blocked.** Additional in-memory and socket-pair probes confirmed the findings. No files were modified. Scheduled live validation did not affect this verdict.

**Final verdict: DO NOT SHIP.**