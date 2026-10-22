# Codex fifth-pass review: mail IMAP sync (2026-10-22)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run by the Fable session against commit 8dbb8bdd3 on pull request #259. Verdict: do not ship because of one remaining in-batch guard ordering bypass; the closing commit follows this record. Links were rewritten from absolute paths to repository-relative text.

Reviewed `8dbb8bdd3`: **five FIXED, one PARTIAL.**

1. **PARTIAL — In-batch merge guards (HIGH).** The shared guard is called at `src/mordred_hermes/imports/mail/threading.py:186` (threading.py:186), but `src/mordred_hermes/imports/mail/threading.py:204` (threading.py:204) processes fewer references first. **Reproduced through sync:** five unrelated two-message threads, each carrying older absent ancestors, plus a crafted message naming their five roots become **one 11-message conversation, `merge_skipped=0`**. The crafted message runs before the six-reference replies establish their threads. Without it, five separate conversations persist.

2. **FIXED — Duplicate copies excluded from grouping.** `src/mordred_hermes/imports/mail/importer.py:386` (importer.py:386) classifies copies before grouping; `src/mordred_hermes/imports/mail/threading.py:214` (threading.py:214) excludes their ID connections and reference edges. The rejected-copy regression passed.

3. **FIXED — Failed revocation retains the lock.** `src/mordred_hermes/imports/mail/imap_sync.py:483` (imap_sync.py:483) prevents release after unsuccessful revocation or settlement; worker exit releases it. Probes confirmed late guarded writes are refused while the run remains open.

4. **FIXED — Bounded cleanup.** `src/mordred_hermes/extension/telegram/mail_tool.py:200` (mail_tool.py:200) runs revocation in a daemon with a fixed deadline; `src/mordred_hermes/extension/telegram/mail_tool.py:236` (mail_tool.py:236) prevents repeated cancellation extending the bound. Stalled-write and revoker probes returned within their configured bounds.

5. **FIXED — Lease guard inside transactions.** `src/mordred_hermes/imports/store.py:621` (store.py:621) acquires the transaction before checking the guard; exceptions roll back. All four guarded operations passed probes.

6. **FIXED — Documented v1 limitation.** `docs/user/USAGE.md:938` (USAGE.md:938) explicitly requires re-fetching historical messages. Accepted; excluded from the verdict.

**New defects introduced:** None confirmed. Item 1 is a remaining vulnerability in the attempted fix.

Verification: 191 focused tests and 29 existing regressions adapted to in-memory execution passed, plus targeted probes. Filesystem-dependent coverage remains unverified here. No files changed; scheduled live validation does not affect this verdict.

**Final verdict: DO NOT SHIP — the crafted-reference merge bypass remains.**