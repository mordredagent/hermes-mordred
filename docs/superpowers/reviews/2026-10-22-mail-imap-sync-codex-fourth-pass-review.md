# Codex fourth-pass review: mail IMAP sync (2026-10-22)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run by the Fable session against commit 42f7043f8 (the first commit on pull request #259). Verdict: do not ship; the closing commit follows this record. Links were rewritten from absolute paths to repository-relative text.

Reviewed `42f7043f8`: **three FIXED, four PARTIAL.**

1. **FIXED — Route lookup deadline.** `src/mordred_hermes/imports/mail/imap.py:598` (imap.py:598) uses `Link.bounded`; stalled-route probes terminated on deadline and cancellation.

2. **PARTIAL — Abandoned worker lock/late writes.** The lease and `src/mordred_hermes/imports/store.py:770` (store.py:770) reject late batches after successful revocation. Cleanup can still hang or release the lock without revoking the run; see new defects below.

3. **PARTIAL — References from rejected copies.** `src/mordred_hermes/imports/store.py:836` (store.py:836) filters reference recording, but `src/mordred_hermes/imports/mail/importer.py:362` (importer.py:362) groups messages first. Reproduced through sync: rejected forged M1 referencing unrelated new M2 puts M2 into M1’s conversation when fetched together, despite recording no references.

4. **PARTIAL — v1-upgrade late-parent case.** `src/mordred_hermes/imports/store.py:859` (store.py:859) supports identical-copy backfill, but `src/mordred_hermes/imports/_schema.py:179` (_schema.py:179) leaves historical references empty. C→B stored under v1, then upgrade/B→A/A, still produces conversations of **2 and 1** messages. Explicitly re-fetching C repairs this.

5. **PARTIAL — Crafted-References merge guards.** `src/mordred_hermes/imports/store.py:988` (store.py:988) guards reconciliation, but earlier `src/mordred_hermes/imports/mail/threading.py:140` (threading.py:140) unions references without those checks. Five unrelated two-message threads plus one crafted message in the same batch became **one 11-message conversation**, with `merge_skipped=0`.

6. **FIXED — Forget key residue.** `src/mordred_hermes/wizard/mail_sync_cli.py:612` (mail_sync_cli.py:612) reports `key_left` and exit 1 even after credential files disappear; both reporting cases passed.

7. **FIXED — Per-address TCP timeout.** `src/mordred_hermes/imports/mail/imap.py:471` (imap.py:471) bounds each attempt; a controlled probe reached the second address after the first timed out.

**New defects introduced, ranked:**

1. **HIGH — Unsafe unlock after failed revocation.** `src/mordred_hermes/imports/mail/imap_sync.py:408` (imap_sync.py:408) exhausts three busy retries, then unlocks with the run still open. Actual SQLite contention reproduced a late batch committing afterward—including restoring mail after account-row deletion.

2. **HIGH — Unbounded cleanup wait reintroduced.** `src/mordred_hermes/extension/telegram/mail_tool.py:187` (mail_tool.py:187) shields cleanup indefinitely; `src/mordred_hermes/imports/mail/imap_sync.py:396` (imap_sync.py:396) holds its mutex during writes. A stalled write prevented abandonment and cancellation completion beyond the configured bounds, including repeated cancellation.

Verification included 19 existing regressions using in-memory stores and targeted probes. Filesystem-dependent tests and TCP listeners were sandbox-blocked. No files changed. Scheduled live validation does not affect this verdict.

**Final verdict: DO NOT SHIP.**