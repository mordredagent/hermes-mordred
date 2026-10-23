# Codex sixth-pass review: mail IMAP sync (2026-10-22)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, narrow scope, run by the Fable session against commit 6b32ff5d5 on pull request #259. Verdict: do not ship because of two remaining order-dependent merge-guard bypasses in the in-batch grouping; the closing commit follows this record. Links were rewritten from absolute paths to repository-relative text.

Reviewed `6b32ff5d5`.

- **PARTIAL — Ordering bypass.** The original direct-parent scenario now produces six conversations. However, `src/mordred_hermes/imports/mail/threading.py:248` (threading.py:248) skips replies lacking `In-Reply-To`, leaving their grouping to sender-controlled date order at `src/mordred_hermes/imports/mail/threading.py:278` (threading.py:278). **Reproduced through IMAP sync:** remove `In-Reply-To` from the new absent-ancestor fixture and date the crafted message earliest: **one 11-message conversation, `merge_skipped=0`**. Without the crafted message, five two-message conversations remain.

- **FIXED — Unguarded reference re-key.** `src/mordred_hermes/imports/mail/importer.py:323` (_join_stored, importer.py:323) resolves only members’ own IDs; `src/mordred_hermes/imports/mail/threading.py:335` (threading.py:335) prevents absent referenced roots from selecting IMAP conversation keys. A fresh-store probe kept a stranger referencing an existing root separate, reporting `merge_skipped=1`.

**New defects, ranked:**

1. **P1 — Broader ordering regression.** The `References`-only attack above also succeeds with just one reference per legitimate reply. Comparing implementations: the parent commit produces six groups; this commit produces one.
2. **P1 — Unguarded sibling bridge.** `src/mordred_hermes/imports/mail/threading.py:258` (threading.py:258) unions siblings without the multi-message guard. Probe: two separate two-message branches reference the same absent parent, with disjoint correspondents. One crafted sibling naming both correspondents merges all five messages, `merge_skipped=0`. The parent implementation retains two groups. Fresh-store IMAP sync confirmed the collapse.

Verification: 50 pytest cases and 16 regressions adapted for read-only execution passed. No files changed. The documented historical-key risk and scheduled live validation do not affect this verdict.

**Final verdict: DO NOT SHIP — two reproduced merge-guard bypasses remain.**