# Codex seventh-pass review: mail IMAP sync (2026-10-22)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, narrow scope (threading.py), run by the Fable session against commit d0336f49c on pull request #259. Verdict: do not ship because of one remaining ordering scenario that also regressed explicit In-Reply-To replies; the closing commit follows this record. Links were rewritten from absolute paths to repository-relative text.

Reviewed `d0336f49c`.

- **PARTIAL — References-only ordering bypass.** The original probes pass: References-only parents now enter phase 1 (`src/mordred_hermes/imports/mail/threading.py:173` (threading.py:173)). **Remaining probe:** create two triples `(Ai, Ri, Pi)`: `Ai` and `Ri` have no references; `Pi` references `(Ai, Ri)`; all share Alice. Add unique-ID message `X`, dated earliest, referencing `(R0, R1)` and including Alice. Without `X`: two conversations. With `X`: **one seven-message conversation, `merge_skipped=0`**, confirmed through in-memory IMAP sync in three mailbox orders. Dating `X` last preserves separation.

- **FIXED — Unguarded sibling bridge.** Siblings now require equal non-owner participant sets (`src/mordred_hermes/imports/mail/threading.py:305` (threading.py:305)); joins reject two established groups (`src/mordred_hermes/imports/mail/threading.py:235` (threading.py:235)). Both sibling and chain probes preserve the two branches across three orders.

**New defects, ranked:**

1. **P1 — Replies with explicit `In-Reply-To` regress.** Add `In-Reply-To: Ri` to each `Pi` above. The parent commit preserves three conversations; this commit collapses all seven messages. The additional-reference condition defers legitimate parent joins (`src/mordred_hermes/imports/mail/threading.py:323` (threading.py:323)), then equal reference counts restore attacker-controlled date ordering (`src/mordred_hermes/imports/mail/threading.py:372` (threading.py:372)). All IDs are distinct; the accepted residual is excluded.

Verification: 37 threading tests and six in-memory IMAP regression scenarios passed. No files changed.

**Final verdict: DO NOT SHIP — a reproduced ordering bypass remains and now affects explicit-parent replies.**