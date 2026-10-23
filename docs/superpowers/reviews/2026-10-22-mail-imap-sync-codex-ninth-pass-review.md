# Codex ninth-pass review: mail IMAP sync (2026-10-22)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, narrow scope (threading.py, merge_guard.py), run by the Fable session against commit 906377025 on pull request #259. The Ai/Pi/X input is fixed; two further order-sensitive inputs led to replacing the greedy grouping with a set-based algorithm in the closing commit that follows this record. Links were rewritten from absolute paths to repository-relative text.

1. **FIXED — the exact Ai/Pi/X input.** Present-reference ordering and unambiguous passes at `src/mordred_hermes/imports/mail/threading.py:384` (threading.py:384) preserve `{A0,P0}` and `{A1,P1,X}` across 43,560 order/date checks, including tied and missing dates.

   **A literal 2+2 union exists, predating this commit.** Use unique IDs `A,B,D,X`, corresponding lowercase keys, shared non-owner Alice, no Gmail IDs or In-Reply-To, dates `(100,101,200,300)`, and References `A:(U), B:(V), D:(A,B,Z), X:(D)`. `U,V,Z` are distinct and absent. Phase 1 establishes `{D,X}`. D’s fold unions A+B, then `{A,B}` with `{D,X}` at `src/mordred_hermes/imports/mail/threading.py:280` (threading.py:280). Both then contain two messages. This happens **within one approved fold**; `src/mordred_hermes/imports/mail/merge_guard.py:89` (merge_guard.py:89) checks sizes before those unions.

2. **P1 — New date-dependent fragmentation.** Extend that input with `C:(A,B,W)`, where W is another absent ID, and change X’s References to `(C,D)`. Dating C at **0** produces `{A,B,C}|{D,X}`; dating C at **1000** produces one five-message conversation. The parent commit produces one conversation for both dates. The new pass at `src/mordred_hermes/imports/mail/threading.py:391` (threading.py:391) lets C or D claim A/B first, according to their dates. Verified across all 120 batch permutations per date and through 12 in-memory IMAP runs. Neither accepted limitation applies.

3. **DO NOT SHIP** — the new regression violates date-independent grouping.

All 41 threading tests pass. No files modified.