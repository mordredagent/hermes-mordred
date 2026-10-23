# Codex eighth-pass review: mail IMAP sync (2026-10-22)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, narrow scope (threading.py, merge_guard.py), run by the Fable session against commit 8d15f73f9 on pull request #259. The two-triples scenario is fixed; one date-ordering case among not-yet-established pairs remains and the closing commit follows this record. Links were rewritten from absolute paths to repository-relative text.

Reviewed `8d15f73f9`.

1. **FIXED — the exact two-triples scenario**, with and without `In-Reply-To`. `src/mordred_hermes/imports/mail/threading.py:321` (threading.py:321) joins each `Pi` to `Ri` before weak edges; `X` attaches to `R1`. The two triples remain separate across 30,252 order/date checks and 18 in-memory IMAP runs. `src/mordred_hermes/imports/mail/merge_guard.py:87` (merge_guard.py:87) rejects subsequent merging of their established groups.

2. **New correctness defects: none identified. One pre-existing P1 date-ordering defect remains outside the accepted limitations.** Precise input: all messages have unique IDs, share non-owner Alice, and have no Gmail IDs or `In-Reply-To`. For `i=0,1`, `Ai` references `(Ui)` and is dated `100+i`; `Pi` references `(Ai,Vi)` and is dated `200+i`. All four `Ui,Vi` IDs are distinct and absent. Add `X`, referencing `(A0,A1)`.

   Without `X`: two pairs. With `X` dated `0`: **one five-message conversation, `merge_skipped=0`**. Dating `X` `1000` preserves both pairs, with `X` joining pair 1. Confirmed across all 120 batch permutations and through IMAP. Every message has references; neither accepted limitation applies.

   Absent parents leave pair formation to weak edges, whose date ordering at `src/mordred_hermes/imports/mail/threading.py:372` (threading.py:372) permits this collapse **before** both pairs become established. This does not demonstrate an actual union of two already-multi-message groups. The parent commit also reproduces it.

3. **DO NOT SHIP — the broader date-independence requirement still fails.**

No files modified.