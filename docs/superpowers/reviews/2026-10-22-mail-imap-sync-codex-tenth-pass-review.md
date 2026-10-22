# Codex tenth-pass review: mail IMAP sync (2026-10-22)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, narrow scope (threading.py, merge_guard.py), run by the Fable session against commit f9b5a80e4 on pull request #259. Confirms that established strong components can never share a thread; one weak-only pair bridge and two subject-grouping determinism nits remain and are closed in the commit that follows this record. Links were rewritten from absolute paths to repository-relative text.

1. **Determinism:** Reference membership is independent of order and dates: strong edges are fixed, and each weak cluster attaches to at most one anchor (`src/mordred_hermes/imports/mail/threading.py:297` (threading.py:297), `src/mordred_hermes/imports/mail/merge_guard.py:104` (merge_guard.py:104)). Two distinct **established strong components** cannot share a final thread. The entire return value has existing exceptions: subject grouping uses dates (`src/mordred_hermes/imports/mail/threading.py:362` (threading.py:362)); two bare messages with identical subject, participants, date and `order` select different keys when reversed (`src/mordred_hermes/imports/mail/threading.py:400` (threading.py:400)).

2. **P1 — New absent-parent bridge between weak-only pairs.** Use unique Message-IDs `A0,P0,A1,P1,X`, corresponding lowercase keys, shared non-owner Alice, no Gmail IDs or In-Reply-To, and dates `(100,200,101,201,0)`. References:

   ```
   A0: (U0)       P0: (A0,V0)
   A1: (U1)       P1: (A1,V1)
   X:  (A0,A1,Z)
   ```

   `U0,U1,V0,V1,Z` are distinct and absent. Without X, both versions produce two two-message conversations. With X, this rewrite produces one five-message conversation, `merge_skipped=0`; the parent commit preserves both pairs and isolates X, counting one refusal. Weak unions have no size guard (`src/mordred_hermes/imports/mail/threading.py:272` (threading.py:272)). These pairs are not established *strong* components, so the narrow invariant survives. Neither accepted exception applies: X’s direct parent is absent, and no Message-ID is reused.

   Confirmed across 480 order/date variants and three in-memory importer/store orderings per version. All 57 threading tests pass. No other new correctness defects found.

3. **DO NOT SHIP** — the absent-parent bridge is an additional regression outside the accepted cases.