# Codex implementation review: mail IMAP sync (2026-10-22)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run by the Fable session against commits 01a4ae8ad, 024d8621b and 50b924f93. Verdict: do not ship yet. The fixes are tracked in the follow-up commits named in `docs/dev/PLAN.md`. Links were rewritten from absolute paths to repository-relative text.

**Do not ship yet.** In-memory probes confirmed data loss, skipped mail, continued work after cancellation, and incomplete deletion. No files were modified. The full pytest suite and live Gmail validation were not run.

## 1. Contract compliance

References use the requested files’ basenames.

| Revision decision | Assessment and evidence |
|---|---|
| Preserve bytes; ignore embedded label/thread headers | **COMPLIANT** — `src/mordred_hermes/imports/mail/normalize.py:123` (normalize.py:123). |
| Distinguish system labels from custom labels | **PARTIAL** — classification loses that distinction: `src/mordred_hermes/imports/mail/owner.py:217` (owner.py:217). |
| Conservative generic Sent evidence; setup selection; scope reporting; no XLIST | **COMPLIANT** — owner.py:223; `src/mordred_hermes/wizard/mail_sync_cli.py:223` (mail_sync_cli.py:223), :338. |
| One atomic transaction containing threads, publication, cursor and epoch | **PARTIAL** — publication/cursor are atomic, preceding thread writes are separate: `src/mordred_hermes/imports/mail/imap_sync.py:530` (imap_sync.py:530). |
| Valid cursor keys; separate backfill state; UID self-inclusion filtering | **COMPLIANT structurally** — imap_sync.py:266, :452, :603; backfill correctness fails below. |
| Preliminary sizes; ≤200 messages; ≤64 MiB literals | **PARTIAL** — reported-size batching exists; actual literal enforcement is **MISSING**: imap_sync.py:475, :499. |
| Mark crashed runs failed; reclaim through existing rules | **COMPLIANT** — imap_sync.py:685; `src/mordred_hermes/imports/store.py:750` (store.py:750). |
| Merge conversation dates, participants and counts | **PARTIAL** — store.py:700; changes escape failed batches. |
| Fixed counts-only serializer, closed codes, suppressed debugging | **COMPLIANT** — imap_sync.py:179; `src/mordred_hermes/imports/mail/imap.py:237` (imap.py:237). |
| Verified TLS/SNI, routes, remote DNS, authentication, port 993 | **PARTIAL** — TLS/SNI and routing implemented; authentication can downgrade, arbitrary ports accepted: imap.py:138, :169, :272, :455. |
| Hardware custody; fresh unwrap; scoped secret lifetime | **COMPLIANT** — `src/mordred_hermes/imports/mail/secrets.py:209` (secrets.py:209), :301; imap_sync.py:688. |
| Forget credentials/cursors, optionally rows | **PARTIAL** — mail_sync_cli.py:493. |
| Strict arguments, repeated gates, reader allowance without taint | **COMPLIANT** — `src/mordred_hermes/extension/telegram/mail_tool.py:70` (mail_tool.py:70), :129; `src/mordred_hermes/privacy_check/egress.py:127` (egress.py:127), :155. |
| Runtime command allowlist | **PARTIAL** — imap.py:225. |
| Partial returns; approximately 60 seconds/600 seconds; joined cancellation | **PARTIAL** — imap_sync.py:79; cancellation joining is **MISSING**, mail_tool.py:135. |
| Decided questions: newest-N/exclusions; All Mail scope; concurrent readers; budgets | **PARTIAL / COMPLIANT / COMPLIANT / PARTIAL**, respectively — imap_sync.py:575; `docs/dev/SPEC.md:4662` (SPEC.md:4662); egress.py:155; mail_tool.py:135. |
| Added tests | **PARTIAL** — weaknesses below. |

## 2. Security findings

No **CRITICAL** finding or demonstrated private-text disclosure through fetch results, logs, or audit was established.

- **HIGH — Resource exhaustion:** a server reporting size 1 can announce a 256 MiB literal; the probe reached `read(268435456)` before validation. Aggregate actual bytes are also unchecked (`imap.py:399`, `imap_sync.py:499`).
- **MEDIUM — Forged provenance:** custom `" \Sent "` or decoded `"&AFw-Sent"` becomes `gmail_label_sent/api_identity` through stripping/decoding. Provider acceptance remains unverified; the parser/classifier collision is reproduced (`owner.py:217`, `src/mordred_hermes/imports/mail/_imap_codec.py:305` (_imap_codec.py:305)).
- **MEDIUM — Allowlist bypass:** `xatom("NOOP", "\r\nZ1 STORE …")` transmits the mutation. Current sync inputs constrain reachability, but the promised wrapper enforcement fails (`imap.py:225`).
- **MEDIUM — Proxy isolation:** configured credentials still permit SOCKS no-auth negotiation, dropping the isolation token (`imap.py:138`).
- **MEDIUM — Retention:** plain forget removes the account identifier; subsequent `forget --rows` can return success while retaining rows/cursors (`mail_sync_cli.py:493`).

## 3. Correctness bugs

- **Publication/merge:** revise committed A, then fail publication: A disappears while its cursor remains unchanged. Adding unpublished B also exposes B’s participant/date/count through committed A, persisting after failure (`imap_sync.py:533`; `store.py:684`).
- **Cap/cursor:** INBOX consumes the cap; first-time Sent receives `uid=top` without fetching anything. Later ordinary syncs omit those messages, with `partial=false` (`imap_sync.py:577–583`).
- **Backfill:** fetch September history, then widen to January. An older-dated UID above the saved backfill watermark remains permanently skipped (`imap_sync.py:608–616`).
- **Deadline/cancellation:** continuously arriving bytes evade inactivity timeouts; forward searches lack deadline checks. Cancelling the handler leaves the worker running (`imap.py:462`; `imap_sync.py:449`; `mail_tool.py:135`).
- **Provenance reconciliation:** identical INBOX→Sent bytes remain duplicates with weak evidence; changed received copies can overwrite stronger Sent evidence (`store.py:756`).
- **Threading:** A→B→C using only immediate `In-Reply-To` forms one conversation together, but splits across batches (`imap_sync.py:521`).
- **Labels:** system labels beyond position 64 disappear; Draft may consequently be imported (`_imap_codec.py:302`).
- **Locking:** setup bypasses the writer lock. Concurrent forget can delete newly installed credentials while deleting the previous account’s rows (`mail_sync_cli.py:278`, :493).

## 4. Test gaps

The Added-tests topics have nominal coverage, but:

- Atomicity/merge tests omit existing revisions, concurrent readers and failed metadata publication (`test_mail_store_batches.py:30`).
- Budget tests advance a fake clock after FETCH; cancellation and progressing sockets are untested (`test_mail_sync_tool.py:180`).
- Size tests trust advertised sizes; label tests miss collisions and late system labels.
- Allowlist tests omit framing injection; proxy tests omit authentication downgrade.
- Forget tests omit retry after credential deletion; setup/forget races are absent.
- Cursor tests miss exhausted subsequent mailboxes and nonmonotonic dates; merge tests miss cross-batch reference chains.

## 5. Required changes before shipping

1. Make complete batches atomic, preserving prior published revisions and conversation metadata.
2. Enforce literal/cumulative byte limits before allocation and absolute deadlines.
3. Stop and join workers on cancellation.
4. Repair cap/backfill cursors, cross-batch threading and provenance reconciliation.
5. Preserve system-label identity through decoding; inspect all system labels.
6. Reject command framing injection, require configured proxy authentication, and enforce port 993.
7. Make deletion retryable; serialize setup and resolve forget targets under the lock.
8. Add adversarial regression tests and record the required live validation.