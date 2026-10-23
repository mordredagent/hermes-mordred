# Codex design review: mail IMAP sync (2026-10-22)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run by the Fable session against commit 27fb24d83 of `docs/superpowers/specs/2026-10-22-mail-imap-sync-design.md`. Decisions taken in response are recorded in that document under "Revision after the Codex design review". Links were rewritten from absolute paths to repository-relative text.

The design needs revisions before implementation. No files were modified.

## 1. Assumptions the code does not support

- **Unchanged importer reuse:** `src/mordred_hermes/imports/mail/source.py:93` (source.py:93) accepts specific source types, not arbitrary `RawMessage` iterators. `src/mordred_hermes/imports/mail/importer.py:281` (importer.py:281) reads twice and materializes the plan; it cannot provide the proposed streaming lifetime unchanged.
- **Generic Sent evidence:** `src/mordred_hermes/imports/mail/owner.py:191` (owner.py:191) emits `gmail_label_sent`, never `imap_sent_folder`. `src/mordred_hermes/imports/mail/link.py:58` (link.py:58) and `src/mordred_hermes/imports/mail/store_link.py:102` (store_link.py:102) exclude the proposed evidence.
- **Partial publication:** `src/mordred_hermes/imports/store.py:543` (store.py:543) publishes only committed **runs**. Thread transactions remain unreadable after `run_fail`; revisions can also replace previously readable rows with unpublished rows.
- **Cursor keys:** `src/mordred_hermes/imports/store.py:111` (store.py:111) permits at most four lowercase components. The proposed five-component keys, especially raw mailbox names, fail validation.
- **Reader allowance:** adding `READER_ALLOWED` alone still reaches normal egress rules, which block unknown tools under lockdown (`src/mordred_hermes/privacy_check/egress.py:699` (egress.py:699)). `history_search_available` checks endpoints offline; private-model verification happens separately during execution (`src/mordred_hermes/extension/telegram/hermes_tools.py:171` (hermes_tools.py:171)). Scope “never enters Hermes” to sync: subsequent history searches intentionally return text.

## 2. Security findings

No **CRITICAL** finding is established.

- **HIGH — private output:** `src/mordred_hermes/imports/mail/report.py:3` (report.py:3) includes arbitrary labels and addresses; `src/mordred_hermes/wizard/mail_cli.py:293` (mail_cli.py:293) prints them. Reuse would violate the counts-only promise. Require an allowlisted result serializer, fixed notes/errors, suppressed IMAP debugging, and no exception text or traceback leakage.
- **HIGH — forged provenance:** `src/mordred_hermes/imports/mail/headers.py:267` (headers.py:267) trusts the first embedded label/thread header. Appending synthetic headers leaves attacker-supplied values authoritative. Use trusted collector metadata separately. Generic `\Sent` identifies folder purpose, not verified authorship; granting `api_identity` and quote-anchor authority overstates its evidence. [RFC 6154](https://www.rfc-editor.org/rfc/rfc6154.html)
- **HIGH — egress:** `src/mordred_hermes/extension/egress.py:109` (extension/egress.py:109) resolves routes, not sockets; `src/mordred_hermes/network/hooks.py:522` (network/hooks.py:522) checks calls, not every socket operation. Specify SOCKS remote DNS/authentication, unsupported-proxy refusal, VPN-drop handling, and verified TLS/SNI to the sealed hostname.
- **MEDIUM — custody:** production Telegram uses hardware-only `src/mordred_hermes/extension/telegram/tee.py:253` (tee.py:253), not cached `VaultSecretStore`. Copy that boundary. Touch ID is optional, and dropping immutable Python strings does not guarantee zeroization.
- **MEDIUM — model arguments/read-only:** schema and `check_fn` are insufficient. Validate exact integer bounds, reject booleans/unknown keys, and repeat gates inside the handler. Enforce a runtime command allowlist including authentication/discovery/logout; prohibit mutation commands and unsafe cleanup.
- **MEDIUM — retention/resources:** failed rows persist; crashes can leave runs open. Define cleanup and forget semantics. A 200-message batch permits roughly 5 GiB before parsing overhead; post-fetch size checks cannot bound IMAP literal allocation.

## 3. Correctness risks

- Advance only across completed UID work, never the highest fetched UID across unresolved failures. Publish data and cursor atomically. Separate forward progress from historical backfill, bind state to account/server identity, and reset epochs atomically on UIDVALIDITY changes. `last+1:*` can include the current last UID, requiring filtering. [RFC 9051](https://www.rfc-editor.org/rfc/rfc9051.html)
- Gmail returns `\Sent`/`\Drafts` and IMAP-encoded label strings; the classifier expects `Sent`/`Drafts`. Decode and map explicitly, distinguishing system labels from custom names. Prefer special-use LIST over deprecated XLIST. [Gmail extensions](https://developers.google.com/workspace/gmail/imap/imap-extensions)
- Generic Sent discovery needs ambiguity handling and setup-time selection; guessed names cannot establish provenance. INBOX plus Sent also omits other folders.
- Injected headers change raw-byte revisions; `src/mordred_hermes/imports/store.py:630` (store.py:630) can consequently replace stronger Sent evidence across runs. Incremental thread metadata currently replaces totals/participants with batch-local values. Partial results must distinguish committed counts, pending work, historical exclusions, and errors; timeout cancellation must actually stop the worker.

## 4. Recommendations on the open questions

1. **Newest 2000:** retain the predictable cap, define “newest” by UID, and report excluded history.
2. **All Mail:** retain archived mail and exclude Spam/Trash; describe that scope explicitly rather than “everything.” [Gmail help](https://support.google.com/mail/answer/7015314)
3. **Concurrent reader sessions:** no process-wide denial; permit counts-only sync after fixing publication consistency and explicit non-tainting policy.
4. **Duration:** prefer approximately 60 seconds with `partial`, a fixed reason, and resumable committed progress. Keep longer execution available through CLI.

## 5. Required changes before implementation

1. Specify bounded replayable batches and aggregate byte/literal limits.
2. Redesign atomic publication, cursor/backfill state, crash recovery, and retention.
3. Introduce trusted IMAP metadata and conservative Sent evidence.
4. Define hardware custody, explicit transport, and runtime command enforcement.
5. Specify handler validation, fixed output/error schemas, and reader-policy integration.
6. Add adversarial leakage, forged-header, crash, partial-response, TLS/proxy, and cancellation tests.
7. Update SPEC/PLAN and record live validation; preserve the `docs/dev/UPSTREAM.md:27` (zero-upstream-PR boundary).