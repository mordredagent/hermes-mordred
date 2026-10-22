# Codex second-pass review: mail IMAP sync hardening (2026-10-22)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run by the Fable session against the fix commit 3ebef33f2. Verdict: do not ship until the partial items below are closed; the closing commit follows this record. Links were rewritten from absolute paths to repository-relative text.

**DO NOT SHIP.** The fix substantially improves safety, but cancellation, threading, credential cleanup, and validation remain incomplete.

Verification: 188 selected tests passed; four TCP-listener tests were blocked by sandbox permissions. Eleven additional checks passed using in-memory SQLite. Adversarial probes reproduced the gaps below. No files were modified; full regression and live validation were not run.

1. **FIXED — Atomic batches.** `src/mordred_hermes/imports/store.py:682` (store.py:682) encloses conversation merges, message writes, publication, recounting, and cursor updates in one transaction. The injected-failure regression preserves the previous revision, metadata, and cursor.

2. **PARTIAL — Resource limits and absolute deadlines.** Literal lengths are checked before reading, with cumulative accounting (`src/mordred_hermes/imports/mail/imap.py:525` (imap.py:525)). However, connection establishment precedes watchdog attachment (`src/mordred_hermes/imports/mail/imap.py:657` (imap.py:657)). A stalled DNS resolver remained active beyond a synthetic 0.1-second hard deadline. The absolute bound must cover connection establishment too.

3. **PARTIAL — Stop and join on cancellation.** The handler joins its worker (`src/mordred_hermes/extension/telegram/mail_tool.py:160` (mail_tool.py:160)), but SOCKS negotiation runs before the cancellation hook exists (`src/mordred_hermes/imports/mail/imap.py:325` (imap.py:325)). Cancelling while awaiting the proxy’s authentication-method response left the worker blocked until the probe closed the proxy socket.

4. **PARTIAL — Cursors, threading, provenance.** The exhausted-cap guard, date-range widening, and Sent precedence are implemented at `src/mordred_hermes/imports/mail/imap_sync.py:637` (imap_sync.py:637), `src/mordred_hermes/imports/mail/imap_sync.py:681` (imap_sync.py:681), and `src/mordred_hermes/imports/store.py:867` (store.py:867). Thread reconciliation only resolves already-stored message IDs (`src/mordred_hermes/imports/mail/importer.py:311` (importer.py:311)). **Failing scenario:** fetch C first, then backfill B and A separately, each reply naming only its immediate parent. The probe produced two conversations containing one and two messages. Existing conversations need reconciliation when missing parents arrive.

5. **FIXED — System-label identity.** `src/mordred_hermes/imports/mail/_imap_codec.py:359` (_imap_codec.py:359) inspects every label and identifies system labels before modified-UTF-7 decoding. `src/mordred_hermes/imports/mail/owner.py:222` (owner.py:222) requires that distinct type. Collision and late-label tests passed.

6. **FIXED — Framing, proxy authentication, port.** Argument framing is rejected at `src/mordred_hermes/imports/mail/imap.py:406` (imap.py:406); configured proxy credentials require authenticated negotiation at `src/mordred_hermes/imports/mail/imap.py:303` (imap.py:303); credential validation restricts the port to 993 at `src/mordred_hermes/imports/mail/secrets.py:107` (secrets.py:107).

7. **PARTIAL — Retryable deletion and locking.** Setup sealing takes the lock, and forget rechecks setup identity (`src/mordred_hermes/wizard/mail_sync_cli.py:292` (mail_sync_cli.py:292), `src/mordred_hermes/wizard/mail_sync_cli.py:534` (mail_sync_cli.py:534)). However, missing/corrupt metadata makes `flags()` return `None`, suppressing credential deletion at `src/mordred_hermes/wizard/mail_sync_cli.py:543` (mail_sync_cli.py:543). **Failing scenario:** the sealed file survives a metadata-write failure; forget reports success without removing it or its key.

8. **PARTIAL — Adversarial tests and live evidence.** Added tests cover many original failures, but cancellation tests start during FETCH (`tests/extension/test_mail_sync_tool.py:263` (test_mail_sync_tool.py:263)); connection stalls and reverse-order threading remain uncovered. The required Gmail/Enclave procedure is documented at `docs/dev/CI.md:397` (CI.md:397), without a corresponding validation-log entry.

New regressions, ranked:

- **HIGH — Unbounded cancellation wait.** `src/mordred_hermes/extension/telegram/mail_tool.py:134` (mail_tool.py:134) suppresses repeated cancellations until the worker exits. A permanently stalled resolver now also prevents handler cancellation from completing.
- **MEDIUM — Credential-cleanup no-op.** Item 7’s new conditional skips cleanup that was previously unconditional, including retries after partial deletion.

No additional counts-only disclosure or `write_batch` rollback hole was established.

**Final verdict: DO NOT SHIP** until these remaining gaps are repaired, regression-tested, and the required live validation is recorded.