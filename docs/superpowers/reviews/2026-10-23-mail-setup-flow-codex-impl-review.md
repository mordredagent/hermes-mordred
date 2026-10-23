# Codex implementation review: mail setup flow library (D2, 2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run by the Fable session against commit b8cf9cb26 (branch feat/desktop-mail-setup-flow, folded into feat/desktop-mail-ceremonies / PR #262). Verdict REVISE (2 HIGH, 4 MEDIUM, test gaps). Absolute links were flattened to `path:line` text. The fixes land on PR #262.


## Findings

Reviewed committed code at `b8cf9cb26`; the scoped implementation is unchanged at the later HEAD, `dc6a6d595`. No files changed, network used, or prohibited files read. Verification used source inspection and in-memory reproductions; pytest was not run.

1. **HIGH — Setup exceptions retain server content through `__context__`.**

   Evidence: setup_flow.py:533, underlying imap.py:966.

   A real `imaplib` parser replay of successful LOGIN followed by CAPABILITY or LIST `BAD` produced:
   `MailSetupError.__context__ → ImapError.__context__ → imaplib.error`, whose `args` contains the server’s address/folder canary. `from None` hides this chain from ordinary traceback formatting; it does not remove it.

   Authentication cleanup also clears only `conn.mo` (imap.py:1017): untagged NO/ALERT and BYE text remains in `untagged_responses`.

   **Fix:** sever content-bearing exception chains at the common IMAP/setup boundary and discard protocol response buffers on failure. Normal CLI/JSON disclosure was not demonstrated, but the required exception and retention boundaries fail.

2. **HIGH — The plaintext check can create an unintended file when the home path contains `#`.**

   Evidence: store.py:1649 calls dbcrypt/_monitor.py:89, which constructs an unescaped URI.

   For `/synthetic/mail#profile/...`, SQLite treats everything after `#` as a fragment—including `mode=ro&immutable=1`. A real SQLite trap-VFS reproduction intercepted an attempted open of `/synthetic/mail` with **READWRITE|CREATE**. Escaping `#` correctly produced READONLY against the complete path. No files were opened by the reproduction.

   **Fix:** escape paths in every verification URI. Escaping `_readonly_opener()` alone does not protect its preceding plaintext probe. The intended file’s `lstat` cannot protect a different URI target.

3. **MEDIUM — Cancellation does not invalidate setup work already in progress.**

   Evidence: setup_flow.py:481, setup_flow.py:500, setup_flow.py:517.

   In-memory interleavings reproduced both failures: `cancel_all()` during the probe returned, after which `start()` registered a pending flow; `cancel(flow_id)` during finish’s key check returned, after which `finish()` sealed credentials. The writer lock does not serialize cancellation.

   **Fix:** invalidate active starts as well as pending entries, and coordinate cancellation with the final registration/sealing decision. Re-check cancellation immediately before committing, with synchronization preventing another gap.

4. **MEDIUM — Read-only status still invokes the provider that can unlock the vault.**

   Evidence: store.py:1590 reaches the captured provider at dbcrypt/_shim.py:214.

   The committed opener plus real shim called a fail-on-call provider in an in-memory reproduction. Stable valid environment material does not make the default provider unlock; malformed material present at admission is correctly refused. However, removing the key between admission and connection triggered the provider’s injection branch at dbcrypt/_key.py:83.

   **Fix:** pass the validated environment-derived key through a dedicated opening path that never consults the runtime provider, including subsequent connections made by the returned store.

5. **MEDIUM — `mode=ro` does not enforce the promised absence of WAL sidecar creation.**

   Evidence: store.py:1589.

   For an initialized WAL database whose sidecars are absent, SQLite can create `-wal`/`-shm` in a writable directory while reading. Protecting the main database with `mode=ro` is insufficient. This finding follows SQLite’s documented behavior; no database-file reproduction was performed.

   **Fix:** enforce no creation at the opening/VFS boundary or refuse unsupported missing-sidecar states. Do not indiscriminately add `immutable=1`: it disables locking/change detection and is unsuitable for concurrent fetch writes.

6. **MEDIUM — CLI cancellation can falsely promise that nothing was stored.**

   Evidence: mail_sync_cli.py:283, cleanup at setup_flow.py:624.

   An in-memory reproduction interrupted generation publication after storing credentials, then made cleanup fail. Credentials remained, but the CLI printed `mail setup cancelled; nothing was stored`. Interrupts after successful sealing can also reach this unconditional message.

   **Fix:** distinguish pre-seal cancellation from committed or uncertain storage, and report residue/remediation whenever cleanup cannot be verified.

## Test gaps

- **Exception privacy:** test_mail_setup_flow.py:469 checks top-level rendering, which misses suppressed context chains. Add real-parser CAPABILITY/LIST BAD, untagged ALERT and BYE cases; inspect recursive context/cause, arguments and retained buffers.
- **Provider exclusion is not proved:** test_import_store.py:751 replaces the SQLite module, bypassing the shim’s captured provider. Test the actual shim with a forbidden provider.
- **Read-only filesystem guarantees:** cover initialized WAL stores, present/absent sidecars, sidecar failures, concurrent writers, and URI-special path characters. The existing `BEGIN IMMEDIATE` test does not exercise WAL.
- **Fault coverage is incomplete:** test_mail_secrets.py:207 meaningfully covers the second write, second rename and directory sync. Add first-write/rename failures, cleanup failures, key creation followed by policy-record failure, and generation publication failures after replacement.
- **Password-release proof is too weak:** test_mail_setup_flow.py:365 weak-references `_Provisional`, not the password or request. Collecting that wrapper does not establish that all password references disappeared. Add direct lifetime tracking and in-flight cancellation/failure cases.

The fixed fetch serializer, hint exclusion from JSON/audit, and Hermes tool’s handling of `flags()` failures appear compatible. No Desktop v4 mail/status consumer exists at this HEAD to validate end-to-end compatibility.

## Verdict

**REVISE.** Fix the exception-content retention, unsafe verification URI, cancellation races, provider invocation, WAL no-create guarantee, and misleading cancellation message. Add the targeted regressions above before shipping.