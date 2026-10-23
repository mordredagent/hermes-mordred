# Codex design review: Desktop mail and ceremony pages (2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run by the Fable session against commit 9b07f0d43 (design doc 2026-10-23-desktop-mail-and-ceremonies-design.md plus the D1 docs). Verdict REVISE (findings 1-24). Absolute links were flattened to `path:line` text. The design doc's section "Revision after the Codex design review" records how each finding was resolved.


## Findings

1. **HIGH — Hand-validating dictionary fields does not prevent secret-bearing 422 responses.**  
   Existing routes still declare `body: dict[str, Any]`, so FastAPI validates the outer shape before entering the handler (api.py:465). Against the actual mounted router, posting `["REVIEW_CANARY_APP_PASSWORD"]` returned HTTP 422 with that string in `detail[].input`. Existing tests exercise malformed fields inside dictionaries, not malformed body shapes (test_desktop_api.py:143). **Change:** specify safe JSON parsing and validation-error handling for every secret-bearing route, plus canaries for non-object bodies, malformed JSON and frontend transport-error notifications.

2. **HIGH — A failed or interrupted memory ceremony can leave an encrypted vault whose recovery phrase was never delivered.**  
   `/memory/enable` creates/enrolls the vault first, runs memory encryption second, and returns the phrase only after complete success (api.py:362). Memory conversion can fail after retaining its marker and changing files (memory_cli.py:392). A retry against the existing vault does not generate its original recovery phrase again. **Change:** design an acknowledgement-before-commit ceremony, or an equally concrete recovery protocol, covering partial failure, lost responses, navigation and backend restart. Never place the phrase in jobs or events.

3. **HIGH — The stale-anchor remedy targets the wrong Keychain service for current helpers, and its “read-only” diagnosis can mutate state.**  
   The identity hash itself contains no key material and is reasonable in the authenticated local response (identity calculation). However, helper-owned anchors use `mordred-hermes.vault.anchor.sekey`, while the proposed command deletes only `mordred-hermes.vault.anchor` (services). `default_anchor_store().read()` can migrate a legacy anchor, write the helper item and delete the legacy item; legacy access can also prompt (migration). Furthermore, `artifacts_present()` checks only manifest filenames, not complete absence of recoverable vault state (vault.py:143). **Change:** make remediation depend on K1’s backend-aware, locked diagnosis/reset contract; remove the unconditional legacy deletion command and “nothing changed/no prompt” guarantees.

4. **HIGH — The split mail setup flow permits stale flows to overwrite a newer setup or undo removal.**  
   The proposed configured check precedes the writer lock, and `finish()` reacquires the lock without a specified identity recheck. Meanwhile, `MailSecretStore.store()` explicitly replaces existing credentials (secrets.py:344). Existing forget deliberately compares setup identities under the lock (mail_sync_cli.py:554). **Change:** specify atomic admission, a setup generation/token checked under the writer lock at sealing, and invalidation of pending flows by forget. Test two browser flows, CLI setup between start/finish, and forget followed by a stale finish.

5. **HIGH — “A failing start leaves no credentials” is not guaranteed by the proposed storage seam.**  
   `store()` writes `credentials.sealed` before writing metadata; failure of the second write leaves sealed credentials behind (secrets.py:348). **Change:** define partial-commit handling and a recoverable residue state, or transactional cleanup under the same lock. Add fault injection between the two writes; do not display “Nothing was stored” for every setup failure.

6. **HIGH — The Touch ID checkbox can report a policy the existing key does not enforce.**  
   `ensure_key(require_presence=…)` preserves an existing key’s policy (secrets.py:278), while `store()` records the requested policy in `touch_id` (secrets.py:350). An unsuccessful unattended setup can therefore leave a key that a later attended setup incorrectly labels as requiring Touch ID. File-vault initialization likewise preserves an existing key’s policy (vault lifecycle:118). **Change:** distinguish requested from effective policy, define safe handling of leftover keys, and test changed choices after failed setup.

7. **HIGH — Three-second status polling is neither a purely read-only operation nor guaranteed prompt-free.**  
   `open_import_store()` calls `initialize()`, which takes `BEGIN IMMEDIATE`, even for an already initialized store (store.py:1501, store.py:649). The protection gate calls the key provider (gate:83); a cold provider can inject/unlock the vault (key provider:78). Existing page polling allows overlapping refreshes (plugin.js:1356). **Change:** define a non-unwrapping status path using already available keys, bounded/coalesced refreshes and a read-only schema-verification path. Preserve the SQLCipher refusal chain; add contention, cold-key and no-plaintext-fallback tests.

8. **HIGH — The database algorithm can leave activation unfinished or schedule conversion that startup will never execute.**  
   The new “no plaintext → `action: nothing`” branch skips arming. The CLI instead calls `migrate()`, which arms even when there are no plaintext files (databases_cli.py:115, migration:391). Conversely, scheduling conversion for an already armed home does not work: startup explicitly skips pending encryption when `armed(base)` is true (dbcrypt startup:76). **Change:** specify separate handling for activation, already protected homes and newly discovered plaintext in armed homes; test all three before promising restart completion.

9. **HIGH — “Hermes never sees a subject, name, address or body” materially misstates the privacy boundary.**  
   Counts-only applies to mail synchronization. History search deliberately returns message items and conversations to Hermes (hermes_tools.py:392); the mail tool explicitly instructs the model to use history search to read mail (mail_tool.py:79). **Change:** distinguish setup secrets, fetch results and retrieved history. Explain that reading history puts the chat into reader mode and restricts subsequent actions. Keep the existing runtime model and reader-mode gates.

10. **MEDIUM — The concurrency table misidentifies three existing synchronization mechanisms.**  
    Same-kind jobs return the existing job; they do not raise `JobBusy` (jobs:97). The macOS memory path has no claimed `memory_cli` custody-lock response; it returns a generic failure, with captures serialized separately (api.py:362, capture:65). Database migration has an exclusive lock and refuses a process holding a runtime lease, even before any database is open (locking:79). **Change:** rewrite the table around these actual mechanisms. Explicitly choose mail-job reuse versus rejection, define memory-ceremony serialization, and remove the claim that a CLI-started normal backend can migrate merely because no files are currently open.

11. **MEDIUM — “TTL 600 seconds, like LoginFlows” does not bound password retention.**  
    Telegram flows reap expired entries only when another flow starts; `get()` rejects an expired flow without removing it (login_flow.py:73, login_flow.py:113). Copying that pattern leaves abandoned mail passwords referenced indefinitely. **Change:** require active expiry cleanup, a bounded flow count, redacted representations, and removal of references on completion/cancel/expiry. Cleanup must remain possible when a protection gate becomes unavailable.

12. **MEDIUM — The proposed state model cannot restore all running, failed or restart-required ceremonies.**  
    `/status.jobs` contains only running registry jobs (api.py:185); memory enable is a direct request and Telegram import belongs to a separate service (api.py:368, api.py:648). Registry state disappears on backend restart. `job.run_sync()` also absorbs cancellation until its worker finishes, without a deadline (jobs:43). **Change:** define state precedence and reconciliation for page reopen, lost jobs, expired flows and backend restart; specify bounded shutdown behavior. “Up to 10 minutes” must account for work outside the IMAP budget.

13. **MEDIUM — The database status schema cannot substantiate the proposed completion text.**  
    With `key=None`, discovery cannot return `encrypted`; it reports unreadable ciphertext as `unreadable`, and omits missing files entirely (migration:105, migration:136). `armed` is persisted intent, not proof of process protection (dbcrypt:48). The gate also considers pending **decryption**, which the proposed status omits (gate:74). **Change:** distinguish intent, pending direction, journal recovery and runtime readiness; remove unsupported “N databases encrypted” claims and specify unknown-state rendering.

14. **MEDIUM — The IMAP hint parser misses real authentication errors, and CLI fetch has no proposed way to receive the hint.**  
    `ImapSession.login()` delegates to `imaplib.login()` (imap.py:982). The installed stdlib raises an error containing response bytes; `str(exc)` becomes `b'[AUTHENTICATIONFAILED] …'`, which fails the proposed anchored regex (imaplib.py:619). Separately, `run_fetch()` retains only the error code, and CLI fetch receives only `FetchResult` (imap_sync.py:1127, mail_sync_cli.py:465). **Change:** parse a bounded bytes/string response-code prefix from the exception argument and discard free text. Define a closed-enum diagnostic channel for CLI hints that does not expand tool/job output.

15. **MEDIUM — The proposed setup object and folder flow do not match the existing credential contract.**  
    `MailCredentials(mailboxes={})` is invalid today (secrets.py:103). Gmail can also require a manual All Mail selection when neither special-use metadata nor fallback names match; the CLI currently offers that selection (mail_sync_cli.py:240). **Change:** use a separate provisional credential type and construct validated `MailCredentials` only after selection. Define Gmail’s missing-All-Mail outcome, validate submitted selections against the flow’s choices, and provide an explicit “No sent folder” option.

16. **MEDIUM — Reusing `imap_status()` and raw flags does not establish a closed, content-free response schema.**  
    `imap_status()` returns the entire decoded `last_fetch` dictionary without field/type validation (mail_sync_cli.py:378); `flags()` returns the metadata dictionary after checking primarily the account label (secrets.py:360). The import-store refusal set also includes omitted cases such as `profile_mismatch`, `schema_newer` and `unkeyed_connection`. **Change:** define explicit response projections, numeric/boolean validation and closed code mappings for both status endpoints. Test extra canary fields and corrupt metadata, including the store-unavailable flags path.

17. **MEDIUM — The forget confirmation does not fully describe deletion scope or support recovery from partial removal.**  
    `delete_source("mail", account)` deletes all mail under that account label, including file-imported mail, not just IMAP-fetched messages (store.py:1235). Existing forget supports `--account` when credentials/flags are gone and reports `account_unknown` or `key_left` (mail_sync_cli.py:529, mail_sync_cli.py:608); the proposed route/UI lacks that recovery path. **Change:** disclose the full account-scoped deletion, strictly validate `rows`, check confirmation before state reads, expose recoverable residue, and allow validated account selection for retry. Credential-only cleanup should not require working memory encryption.

18. **MEDIUM — Per-source counts are not necessarily counts for the connected account or its active archive.**  
    `ImportStore.status()` groups by source across accounts (store.py:1458). Existing macOS Telegram archives with dialogs continue using `.enc` until migration; encryption alone does not move them into `mordred.db` (history.py:560). **Change:** label aggregate counts explicitly or add account-scoped counts. Specify legacy-archive detection/migration and its UI; do not show “nothing imported” or imply all macOS imports write to the shared store.

19. **MEDIUM — `last_fetch` cannot currently report the latest failed attempt as promised.**  
    Metadata is written after `_sync()` returns, while IMAP errors are converted into `result.error` by the outer handler after that path has unwound (imap_sync.py:1072, imap_sync.py:1127). A failed fetch can leave the previous successful timestamp/status visible. **Change:** distinguish last successful fetch from last attempt, and specify safe persistence of failed/partial outcomes without overwriting another setup’s metadata.

20. **MEDIUM — Existing secret inputs are not all cleared after failed submissions.**  
    Telegram’s API hash is cleared only after successful start (plugin.js:368); the Venice key is cleared only after success (plugin.js:444). **Change:** include these existing controls in the overhaul’s cleanup contract and tests, covering success, failure, cancellation and unmount—not only the new mail inputs.

21. **MEDIUM — “Say ‘sync my mail’ in any Hermes chat” promises a path already known to fail.**  
    TODO records the production model repeatedly failing through the deferred-tool bridge without syncing anything (TODO.md:865). Tool visibility also checks endpoint eligibility separately from the live private-model check at execution (mail_tool.py:138, mail_tool.py:262). **Change:** present Desktop fetch as the reliable path until the separate bridge fix passes production-model validation. Replace “tools are not offered” with the precise availability/refusal behavior.

22. **MEDIUM — D3 cannot replace the shared `Step` interface while leaving Windows unchanged.**  
    Windows components pass `done`, including its memory and helper steps (plugin.js:624, plugin.js:581). The supposedly unchanged Windows test explicitly requires `client_version=3` (test_desktop_windows_page.py:78). **Change:** retain a compatibility wrapper or introduce a macOS-specific step component; specify the necessary version-test update and Linux/Windows regression cases.

23. **MEDIUM — D1’s CI-map changes contradict the repository’s existing-path rule, and parallel execution needs an integration plan.**  
    The design places future-file inventory entries in D1, but the inventory test requires every path to exist (test_ci_change_scope.py:109). The canonical PLAN already assigns those entries to D2/D3 instead (PLAN.md:2510). Consequently, D2 and D3 share `ci_scope_paths.json`; separate files alone do not establish independence. **Change:** align the design with PLAN, freeze shared contracts in D1, use separate worktrees as required by AGENTS.md:82, and assign integration ownership. Preserve component boundaries if fixes require changes to imports, dbcrypt or keyvault; explicitly retain the 80% coverage floor.

24. **MEDIUM — The acceptance plan misses several new surfaces and contains an impossible live sequence.**  
    After successful setup, the proposed second setup with a wrong password must return `mail_already_configured`, not an authentication hint. The checklist also requests a page fetch capped at 100 although no limit control is specified. Existing page tests cover selected Windows code tables, not every API code (test_desktop_windows_page.py:86). Several reused messages are explicitly Telegram-specific, including mail-relevant confirmation and credential errors (plugin.js:81). **Change:** reorder the negative setup test before successful setup; align the fetch limit with the UI; add `/imports/status`, `/databases/status`, finish/cancel, residue, restart and malformed-input coverage. Extend canaries across responses, job views, events, logging, captured output and notifications, with explicit exceptions only for folder selection and the recovery-phrase display.

25. **LOW — Accessibility requirements omit accessible names and relationships for the new navigation and disclosures.**  
    The design introduces repeated “Go” links, state glyphs, Details/Change toggles and a folder radio group without specifying their accessible names, expanded state or grouping (design:186, design:206). **Change:** require contextual navigation names, textual state announcements, disclosure relationships, and a labelled radio group. Test focus preservation during polling and actual keyboard/VoiceOver behavior.

26. **LOW — A few baseline assertions are already stale.**  
    TODO already identifies the correct Desktop page and REST bridge (TODO.md:809), so the claimed location correction is already present. There is also another bare `#b91c1c` in the update failure panel beyond the two locations named in the design (plugin.js:1307). **Change:** refresh the baseline statements and enumerate the actual styling cleanup.

## Questions the design must answer before implementation

1. How does the owner obtain and acknowledge the recovery phrase before any failure or restart can make it unavailable?
2. Is K1 a prerequisite for stale-anchor remediation, and what backend-aware contract replaces the legacy deletion command?
3. What status interface guarantees no credential unwrap, no schema initialization and bounded contention while retaining SQLCipher protection?
4. What invalidates pending setup flows, and how are interrupted jobs, partial writes and leftover keys reconciled after reopening or restarting?
5. Which archive/account do displayed counts and deletion confirmations describe, and what evidence must pass before chat synchronization is advertised as reliable?

## Verdict

**REVISE — findings 1–24 must be resolved before implementation.**

Read-only review completed. No files changed; prohibited paths and database files were not read.