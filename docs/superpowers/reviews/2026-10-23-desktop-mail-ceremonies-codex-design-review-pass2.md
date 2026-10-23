# Codex design review, second pass: Desktop mail and ceremony pages (2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run by the Fable session against commit f782f9cff (design revision + SPEC/PLAN/USAGE sync). Verdict REVISE (11 new findings, 6 SPEC gaps). Absolute links were flattened to `path:line` text. Resolved by the design doc section "Second revision".


## First-pass findings

Reviewed HEAD `f782f9cff`. “RESOLVED” below means the revised design addresses the finding; it does not mean the change is implemented.

| Number | Status | Reason |
|---|---|---|
| 1 | RESOLVED | Replacing body parameters with `request: Request` and catching JSON parsing failures prevents the relevant body-validation 422s. An isolated check using the installed FastAPI returned content-free `invalid_body` responses for arrays, malformed JSON, `null`, and empty bodies. |
| 2 | PARTIAL | Splitting memory conversion from vault creation protects against failures in the memory half. Vault creation/enrollment failure, lost responses, navigation, and backend restart can still lose the only delivered recovery phrase; see new finding 1. |
| 3 | PARTIAL | Backend-specific messaging fixes the wrong-service advice. The proposed helper “plain read” is not a dedicated public API, and manifest absence remains insufficient grounds for recommending anchor deletion; see finding 6. |
| 4 | PARTIAL | Admission and finish checks prevent overwriting credentials that remain configured. The revision explicitly permits stale completion after CLI forget, without a persistent generation check; see finding 7. |
| 5 | RESOLVED | Cleanup plus an explicit `credentials_left` residue state addresses partial publication, and “Nothing was stored” is restricted to pre-seal refusals. Implementation must test interruption between renames as well as ordinary exceptions. |
| 6 | PARTIAL | The mail policy contract improves, but concurrent pending flows can invalidate its assumptions, and the file-vault key still preserves an existing policy. See finding 8. |
| 7 | PARTIAL | Removing `initialize()` and coalescing polling addresses write-lock contention. The specified opener can still create a file and invoke an unlocking provider; see findings 4–5. |
| 8 | PARTIAL | The armed-home plaintext case correctly avoids useless scheduling. The revised algorithm still has an invalid `arm` argument, an unreachable immediate-arming outcome in Desktop, and missing state combinations; see finding 3. |
| 9 | RESOLVED | The revised privacy boundary distinguishes setup secrets, synchronization results, and retrieved history, consistent with `mordred_history_search` returning message items under reader-mode protection. |
| 10 | PARTIAL | Same-kind job reuse and the runtime lease are now described correctly, and ceremony serialization is explicitly required. Immediate database arming contradicts that lease, and direct-request worker ownership remains unspecified. |
| 11 | PARTIAL | Bounded flow count, redacted representations, and gate-independent cleanup help. Reaping only when called still does not bound idle password retention; see finding 9. |
| 12 | PARTIAL | `job_not_found` and reconciliation precedence improve registry-job handling. Telegram import is incorrectly treated as request-lifetime work, and neither direct ceremonies nor shutdown have a complete lifecycle contract; see finding 10. |
| 13 | PARTIAL | Intent, pending directions, journal state, and unknown ciphertext are now distinguished. However, the chosen runtime check can unlock, and it does not prove every discovered database is protected; see findings 3 and 5. |
| 14 | RESOLVED | Parsing `exc.args[0]` handles actual byte-valued IMAP errors, and a separate CLI diagnostic channel addresses propagation. SPEC still contains the superseded `str(exc)` requirement. |
| 15 | RESOLVED | Provisional credentials, Gmail All Mail selection, validated choices, and “No sent folder” address the code’s actual constraints. SPEC’s original fields and route table must still be reconciled with this resolution. |
| 16 | PARTIAL | Explicit projections address arbitrary metadata leakage. The allegedly complete refusal mapping still omits `disk_full`, which `ImportStore` can emit, and needs an explicit fallback policy. |
| 17 | PARTIAL | Account-wide deletion wording, retry account selection, and residue codes are corrected. Credential-only removal is still covered by SPEC’s blanket `_require_memory()` requirement, which can block the recovery path. |
| 18 | PARTIAL | Aggregate labeling and an honest `null` archive state prevent misleading zero counts. Positive legacy detection and the promised transition “until the next import” have no specified implementation path; see finding 11. |
| 19 | RESOLVED | Separate attempt/success metadata, finalized error/partial state, and setup-identity checks address the existing write-after-`_sync()` failure gap. |
| 20 | RESOLVED | The cleanup contract now explicitly covers existing Telegram and Venice controls on success, failure, cancellation, and unmount. |
| 21 | PARTIAL | Desktop fetch is correctly presented as the reliable path. The original “tools are not offered” claim remains in the design, although endpoint eligibility and execution-time model checks are separate. |
| 22 | RESOLVED | Mapping legacy `done` to `state` and explicitly updating the version assertion resolves the compatibility issue. PLAN still incorrectly says the assertions remain unchanged. |
| 23 | RESOLVED | File-owning PRs now add inventory entries; separate worktrees, integration order/ownership, and the 80% coverage floor are explicit. |
| 24 | PARTIAL | Negative-test ordering, the fetch-limit control, and additional endpoint coverage are corrected. Acceptance still lacks the critical revised-protocol cases identified below, and several original test expectations remain contradictory. |
| 25 | RESOLVED | Contextual navigation names, disclosure relationships, textual states, grouped choices, and focus-preserving polling are now explicit. |
| 26 | PARTIAL | All three color literals are accounted for. The claim that D1 must correct TODO’s page location remains stale in the design’s “Contradictions with the brief” section. |

## New findings

1. **BLOCKER — `/vault/enable` moves the recovery-phrase loss window; it does not close it.**

   The revision returns the phrase only after creating the vault and enrolling `.env`. Actual `env_decrypt_cli.enable()` initializes the vault before `add_and_verify()`, which can fail. A successful commit followed by a lost response is equally problematic: retry returns `vault_exists`, without the phrase. `FlowSession.close()` drops the retained passphrase.

   **Change:** require prepare → display/acknowledge → commit, with no vault or `.env` mutation before acknowledgement. Define expiry before commit and state-based retry after commit, including backend restart and response loss. A checkbox displayed after creation does not meet “delivered before anything can fail.”

2. **HIGH — The split creates a dead end for existing but incompletely configured vaults.**

   There is **no circular memory-key prerequisite**: env enable does not require the memory key. The dependency goes the other way—`memory_cli._enable_gate_reason()` requires an enrolled, injecting `.env`, then `_ensure_key()` creates/adopts the memory key.

   Consequently, a CLI-created empty vault, an opted-out env target, or a vault left after failed enrollment cannot progress: `/vault/enable` refuses with `vault_exists`, while memory-only enable refuses because env is not ready. Also, `env_decrypt_cli.enable()` does not create a vault when plaintext `.env` is absent and no enrolled copy exists.

   **Change:** distinguish vault existence, env enrollment/injection, and memory readiness. Allow safe resumption of env enrollment on an existing vault without generating another phrase; specify missing-env handling. Document that separate requests lose the shared `FlowSession` handle and may require another attended unlock.

3. **HIGH — The three-case database algorithm is neither executable as written nor complete.**

   `migrate()` requires `arm: Callable[[Path], None]`, not `arm=True`. If execution reaches that call, it writes the journal before calling `arm(home)`, so passing `True` fails after mutation. More fundamentally, it acquires `migration_lock()` before discovering whether any conversion is needed; the `runtime-lease refusal` therefore applies even with no plaintext files.

   The “arm immediately” Desktop outcome conflicts with both that behavior and the revision’s “always scheduled” statement. The algorithm also omits already-armed/no-plaintext homes, armed homes with stale encryption-pending markers, and conflicting decryption/journal states. `Startup` skips pending encryption when armed and processes pending decryption after pending encryption.

   **Change:** specify a total state table. Schedule unarmed Desktop activation even when no files need conversion; use the callable `dbcrypt.arm` on an authorized offline migration path. Define already-protected, restart-required, stale-pending, conflicting-direction, and journal outcomes. Do not claim `MigrationError` means “nothing changed”; reread persisted state. Discovered plaintext must force attention even when the process-level protection gate passes.

4. **HIGH — The “read-only” opener can create the store before its schema SELECT fails.**

   `keyed_opener()` uses ordinary `connect(str(path))`, which opens with creation enabled. A never-created store can therefore become an empty file before the `import_meta` query reports missing schema. Reusing `store_path()` also creates directories and can change their permissions.

   **Change:** specify noncreating path resolution and a genuinely read-only SQLCipher connection, including sidecar behavior. Missing file/schema must return `store_uninitialised` without creating anything. Preserve profile binding, keyed-connection/plaintext checks, and schema-version validation without calling `initialize()` or performing upgrades. An existence check followed by the current creating opener is insufficient.

5. **HIGH — The proposed status path still has two routes to a vault unlock.**

   The database status definition directly calls `check_protection()`, whose `_key_resolves()` invokes the provider. Separately, bypassing that check for imports does not bypass the provider inside the `SQLCipher shim’s connect()`.

   Environment membership is not sufficient protection: an empty or malformed `HERMES_MEMORY_KEY` passes the proposed membership test, but `KeyProvider.__call__()` treats it as unresolved and can inject/unlock the vault.

   **Change:** define one injection-disabled protection/key-resolution interface for both status objects and the connection itself. Validate/decode available key material; do not merely test membership. Test absent, empty, malformed, and valid keys with an injector that fails the test if called.

6. **HIGH — The helper-anchor diagnosis relies on an unspecified API and still authorizes unsafe legacy deletion.**

   `HelperAnchorStore` has no dedicated public nonmigrating read method. Its `read()` migrates when the default store has a legacy fallback. A private `_helper_read()` exists; alternatively, explicitly constructing the store without a legacy fallback avoids migration, but older-helper behavior must then be handled.

   Thus this is feasible, but not through an unspecified “plain read” of the default instance. Moreover, `artifacts_present()` only checks manifest filenames. It does not establish that deletion is safe or protect against concurrent initialization.

   **Change:** name and test the exact nonmigrating adapter, including unsupported helpers, read failures, and both stores being present. Keep diagnosis informational until K1 supplies locked reset semantics; do not recommend legacy-anchor deletion based solely on this heuristic.

7. **HIGH — CLI forget remains reversible by a stale browser flow.**

   The revision explicitly permits: start a pending setup → CLI forget → finish the old browser flow → credentials are sealed again. Checking “no credentials sealed” cannot distinguish a pristine home from one where the user deliberately removed credentials. The existing `forget identity check` protects against changed setups during removal, but it provides no surviving generation for a pending setup to validate afterward.

   **Change:** introduce a nonsecret setup generation/tombstone shared by CLI and Desktop, updated under the writer lock and retained across forget. Finish must compare its admission generation under that lock. Inability to call an in-memory `cancel_all()` from CLI is not a reason to permit resealing after removal.

8. **HIGH — Key recreation can invalidate another flow’s effective-policy result, and vault policy remains untreated.**

   Two pending flows are allowed. Flow A can create an attended key and wait for folder selection; flow B can see “no sealed credentials” and recreate that same key with unattended policy. A’s later finish checks only credentials and TTL, so its earlier policy result can be stale. The current `mail seal` uses whichever key currently exists under the fixed key ID.

   Separately, `file-vault initialization` explicitly reuses an existing key and preserves its policy; the revision’s mail-only changes do not address that first-pass concern.

   **Change:** establish/revalidate key identity and effective policy at sealing under the writer lock, or invalidate pending flows whenever key generation changes. Extend the effective-policy contract to vault creation, with safe orphan detection; never silently promise the requested policy for an existing key.

9. **MEDIUM — “Reap on every call” still permits indefinite password retention.**

   With no subsequent call, expiry never runs. The two-flow cap limits quantity, not lifetime; navigation cleanup cannot be relied upon after a crashed or disconnected browser. This retains the essential defect of the existing `LoginFlows` lifecycle`.

   **Change:** require backend-owned expiry timers or a periodic reaper independent of requests and protection gates, plus shutdown cleanup. Test expiry while no requests arrive.

10. **MEDIUM — The revised operation-state and shutdown claims contradict the actual execution model.**

    Telegram import is not merely running “during the request”: `start_sync()` creates a background task and returns. Its existing service status exposes `syncing`, progress, and failure, so ignoring that status regresses reopen behavior.

    Fetch timing also includes store preparation and credential unwrap before the IMAP deadline is created. `Job.run_sync()` drains cancellation until the worker finishes; it has no shutdown deadline.

    **Change:** reconcile Telegram execution through `/sync` status, and give vault/memory workers ownership and serialization that survive request cancellation. Define an actual shutdown/cancellation policy covering pre-IMAP work and final writes, or remove the bounded-shutdown claim. “About 10 minutes” is not that policy.

11. **MEDIUM — `legacy_dialogs > 0` is unreachable through the specified metadata-only path.**

    `ArchiveStore.load_index()` decrypts the entire index before obtaining either its version or dialogs. There is no plaintext dialog-count metadata. The `null` fallback is therefore correct for an existing index without its key, but “unknown until the next import” requires an additional observation/update path that the revision does not specify. Existing legacy dialogs also cause `select_sink()` to continue using the archive.

    **Change:** either specify an unknown-only cold-status contract with suitable migration guidance, or add a counts-only observation populated during an already-authorized import and define its freshness/invalidation. Polling must not unwrap Telegram credentials to manufacture the positive case.

## SPEC gaps

- **Vault controls still target the wrong ceremony.** SPEC:4933 sends the Touch ID choice to `/memory/enable`; SPEC:5147 moves key creation to `/vault/enable`. Move the control and payload to the creation step, and define status fields for vault existence and env readiness.

- **The mail flow has two incompatible contracts.** SPEC:5022 still declares `creds: MailCredentials`, empty Gmail choices, and `finish(flow_id, sent)`; the route table accepts `sent` and omits `question`. SPEC:5093 requires provisional credentials, Gmail selection, `question`, and `selection`. Replace the obsolete definitions with one complete request/response contract.

- **Cleanup gating remains contradictory.** SPEC:5052 puts all listed routes behind `_require_memory()`, while cleanup must remain possible when protection is unavailable. Explicitly exempt cancellation and credential-only forget, add `account` to the forget body table, and specify strict boolean validation for `rows`. Also reconcile body-free cancel routes with the universal object-body requirement: either clients send `{}` or empty bodies are explicitly accepted there.

- **The IMAP parser has mutually exclusive requirements.** SPEC:5126 still requires `str(exc)`; line 5139 requires `exc.args[0]`. Remove the former and reconcile “FetchResult unchanged” with the diagnostic attribute. Its current serializer enumerates dataclass fields, so adding a dataclass field without adjusting serialization would violate the closed result schema.

- **Database and state rules must be rewritten consistently.** SPEC:5157 says database migration is always scheduled, while SPEC:5195 promises immediate arming. The earlier generic “running restored from jobs” rule also conflicts with the later exceptions; specify precedence per operation so configured status does not hide a running fetch or failed ceremony.

- **The closed mappings and privacy exceptions are incomplete.** Add an explicit mapping for `disk_full` from `ImportStore._classify()`, and a safe fallback for unexpected codes. Narrow “secrets never reach storage” to plugin/browser storage and unencrypted persistence; deliberate sealed storage is required. Explicitly exempt folder-selection labels and the recovery display from the blanket counts-and-codes-only rule.

- **PLAN and USAGE still contradict the revision.** PLAN:2549 says Windows assertions remain unchanged, despite the required version update. USAGE:642 still promises encrypted/missing classifications and immediate arming; USAGE:658 places the vault-policy choice at the memory step and gives unconditional anchor-deletion advice. Update these, the stale TODO-location assertion, and superseded acceptance expectations rather than relying on readers to combine conflicting clauses.

## Verdict

**REVISE.** Before implementation:

1. Close recovery-phrase delivery failures and define resumable vault/env states.
2. Make database activation exhaustive and executable; make status genuinely noncreating and non-unlocking.
3. Replace heuristic anchor-deletion advice with a safe diagnosis/reset boundary.
4. Add cross-process setup invalidation, policy-safe sealing, active expiry, and operation reconciliation.
5. Reconcile SPEC, PLAN, USAGE, and acceptance tests with those contracts.

Read-only review completed. HEAD and the clean worktree were unchanged. No prohibited paths or database files were read; execution was limited to an isolated, in-memory FastAPI check.