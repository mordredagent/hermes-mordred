# Maintenance implementation plan

Scope: two reproduced bugs, three refactors, and three test-fixture optimizations against a904a840b. Claude Code Fable reviewed this plan on 2026-10-18 and approved it with amendments incorporated below.

## Constraints and ordering

- Read AGENTS.md; docs/dev/SPEC.md, PLAN.md, TODO.md and CI.md are authoritative.
- Publish the cross-component SPEC/PLAN documentation change first. Keep component migrations independently reviewable and target dev, never upstream/main.
- Separate worktrees for parallel agents. Initial independent tracks: LLM settings, package provenance, fixture optimization. Dotenv and jobs follow; serialize edits to desktop/api.py across settings/jobs.
- Preserve CLI options, HTTP/wire fields, exception/error contracts, credential serialization and security gates except the specified fixes and bounded job history.
- Use repo uv/.venv; verify imported package provenance. Isolate HERMES_HOME before imports; never use production state or port 7788.
- Critical preset plus complete affected modules during iteration. Full regression/coverage once at final integration; retain >=80% line coverage, strict mypy (including minimal CI extras), Ruff/format/shellcheck and relevant native/live gates. A skip is not a live acceptance pass.

## Task 1: Pure Telegram LLM settings and stale-key fix

Add extension/telegram/llm_settings.py with immutable-record transformations. Inputs are concrete TelegramSecrets; creating an empty record and store access remain in adapters.

    with_local_settings(current, *, endpoint, model, api_key=KEEP_KEY)
    with_venice_settings(current, *, api_key=KEEP_KEY, model=None)

Use a typed KEEP_KEY sentinel. Local omitted key retains only for an exactly equal normalized full endpoint (scheme, IP, port, path). None clears; str validates/replaces using existing validate_local_api_key. Missing/malformed old endpoints clear. Normalize with existing normalize_local_endpoint; localhost and 127.0.0.1/trailing slash equivalences follow it. Strip local model as current adapters do. Preserve all unrelated record fields.

Desktop /llm/local passes KEEP_KEY and gains no public key option. CLI maps existing omitted/clear/provided flags to KEEP_KEY/None/str. This fixes desktop/api.py:629 retaining the old key when moving to another local endpoint (confirmed in-memory repro; SPEC:186-189 requires clearing).

Venice supplied key replaces, KEEP_KEY retains; absent both raises LlmConfigError("venice_not_configured"), which the CLI maps to its current "no Venice API key given." message. Falsey/absent model retains old model; keep CLI whitespace behavior. Adapter input length/type validation, key prompts, Windows custody/acknowledgement, ensure_key ordering and public error mappings stay in place. One store.update(callback), no preliminary load/unseal.

Deliver common helper then Desktop migration then wizard migration as separate reviewable changes. Red-green bug regression must assert the saved store local_api_key is None after changing the Desktop endpoint, and show resolve_target no longer passes the old key to that endpoint.

Tests: pure table-driven transformations; same/changed/malformed endpoint, replacement/clear, unrelated fields; Desktop and CLI adapters, one update/no extra load, Windows gates. Complete test_desktop_api, test_telegram_tee, test_telegram_local_llm, test_telegram_llm_probe, test_desktop_windows_api, test_wizard_windows_telegram modules. Extend relevant synthetic settings portion of existing explicit Windows CNG gate and fresh-process reload. Real local inference gate remains relevant.

## Task 2: Environment-bound package provenance

desktop/member.py:321 currently trusts any /plugin-sources/ substring. A normal editable checkout beneath that name is accepted by update preflight and skipped by member registration (confirmed offline).

Make built_from_member(source, *, env) use the explicitly supplied target distribution Environment. Require in_venv, the managed venv layout and strict resolved descendant membership under <environment>/workspace/plugin-sources/. Reject another environment, arbitrary same-named folder, root itself, unresolved/invalid provenance and symlink escapes. Legitimate pm builds may be editable: do NOT blanket-reject editable installs (test_pm_member already covers an editable pm build). Resolve target Environment once in updater and use environment(dist) in registration. Ordinary source installs retain source-install refusal and normal member recording. Preserve existing foreign_source fresh-interpreter behavior. Share its managed-layout recognition with built_from_member and return False on OSError/ValueError from path resolution, including unsupported Windows-style provenance. Rewrite existing substring-based registration/updater fixtures with realistic sibling venv/workspace paths; patch the existing environment lookup seam where needed, without adding public env parameters merely for tests.

Tests: normal arbitrary-folder editable/noneditable source; legit managed editable/noneditable; another venv; same-name prefix; source root; symlink escape; actual installed()->refuse and member registration paths. Complete test_pm_member, test_self_update and test_desktop_windows_pm_compat.

## Task 3: Test setup reductions

- test_keyvault_backup: module-scoped immutable real backup bytes for 29 consumer cases, eliminating 28 real exports. Each tamper creates an independent bytearray. Preserve exporter roundtrip and two salt/freshness tests performing their own exports.
- test_keyvault_recovery: module-scope existing immutable valid_blob, removing 10 exports across 11 cases; each test-local monkeypatch applies only after fixture generation.
- test_keyvault_bip32: module-scoped immutable seed, removing 12 repeated PBKDF2 calls. Keep vectors, all inputs and repeated derive_path determinism assertion. Run with ethereum extra; retain BIP39 seed tests.

Do not delete security cases or mock KDF globally. Compare collection, focused line/branch coverage, call counts and timings before/after. Verify premature-decrypt/KDF fault detection remains effective. No wall-time improvement is claimed before measurement.

## Task 4: Shared dotenv text and transaction ownership

Root _dotenv_text.py owns pure parsing/validation/merge; _dotenv_io.py owns update_dotenv_file(path, transform), one process-wide RLock and transaction. Root _config_text_io.py receives existing generic POSIX bounded encoding/directory/read/atomic write/fsync helper bodies from wizard/policy_writer.py; preserve wrappers for consumers and Windows refusals. No root-to-wizard dependency; move generic implementation unchanged rather than rewriting policy I/O.

merge_assignments(text, updates, *, mode) has exactly two preserved modes:
- wizard: exact unindented KEY=/export KEY= matching, first-match deduplication, empty value removes, empty output is empty string, existing uppercase key validation.
- extension: existing trim/whitespace recognition, rewrite all matching duplicates, empty value writes KEY=, empty output newline, existing CR/LF key/value validation.

Preserve unrelated lines, export prefix behavior, insertion order, splitlines/newline normalization; no new quoting/expansion interpretation. Keep thin old private adapters where needed. Validate before filesystem mutation; preserve Windows upfront value UTF-8/size check.

POSIX transaction: same RLock, parent checks, private_flock on sibling .lock, safe read, mode-0600 atomic write, exception type/errno/chaining, idempotency/permissions, private randomized temp files and fsync/cleanup. Windows: exact .env filename, canonical_session checked bounded read/transform/write, uncertainty semantics, no raw fallback. Slack overwrite check and merge remain one locked callback.

Tests: both mode exact outputs, CRLF/comments/export/whitespace/duplicates/empty/invalid values; extension+wizard concurrent updates; permissions/symlink/unsafe files; Windows UTF-8/size/uncertainty and Slack overwrite refusal. Run complete existing dotenv/extension API/file-lock/policy-writer/config-I/O and affected wizard consumer modules, including native Windows modules. Update fault injection seams to implementation owner. Explicitly migrate policy_writer.os.open, _windows, _fsync_durable, _fsync_parent, os.replace and os.fchmod patches in test_env_file_writer, test_wizard_config_windows, test_desktop_windows_install and test_policy_writer; preserve env_file_writer._atomic_write_text compatibility where used. Audit consumers openclaw_migration, _uninstall_config, credentials_writer, memory_cli and egress_cli. Update ownership references in _file_lock.py and test_file_lock. Keep extension _validate_env_updates and wizard key validation as adapter raising sites with their current error types/text. Extract generic I/O mechanically in a separate commit before wiring the new dotenv owner.

## Task 5: Desktop bounded job lifecycle

Extract desktop/_jobs.py with typed Job/JobRegistry/JobBusy, Callable[[Job], Awaitable[None]], running/done/failed states and registry start/get/running/is_running/prune. Existing API private _start_job remains a thin seam.

Default retention: terminal results for 3600 seconds from completion, at most 64 terminal records; active jobs never expire/count toward cap. Use monotonic injected clock. Prune on start, lookup, status, completion; evict oldest completion then insertion order. No timer task. Existing update UI polls up to 30 minutes; no new UI settings.

Own Task strongly until finalization. Use typed Job.run_sync for four blocking job callbacks, retaining executor Future; preserve contextvars, shield from waiter cancellation, drain repeated cancellation until actual callable completion. Do not mark running side effects terminal or release dedup/exclusion merely because a waiter was cancelled. Preserve actual return/error after callable finishes. A callback cancelled with no backing work becomes failed/<kind>_failed. Handle pre-first-execution cancellation. Fable suggested a detached Future finalizer; retain shield-and-drain instead because the existing update/uninstall callbacks interpret return codes and construct progress after the await. A detached finalizer would lose that result mapping. Cancellation is internal only and may wait for an uninterruptible thread; it must not falsely advertise released side effects. Exactly one finalization/event; release Task/Future references. No public cancellation API.

Same-kind active start returns existing ID; update/uninstall exclusion is synchronous at final admission. Preserve update preflight/post-await checks and uninstall confirmation order. Hardware/enclave retain independence. Keep wire/event/progress shapes and HTTP 200 error behavior, including job_not_found for missing/expired/evicted records. Process restart still loses in-memory records. Migrate fixtures that patch/read api._JOBS in test_desktop_api, test_desktop_platform and test_desktop_windows_api to a fresh registry per test.

Tests: event-controlled actual callbacks (no timing sleeps), success/error, retained references/release, pre-start and active-thread cancellation including repeated cancellation, contextvars, same-kind dedup, both conflict orderings and post-preflight race, TTL exact boundary and long-running completion age, 65th terminal result, active preservation, prune triggers, event failure and wire compatibility. Run new jobs module plus complete Desktop API/platform/Windows API/page modules; affected blocking consumer modules as needed.

## Final validation and reporting

Run integrated full default suite with coverage once, relevant linters/typing including minimal extras, optional ethereum test execution and required platform checks. Run relevant explicit native/live tests only on isolated task-owned profiles/devices; record actual passes, skips and unavailable platforms separately. Do not claim hardware/live acceptance from mocks. Review each task and the whole branch. No production mutation, deployment or release is included.
