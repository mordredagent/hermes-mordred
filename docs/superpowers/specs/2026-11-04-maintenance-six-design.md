# Six scoped maintenance improvements

Date: 2026-11-04. Status: design for the user-requested Astra design / SOL
implementation workflow. The user selected all six items and asked execution
to continue without another approval round. Implementation uses separate local
branches; this document does not authorize a push, PR, native ceremony or release.

## Intent and boundaries

Remove a YAML diagnostic leak, make passive status promptly report contention,
reduce unnecessary test setup and database admission work, encapsulate imported
history reads, and make acceptance evidence validation reviewable. Preserve
security and externally visible results. The coordinating SPEC/PLAN change lands
before the cross-component implementation. The older TODO recommendation to
check authority only at admission/commit is **not** the design chosen here.

### Global constraints

- Keep SQLCipher-only operation, production cryptographic parameters and production timeouts unchanged.
- Preserve fail-closed custody, fork/revocation, metadata, marker, native-source, path and WAL checks.
- Keep full authenticated integrity scans on every protected database open.
- Keep ordinary nonblocking canonical admission's 2.0-second in-process wait; passive presentation explicitly opts into zero wait.
- No cached keys, shared mutable test homes, copied proof capabilities or inode-based integrity cache.
- Keep security/fault cases, real installed-child proof coverage and native-gated coverage.
- Keep CLI names, evidence formats, stable error codes, packaging and collector entrypoints compatible.
- Use one worktree per branch. No upstream PRs, pushes or release changes.
- Run critical feedback and complete affected security modules; one full regression at final integration.
- Documentation is English; preserve existing headings and record measurements with platform, interpreter and commit.

## Approaches and decisions

These are architect choices within the requested scope, not additional user
preferences. Broad caches, production timeout changes and removal of security
checks offer larger apparent savings but cannot establish equivalent safety.
The selected approach is narrow diagnostic suppression, an explicit passive
read policy, minimal fixture prerequisites, redundant-check removal, public
storage methods and a responsibility-based tool split. This produces modest,
measurable improvements without changing the trust model.

## 1. Content-free YAML diagnostics

`_core/_yaml_io.py` currently logs exception values in both generic and Windows
checked-config failure paths. Both parse paths can emit ruamel YAML warnings;
a duplicate anchor embeds the anchor name in `ReusedAnchorWarning` (the audit
used a synthetic dummy value). Suppress ruamel `YAMLWarning` subclasses only
within these loader calls. Do not convert warnings to errors or change parser
configuration: safe/pure and `round_trip=True`, custom tags, duplicate-anchor
resolution, return shapes and selected exception sets retain their semantics.
Log the exception class name, never its value or traceback. Use a shared private
parse helper for snapshots and files, keeping ruamel's lazy imports. Do not
install a process-global warning suppression policy.

## 2. Passive status has a zero-wait observation policy

`canonical_session(blocking=False)` deliberately waits up to 2.0 seconds for
the in-process guard. Status composes several such reads; the audited held-lock
case took 10.52 seconds on macOS. Preserve ordinary runtime admission behavior.
Add an internal, thread-local and nestable `passive_canonical_reads()` scope;
inside it only nonblocking canonical acquisitions use immediate acquire.
Restore policy on every exit, including exceptions and fork reset. No state,
capability or successful snapshot is cached by this scope.

Apply the scope to presentation collectors (`status_cli.collect`,
`encryption_cli.collect_status`, and independently callable Windows status
collectors) so nested capability and config reads cannot each consume a wait.
Setup may use scoped presentation helpers, but its mutation/proof/gate operations
must execute outside that scope. Held locks still produce unavailable/classified
custody results, never readiness from stale or empty state. Do not change the
semantics of `blocking=True` or hold a custody lock around a full status report.

## 3. Test setup follows each test's actual prerequisite

Historical `tools/native_test_durations.json` weights (~409s lifecycle, ~227s
wizard memory, ~173s uninstall, ~135s status) are scheduling history, **not** a
current benchmark or measured local Windows timings. `installed_runtime` in
`test_windows_memory_proof.py` is already session-scoped; do not propose that
change again.

Concrete remaining candidates are `proven` (enrollment, seed files and a real
proof child for every consumer), uninstall's `enabled` (full memory enable plus
audit enrollment), and `proof_env` (eager installed-runtime dependency even for
refusals before launch). Split prerequisites and lazily request the immutable
session runtime when needed. Optimize explicit early-refusal tests such as
`test_keep_key_false_refuses_before_any_lock_or_mutation` and
`test_erase_encrypted_is_refused_on_windows`; retain representative enrolled/
armed cases and all state-preservation assertions. Use tripwires to prove the
refusal precedes proof or native work. Do not replace lifecycle fault matrices,
stale/expired proofs, successful wizard flows or installed children with fakes.
Measure focused cases before and after, reporting setup/call separately. No
claimed speedup is accepted without same-host evidence; native Windows timings
remain a separate result.

## 4. Remove redundant admission work, preserve observation frequency

Today `Authority.operation()` does a full check before taking its lock and
another immediately under it. `register_connection()` similarly checks twice.
`ProtectedConnection._operation()` then checks after acquiring its I/O lock,
and authorizer/progress callbacks check metadata and path during SQL execution.
The outer duplicate full checks can be replaced by a PID-only pre-lock guard,
leaving the full check under the authority lock. Preserve the facade check after
the possibly blocking I/O-lock acquisition and the exit check.

Every authorizer/progress callback remains a full fresh check, including during
long SQL and before autocommit; callbacks run after arbitrary external state can
change. Do not introduce a per-operation snapshot that hides these changes.
The concrete optimization is fewer complete metadata observations per ordinary
SQL admission/registration, with identical callback observation counts. Test
this using call counters, then measure representative many-statement workloads.
Do not extend the authority lock over SQLite calls or busy waits.

Keep `cipher_integrity_check` on each protected open. An inode, size, timestamp,
SQLite data-version or authority lifetime alone cannot prove that a third party
has not corrupted an unread page or changed a WAL. A safe whole-file freshness
proof would itself need a comparable authenticated scan or a new storage trust
boundary. This scope deliberately retains scans and claims only the measured
admission savings, not an open-time integrity-cache speedup.

## 5. Public imported-history reads

`extension/telegram/history.py` owns direct SQL in `stored_conversations`,
`committed_stats` and `_committed_messages`, and duplicates conversation decoding.
`search.py` already uses public `search`, `parts_for`, `neighbors` and `sources`;
retain that boundary rather than inventing a rewrite.

Add `ImportStore.conversations(source, source_account)`, returning records whose
public `sync_cursor` is the last published cursor; `conversation_stats(conv_uids)`;
and `conversation_messages(conv_uids, *, since=None, until=None)`. These methods
own decoding, parameterized chunked selection, committed-run visibility and
hydration. The conversation API is also the public cursor read API; existing
`upsert_conversation` remains the public cursor publication API. No schema or
run-commit semantics change. Each multi-query read uses one read transaction,
so anchor selection and hydration cannot see different committed snapshots.

Preserve source/account filtering, absent statistics entries, one result per
message with parts, half-open dates, unknown-date behavior, numeric Telegram
message-ID tie breaking, archive retirement, error projection and legacy reads.
Do not adopt `find_messages` unchanged: its date upper bound is inclusive and
its tie breaker is source UID. Keep thin history compatibility wrappers where
existing tests/callers import them. No store connection/private member access or
SQL remains in the two requested extension consumers.

## 6. Acceptance tool decomposition and real negative evidence tests

Split `tools/dbcrypt_acceptance.py` by responsibility into evidence validation,
execution/build orchestration, Windows qualification, shared contracts, and a
small CLI/compatibility facade. Keep the script path and public/private helper
names used by tests and native collectors. Simple function re-exporting does not
preserve monkeypatching: execution wrappers must pass the current facade seams
explicitly to extracted code; do not silently bind old globals in another module.
Do not use dynamic `exec`, module-global mutation or cyclic import tricks.

Add direct tests for `_verify_mode_sequences` and `_verify_native_stops` using
valid synthetic baselines and independent missing, duplicate, reordered,
continuity-breaking and tampered evidence. Verify integration projects malformed
evidence to refused / `live_accepted=False`. Synthetic unit fixtures never count
as native acceptance. Verify tracked tools closure, sdist contents where applicable,
extracted source, dynamic imports and native collector script imports. Prefer
focused new test modules and shared inert evidence builders; split the destructive
native collector only if required by a real dependency boundary, not line count.

## Validation and acceptance limits

The implementation plan defines branch-specific checks. Run the explicit relevant
native gates for changed gated paths and record actual outcomes in
`docs/dev/VALIDATION_LOG.md`; unavailable hardware is an unmet gate, not a pass.
Task 4 requires current native database validation on macOS Secure Enclave,
Linux NitroTPM and qualified Windows CNG/VFS before claiming platform acceptance.
Task 2 needs native Windows read-only status contention evidence. Task 3 keeps
all existing live gates unchanged. Task 5 retains Telegram archive and native
Windows store gates; no live account claim follows from synthetic fixtures.
Task 6's tool refactor needs import/CLI/package smoke checks; native execution
behavior changes require the corresponding source/wheel acceptance path.
