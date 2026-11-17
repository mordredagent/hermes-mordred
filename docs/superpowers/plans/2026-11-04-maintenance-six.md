# Six Scoped Maintenance Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. The user selected Astra design followed by SOL implementers. Steps use checkbox syntax.

**Goal:** Deliver the six reviewed maintenance changes with measured improvements and unchanged security boundaries.

**Architecture:** Six component branches/worktrees based on the committed coordination spec, followed by local integration. Shared-core and cross-component changes remain separately reviewable; no push or PR is requested.

**Tech Stack:** Python, pytest, ruamel.yaml, SQLCipher, existing native custody backends and acceptance tooling.

**Spec:** [Six scoped maintenance improvements](../specs/2026-11-04-maintenance-six-design.md); authoritative coordination: [SPEC](../../dev/SPEC.md), [PLAN](../../dev/PLAN.md), [CI](../../dev/CI.md).

## Global Constraints

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

Commands below assume `uv run` in the task worktree. If it has no environment,
use `PYTHONPATH=src ../hermes-mordred/.venv/bin/python`
with `-m pytest`, `-m ruff`, or the named script. Verify
`mordred_hermes.__file__` resolves to the task worktree before testing. Do not
reinstall dependencies merely to duplicate the existing environment.

## Review Focus

- Parser warnings under a caller's warning-as-error policy must not disclose configuration or change duplicate-anchor/custom-tag results (Task 1).
- Passive status invoked beside a contending thread must fail unavailable promptly; leaving its scope must restore normal bounded admission (Task 2).
- Fixture slimming must not turn an armed-state refusal or a real proof/fault test into an unexercised branch (Task 3).
- Metadata changes during SQL and same-inode unread-page corruption between opens must still refuse; fork must refuse before inherited locks (Task 4).
- Run-state changes during hydration and incomplete/tampered source/wheel evidence must not expose uncommitted content or grant acceptance (Tasks 5 and 6).

## Execution boundaries

Each task is one independently reviewable local branch. Task 3 follows Task 2
when editing `test_wizard_windows_status.py`, avoiding overlapping changes.
Tasks 1, 4, 5 and 6 otherwise have independent code ownership. Integrate only
reviewed commits. Each task records focused command/result/measurement evidence
in its handoff; do not update historical timing weights with host-emulated data.
Run `uv run python tools/run_critical_tests.py` once per meaningful code branch,
then its containing test modules. No worker runs the full repository suite.

### Task 1: Suppress content-bearing YAML diagnostics

**Branch:** `fix/yaml-diagnostics`.

**Files:** Modify `src/mordred_hermes/_core/_yaml_io.py`, `tests/test_yaml_io.py`;
add `src/mordred_hermes/_core/_yaml_warnings.py` for coordinated warning routing.

**Interfaces:** Preserve `load_yaml_mapping`, `yaml_mapping_from_snapshot`, and
`load_plugin_section` signatures. A private parse helper may accept a text stream
or string and `round_trip: bool`; it returns the parser's original object.

- [ ] Add parameterized tests for generic-file and checked-snapshot paths, safe/pure and round-trip modes. Use a synthetic secret-like anchor token twice, malformed scalar content and a custom tag. Assert the token appears nowhere in caplog/capsys/captured warnings, exception class is logged, existing catch selection remains exact, and round-trip tags/duplicate-anchor values retain old behavior. Assert an unrelated warning outside the parse scope still reaches its caller.
- [ ] Run `uv run pytest -q tests/test_yaml_io.py` and confirm leak tests fail before implementation.
- [ ] Route both `yaml.load` calls through thread-local ruamel `YAMLWarning` suppression without mutating warning filters. Temporarily install a coordinated `warnings.warn` dispatcher only while scopes exist; preserve unrelated warnings, arguments/source locations, nesting, exceptions and fork cleanup. Replace exception-value logging with `type(exc).__name__`, without traceback or exception chaining in logs. Preserve missing/nonmapping and exception propagation behavior.
- [ ] Run complete YAML/config/direct-tools modules and Ruff on changed files. Real-parser concurrent tests must cover both exit orders, duplicate anchors and YAML 1.1 float warnings, warning-as-error in unrelated threads, unchanged filters, nested/exception restoration, forwarding compatibility and fork cleanup. A bare lock around `catch_warnings` or an anchor-only parser switch is insufficient.
- [ ] Commit `fix(core): keep YAML diagnostics content-free` and hand off exact tests.

### Task 2: Make passive status refuse contention promptly

**Branch:** `fix/passive-status-wait`.

**Files:** Modify `src/mordred_hermes/_core/_config_io.py`,
`src/mordred_hermes/wizard/status_cli.py`,
`src/mordred_hermes/wizard/encryption_cli.py`,
`src/mordred_hermes/wizard/_windows_status.py`,
`tests/test_config_io.py`, `tests/test_wizard_windows_status.py`.

**Interfaces:** Add internal `passive_canonical_reads() -> Iterator[None]`
(context manager). Existing canonical-session APIs remain source-compatible.
Within the scope `blocking=False` performs immediate in-process acquire; outside
it uses `IN_PROCESS_WAIT_SECONDS`; `blocking=True` is unchanged.

- [ ] Measure the existing held-lock case with `uv run pytest -q tests/test_wizard_windows_status.py::test_held_lock_is_reported_not_awaited --durations=10`; record host and separate setup/call costs.
- [ ] Add tests with a real thread holder and synchronization events: passive read promptly refuses with the existing busy classification, nested passive scopes and exception exits restore policy, another thread keeps ordinary bounded admission, and same-thread nested canonical sessions still work. Keep the existing 2.0-second ordinary-wait tests. Instrument timed acquire arguments to avoid relying solely on flaky elapsed-time thresholds; use a generous under-one-second held-status check excluding fixture setup.
- [ ] Implement the scope on thread-local state with fork reset, and wrap the presentation entrypoints named above. Do not change `_windows_memory.observe` or capability admission globally: these also serve mutations. Ensure setup's later enable/proof work is outside the passive scope.
- [ ] Assert held status still reports `custody-uncertain`, no active readiness, no unwrap, subprocess, creation or mutation. Cover direct encryption status and report collection, not just one private helper.
- [ ] Run `uv run pytest -q tests/test_config_io.py tests/test_config_io_windows.py tests/test_config_io_custody.py tests/test_wizard_windows_status.py`; repeat the focused measurement. Check `tests/test_wizard_windows_memory.py` for unchanged ordinary ceremony admission.
- [ ] Commit `fix(wizard): avoid config waits in passive status`; report native Windows status evidence separately if the host is available, otherwise explicitly leave that gate outstanding.

### Task 3: Remove unnecessary Windows fixture prerequisites

**Branch:** `test/windows-fixture-cost`; base on Task 2 if touching its status test.

**Files:** Candidate edits `tests/test_windows_memory_proof.py`,
`tests/test_windows_memory_lifecycle.py`, `tests/test_wizard_windows_memory.py`,
`tests/test_wizard_windows_uninstall.py`, `tests/test_wizard_windows_status.py`.
Create `tests/_windows_memory_fixtures.py` only if shared fixture factoring actually
removes duplicated dependencies; preserve imported fixture names as needed.
No production files or native gate selectors change.

**Interfaces:** Keep `installed_runtime` session-scoped. Split the lightweight
custody/proof environment from its runtime selection, or lazily obtain that same
session fixture with `request.getfixturevalue` when a real proof requires it.
Keep per-test homes, backends, monkeypatches and issued proofs isolated.

- [ ] Collect before measurements for the four historical top modules using `--durations=20 --durations-min=0`, or a fixed documented focused selection if the whole set is slow. Preserve the selection for the after run and count installed-child launches as well as wall time.
- [ ] Audit actual consumers of `proven`, `enabled`, `proof_env`, `win` and `seeded`. Remove proof/enrollment from pure precondition tests only. First concrete candidate: `test_keep_key_false_refuses_before_any_lock_or_mutation` can use seeded files and an unusable proof sentinel with proof/lock tripwires because `keep_key=False` must refuse before inspecting it. Retain separate genuine-proof coverage.
- [ ] For `test_erase_encrypted_is_refused_on_windows`, use minimal state for redundant preflight variants while retaining an armed-state preservation case. Keep a runner on the lightweight environment and tripwire cleanup/proof/native entrypoints. Do not replace tests whose subject is a custody/proof state transition.
- [ ] Eliminate eager installed-runtime creation for tests that never launch a proof. Keep actual installed runtime/protocol/timeout/environment tests, success paths and every lifecycle publication-fault parameter intact. Do not share a mutable enrolled home or pre-issued proof across tests.
- [ ] Run `uv run pytest -q tests/test_windows_memory_proof.py tests/test_windows_memory_lifecycle.py tests/test_wizard_windows_memory.py tests/test_wizard_windows_uninstall.py tests/test_wizard_windows_status.py --durations=20`; compare the same focused selection and verify collection IDs/security cases remain. Report modest savings honestly; do not infer Windows speedups from macOS emulation.
- [ ] Commit `test(windows): avoid unnecessary proof setup in preflight cases`. Existing real-CNG live modules remain unchanged and must still collect.

### Task 4: Coalesce redundant database admission checks

**Branch:** `perf/dbcrypt-admission-checks`.

**Files:** Modify `src/mordred_hermes/dbcrypt/_authority.py`,
`tests/test_dbcrypt_authority.py`, `tests/test_dbcrypt_connections.py`.
`src/mordred_hermes/dbcrypt/_connection.py` should need only explanatory comments
or targeted instrumentation-related test support, not weaker checks.

**Interfaces:** Preserve `Authority.check`, `operation(*, check=True)`,
`register_connection`, all protected connection APIs and callback cadence.
Add a private PID-only guard if useful; it must reuse the existing fork refusal
and invalidation behavior before taking any inherited lock.

- [ ] Add observation-counter tests for one `Authority.operation` admission and registration: exactly one full metadata validation under the authority lock replaces the two old validations. Cover `check=False` semantics explicitly and do not turn it into a new external bypass. Assert callback full-check counts are unchanged.
- [ ] Add/retain refusal tests for changed marker/native source/profile metadata during a long query, cross-thread revocation, row-factory and parameter-generator reentrancy, and fork with a held inherited lock. Add same-inode corruption in a non-schema authenticated page between two opens; the second open must fail even when metadata/size are unchanged. Include an external committed write/WAL reopen control that remains readable.
- [ ] Replace only the redundant pre-lock full check with a PID guard in `operation` and `register_connection`; keep the full check under the lock. Keep the facade check after I/O-lock acquisition, all authorizer/progress checks, operation exit checks and every integrity scan. Never hold the authority lock during SQL or a busy wait.
- [ ] Run `uv run pytest -q tests/test_dbcrypt_authority.py tests/test_dbcrypt_connections.py tests/test_dbcrypt_marker.py tests/test_dbcrypt_monitor.py tests/test_dbcrypt_backup.py`. Measure a fixed many-statement workload before/after with check counters and elapsed time; explicitly state integrity scans remain and open-time cache savings are not claimed.
- [ ] Run relevant explicit database native gates from CI/VALIDATION_LOG on available isolated native hosts (source and wheel as required); preserve missing-platform gates as outstanding evidence. Do not touch production home or port 7788.
- [ ] Commit `perf(dbcrypt): remove duplicate locked admission observations` and report safety review plus measured effect.

### Task 5: Encapsulate conversation, cursor and statistics reads

**Branch:** `refactor/import-store-history-api` (cross-component spec-first slice).

**Files:** Modify `src/mordred_hermes/imports/store.py`,
`src/mordred_hermes/extension/telegram/history.py`,
`tests/imports/test_import_store.py`, `tests/extension/test_telegram_history.py`,
`tests/extension/test_history_search_tool.py`. Inspect `search.py`; modify only
if a direct/private store access is found on the execution base.

**Interfaces:** Add:

```python
ImportStore.conversations(source: Source | str, source_account: str) -> dict[str, ImportConversation]
ImportStore.conversation_stats(conv_uids: Iterable[str]) -> dict[str, tuple[int, int | None]]
ImportStore.conversation_messages(conv_uids: Sequence[str], *, since: int | None = None, until: int | None = None) -> dict[str, list[ImportMessage]]
```

`conversations` exposes the public `sync_cursor`; existing `upsert_conversation`
publishes it. The extension's existing `stored_conversations`, `committed_stats`
and `_committed_messages` can remain thin delegates for compatibility.

- [ ] Add tests using committed, open and failed runs across Telegram/mail and multiple accounts. Pin empty/duplicate/over-chunk UID sets, empty stats entries, custom participants, malformed stored rows, half-open date bounds, null dates and numeric message IDs `2`/`10`. Assert cursor publication behavior is unchanged on failed and successful sync.
- [ ] Implement public methods with store-owned decoder/helpers and one `_transaction(write=False)` per multi-query read. Hydrate on that same connection rather than calling public `parts_for` to reopen it. Preserve only messages with parts, committed-only visibility and the current Telegram reading order.
- [ ] Add a transaction regression that changes run state from another connection between selection and hydration; returned rows must reflect one committed snapshot. Preserve content-free `ImportRefused`/`StoreError` mappings.
- [ ] Replace history SQL and duplicated row decoding with delegates; keep `ImportSink.finish`'s existing run-commit/publication sequence. Do not invent atomic sync writes or alter legacy archive fallback as part of this refactor. Confirm search continues using existing public APIs.
- [ ] Run `uv run pytest -q tests/imports/test_import_store.py tests/extension/test_telegram_history.py tests/extension/test_history_search_tool.py`; run `uv run lint-imports`. Inspect the two consumers for SQL, `store.connection` and store-private access. Run complete containing Windows Telegram archive modules when touched; retain live Telegram/CNG acceptance limits.
- [ ] Commit `refactor(imports): expose public conversation history reads` separately from all other components.

### Task 6: Split acceptance tooling and test sequence/stop validation

**Branch:** `refactor/dbcrypt-acceptance`.

**Files:** Keep `tools/dbcrypt_acceptance.py` as CLI/compatibility facade. Create
`tools/_dbcrypt_acceptance_common.py` (types/constants/errors),
`tools/_dbcrypt_acceptance_evidence.py` (manifest/provenance/control/phase/sequence/stop validation),
`tools/_dbcrypt_acceptance_execution.py` (build, subprocess and phase execution),
`tools/_dbcrypt_acceptance_windows.py` (Windows package/VFS qualification).
Modify `tests/test_dbcrypt_acceptance_manifest.py` only as necessary; create
`tests/test_dbcrypt_acceptance_sequences.py` and reuse/extend inert builders in
`tests/_dbcrypt_acceptance_evidence.py`. Inspect `tests/_dbcrypt_support.py`,
`tests/_dbcrypt_acceptance_native.py`, packaging and all script imports.

**Interfaces:** Preserve existing tool function signatures and names, particularly
`_verify_mode_sequences(phases) -> None`,
`_verify_native_stops(root, matrix, phases) -> list[dict[str, Any]]`,
`verify_native_spool(root) -> dict[str, Any]`, `main() -> int` and `AcceptanceRefused`.
Execution functions may accept a private explicit dependency namespace assembled
from current facade globals on each wrapper call; it must preserve existing
`monkeypatch.setattr(tool, ...)` seams. Pure validators need no execution API.

- [ ] Build one valid synthetic 16-phase Linux/Windows source/wheel baseline and valid final stop receipts. Assert both target validators accept it, without mocking the validator being tested. Reuse evidence builders rather than native collectors.
- [ ] Parameterize missing/duplicate observation, missing mode/platform, reversed timestamps, non-increasing control sequence, action before previous completion, changed continuity identity and invalid boot relationships. Each independent mutation must refuse `_verify_mode_sequences`.
- [ ] Test missing/duplicate stop receipt, wrong instance/run, stale final stop timestamp, wrong last-cycle digest and tampered referenced receipt bytes. Exercise real `_evidence_ref`, receipt validation and control-cycle validation with inert on-disk evidence. Test `verify_native_spool` refuses invalid evidence with `live_accepted=False`, without native or cloud operations.
- [ ] Extract by the responsibilities above. Keep pure dependency direction toward common contracts, avoid import cycles, and preserve monkeypatch seams through explicit wrappers. Do not use `exec`, wholesale globals copying to another module, or magic import forwarding. Keep top-level native collectors loadable as scripts. Split large tests only along the same responsibilities if needed; do not split native collectors arbitrarily.
- [ ] Run `uv run pytest -q tests/test_dbcrypt_acceptance_manifest.py tests/test_dbcrypt_acceptance_sequences.py`; run `uv run python tools/dbcrypt_acceptance.py --help`. Exercise dynamic `acceptance_tool` imports and an existing monkeypatched `_collector_child` / `_execute_native_phase` test to prove seams still work.
- [ ] Check `_copy_inputs`/tracked-tool closure includes the extracted modules and matches hashes. Build sdist/wheel using the repository's established build command, inspect relevant entries and run inert import/CLI checks from extracted/bundled locations. Add only necessary packaging entries; the tool is not automatically a runtime wheel module. Do not launch native acceptance as a packaging smoke test.
- [ ] Run Ruff and strict mypy for changed tooling; commit `refactor(tools): separate database acceptance responsibilities`. Record that synthetic evidence tests are not live acceptance.

## Final integration

- [ ] Review each task's diff, exact focused tests and measurement limits, then integrate into a local branch. Resolve shared test conflicts preserving both changes.
- [ ] Run one `uv run pytest -q` full regression, repository Ruff check/format, strict mypy, `uv run lint-imports`, documentation links and required shell checks for touched scripts. Use the CI extras environment if optional-extra code changed.
- [ ] Reconcile only actually completed TODO items; preserve pending platform/live acceptance. Record live-device evidence only for commands actually run. Keep PR descriptions ready as `### Changes` / `### Fixes` one-line entries if later requested.
- [ ] Report six commits/branches, measured differences, full-regression result and any unavailable native gates. No claim that all Windows product acceptance is complete.
