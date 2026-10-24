# Cross-platform Database Encryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Protect every scoped Hermes database and `mordred.db` with one root-owned SQLCipher authority on macOS, Linux, and supported Windows, including usable activity, Telegram, and mail storage.

**Architecture:** Preserve the existing ciphertext and migration protocol while replacing ambient keys with leased native root authority and non-interactive metadata validation. Establish low-level
key-destruction guards before activation; Windows additionally requires a proven same-library extension boundary followed by a separately reviewed checked native VFS. Land prerequisite contracts and
consumers in separate component PRs.

**Tech Stack:** Python 3.11+, `uv`, pytest, SQLCipher via `sqlcipher3-wheels>=0.5.4`, HKDF-SHA256, existing Secure Enclave/TPM/CNG backends, POSIX leases and Windows native handles, a C SQLite
extension using `sqlite3_api_routines`.

**Spec:** [Approved design](../specs/2026-10-24-cross-platform-database-encryption-design.md). Read with `docs/dev/STATE_DB_ENCRYPTION.md`, `docs/dev/CI.md`, `docs/dev/PATHS.md`, and repository
`AGENTS.md`.

## Global Constraints

- Preserve HKDF-SHA256 with length 32, `salt=None`, and `info=b"mordred sqlite v1"`; SQLCipher salt is `HMAC-SHA256(database_key, b"mordred sqlite salt v1")[:16]`; preserve the 112-byte plaintext
  header.
- Keep the Python 3.11 minimum; root database keys and child memory/Journey keys remain independent.
- One root domain covers root `state.db`, protected siblings, child profiles, `mordred.db`, recognized backups, and sidecars. JSONL/text logs retain separate policy.
- Managed Linux/Windows homes require explicitly enrolled root native memory custody; no environment/file-vault fallback, silent repair, empty recreation, or implicit rekey.
- Acquisition order: root shared/exclusive database lease → custody locks in existing internal order → database locks in canonical path order. No shared-to-exclusive upgrade or reverse-lock callback.
- Runtime metadata checks must not unwrap private keys or prompt per query/commit. Cached RAM keys cannot promise immediate hardware revocation.
- Windows initial scope is fixed local NTFS, x64 Windows Server, ordinary non-elevated token; neither Windows 11 nor Desktop acceptance is implied.
- Windows VFS feasibility PASS precedes Windows implementation; feasibility is not security acceptance. Failure requires a revised reviewed design, never an unchecked fallback.
- No second SQLite library or raw database-file probes in a live protected process; retain rollback journal for `mordred.db` and the WAL-reset vulnerability guard.
- No production homes, port 7788, upstream PRs, new account integrations, or portable Linux/Windows recovery.
- English documentation; preserve existing headings; PRs target `dev`, one component per PR; record one-line Changes/Fixes in PR descriptions, no CHANGELOG.
- This document authorizes no execution by itself. Implementation follows plan review; AWS starts additionally require the bounded-stop prerequisite below.

## Review Focus

1. Same spelling, different physical root/SID: reject before access and terminate
   held connections; Task 4 `test_replaced_root_invalidates_held_cursor`.
2. Cached key with absent hardware versus absent metadata: metadata loss is
   terminal without another unwrap; Task 4
   `test_cached_hardware_loss_differs_from_record_loss`.
3. Legacy `1\n` marker with child-key ciphertext: preserve bytes and refuse
   ambiguous adoption; Task 7 `test_legacy_mixed_profile_keys_refuse_without_mutation`.
4. Backup publication crash before inventory commit: retain the key dependency;
   Task 7 `test_backup_publish_crash_retains_dependency`.
5. Windows sidecar creation during parent replacement or hostile inheritance:
   no public creation window; Task 5 `test_sidecar_creation_race_has_no_public_window`.

---

## File map, PR ownership, and execution order

**Execution amendment (owner follow-up, 2026-10-24):** Consolidate all tasks in
PR #270. The PR slices below remain logical ownership and validation checkpoints,
not separate delivery PRs. Use isolated subagent worktrees for independent
implementation tasks; the primary agent integrates them and maintains this
plan’s ledger across context compactions. This supersedes the earlier Native-only
execution and one-component-per-PR delivery preference for this approved change.

Paths below are exact intended files; new paths are inline code deliberately. Tests listed in tasks are complete-module acceptance sets, not permission to run only new test functions.
Module paths starting with a component name are relative to
`src/mordred_hermes/`; bare sibling filenames in a task's file row belong to
that named component, except explicitly listed test/native/document paths.

| PR | Tasks | Owner and file responsibilities |
| --- | --- | --- |
| P0 | prerequisite | Approved cross-component specification and this plan; no runtime changes. |
| P1 | 1 | dbcrypt research: `native/dbcrypt-vfs/probe.c`, `build.ps1`, `tools/dbcrypt_vfs_probe.py`, `tools/dbcrypt_acceptance_control.py`; diagnostic artifacts only. |
| P2 | 2 | dbcrypt-owned shared prerequisites: top-level `_database_contracts.py` bindings, `_database_inventory.py` dependencies, `_database_lifecycle.py` leases, `_database_locking_posix.py`/`_database_locking_windows.py`; inert contracts before consumer activation. |
| P3 | 3 | keyvault: new `_database_authority.py` native snapshots and `_database_mutation.py` preceding broker; existing memory/native/Windows custody deletion boundaries. |
| P4 | 4–8 | dbcrypt: authority/marker, checked Windows VFS, guarded connection/monitor, migration/backup, driver packaging and CI mappings. Review each task before proceeding; activate only after P3. |
| P5 | 9 | activity/import storage: `_gate.py`, store/peers/path checks, shared import destination adapter. |
| P6 | 10 | keyvault: versioned Windows role schema and independent native mail key API; mail consumer remains disabled. |
| P7 | 11 | Telegram: store, migration/archive/destinations/forget; no mail or wizard edits. |
| P8 | 12 | mail: independent native credentials and import/sync/forget storage. |
| P9 | 13 | wizard: CLI/setup/status/lifecycle consumers. |
| P10 | 14 | Desktop/extension UI consumers; storage support distinct from native Windows Desktop qualification. |
| P11 | 15 | Acceptance tooling and source-of-truth documentation only; any discovered product fix returns to its owning component PR. |

P1 is the first execution gate. P2–P3 can be independently reviewed as inert prerequisites, but all Windows downstream tasks depend on a recorded P1 PASS. P4 precedes P5/P7/P8/P9/P10; P6 precedes P8.
These PR-sized slices can become separate execution plans without changing the contracts here. Do not combine components to make an intermediate UI advertise unfinished support.

At the start of each owning PR slice run `uv run python tools/run_critical_tests.py`; repeat only for meaningful changes. For every task: write its named tests; run the specified red command and
require an assertion/import failure (not a skipped gate); implement; run its complete modules and relevant native gate; inspect diff; commit only the named task files. All new test helpers belong in
`tests/_dbcrypt_support.py` (synthetic homes, drivers, fault scheduler) or `tests/_dbcrypt_native_support.py` (native devices); neither may substitute mocks for a claimed live result. Code assertions
below belong inside the named scenario tests immediately above them; scalar observations are local values captured by those tests, not additional product/helper APIs. Implement fixtures in the named
helper modules and use spies for call counts.

## Task 1: Establish Windows VFS viability and bounded AWS operation (P1)

**Files:** Create `native/dbcrypt-vfs/probe.c`, `native/dbcrypt-vfs/build.ps1`, `native/dbcrypt-vfs/README.md`, `tools/dbcrypt_vfs_probe.py`, `tools/dbcrypt_acceptance_control.py`,
`tests/test_dbcrypt_vfs_probe.py`, `tests/test_dbcrypt_acceptance_control.py`, `tests/integration/test_dbcrypt_windows_vfs_probe.py`. Evidence goes under an external private acceptance root, not
committed secrets or fabricated CI history.

**Interfaces:** Produce `probe(*, output: Path) -> ProbeResult` with frozen `ProbeResult(wheel_version: str, sqlite_version: str, sqlcipher_version: str, extension_loaded: bool, persistent: bool,
selected_vfs: str, callbacks: tuple[str, ...], same_library: bool, shm_boundary_viable: bool)`; CLI `uv run python tools/dbcrypt_vfs_probe.py --output <evidence.json>`. Produce controller subcommands
`arm`, `start`, `stop`, `verify` accepting `--instance`, `--profile intmax-dev`, `--region ap-southeast-1`, `--evidence`; `arm` additionally requires `--deadline-utc` and returns a durable receipt.

- [ ] Write `test_probe_rejects_missing_shm_boundary` asserting a successful encrypted SELECT with `shm_boundary_viable=False` returns failure; `test_watchdog_stops_after_worker_crash` asserts mocked
  EC2 stop precedes the deadline and start without a verified receipt raises. Native `test_current_wheel_vfs_callbacks` requires `extension_loaded`, `persistent`, `same_library`, and
  `shm_boundary_viable` all true and observed `xOpen/xDelete/xShmMap/xShmUnmap`.

```python
assert not result.shm_boundary_viable  # encrypted SELECT alone is insufficient
assert probe_exit_code == 1
assert ec2_stop_calls == [owned_instance_id]
```

- [ ] Red: `uv run pytest -q tests/test_dbcrypt_vfs_probe.py tests/test_dbcrypt_acceptance_control.py`; expect missing API/assertion failures.
- [ ] Implement the controller independently of the guest/test worker: persistent external supervisor, bounded deadline (maximum 2 hours), credential validity beyond deadline, watchdog heartbeat and
  unconditional stop/retry/verification. Record pre-start state and a unique owned-run token; refuse to take over or stop an already-running instance belonging to another task. Stop only instances
  this receipt started. An existing approved external scheduler is acceptable with a verified receipt; do not create IAM/ingress speculatively. If no independent bounded stop can be armed, do not
  start. Record failure and stop this gate.
- [ ] Implement a diagnostic C VFS wrapper loaded into an in-memory connection through that connection's extension loader and `sqlite3_api_routines`; pin its registration/library lifetime with
  `SQLITE_OK_LOAD_PERMANENTLY` persistent-extension support
  ([SQLite result-code reference](https://sqlite.org/rescode.html)). Record wheel hash/module location, compiler/ABI, SQLCipher/SQLite versions, loaded modules, selected VFS, callbacks, and SHM ownership. Trace
  whether an owned implementation of SHM is possible without delegating pathname opens; a tracing wrapper alone is not the production boundary.
- [ ] Green unit modules above. After execution approval, verify existing stopped instance `i-00f4db5c3a204906b`, arm then start through the controller, reuse prior SSM/ordinary-user SSH. If guest
  access is absent, stop and report; do not assume stopped SSM inventory proves access. Build against current installed SQLCipher wheel, disable arbitrary extension loading after initialization, close
  bootstrap and prove later connections retain registration.
- [ ] Native command: set `MORDRED_DBCRYPT_VFS_PROBE=1` and `MORDRED_DBCRYPT_TEST_ROOT` to an existing private synthetic root, then `uv run pytest -q -o addopts= -m integration
  tests/integration/test_dbcrypt_windows_vfs_probe.py`. Run from source and a fresh sdist-built installed wheel outside checkout. Copy probe runner/tests and the diagnostic DLL to the external
  acceptance bundle explicitly: current package force-includes do not ship them automatically. Verify product imports come from the fresh wheel and `sqlcipher3` from its installed driver; the
  diagnostic DLL must load from the copied bundle, never the checkout. PASS requires rollback/WAL/SHM, bootstrap-close persistence, encrypted FTS/Japanese round trip, and same-library ABI evidence.
  Record failure artifacts even when PASS is impossible.
- [ ] Independently query EC2 until stopped, preserve receipt/evidence. On FAIL,
  stop Windows work and return for design review; on PASS, label the probe as
  feasibility only.
- [ ] Commit P1 files with `test(dbcrypt): establish Windows VFS feasibility gate`.

## Task 2: Freeze shared bindings, lease ordering, and dependency inventory (P2)

**Files:** Create `src/mordred_hermes/_database_contracts.py`, `_database_inventory.py`, `_database_lifecycle.py`, `_database_locking_posix.py`, `_database_locking_windows.py`,
`tests/test_dbcrypt_contracts.py`, `tests/test_dbcrypt_inventory.py`, `tests/test_dbcrypt_locking.py`; modify `dbcrypt/_locking.py` without activating Linux/Windows database use.

**Interfaces:** Frozen dataclasses in top-level `_database_contracts.py`: `RootIdentity(platform: Literal['darwin','linux','win32'], volume: int, file_id: str, owner: str)`; `NativeSnapshot(root:
RootIdentity, provider: Literal['secure-enclave','tpm','cng'], generation: str, record_sha256: str)`; `Dependency(path: Path, kind: Literal['database','pending','journal','backup','unknown'],
generation: str | None)`; `Inventory(entries: tuple[Dependency, ...], complete: bool)`. Export `DatabaseRefused(RuntimeError)`, `ExclusiveLease.assert_held(root: Path) -> None`,
`acquire_exclusive(root: Path, *, timeout: float = 0.0) -> ContextManager[ExclusiveLease]`, and `acquire_runtime(root: Path, *, timeout: float = 120.0) -> ContextManager[RuntimeLease]`;
`RuntimeLease.check() -> None`, `RuntimeLease.close() -> None`. `_database_inventory.scan_dependencies(root: Path) -> Inventory`; `assert_mutation_safe(root: Path, generation: str | None, lease:
ExclusiveLease) -> None`.

- [ ] Write `test_root_lease_precedes_custody` asserting event order `['database_exclusive','custody','database_operation']`; `test_no_in_place_upgrade` asserts `DatabaseRefused`;
  `test_unreadable_inventory_blocks_deletion` asserts `complete is False` and no deletion; parameterize database/pending/journal/backup/unknown and unknown generation, all block destruction.
  `test_unrelated_home_files_are_not_database_dependencies` preserves ordinary
  config/memory files and denied program trees while an unknown in-scope DB
  candidate still refuses destructive mutation.

```python
assert events == ["database_exclusive", "custody", "database_operation"]
assert inventory.complete is False
assert native_delete_calls == []
```

- [ ] Red: `uv run pytest -q tests/test_dbcrypt_contracts.py tests/test_dbcrypt_inventory.py tests/test_dbcrypt_locking.py`.
- [ ] Implement types and OS adapters in these top-level no-SQL modules: keyvault imports them without importing `dbcrypt.__init__`, the shim, or native custody. `_database_lifecycle.py` owns lease
  functions; `_database_inventory.py` owns scans/guards; `dbcrypt/_locking.py` re-exports compatibility wrappers. Export no public callback that acquires a lease from inside custody. Implement OS
  adapters. POSIX uses stable private lock inodes and `flock`; Linux holder inspection uses `/proc` with permission/disappearance uncertainty distinguished from empty. Windows uses checked native
  handles/shared-exclusive locking, fixed identity, and verified sharing/rename exclusion; do not hold canonical custody sessions for runtime lifetime. Forked children discard inherited authority and
  reacquire, never unlock a parent's lease accidentally.
- [ ] Implement conservative inventory of root, profiles, recognized backups, pending conversions, sidecars, and recovery journals; unknown/unreadable entries block mutation. No raw live DB reads.
  Discovery and monitor `OSError` paths retain unknown/error states; swallowed permission errors cannot be treated as absent files. `generation=None` means unknown/all, never no dependency. Exclusive
  lease is checked before scan and held until mutation completes. Apply the
  existing database scope/deny policy: unrelated program trees and ordinary
  non-database home files are not unknown database dependencies. An unknown
  in-scope database/state/registered-backup candidate still blocks mutation.
- [ ] Green complete modules above plus `tests/test_dbcrypt_lifecycle.py tests/test_dbcrypt_migrate.py`. Add `test_holder_visibility_unknown_refuses` and multiprocess shared/exclusive/crash-release
  tests. Native Windows lease/rename assertions later run under Task 5's explicit gate; untested Windows lease capability stays false.
- [ ] Commit P2 only: `refactor(dbcrypt): define inert authority and lifecycle contracts`.

## Task 3: Put custody snapshots and mutation guards below every destructive API (P3)

**Files:** Create `keyvault/_database_authority.py`, `keyvault/_database_mutation.py`, `tests/test_keyvault_database_authority.py`, `tests/test_keyvault_database_guard.py`; modify
`keyvault/_memory_key.py`, `_windows_custody.py`, `_memory_storage.py`, `native.py`, `_storage.py`, `vault.py`, `api.py` only at native-memory/vault destruction entrypoints; update
`docs/dev/PATHS.md` for the new source-binding record. Paths are under
`src/mordred_hermes/` unless prefixed `tests/`.

**Interfaces:** Consume Task 2 types. Produce `observe_database_source(*, root: Path) -> NativeSnapshot` (no unwrap); `load_database_source(*, root: Path, expected: NativeSnapshot) -> bytes` (fresh
native resolution); `database_key_mutation(*, root: Path, generation: str | None) -> ContextManager[ExclusiveLease]`. Add keyword `database_lease: ExclusiveLease | None = None` to Windows
`delete_role`, `reset_role`, and `reconcile_pending`; memory mutations without a valid preceding lease refuse. A public broker acquires exclusive authority BEFORE opening `windows_custody_session` or
`memory_key_lock`.

Also produce `enroll_database_source(*, root: Path, lease: ExclusiveLease) -> NativeSnapshot`
for explicit enable/adoption. On Linux/macOS it authenticates the existing
memory-key source before creating private `mordred/db-key-source.json`: exact
JSON fields `{version: 1, root: {platform, volume, file_id, owner}, provider,
generation, record_sha256}` plus LF, using Task 4's encodings. Source observation
is load-only and refuses an absent/unreadable binding; runtime cannot create it.
Windows uses its existing checked memory-role generation and needs no duplicate
generation file. An existing source binding is reused only if it matches; a
change requires exclusive reconciliation and authenticated dependency checks.

- [ ] Write `test_direct_delete_and_reset_cannot_bypass_database_dependencies`, parameterized over Linux delete, Windows delete/reset/reconcile, macOS memory-key deletion and vault purge; assert
  native delete call count is zero for every dependency kind. `test_already_locked_custody_does_not_acquire_database_lease` asserts refusal before attempting any lock callback;
  `test_snapshot_does_not_unwrap` asserts unwrap count zero.

```python
with pytest.raises(DatabaseRefused):
    delete_linux_memory_key(home=root, backend=backend)
assert native_delete_calls == []
assert unwrap_count == 0  # observe_database_source only
```

- [ ] Red: `uv run pytest -q tests/test_keyvault_database_authority.py tests/test_keyvault_database_guard.py`.
- [ ] Implement snapshots with checked physical root and owner (canonical binary SID hex on Windows; decimal UID on POSIX). Generation is the existing native role generation where available;
  Linux/macOS adoption writes a private random 32-hex generation only under exclusive authority after source verification. `record_sha256` hashes canonical public authority metadata plus wrapped
  memory-key bytes or the macOS vault's stable device-wrapping header record;
  never hash plaintext secrets into public records. Exclude unrelated manifest
  epochs and `.env` payload ciphertext so normal unrelated secret/file updates
  do not revoke database authority. Supported memory-key-value replacement must
  pass the preceding mutation broker. Missing/unreadable/malformed inputs refuse.
  Add `test_unrelated_vault_update_preserves_database_source_binding` and
  `test_enrollment_requires_exclusive_source_verification`.
- [ ] Refactor `delete_linux_memory_key`, Windows `delete_role/reset_role/reconcile_pending/enroll_memory`, `_memory_storage.disable_memory_encryption`, macOS vault destruction/rekey, and
  helper-removal guard APIs through the preceding broker; do not bolt a reverse-lock dbcrypt callback into `_delete_guard`. Guard enrollment replacement, native-key deletion, purge, reset, disable,
  rotation and pending-delete recovery. Reject unbrokered root-memory destructive calls even with `erase_authorized=True`; preserve independent child memory operations while validating their actual
  root/domain relationship. Native low-level backends must not expose an unguarded managed-memory delete route. Raw external TPM/CNG tools are outside the same-user threat model. Add an import-graph
  subprocess test loading keyvault guards while rejecting any import of `dbcrypt`, its shim, or SQLCipher. Expose `assert_database_helper_removal_safe(root: Path, lease: ExclusiveLease) -> None` for
  later wizard uninstall consumers; absence of a configured dbcrypt plugin does not bypass pending/marker checks.
- [ ] Green new modules plus complete `tests/test_keyvault_memory_key.py tests/test_windows_custody.py tests/test_windows_custody_reset.py tests/test_windows_memory_lifecycle.py`. Execute relevant
  existing gates: `MORDRED_LINUX_ORCHESTRATION_TEST=1` with `tests/integration/test_linux_memory_orchestration_tpm.py`; `MORDRED_TEST_WINDOWS_CUSTODY_LIVE=1` with `tests/test_windows_custody_live.py`;
  `MORDRED_KEYVAULT_LIVE=1` with `tests/integration/test_keyvault_macos.py`, each using `uv run pytest -q -o addopts= -m integration` and isolated roots as CI.md requires.
- [ ] Commit only keyvault slice: `fix(keyvault): guard native memory mutation with database dependencies`. Do not activate cross-platform databases in this PR.

## Task 4: Bind runtime authority and terminal invalidation (P4a)

**Files:** Create `dbcrypt/_authority.py`, `_marker.py`, `tests/test_dbcrypt_authority.py`, `tests/test_dbcrypt_marker.py`; modify `dbcrypt/_key.py`, `__init__.py`.

**Interfaces:** `Authority.acquire(home: Path) -> Authority` (classmethod); properties `root: Path`, `snapshot: NativeSnapshot`, `key: DatabaseKey`, `terminal: bool`; methods `check() -> None`,
`invalidate(reason: str) -> None`, `close() -> None`, `register_connection(connection: GuardedConnection) -> None`. `GuardedConnection` is a protocol in top-level `_database_contracts.py` with
`invalidate() -> None`. Marker types are frozen `Marker(snapshot: NativeSnapshot)` and `LegacyMarker(raw: bytes)` in `_marker.py`; the codec owns fixed version/format fields. Marker API:
`read_marker(root: Path) -> Marker | LegacyMarker | None`, `write_marker(root: Path, snapshot: NativeSnapshot, *, lease: ExclusiveLease) -> None`.

Marker v2 at existing `mordred/db-encryption.marker` is canonical UTF-8 JSON plus LF with EXACT fields: `version: 2`, `format: 'mordred-sqlcipher-v1'`, `root: {platform, volume, file_id, owner}`,
`provider`, `generation`, `record_sha256`. Reject duplicate/extra fields, bool-as-int, noncanonical hex, unsupported versions, missing fields. POSIX file identity is decimal inode in `file_id`;
Windows file ID is 32 lowercase hex. Volume is st_dev/volume serial; digest is 64 lowercase hex. Marker bytes `b'1\n'` mean legacy, never implicitly v2. Windows generation is 64 lowercase hex from its
existing role record; Linux/macOS generated authority IDs are 32 lowercase hex. Generation changes are not accepted in place. Snapshot hashes include only canonical root/provider/memory-role binding
and its authoritative wrapped bytes, not unrelated role metadata; adding mail must not silently change database authority.

- [ ] Write `test_child_profile_uses_root_key_not_memory_key`: different root/child keys, assert database derivation equals root and child memory still uses child.
  `test_replaced_root_invalidates_held_cursor` and generation/SID/wrapped-record variants assert all held objects refuse and no committed writes. `test_cached_hardware_loss_differs_from_record_loss`:
  hardware inaccessible with unchanged metadata may keep cached operations; missing record terminates; reacquisition with absent hardware refuses.

```python
assert child_authority.key == derive(root_memory_key)
assert child_authority.key != derive(child_memory_key)
assert unwrap_count == 1  # acquire plus 100 operations/commits
assert authority.terminal is True  # after wrapped-record disappearance
```

- [ ] Red: `uv run pytest -q tests/test_dbcrypt_authority.py tests/test_dbcrypt_marker.py`.
- [ ] Implement exact root resolution through trusted profile/path policy, checked physical identity and Task 3 snapshots; require already-enabled native root custody. Retain one derived key per
  active root identity/generation under shared runtime lease, never a process-global unscoped key. Initial acquire loads once; `check()` performs metadata-only short custody scopes. Failure
  irreversibly invalidates all registered connections/cursors, rolls back where possible, closes them, then releases authority; a fresh runtime is required.
- [ ] Pin derive compatibility with golden fixture assertions for key/salt and `PRAGMA cipher_plaintext_header_size == 112`; no adoption writes here. `test_hundred_operations_one_unwrap` asserts
  exactly one unwrap for acquisition and zero for 100 checks/commits. `test_marker_unknown_fields_refuse` preserves bytes. Status must not call `Authority.acquire`.
- [ ] Green complete new modules plus `tests/test_dbcrypt.py tests/test_dbcrypt_lifecycle.py`. Re-run Task 3 native acquisition gates when native adapter behavior changes, with separate metadata-loss
  and fresh-native-failure evidence.
- [ ] Commit: `feat(dbcrypt): bind runtime keys to root native authority`.

## Task 5: Implement and review the production checked Windows VFS (P4b; P1 PASS required)

**Files:** Create `native/dbcrypt-vfs/vfs.c`, `checked_io.c`, `checked_io.h`, `src/mordred_hermes/dbcrypt/_windows_vfs.py`, `tests/test_dbcrypt_windows_paths.py`,
`tests/integration/test_dbcrypt_windows_vfs.py`; modify `native/dbcrypt-vfs/build.ps1` and README. Probe code stays diagnostic and is not the production opener.

**Interfaces:** C entrypoint `int sqlite3_mordredvfs_init(sqlite3 *db, char **error, const sqlite3_api_routines *api)` registers VFS `mordred_checked_v1`; no SQLite static/import library linkage.
Python `register_checked_vfs(driver: ModuleType, *, root: Path) -> VfsRegistration`, `VfsRegistration.name: str`, `VfsRegistration.close() -> None`; registration must outlive every connection.
`classify_windows_database(path: str, *, uri: bool, root: Path) -> Path` refuses unknown forms before any open.

- [ ] Write `test_unsupported_path_never_calls_xopen` parameterized over UNC, device namespaces, ADS, drive-relative, trailing-dot/space, ambiguous encoded URI, non-NTFS, reparse/hardlink paths;
  assert zero native opens. Native `test_sidecar_creation_race_has_no_public_window` races parent/child replacement and inherited DACL changes; assert every created DB/journal/WAL/SHM handle has
  expected identity/owner/private DACL from creation or operation refuses without sensitive output.

```python
assert unchecked_opens == []
assert all(event.private_at_creation for event in creation_events)
assert observed_callbacks >= {"xOpen", "xDelete", "xShmMap", "xShmUnmap"}
```

- [ ] Red: `uv run pytest -q tests/test_dbcrypt_windows_paths.py`; native red requires `MORDRED_DBCRYPT_WINDOWS_VFS_TEST=1` and `MORDRED_DBCRYPT_TEST_ROOT`, then `uv run pytest -q -o addopts= -m
  integration tests/integration/test_dbcrypt_windows_vfs.py`.
- [ ] Implement all actual file I/O through checked handles: `xOpen/xRead/xWrite/xTruncate/xSync/xFileSize/xLock/xUnlock/xCheckReservedLock/xFileControl/xDelete/xAccess`, parent identity,
  rollback/super-journals, WAL and owned `xShmMap/xShmLock/xShmBarrier/xShmUnmap`. Never delegate SHM to unchecked parent VFS pathname opens. Implement rename/recovery via the same handle policy; no
  validation-then-reopen handoff. Atomic private SECURITY_ATTRIBUTES or proven trusted inheritance is required at creation; re-ACL afterward fails acceptance.
- [ ] Force memory temporary storage and test sort/index/temp tables/VACUUM behavior. Refuse unsupported disk temp/super-journal/ATTACH cases before writes unless checked coverage is implemented. URI
  VFS selection cannot override the approved name; untrusted extension loading is disabled after bootstrap. Unknown native capability remains unavailable.
- [ ] Green both complete modules plus `tests/test_private_fs_windows.py tests/test_private_fs_windows_faults.py tests/test_private_fs_processes.py tests/test_private_fs_lifecycle.py`, and existing
  `tests/integration/test_private_fs_windows.py` under its existing `MORDRED_WINDOWS_FS_LIVE=1`/`MORDRED_WINDOWS_FS_TEST_ROOT` gate. Assert journal and WAL callback traces,
  flush/truncate/delete/recovery, multiprocess locking and SHM cleanup; deterministic failure injection plus an ordinary-token NTFS race run. Obtain a native/security review before enabling the
  capability bit, distinct from P1 review.
- [ ] Commit: `feat(dbcrypt): enforce Windows SQLCipher I/O through checked handles`.

## Task 6: Guard all SQL entrypoints and same-library monitoring (P4c)

**Files:** Create `dbcrypt/_connection.py`, `tests/test_dbcrypt_connections.py`, `tests/test_dbcrypt_hermes.py`; modify `dbcrypt/_shim.py`, `_monitor.py`, `_hooks.py`, `_policy.py`.

**Interfaces:** `open_protected(path: Path, *, authority: Authority, timeout: float = 5.0, readonly: bool = False) -> ProtectedConnection`; `ProtectedConnection` preserves sqlite3 connection/cursor
behavior and implements `GuardedConnection`; `verify_database(connection: ProtectedConnection) -> None`; `monitor_runtime(authority: Authority) -> tuple[Finding, ...]`. Existing `build_module` routes
scoped connections through this opener; out-of-scope behavior stays policy-defined.

- [ ] Write `test_every_held_sql_surface_revalidates`: execute/executemany/executescript, cursor iteration/fetch, transaction context exit, commit, backup, blob handles where exposed; metadata change
  causes `DatabaseRefused` and zero durable new rows. `test_monitor_preserves_other_connection_locks` uses two processes and verifies monitoring never releases active SQLite locks.
  `test_wrong_key_no_recreate` asserts DB identity/bytes unchanged after refused open. `test_factory_cannot_bypass_authority` passes custom `factory=` and asserts rejection before open unless it is a
  guarded subclass validated by the connection protocol; exercise actual Hermes subclass/factory behavior and preserve the compatible `Connection.backup` API through checked authority/destinations.
  `test_native_backup_detection_ignores_environment` unsets `HERMES_MEMORY_KEY`, asserts registered backup detection still uses valid native authority, and rejects unregistered foreign copies.

```python
with pytest.raises(DatabaseRefused):
    held_cursor.fetchone()  # metadata changed after this cursor opened
assert committed_rows == original_rows
assert competing_writer_was_blocked is True  # monitor did not drop locks
```

- [ ] Red: `uv run pytest -q tests/test_dbcrypt_connections.py tests/test_dbcrypt_hermes.py`.
- [ ] Replace `_shim.build_module` environment-based `has_key()` decisions with authority state, including encrypted-copy handling outside home. Implement connection/cursor admission and precommit
  checks, terminal propagation, root/path destination enforcement and approved Windows VFS. Deny SQL `ATTACH`, `VACUUM INTO`, unsafe URI options and arbitrary load_extension by default; authorized
  backup uses Task 7 API. Validate cipher/schema via the same owning SQLCipher driver, never stdlib SQLite or raw file reads in the active runtime. Header magic is not plaintext classification.
- [ ] Add `test_real_sessiondb_fts_japanese`: import actual installed Hermes `SessionDB`, create/read/search Japanese conversation records across restart and profile homes; assert FTS result IDs/text
  exact and keyless SQLCipher access fails. Assert plaintext-under-marker and unsupported schema refuse without quarantine/empty replacement.
- [ ] Green new modules plus complete `tests/test_dbcrypt.py tests/test_dbcrypt_monitor.py tests/test_dbcrypt_lifecycle.py`; include real SQLCipher tests without silently skipping missing driver on
  claimed platforms. Run Task 5 native VFS module on Windows.
- [ ] Commit: `feat(dbcrypt): enforce authority on held SQLCipher connections`.

## Task 7: Journal migration/adoption, encrypted backup, and teardown dependencies (P4d)

**Files:** Create `dbcrypt/_backup.py`, `tests/test_dbcrypt_backup.py`, `tests/test_dbcrypt_adoption.py`, `tests/integration/test_dbcrypt_native.py`; modify `dbcrypt/_migrate.py`, top-level
`_database_inventory.py`, `dbcrypt/_marker.py`, `dbcrypt/_locking.py`, `tests/test_dbcrypt_migrate.py`, `tests/test_dbcrypt_lifecycle.py`.

**Interfaces:** `adopt_legacy(root: Path, *, lease: ExclusiveLease) -> NativeSnapshot`; `backup_database(source: Path, destination: Path, *, authority: Authority) -> Path`; `restore_database(source:
Path, destination: Path, *, lease: ExclusiveLease) -> None`. Preserve public `migrate/decrypt_all/resume` signatures; inside acquire exclusive lease before custody/DB locks. `_backup` owns
`mordred/db-backups.json` and `mordred/db-backups.journal.json`.

Journal v2 records `version: 2`, root binding/snapshot, direction, transaction ID, and per-file source/prepared identities, relative path, schema/count verification and phase (`prepared`, `verified`,
`armed`, `swapped`, `complete`). Fsync staged bytes, journal and parent transitions; preserve existing recognized v1 recovery only where identities/key proof make recovery unambiguous. Backup
inventory v1 binds each private checked destination's canonical path AND physical identity to root, generation and format; pending journal is a dependency before publication, removed only after
durable inventory commit. Never store key material.

- [ ] Write `test_legacy_mixed_profile_keys_refuse_without_mutation`: `b'1\n'`, root DB decrypts only with root historical key and child DB only with child key; assert refusal and byte-identical
  originals/marker. Valid legacy macOS adoption proves every protected DB with its existing authority and writes v2 without changing ciphertext. Empty, unknown or ambiguous historical source selection
  refuses rather than choosing a new key.
- [ ] Write `test_crash_at_every_durable_transition` over encryption/decryption/adoption phases: after restart either original or fully verified target survives, no plaintext write under armed
  protection. `test_backup_publish_crash_retains_dependency` asserts reset blocked before recovery and after successful registered backup. Unreadable directory, unknown sidecar, missing key, foreign
  root/generation backup, uncertain holder and concurrent writer all refuse.

```python
assert marker.read_bytes() == b"1\n"  # ambiguous adoption refused
assert after_database_bytes == before_database_bytes
assert any(d.kind == "backup" for d in inventory.entries)
assert native_delete_calls == []  # crash after backup publication
```

- [ ] Red: `uv run pytest -q tests/test_dbcrypt_adoption.py tests/test_dbcrypt_backup.py tests/test_dbcrypt_migrate.py tests/test_dbcrypt_lifecycle.py`.
- [ ] Implement exhaustive inventory and crash journal bindings; startup blocks scoped opens until recovery finishes. For macOS use the existing ciphertext authority; automatic adoption cannot invent
  custody or pick among divergent historical keys. Conversion/decryption replace only under exclusive authority and confirmed quiescence. Linux `/proc` and Windows holder/rename uncertainty refuse;
  remove hardcoded `/usr/sbin/lsof` assumptions without relaxing macOS checks.
- [ ] Authenticate maintenance under the existing exclusive lease using Task 3's
  source snapshot/load API; do not call the shared-runtime `Authority.acquire`
  from inside it. Preserve public raw-key test seams, but production entrypoints
  must prove the supplied key belongs to the current bound snapshot before any
  migration or restore. Never upgrade an existing runtime lease in place.
  Pin this in `test_maintenance_never_acquires_shared_runtime_inside_exclusive`:
  assert the shared-runtime acquisition spy is never called and no mutation
  occurs if source verification fails.
- [ ] Implement encrypted same-driver backups with checked destination and journaled dependency registration; restores require exclusive authority and key/root/generation/schema proof. Serialize
  backup registration safely under the runtime lease without upgrading it; the shared lease prevents destruction while backup metadata is published. Inventory mutation uses a dedicated lock after
  custody scopes. Deletion of a managed backup unregisters only after identity-checked deletion is durable. External/offline backups remain explicitly undiscoverable.
- [ ] Green all listed complete modules plus `tests/test_dbcrypt_inventory.py tests/test_dbcrypt_locking.py`; prove `mordred.db` retains rollback journaling and WAL-reset vulnerable versions refuse.
  Run new `tests/integration/test_dbcrypt_native.py` with `MORDRED_DBCRYPT_NATIVE_TEST=1` and synthetic existing `MORDRED_DBCRYPT_TEST_ROOT` on every claimed OS, using real native authority and crash
  subprocesses.
- [ ] Commit: `feat(dbcrypt): preserve authority through migration and backup recovery`.

## Task 8: Ship driver/native assets and truthful read-only capability (P4e)

**Files:** Modify `pyproject.toml`, `dbcrypt/__init__.py`, `_hooks.py`, `.github/workflows/ci.yml`, `tools/ci_scope_paths.json`, `tools/ci_change_scope.py`, `tools/run_critical_tests.py`; create
`dbcrypt/_capability.py`, `tests/test_dbcrypt_capability.py`, `tests/test_dbcrypt_packaging.py`; create root `hatch_build.py`; configure `[tool.hatch.build.hooks.custom]` in `pyproject.toml`. The P1
compiler/load proof must pass before this build path is enabled.

**Interfaces:** `hatch_build.py` defines `CustomBuildHook(BuildHookInterface).initialize(self, version: str, build_data: dict[str, Any]) -> None`; Windows x64 wheel builds invoke
`native/dbcrypt-vfs/build.ps1 -OutputDirectory <staging>`, set `pure_python=False` and wheel tag `py3-none-win_amd64`, and include `mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll`. Sdist
includes C/header/PowerShell assets and the hook; non-Windows builds retain current pure-wheel behavior. Unsupported Windows architecture/build failure refuses; no SQLite static/import library is
added. Status interface: `DatabaseStatus(configured: bool, dependencies: int | None, capability: Literal['available','unavailable','unknown'], authenticated: bool, reason: str | None)`;
`database_status(home: Path) -> DatabaseStatus` never resolves key or writes. `diagnose_database(home: Path) -> DatabaseStatus` explicitly acquires/authenticates authority and releases it.
`authenticated` is false in ordinary status even when driver imports.

- [ ] Write `test_status_never_enrolls_or_unwraps` asserting zero writes/native unwrapping; `test_driver_import_is_not_readiness` asserts authenticated false and unsupported VFS capability
  unavailable. Packaging test builds sdist→wheel and asserts driver extra and owned VFS artifact reachable outside checkout, no source-tree DLL dependency.

```python
status = database_status(home)
assert status.authenticated is False
assert unwrap_count == 0
assert filesystem_writes == []
```

- [ ] Red: `uv run pytest -q tests/test_dbcrypt_capability.py tests/test_dbcrypt_packaging.py`.
- [ ] Add `[project.optional-dependencies].dbcrypt = ['hermes-mordred[keyvault]', 'sqlcipher3-wheels>=0.5.4']`; have `macos` include `hermes-mordred[dbcrypt]` without losing its existing native
  frameworks. Gate Windows runtime activation on production VFS/native proof, not platform string or probe PASS alone. Package native library with compatible platform tags and an explicit build
  failure when unavailable; never silently ship Windows support without its bridge.
- [ ] Update Windows native module-selector/inventory tests in the same owning component PR; the original 84-module selector does not cover new tests by implication. Map dbcrypt/native/security files
  to conservative full CI and add `[dev,keyvault,extension,dbcrypt]` driver environments for relevant Linux/Windows packs; retain lean existing-extra type checking to expose optional-import mistakes.
  Add new test modules to critical/mapped packs, without representing simulated tests as live device automation.
- [ ] Green new modules plus `tests/test_packaging_versions.py tests/test_critical_test_runner.py tests/test_ci_change_scope.py tests/test_windows_database_compat.py`; run `uv run ruff check src tests
  scripts`, `uv run ruff format --check src tests scripts`, `uv run mypy --strict src tools scripts/keyvault_offline_digest.py`. Reproduce typing in fresh CI-extra-only environment. Update only
  admitted supported witnesses in `test_windows_database_compat.py`; keep foreign-home, legacy and unsafe-path refusals rather than deleting the old unsupported guards wholesale. Full regression waits
  until Task 15.
- [ ] Commit: `feat(dbcrypt): package cross-platform capability and SQLCipher extra`.

## Task 9: Route activity and imports through shared protection (P5)

**Files:** Modify `activity/_gate.py`, `_paths.py`, `store.py`, `peers.py`, `ingest.py`, `imports/store.py`; create `imports/_protected_destination.py`, `tests/test_import_protected_destination.py`;
modify `tests/test_activity_gate.py`, `test_activity_store.py`, `test_activity_peers.py`, `tests/imports/test_import_store.py`.

**Interfaces:** Preserve `keyed_opener(path: Path, *, timeout: float | None = None)` and `check_protection(home: Path) -> Refusal | None`; delegate SQL to Task 6. Produce `checked_import_source(path:
Path, *, home: Path) -> ContextManager[BinaryIO]` and `checked_store_destination(path: Path, *, home: Path) -> Path`; the latter is policy classification only, while actual DB open remains checked by
VFS. Never imply returning a Path secures later opens.

- [ ] Write `test_activity_roundtrip_dedup_search_restart_backup` with real SQLCipher: identical import twice yields one event, Japanese search returns exact event, restart and Task 7 restore preserve
  it. `test_windows_peer_swap_refuses` asserts checked source handles reject swapped/reparse/hardlink input and no event is committed. `test_missing_authority_no_store_created` asserts path absent
  after refusal.

```python
assert second_import_count == 0
assert search_ids == [expected_japanese_event_id]
assert restored_rows == original_rows
assert missing_authority_store.exists() is False
```

- [ ] Red: `uv run pytest -q tests/test_activity_gate.py tests/test_activity_store.py tests/test_activity_peers.py tests/test_import_protected_destination.py`.
- [ ] Replace activity and `imports/store.py` independent `_readonly_gate` macOS checks and `_env_database_key` environment lookup with shared authority. Passive read-only availability/status is
  metadata-only and never unwraps; actual record reads acquire or reuse valid runtime authority. Replace macOS-only gate with authenticated shared authority, keep explicit test opener injection, never
  plaintext fallback. Validate activity directories, peer sources and destinations at actual handle use; use memory for sensitive temporary state. Preserve rollback journal and existing
  schema/retention behavior.
- [ ] Green complete listed modules plus `tests/imports/test_import_store.py tests/test_activity_ingest.py tests/test_activity_ingest_retention.py tests/test_activity_history.py
  tests/test_activity_schema.py`; add activity cases to native Task 7 suite and run it on Linux/Windows real driver/native custody.
- [ ] Commit: `feat(activity): use shared native database protection for imports`.

## Task 10: Add independent native mail role and versioned Windows custody (P6)

**Files:** Modify `keyvault/_windows_profile.py`, `_windows_custody.py`, `_native_key_id.py`; create `keyvault/_mail_key.py`, `tests/test_keyvault_mail_key.py`,
`tests/test_windows_custody_schema_v2.py`; modify `tests/test_windows_custody_profile.py`.

**Interfaces:** `mail_backend(*, home: Path) -> NativeBackend`; `mail_key_id(home: Path) -> str` preserves logical ID `mordred-hermes.mail.credentials.v1` and binds native generation/root through
custody. Windows role type becomes `Literal['memory','audit','telegram','mail']`. `upgrade_manifest_v2(*, home: Path) -> None` is explicit, transactional, and leaves existing native role keys
untouched.

- [ ] Write `test_v1_three_roles_upgrade_without_rekey` asserting memory/audit/telegram record bytes, generations and native IDs unchanged; new mail role empty.
  `test_mail_cannot_unseal_telegram_or_database_key` asserts cross-role failures and distinct native selectors. `test_schema_upgrade_crash_recovers_exactly_once` checks journal phases and
  unknown-schema refusal. `test_mail_upgrade_preserves_database_authority_snapshot`
  asserts the memory-role snapshot and held database authority remain unchanged.

```python
assert after.role("memory") == before.role("memory")
assert after.role("audit") == before.role("audit")
assert after.role("telegram") == before.role("telegram")
assert after.role("mail").current is None
assert memory_snapshot_after == memory_snapshot_before
```

- [ ] Red: `uv run pytest -q tests/test_keyvault_mail_key.py tests/test_windows_custody_schema_v2.py tests/test_windows_custody_profile.py`.
- [ ] Implement v1 exact three-role read compatibility; v2 exact four-role schema and explicit private journaled migration under existing canonical custody locks. Preserve the existing native selector
  encoding and IDs for memory/audit/telegram; v2 is a manifest schema change, not a selector-domain migration. No adding an optional `mail` field to permissive v1. Upgrade neither mutates memory
  generation nor unwraps it; refuse pending ambiguous custody recovery. Add independent Linux TPM mail source, macOS existing mail source, and Windows CNG mail role, preserving no portable fallback.
- [ ] Green complete listed modules plus `tests/test_windows_custody.py tests/test_windows_custody_reset.py tests/test_windows_telegram_custody.py`; run existing Windows custody live gate with new
  mail cases, plus new `tests/integration/test_mail_native_custody.py` gated `MORDRED_MAIL_NATIVE_TEST=1`/existing synthetic `MORDRED_DBCRYPT_TEST_ROOT` on Linux and Windows.
- [ ] Commit: `feat(keyvault): add versioned independent native mail custody`. Do not enable mail collection yet.

## Task 11: Complete Telegram storage, migration, destinations and forget (P7)

**Files:** Modify `extension/telegram/store.py`, `migrate.py`, `_windows_archive.py`, `history.py`, `service.py`, `search.py`, `hermes_tools.py`; create
`tests/extension/test_telegram_cross_platform_storage.py`; modify `tests/extension/test_telegram_migrate_store.py`, `tests/test_windows_telegram_archive.py`.

**Interfaces:** Consume Task 9 checked source and Task 6 opener plus Task 7 backup. Preserve public Telegram store/service APIs; introduce `migrate_telegram_store(source: Path, *, home: Path) -> int`
in `migrate.py` returning imported row count, and `forget_telegram_storage(*, home: Path, remove_records: bool) -> int` in `store.py` returning deleted row count. Credential custody remains existing
Telegram role, not database authority.

- [ ] Write `test_telegram_import_search_forget_restart`: synthetic Telegram export with Japanese messages imports once, deduplicates, searches, and removes only requested rows; credentials and shared
  DB generation remain independent. `test_migration_wrong_key_preserves_source` asserts zero source changes and no empty destination. `test_archive_destination_escape_refuses` asserts no output
  outside checked scope.

```python
assert repeated_import_count == 0
assert forgotten_count == requested_message_count
assert database_generation_after == database_generation_before
assert foreign_destination.exists() is False
```

- [ ] Red: `uv run pytest -q tests/extension/test_telegram_cross_platform_storage.py tests/extension/test_telegram_migrate_store.py tests/test_windows_telegram_archive.py`.
- [ ] Update Telegram search/history tool availability and runtime registration gates for admitted platforms, with passive metadata-only availability. Route normal collection, migration, archive
  export/import and forget through shared store authority and checked destinations; sealed credential material never uses plaintext temporary files. Storage forget cannot delete root database key.
  Keep existing account/setup generation and stale-forget defenses.
- [ ] Green complete listed modules plus `tests/extension/test_telegram_hermes_tools.py tests/extension/test_telegram_import.py tests/extension/test_telegram_history.py
  tests/extension/test_telegram_memory_guard.py tests/extension/test_telegram_memory_guard_windows.py`; live native gates `MORDRED_LINUX_TELEGRAM_TEST=1` with
  `tests/integration/test_linux_telegram_tpm.py` and `MORDRED_TEST_WINDOWS_TELEGRAM_LIVE=1` with `tests/test_windows_telegram_live.py`, using `uv run pytest -q -o addopts= -m integration`. These
  custody/storage results do not claim real Telegram account/LLM acceptance.
- [ ] Commit: `feat(telegram): complete protected cross-platform store lifecycle`.

## Task 12: Enable native mail credentials and protected import/sync/forget (P8)

**Files:** Modify `imports/mail/secrets.py`, `source.py`, `importer.py`, `imap_sync.py`, `store_link.py`, `forget.py`, `setup_flow.py`; create `tests/test_mail_cross_platform_storage.py`; modify
`tests/test_mail_secrets.py`, `tests/test_mail_importer.py`, `tests/test_mail_imap_sync.py`.

**Interfaces:** `MailSecretStore` preserves existing public signatures, `KEY_ID='mordred-hermes.mail.credentials.v1'`, MMC1/AES-GCM payload and setup-generation semantics; consumes
`mail_backend(home=...)` from Task 10. Imports consume Task 9 checked source and protected store, not a new SQLite connection provider.

- [ ] Write `test_native_mail_credential_roundtrip_distinct_roles`: store/load/forget synthetic IMAP password under mail only, other roles unchanged. `test_mail_mbox_imap_dedup_search_restart`: real
  SQLCipher plus mocked IMAP transport, Japanese mbox/IMAP messages deduplicate and search identically after restart. `test_forget_stale_setup_preserves_replacement` and wrong-root/generation variants
  assert no unintended erasure.

```python
assert loaded.app_password == synthetic_password
assert mail_native_selector != telegram_native_selector
assert restarted_search_ids == imported_japanese_ids
assert stale_forget_removed_replacement is False
```

- [ ] Red: `uv run pytest -q tests/test_mail_cross_platform_storage.py tests/test_mail_secrets.py tests/test_mail_importer.py tests/test_mail_imap_sync.py`.
- [ ] Replace macOS-only credential restriction with native mail role; handle migration/metadata/partial publication through checked filesystem primitives. Preserve port 993 and payload validation, no
  credential cache or plaintext temp spool. Credential forget and database row forget are separate operations and must not destroy root database authority.
- [ ] Green complete listed modules plus `tests/test_mail_source.py tests/test_mail_setup_flow.py tests/test_mail_store_link.py tests/test_mail_store_batches.py tests/test_mail_imap_client.py`;
  execute Task 10 native mail gate and Task 7 native database suite with mail storage cases. Keep real IMAP account connectivity a separately opted-in gate, `MORDRED_MAIL_ACCOUNT_TEST=1` in new
  `tests/integration/test_mail_account.py`, credentials injected privately and never assumed available.
- [ ] Commit: `feat(mail): enable independent native credentials and encrypted storage`.

## Task 13: Expose safe wizard enrollment, lifecycle, and truthful status (P9)

**Files:** Modify `wizard/_cli_parsers.py`, `wizard/databases_cli.py`, `_windows_databases.py`, `_encryption_status.py`, `encryption_cli.py`, `_vault_lifecycle.py`, `vault_memory_key.py`,
`uninstall_cli.py`, `_uninstall_databases.py`, `_uninstall_windows.py`, `telegram_migrate_cli.py`, `mail_cli.py`; create `tests/test_wizard_database_authority.py`; update `docs/dev/SPEC.md` CLI tree
and `tests/test_docs_links.py` in this owning PR when adding the command.

**Interfaces:** Wizard consumes `database_status`, `diagnose_database`, `adopt_legacy`, `acquire_exclusive`, and keyvault preceding mutation broker. Preserve existing CLI command spellings; explicit
authenticated diagnostic is `hermes-mordred databases diagnose`; status only projects observable facts. Enrollment refuses until native root memory custody is enabled.

- [ ] Write `test_cli_status_no_native_auth`; assert zero unwrap/enrollment/writes. `test_disable_purge_reset_uninstall_dependencies_refuse` covers each public command with DB/pending/journal/backup
  dependencies, asserts exit failure and native key intact. `test_child_memory_disable_does_not_disable_root_database` asserts independent profile behavior. `test_diagnose_auth_failure_is_not_ready`
  asserts no readiness claim.

```python
assert status_exit_code == 0
assert status_unwrap_count == 0
assert destructive_exit_code != 0
assert root_native_key_still_exists is True
```

- [ ] Red: `uv run pytest -q tests/test_wizard_database_authority.py`.
- [ ] Wire commands to preceding broker rather than legacy in-custody destructive calls. Display configured/capable/authenticated as distinct fields; unsupported Windows capability is actionable
  refusal. Decrypt/remove managed dependencies before memory teardown; explain external/offline backups may become unrecoverable and are not proven absent. No automatic database rotation on native key
  reset.
- [ ] Green new module plus `tests/test_docs_links.py tests/test_wizard_vault_cli_memory_key.py tests/test_wizard_windows_memory.py tests/test_wizard_windows_status.py
  tests/test_wizard_windows_uninstall.py tests/test_mail_import_cli.py tests/test_mail_sync_cli.py`; relevant existing Windows wizard live gates in CI.md (`MORDRED_TEST_WINDOWS_WIZARD_LIVE=1`,
  `MORDRED_TEST_WINDOWS_TELEGRAM_WIZARD_LIVE=1`) with their complete live modules and isolated roots.
- [ ] Commit: `feat(wizard): expose guarded cross-platform database lifecycle`.

## Task 14: Update Desktop and extension consumers without overstating support (P10)

**Files:** Modify `desktop/_databases.py`, `_ceremony_routes.py`, `_status_v4.py`, `desktop/assets/desktop/plugin.js`, `_maintenance_routes.py`, `_mail_routes.py`, `_windows.py`,
`extension/telegram/mail_tool.py`; create `tests/extension/test_cross_platform_storage_status.py`; modify `tests/extension/test_desktop_activity.py`, `test_desktop_mail.py`.

**Interfaces:** Consume `DatabaseStatus` projection and Task 9 protected store; no new authority provider or credential role. Preserve `client_version=4` and its exact response keysets: project
capability/authentication through existing v4 database status/reason fields, without adding unversioned top-level keys. Add a pure `database_status_projection(status: DatabaseStatus) -> dict[str,
object]` adapter in `_databases.py` matching that existing schema; existing refusal codes remain compatible. Any schema expansion requires a separately tested API-version change, not a permissive
keyset.

- [ ] Write `test_desktop_poll_does_not_prompt_or_enroll` asserting repeated polls make zero unwraps; `test_activity_mail_tools_refuse_lost_authority` asserts no sensitive result/new write after
  terminal metadata change; `test_server_acceptance_does_not_claim_windows11_support` asserts capability projection retains qualified platform scope.

```python
assert polled_status_keyset == existing_v4_keyset
assert poll_unwrap_count == 0
assert lost_authority_result_contains_records is False
```

- [ ] Red: `uv run pytest -q tests/extension/test_cross_platform_storage_status.py tests/extension/test_desktop_activity.py tests/extension/test_desktop_mail.py`.
- [ ] Replace platform blanket blocks only when shared capability is available; explicit user operation may acquire authority, passive polling may not. Propagate terminal failures and restart
  instruction without quietly reopening empty databases. Keep server storage qualification separate from Desktop runtime support.
- [ ] Green complete modules above plus `tests/test_desktop_windows_api.py tests/test_desktop_windows_page.py tests/test_desktop_page.py tests/extension/test_desktop_databases.py
  tests/extension/test_desktop_platform.py tests/extension/test_desktop_status_v4.py tests/extension/test_mail_sync_tool.py`; native Desktop acceptance remains the separate
  `MORDRED_TEST_WINDOWS_DESKTOP_LIVE=1` gate in `tests/test_desktop_windows_live.py`, not a claim established by the AWS server suite.
- [ ] Commit: `feat(desktop): project protected storage capability without native prompts`.

## Task 15: Execute installed-package/native acceptance and reconcile evidence (P11)

**Files:** Create `tools/dbcrypt_acceptance.py`, `tests/test_dbcrypt_acceptance_manifest.py`, `tests/integration/test_dbcrypt_collectors.py`; extend `tests/integration/test_dbcrypt_native.py` (created
in Task 7); modify `docs/dev/CI.md`, `STATE_DB_ENCRYPTION.md`, `SPEC.md`, `PLAN.md`, `TODO.md`, `PATHS.md`, `setup.md` only with actual final behavior/evidence. Product changes require their owning
slice.

**Interfaces:** `build_acceptance_bundle(*, checkout: Path, output: Path) -> Path` creates an isolated bundle and returns its root; `run_acceptance(*, root: Path, phase:
Literal['provision','reopen','verify'], output: Path) -> int`; CLI subcommands: `uv run python tools/dbcrypt_acceptance.py build --checkout <checkout> --output <external-bundle>` and `uv run python
tools/dbcrypt_acceptance.py run --root <private-root> --phase <phase> --output <evidence.json>`. Bundle contains copied tests/tools, an extracted sdist, one built wheel and isolated `wheel-env`; never
copy the product `src` onto test import paths. Evidence schema records commit, sdist/wheel hashes, `mordred_hermes.__file__`, interpreter/driver/native helper versions, actual native provider,
root/token/filesystem identities, phase/test counts/skips, instance state timestamps, and independent stop receipt; no keys or account secrets.

- [ ] Write `test_acceptance_rejects_source_import_in_wheel_run` and `test_live_claim_requires_all_phases_and_stopped_receipt`; assert nonzero exit for missing provenance, unexpected skip, elevated
  Windows token, absent TPM/CNG or incomplete final stop.

```python
assert wheel_import_path.is_relative_to(checkout) is False
assert native_provider in {"EC2 NitroTPM", "Microsoft Platform Crypto Provider"}
assert all(row["state"] == "stopped" for row in owned_instance_receipts)
assert evidence["unexpected_skips"] == []
```

- [ ] Red: `uv run pytest -q tests/test_dbcrypt_acceptance_manifest.py`.
- [ ] Implement runner/control integration. Existing Linux `i-095cbe655c196c749` (`t3.medium`, UEFI NitroTPM, no IAM profile) uses pinned SSH/existing ingress; Windows `i-00f4db5c3a204906b`
  (`t3.large`, Server 2025, fixed NTFS x64) uses existing access and ordinary token. Profile `intmax-dev`, region `ap-southeast-1`. Both were observed stopped on 2026-10-24; guest access remains
  unverified until execution. Arm external bounded stop BEFORE EVERY start, including persistence stop/start. Never add ingress/IAM merely to avoid investigating existing access.
- [ ] Build `uv build --sdist`, then build a wheel FROM that sdist in a fresh build environment. Install wheel plus needed test extras into a fresh environment outside checkout; verify import
  provenance before tests. Run complete affected modules once against source and once against installed wheel, with tests copied outside checkout and no source-root PYTHONPATH. On each host use real
  native custody, synthetic private root/profiles and independent credentials, not software TPM/mock CNG.
- [ ] Run `MORDRED_DBCRYPT_NATIVE_TEST=1` and `MORDRED_DBCRYPT_COLLECTORS_TEST=1` with `MORDRED_DBCRYPT_TEST_ROOT` using `uv run pytest -q -o addopts= -m integration
  tests/integration/test_dbcrypt_native.py tests/integration/test_dbcrypt_collectors.py`. Windows also runs Task 5 native VFS suite; Linux existing memory/Telegram gates and Windows existing
  custody/memory/Telegram gates remain explicit. Set `MORDRED_TEST_WINDOWS_MEMORY_LIVE=1` for `tests/test_windows_memory_live.py` as CI.md prescribes.
- [ ] Execute copied tests through these exact environment boundaries (set shell variables to absolute private paths first). POSIX: source `uv run --project "$DBCRYPT_CHECKOUT" pytest -q
  "$DBCRYPT_BUNDLE/tests/test_dbcrypt.py"`; wheel `uv run --no-project --python "$DBCRYPT_BUNDLE/wheel-env/bin/python" python -m pytest -q "$DBCRYPT_BUNDLE/tests/test_dbcrypt.py"`. PowerShell: source
  `uv run --project $env:DBCRYPT_CHECKOUT pytest -q "$env:DBCRYPT_BUNDLE/tests/test_dbcrypt.py"`; wheel `uv run --no-project --python "$env:DBCRYPT_BUNDLE/wheel-env/Scripts/python.exe" python -m
  pytest -q "$env:DBCRYPT_BUNDLE/tests/test_dbcrypt.py"`. Replace the final test operand with each complete module set and gate module in its task; native gates also pass `-o addopts= -m integration`.
  Set gate environment variables in that shell, use bundle cwd for wheel runs, unset PYTHONPATH, and assert installed product path before each run. The runner executes these same argument arrays and
  records them.
- [ ] Require all acceptance rows: real Hermes SessionDB/FTS/Japanese; every scoped root/sibling/profile DB and activity/Telegram/mail import/search; wrong/missing key/profile/generation;
  held-connection terminality and unwrap counts; cached hardware-loss limit; sidecars/URI/ATTACH/destinations; multiprocess writers/reader/migration exclusion and uncertain holders; every durable
  crash phase; backup/restore/dependency destruction guards. Compare logical records before/after process restart, OS reboot, and actual EC2 stop/start; retained ciphertext and native generation must
  reopen correctly.
- [ ] Run final integration regression ONCE after all product slices stabilize: `uv run pytest -q --cov=src/mordred_hermes --cov-fail-under=80`, lint/format/mypy commands from Task 8 and `shellcheck
  scripts/*.sh native/*/build.sh`; require CI's 80% coverage floor and final changed-scope/full CI policy. A failure returns to the owning component; rerun only justified affected checks before the
  final regression evidence is renewed.
- [ ] Stop both task-owned started instances in unconditional cleanup, independently verify stopped via EC2, inventory residual test artifacts and remove only owned resources. Green
  `tests/test_dbcrypt_acceptance_manifest.py`. Record actual commands, versions, source/wheel results and limitations under CI.md's existing Manual live-device validation log; inventory-only work is
  not live success. Real Telegram/IMAP accounts and live LLM tests remain separate, explicitly skipped/unrun when unavailable. Never represent Windows Server results as Win11/Desktop validation.
- [ ] Commit acceptance tooling/docs: `test(dbcrypt): record native installed-package acceptance`. Reconcile source-of-truth support matrix, setup `[dbcrypt]` extra, lifecycle and backup limits,
  remaining platform qualifications, and actual failures. Open component PRs to `dev` with Changes/Fixes and precise validation, never an upstream PR.

## Plan self-review and handoff

- Spec coverage: root/profile authority and metadata (2–4), Windows feasibility/security (1/5), connection/monitoring (6), migration/backups/lifecycle (2/3/7/13), packaging/status (8),
  activity/imports (9), native mail role (10), Telegram/mail (11/12), Desktop (14), AWS/source-wheel acceptance (15).
- Five Review Focus cases are pinned to named owning tests; all interfaces above are defined before use. Existing public APIs retain compatibility unless the explicit low-level mutation lease
  requirement changes them.
- P1 PASS remains an evidence gate, not a presumption. No implementation, native validation, AWS start, dependency installation, or successful live result is asserted by this plan.
- Review this plan before implementation. Preserve the user's previously chosen execution method if one exists; otherwise choose native execution or task-by-task subagents at handoff. This
  multi-component plan should execute as the PR slices above, with fresh review at each security boundary.
