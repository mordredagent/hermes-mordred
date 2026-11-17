# Additional performance design — 2026-11-04

Status: design for SOL implementation after the controller publishes the required documentation-first PR. No implementation or new full-suite evidence is claimed here. Baseline: integration `30bbf56c3ab0403d99eed26a0106140a7285ffb1`; see the adjacent test/runtime profile reports. The user has authorized hands-off work and asked for substantially larger effects.

## Intent and boundaries

Prioritize a large reduction in elapsed CI time while retaining every selected case, assertion, platform worker and acceptance gate. Deliver three independently reviewable changes: Unix default-suite parallel execution; cheaper setup for three existing Windows audit preflight cases; one protected read for import-history search. Activity summary batching is a separate, benchmark-gated follow-up, not a prerequisite or an assumed saving.

No changes to cryptographic parameters, full integrity checks on each actual database open, protected callback freshness, SQLCipher-only storage, selectors, native Windows shard weights, live-device gates, timeouts, skip conditions, CI acceptance schema or worker identities. Ordinary local pytest remains serial by default. No new live tests run automatically.

The controller reports that completed hosted run `41820354815` passed all ten jobs: default-suite plus coverage steps took 1,317s (Linux 3.11), 1,360s (Linux 3.13) and 1,341s (macOS); the floor suite took 650s. The longest Windows native step was 798s, and the workflow took roughly 28 minutes. These are baseline observations from the original source-task run, not performance evidence for this proposed change. They justify prioritizing the Unix suite critical path.

## Approaches

1. **Selected: two local pytest processes for Unix default suites.** This attacks suite wall time directly without removing tests. File scheduling preserves module fixtures and same-file fixed-port serialization. It requires verified process-local homes and resource safety. Benefit is a measurement target, not an estimate.
2. **Selected complementary work: remove demonstrated unnecessary setup and reopening.** The three audit cases spend most local time constructing encrypted history that they must never decrypt; search opens the same store twice. These are narrow changes with structural before/after evidence.
3. **Deferred: more workers, new CI shards, shared mutable fixtures, broad query rewrites.** More workers duplicate collection/startup and risk contention; extra jobs alter CI policy/evidence; shared enrolled fixtures weaken isolation. Activity batching has plausible statement savings but needs a bounded-query benchmark before acceptance.

These are implementation choices under the user's hands-off authorization, not a claim that the user selected a particular scheduler.

## A. Two-process Unix default suites

### Scheduling and ownership

Add `pytest-xdist>=3.8,<4` to the dev extra and resolve its lock entries. Keep the current pytest exclusions (`!=9.1.0,!=9.1.1`). Verified on 2026-11-04: upstream xdist is 3.8.0 (Python >=3.9, pytest >=7, execnet >=2.1); the integration environment has pytest 9.0.3, pytest-cov 7.1.0 and coverage 7.14.0. CI uses pip with the declared ranges, so validate the resolved CI versions too.

Use explicit `-n 2 --dist=loadfile --max-worker-restart=0` only in the existing Linux/macOS non-critical default pytest command and the Hermes-floor suite command. Preserve all current arguments, including both floor deselections. Fail visibly on worker crashes rather than silently replaying cases. Keep critical, feature, package, native Windows, docs, and explicit live/integration paths unchanged. Do not put `-n` in global addopts or environment variables inherited by child pytest.

`tests/conftest.py` owns process-home isolation; no production imports may be added to its module scope. Keep the current import-time fallback for serial invocations. Add an early `pytest_configure` hook which recognizes a **real** xdist worker by `config.workerinput`, never solely by `PYTEST_XDIST_WORKER`. It creates a unique private temporary `HERMES_HOME`, sets it before collection, and registers cleanup only for that worker-owned directory. A worker must refuse if `mordred_hermes._core._home` or another home-freezing product module has already been imported before this transition; do not repair frozen constants or reload product modules.

True workers replace their inherited ambient home with a fresh worker home even when the controller was given `HERMES_HOME`. Ordinary serial pytest, `-n 0`, and nested serial pytest preserve explicit caller-home semantics exactly. A nested child inherits xdist environment variables but lacks `config.workerinput`; its explicitly provided home must win. Never delete the controller/caller home. Update the conftest docstring: early configure precedes test-module collection; fixtures are too late.

At minimum, independent subprocess tests prove: two workers have different frozen homes; no import-time defaults point at the controller or production home; serial unset-home isolation; serial explicit-home preservation; nested serial explicit-home preservation despite inherited xdist variables; frozen-before-configure refusal; worker-owned cleanup without caller deletion. Use small temporary test trees with at least two files so file scheduling actually exercises both workers. Verify the existing extension fixture-closure guard still runs in workers.

### Shared resource audit before enabling the workflow

Audit actual binds and writes, not numeric constants alone. Current bounded findings: port 7799 binds reside in `tests/extension/test_extension_serve_shutdown.py`, so loadfile keeps them together; other inspected server modules allocate port 0. The 7788 occurrences inspected are configuration/URL assertions or refused launches, not authorization to bind production port 7788. Recheck all socket/server/subprocess entry points before activation and record a compact resource table.

Package fixtures need particular attention: `test_packaging_native.py` builds from the checkout with a private output/cache; `test_dbcrypt_packaging.py` creates a source sdist then builds/installs outside the checkout; `hatch_build.py` uses unique staging and returns immediately for non-Windows wheel builds; helper build-script tests copy scripts to temporary directories. This is promising but not a complete write-isolation proof. Inspect all selected native/build fixtures and their output paths, including collection-time effects and child commands. Do not run gated native builds merely to perform the audit.

If a small shared resource remains, prefer isolated test-owned outputs. Otherwise serialize its complete owning modules with a test-only interprocess lock acquired before fixture setup and held through teardown, keyed by the same controller-run resource directory. Do not use `xdist_group` with loadfile: that scheduler does not honor group marks. An alternative `loadgroup` design would have to assign **every** test a file group and collapse cross-file resource owners, preserve external case identity, and receive its own tests; do not add that complexity speculatively. If safe parallelism requires broad test rewrites, leave the workflow serial and ship the other two improvements.

### Evidence and rollout gate

Run focused harness/resource tests before one controlled same-host comparison of complete default suites, with xdist installed in both runs. Serial uses `-n 0`; parallel uses the proposed flags. Use the same revision, interpreter, dependencies, extras, source origin, machine and marker expression, no concurrent jobs; include coverage in both and use distinct test-owned homes and artifact paths. Record machine/load, versions, collection time, suite/total elapsed, counts, exact per-case terminal outcomes and skip reasons, combined coverage file/line sets and percentage. Capture JUnit as supplementary evidence; a temporary pytest report plugin can preserve exact node IDs when JUnit naming is insufficient. Each selected case executes once; collection manifests and reports must match, with no new skip caused by contention or lost fixtures.

Target at least **25% elapsed reduction**, preferably 25–40% or more; no speedup claim precedes measurement. Existing ≥80% per-cell combined coverage remains mandatory. Compare covered lines, not only rounded totals; explain any platform/timing-dependent difference and fix unexplained losses. Worker coverage must be combined by pytest-cov, not averaged. A second controlled comparison is justified only if noise, anomalies or a change prevents interpreting the first.

After local equivalence and the speed gate, change the workflow and let the next authorized CI establish Linux/macOS/floor behavior with current packs. Preserve `id: pytest`, `id: floor_tests`, artifact/evidence consumers and final accepted-baseline rules. A local macOS result is not hosted Linux evidence. Do not rewrite native Windows historical timing weights from Unix data. Record observed hosted duration only after a green run.

## B. Three audit preflight cases

Owner: existing Windows fixture-cost task; amend its pending branch only through the controller. Modify only `tests/test_wizard_windows_audit_cli.py` unless a dedicated test helper is warranted.

Keep real fresh enrollment, capability checks, checked private-directory creation/writes, checked listing/stat and actual OS hardlink refusal. Replace `history(...)` only in `test_decrypt_enumeration_is_bounded_before_any_native_call` (two parameter sets) and `test_decrypt_refuses_an_unsafe_target_before_any_native_call` with opaque files named as valid audit rotations. Use actual bytes exceeding the 64-byte test limit, more than two entries for the list test, and a real second hardlink to the dated target for the unsafe test.

Retain all node IDs and original assertions: exit 1, empty stdout, `audit-unsafe`, exact size/list operation, no decrypt call and unchanged backend calls. Add byte-inventory equality and a decrypt tripwire. Do not fake capability/list/stat/link checks or share enrolled state. Other encrypted-history tests remain real and unchanged.

Measured baseline: the three hosted Windows cases totaled 30.193s; local history creation alone consumed 0.7061s of a 0.96s focused run. These are different environments and establish neither a 30-second saving nor native acceptance for this change. Measure after locally and on the next normal Windows run. Run the complete containing audit CLI/native test modules and critical preset; prove removing each real size/list/link refusal makes its test fail.

## C. One public search read and one snapshot

Owner: imports/extension search boundary, within the pending original import-read task if that branch remains unmerged. No raw connection crosses to the extension caller.

Add `ImportStore.search_with_parts(query, *, conv_uids=None, since=None, until=None, source=None, limit=20, parts_limit=20) -> tuple[list[SearchHit], dict[str, StoredPart]]`. `limit` retains the existing bounded candidate semantics (clamped by `MAX_SEARCH_LIMIT`); `parts_limit` selects at most the nonnegative prefix of returned hits, independently of the candidate cap. Factor search execution and part hydration into connection-local helpers shared by existing `search`/`parts_for`; preserve their public behavior. The new method performs selection and hydration inside one `_transaction(write=False)` and does not perform a second open for zero hits. Existing nonpositive-limit/empty-conversation early returns still avoid unnecessary work.

`extension/telegram/search.py::_store_found` calls the new public method with `limit=_MAX_CANDIDATES` and `parts_limit=request.limit`, preserving hit-order projection, candidate/partial counts, error conversion, budget handling, legacy merge and around-evidence behavior. Keep all existing APIs usable.

The explicit consistency improvement is a single committed snapshot for hit selection and hydration. A concurrent writer cannot produce old hit IDs with newly edited contents in this one result; a subsequent call sees the update. This does not cache authority: every actual open still performs full integrity validation and protected callbacks remain fresh throughout the call. Revocation/path/metadata changes still refuse as before.

Structural target for the profiled three-result request: 2 opens → 1, 11 application executes → 8, five SELECTs unchanged. Zero-hit target: 2 → 1 opens, 7 → 4 executes, one SELECT unchanged. These are deterministic accounting goals, not measured protected latency promises. Test all existing filters/ranking/ordering, unknown/uncommitted data, multipart messages and candidate/output limits. Prove snapshot behavior with a WAL writer between selection and hydration and a second request. Use explicit test openers for accounting; never introduce plaintext production fallback.

## Deferred activity batching contract

If subsequent work is warranted, open a separate activity-only PR. `_summaries(conn, chosen_heads, sites)` may execute three query families for only the chosen bounded heads and share pure `EpisodeSummary` projection with `_summary`. Use per-episode ordered LIMIT subqueries combined with UNION ALL, or a query-plan-proven equivalent; preserve 400 summary events, one task and two corrections per episode. Group the step aggregate only over chosen IDs. Do not rank or hydrate all historical events merely to return ten summaries. Retain the existing read transaction and every privacy/revision/ownership filter.

Target 33 → 6 SELECTs for ten site results, not a promised wall-time improvement. Acceptance requires complete value equivalence (ties, routes, flags, attempts/null steps, human words beyond event cap, correction order, redaction and terminal fallback), actual query-plan/large-history measurements and no material small-request regression. Defer this change if a bounded prototype does not show worthwhile elapsed benefit.

## Primary references checked

- [xdist scheduling](https://pytest-xdist.readthedocs.io/en/stable/distribution.html): fixed worker count, whole-file scheduling and distinct loadgroup behavior.
- [xdist 3.8.0 worker startup source](https://github.com/pytest-dev/pytest-xdist/blob/v3.8.0/src/xdist/remote.py): assigns `config.workerinput` before the normal pytest command hook.
- [pytest hook reference](https://docs.pytest.org/en/stable/reference/reference.html#pytest.hookspec.pytest_configure): initial configure before collection, unlike runtime fixtures.
- [pytest-cov distributed coverage](https://pytest-cov.readthedocs.io/en/latest/xdist.html): combines coverage from distributed workers.
- [pytest-xdist package metadata](https://pypi.org/project/pytest-xdist/3.8.0/): verified version and dependency requirements.
