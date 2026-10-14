# Windows CI Runtime Plan

Goal: finish routine CI in approximately 25 minutes with two Windows runners.
Architecture: balance whole native modules using measured durations, reduce only 28 reviewed portable cases on routine Windows runs, bind actual test selection to shard evidence, and preserve full Windows release/manual validation.
Spec: the user approved splitting Windows and reducing tests; docs/dev/CI.md remains the operational policy.

## Global Constraints

- Keep every Windows ACL, process, locking, crypto, storage, restore and native test.
- Full Linux/macOS suites remain; main, manual and ci:full retain all Windows cases.
- Use two isolated hosted VMs; never parallelize shared HOME/ports in one VM.
- No product behavior changes or edits to the original checkout's concurrent work.
- Release evidence must prove the full Windows tier, not routine exclusions.

## Review Focus

Exact parametrized exclusions must never omit newly added cases; missing reviewed IDs must fail. Shard identity and completeness must reject missing, duplicate or stale workers. Release gates must reject routine evidence. Helpers must run once even after matrix expansion. Host timings must distinguish elapsed time from summed runner time.

### Task 1: Shared planner and reviewed fixture

Interfaces: plan_native_modules(modules, *, tier, shard, count), exclusions_for(modules,tier), exclusions_digest(tier), as specified in /tmp/mordred-windows-ci-interfaces.md.
Astra implements deterministic weighted planning and exact exclusion validation in its own worktree, with failing tests first, then commits for integration.
Expected: 84 modules once across two shards; routine test weight about 22 minutes each.

### Task 2: Actual native execution

Root adds a pytest recorder and the runner's tier/manifest options. Tests first demonstrate exact exclusion, retained new parameters, failed test propagation and missing-ID failure using isolated temporary suites.
Expected: real manifest binds actual collection, outcomes and both shard inputs; existing CLI works.

### Task 3: Admission and workflow

Astra extends policy/worker/acceptance/remote evidence to schema 2 and full release gating. Root expands the Windows matrix and runs helpers only on shard 1; updates graph tests and CI.md.
Expected: routine final graph has seven jobs, ordinary still three to five; missing shard fails; routine Windows evidence cannot release.

### Task 4: Integration and hosted benchmark

Run critical and changed modules, required static/type checks and one full regression. One fresh Astra whole-branch review; fix material findings with reproducing tests. Create PR to dev, run hosted CI, inspect both native JUnit unions, actual exclusion set, skip counts and elapsed time.
Expected: accepted exact current PR context, approximately 25-minute workflow; report actual result and any variance.
