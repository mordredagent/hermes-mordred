# Additional Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Follow the controller's Astra design → SOL implementation ownership. Use separate worktrees for concurrent sessions.

**Goal:** Substantially reduce Unix CI elapsed time, remove irrelevant audit-fixture work and eliminate the second protected search open without dropping validation.

**Architecture:** Two explicit pytest workers execute whole files using process-private ambient homes. Independent test and import-store changes remove demonstrated setup and transaction redundancy. Each workstream has its own review and PR scope.

**Tech Stack:** Python 3.11–3.13, pytest, pytest-xdist 3.8.x, pytest-cov, GitHub Actions, SQLCipher-backed store with explicit SQLite test openers.

**Spec:** [Additional performance design](../specs/2026-11-04-additional-performance-design.md).

## Global Constraints

- Preserve every selected case/assertion, ≥80% combined coverage per currently covered CI cell, all packs, timeouts, worker identities and existing evidence schema.
- Keep native Windows four-shard execution and every explicit live/integration gate unchanged; no automatic live execution.
- No integrity/key/metadata cache, shared enrolled home, plaintext production storage, production port binding or upstream PR.
- CIpolicy changes require the documentation-first PR before implementation integration; component changes remain separate PRs/commits.
- Never use the delivery worktree, branch refs or environment from a delegated implementation session. The controller owns publication.
- Use each isolated worktree's own editable `.venv`; inspect `mordred_hermes.__file__`. Start with critical feedback and affected modules; the controlled full comparison is the final integration evidence, not a repeated progress check.

## Review Focus

- Nested serial pytest inherits xdist environment variables yet must keep its explicit home: subprocess regressions in task A.
- Product imports can freeze ambient paths before worker isolation: early-import refusal and collection-time defaults in task A.
- Resource contention can silently turn execution into skips or corrupt a build: inventory and per-case outcome comparison in task A.
- Opaque audit setup could accidentally bypass admission or cease testing the real preflight: native-call tripwires, real checked I/O and negative controls in task B.
- Search snapshot batching must not stale authority or change candidate limits: WAL interleaving, second-call freshness and protected refusal modules in task C.

### Task A: Safe two-process default suites

**Files:**
- Modify: `pyproject.toml`, `uv.lock`, `tests/conftest.py`, `.github/workflows/ci.yml`.
- Create: `tests/test_parallel_test_home.py` (small subprocess harness); modify `tests/test_ci_workflow.py` for exact command assertions.
- Modify only as proven necessary: specific test fixtures holding shared process-external resources.
- Document: `docs/dev/CI.md` and `docs/dev/setup.md`, preserving headings; append measured evidence to the agreed performance record.

**Interfaces:**
- `pytest_configure(config: pytest.Config) -> None` recognizes `getattr(config, "workerinput", None)`; environment-only worker recognition is forbidden.
- No new public product API. Workflow command suffix is exactly `-n 2 --dist=loadfile --max-worker-restart=0` at the three scoped existing command sites.

- [ ] Read the design, AGENTS and current CI contract. Create the isolated worktree/environment through the controller's normal workflow; record source/dependency origins.
- [ ] Add the dev dependency and lock resolution. Verify pytest exclusions and resolved pytest/xdist/cov compatibility without upgrading unrelated dependencies.
- [ ] Write subprocess regressions for genuine two-worker import-time isolation, bare serial isolation, explicit serial and nested-serial homes, early frozen-import refusal, cleanup ownership and extension fixture closure. Use two temporary modules and collected constants, not a fixture-only test of the environment.
- [ ] Run these tests before the home change; verify a real isolation failure, not an unavailable dependency or collection error.
- [ ] Implement the minimal root-conftest hook and revise the inaccurate timing explanation. Keep module-level imports product-free and cleanup restricted to newly created homes.
- [ ] Run `uv run pytest -q tests/test_parallel_test_home.py tests/test_critical_test_home.py tests/test_critical_test_runner.py`; test the temporary harness with `-n 0` and `-n 2 --dist=loadfile --max-worker-restart=0` explicitly.
- [ ] Inventory bind/write ownership for all selected default tests and child tools. Record path/port, module owners, private/shared status, fixture lifetime and resolution. Inspect build outputs and initial conftest imports. Port 7799 stays in its existing module; no new skips are allowed.
- [ ] Fix only established unsafe resource sharing using private outputs or a narrowly scoped pre-setup-through-teardown interprocess lock. Prove the lock covers module fixtures if used. If this expands broadly, stop the parallel rollout and report the concrete blocker while completing B/C.
- [ ] Run complete affected resource modules with the proposed flags and run `uv run python tools/run_critical_tests.py`. Resolve failures causally; do not increase timeouts or change selectors to obtain green.
- [ ] At code freeze, run one controlled complete default-suite pair in the same otherwise idle host/environment. Record all resolved dependency versions. Execute serial `uv run pytest -q -n 0 --cov=mordred_hermes --cov-report=xml:<serial-path> --cov-report=json:<serial-json> --junitxml=<serial-junit>` then equivalent parallel with `-n 2 --dist=loadfile --max-worker-restart=0`, using separate coverage data locations and test-owned homes. Keep existing addopts. A temporary exact-node report plugin may supplement JUnit. These are placeholders to substitute with concrete absolute scratch paths.
- [ ] Compare exact collected cases, terminal outcomes, skip reasons and unique execution counts; compare combined covered lines and ≥80% coverage. Compute elapsed reduction `(serial - parallel) / serial`. Record overhead and any investigated differences. Require ≥25% interpretable same-host improvement before enabling the workflow; rerun only to resolve noise or changes.
- [ ] Add workflow assertions before changing the workflow: only non-critical Linux/macOS defaults and floor receive flags; existing floor deselections, Windows and explicit suites, evidence IDs, coverage and all commands remain enforced. Add the flags only after acceptance evidence exists.
- [ ] Run the existing CI policy/evidence/workflow contract modules, Ruff, format, strict typing (including reduced-extras if relevant), import layering and documentation link checks as applicable. Do not rerun the full pair merely for documentation edits.
- [ ] Commit the scoped CI/test-infrastructure change for controller review/publication. The next authorized hosted CI supplies platform evidence; retain serial fallback if hosted equivalence or benefit fails.

### Task B: Audit preflight setup cost

**Files:**
- Modify: `tests/test_wizard_windows_audit_cli.py`.
- Validate: `tests/test_windows_encrypted_audit.py` and the full audit CLI module; identify any additional containing native module from current test helpers before execution.

**Interfaces:**
- Preserve both named test functions, parametrization IDs and original assertions.
- A local opaque-history helper, if introduced, takes the already enrolled test context and creates files through the same checked private writer/session used by the existing test support. It does not enroll or mock admission.

- [ ] Capture current focused three-case node IDs, assertions, actual checked-write API and baseline timings using the worktree interpreter. Reuse the supplied baseline when revision/environment match.
- [ ] Replace only the irrelevant encrypted history in these three cases with controlled opaque rotation files. Keep fresh real enrollment per case, real sizes/counts and genuine hardlink creation.
- [ ] Add before/after byte inventories and explicit decrypt tripwires; retain backend-call accounting. Check that the tested preflight operation is still classified exactly as before.
- [ ] Run the exact three cases and compare IDs/outcomes and timing. Run negative controls temporarily: bypass total-size bound, entry-count bound and link refusal separately; each corresponding test must fail. Restore production/test files immediately and verify no temporary changes remain.
- [ ] Run the complete audit CLI and containing encrypted/native modules plus critical preset. Skips on this host are not Windows acceptance. Run Ruff/format for touched tests.
- [ ] Commit separately to the existing fixture-cost task via controller coordination; report observed local savings. Obtain actual Windows savings from its next normal authorized green run, without changing historical weights.

### Task C: Single-snapshot public search hydration

**Files:**
- Modify: `src/mordred_hermes/imports/store.py`, `src/mordred_hermes/extension/telegram/search.py`.
- Modify tests: `tests/imports/test_import_store.py`, `tests/extension/test_history_search_tool.py`.
- Validate `tests/test_import_protected_destination.py` and all containing protected-import modules identified by the existing store tests; do not modify protected-open plumbing.

**Interfaces:**
- Add `ImportStore.search_with_parts(query, *, conv_uids=None, since=None, until=None, source=None, limit=20, parts_limit=20) -> tuple[list[SearchHit], dict[str, StoredPart]]`, with query/filter types matching `search`.
- Existing `search`, `parts_for`, `neighbors` keep their public contracts. New connection-local helpers remain inside imports/store.
- `_store_found` requests `_MAX_CANDIDATES` hits and `request.limit` hydrated parts; no extension-owned SQL or private connection access.

- [ ] Add opener/statement-count tests at nonempty, zero-hit and early-return boundaries; desired nonempty counts are one open/eight application executes/five SELECTs for the profiled fixture. Test independent candidate versus hydration caps, negative/zero limits and deduplicated conversation filters.
- [ ] Add WAL-writer interleaving evidence: commit a competing edit/delete after selection, before hydration; require a coherent original result, then require a fresh second request. Assert transaction cleanup on hydration failure.
- [ ] Run new regressions and verify they fail for absent API or second-open behavior as intended.
- [ ] Factor connection-local selection/hydration; implement the new public transaction and switch `_store_found`. Keep ranking, ordering and existing compatibility APIs unchanged.
- [ ] Run complete import-store and search-tool modules, preserving FTS/LIKE/date/source/chat filters, unknown/uncommitted cases, multipart order, partial counts, response budget, legacy merge and around-evidence.
- [ ] Run complete containing protected-store/refusal modules and critical preset; if implementation unexpectedly changes protected-read plumbing, stop scope expansion and identify/run the existing relevant explicit gates through the controller rather than claiming synthetic evidence suffices.
- [ ] Verify one actual open still invokes the full integrity path and fresh authority/path callbacks; no state persists between requests. Record structural counts separately from any measured SQLCipher latency.
- [ ] Run scoped Ruff/format, strict typing and import-layer contracts. Commit independently in the pending imports task through the controller; otherwise open its own dev-targeted PR. Use the final shared integration freeze for full regression rather than repeating the suite now.

## Deferred work

Activity summary batching is not part of these three acceptance units. A separate activity owner may benchmark bounded per-episode UNION ALL query families against current summaries. Require full value/privacy equivalence and useful measured elapsed improvement before writing a production implementation plan or opening an activity PR. Never combine it into the imports PR to chase statement-count optics.
