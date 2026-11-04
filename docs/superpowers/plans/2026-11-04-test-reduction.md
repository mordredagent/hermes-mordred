# Focused Test Reduction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Remove proven duplicate test execution and callback boilerplate from the approved combined PR.

**Architecture:** Transfer assertions to stronger existing scenarios, retaining independent expectations. Exhaustive pure mappings cover data variants; representative real component flows cover their shared lifecycle. Typed dependency records retain precise callable signatures.

**Tech Stack:** Python 3.11, pytest, Node ES modules, strict mypy, SQLCipher.

**Spec:** [Approved reduction design](../specs/2026-11-04-test-reduction-design.md).

## Global Constraints

- Keep product behavior, unique fault/security cases, the complete BASE_SPANS oracle, live gates, timeouts and the 80% full-suite floor.
- Keep component commits; preserve PR #295 and target dev.
- Remain in the existing isolated `perf/maintenance-combined` worktree and own editable venv.
- Save diagnostic coverage and JUnit outside tracked sources; a focused diagnostic floor override does not replace full acceptance.
- One final complete local regression after implementation/review; rerun only if code changes or failures justify it.

## Review Focus

- Removed scenario assertions must reach a retained execution, including repeated/changed idle polls and late-cancelled secret flows.
- Mail/DirectTools mappings must assert literal expected wording, not derive expectations from the implementation.
- Historical redaction spans must be checked for every original input even when expectations evolve.
- Secret-value and field axes must each remain exercised without sharing mutable test state.
- Default, named and variadic callbacks must retain their full call contracts.

### Task 1: Desktop redundancy

**Files:** `tests/test_desktop_page.py`, `tests/test_desktop_windows_page.py`, `tests/_desktop_page.py`.

**Interfaces:** Add a pure namespaced `treeText(node)` in the Node harness. Existing render APIs remain unchanged. Preserve all unique component/race/secret/Windows outcomes.

- [x] Transfer repeated-idle/changed-count assertions into both retained import race scenarios; run them before removing the older happy-path harness.
- [x] Transfer late-cancellation request/UI assertions into its existing secret scenario; verify that case, then remove duplicate execution.
- [x] Extend pure mail/DirectTools error mapping checks using the existing literal phrases for all original codes. Keep 3 mail and 1 DirectTools lifecycle representatives, plus expired/busy vault representatives.
- [x] Remove duplicate syntax/plain-layout checks; consolidate identical text walkers and repeated preparation launches while preserving intermediate assertions.
- [x] Run `uv run pytest tests/test_desktop_page.py tests/test_desktop_windows_page.py -q -o 'addopts=--strict-markers -m "not integration"' --cov=mordred_hermes.desktop --cov-fail-under=0 --cov-report=json:<after> --junitxml=<after> -o junit_family=xunit1`.
  Expected: all retained cases pass; every removed node is explained; Python covered-line sets do not shrink. Inject representative JS lifecycle/mapping faults and require retained tests to fail.
- [x] Commit `test(desktop): remove redundant component scenarios`.

### Task 2: Activity matrix and historical execution

**File:** `tests/test_activity_contracts.py` only.

**Interfaces:** Local `assert_historical_spans(text: str) -> None` preserves the original independent BASE_SPANS containment assertion. Local `assert_redacted(text: str, expected: str) -> None` checks the literal public result then invokes historical checks for overlapping inputs.

- [x] Move the historical span assertion into the local helper and call it from overlapping current corpus tests. Verify all 119 original input expectations still have an owner before removing duplicate standalone selection.
- [x] Keep standalone historical selection for inputs absent from the current corpora; define the selection after those corpus tables exist. Do not remove or alter BASE_SPANS values.
- [x] Change the 30×3 value/field matrix to all 30 values through `text`, plus one representative secret each through `search` and `other`. Keep existing ordinary field/operation classification tests.
- [x] Run the complete activity contract module with diagnostic coverage/JUnit; expect 91 fewer cases and unchanged covered-line sets. Inject secret-filter and historical-span faults; retained tests must fail.
- [x] Commit `test(activity): coalesce redundant secret and history checks`.

### Task 3: Acceptance callback declarations

**File:** `tools/_dbcrypt_acceptance_common.py` only.

**Interfaces:** Frozen EvidenceAPI/QualificationAPI/ExecutionAPI/WindowsAPI fields use exact `Callable[[Arg, ...], Result]` where every internal call is positional and no default exists. Keep optional, named and variadic protocols, including `_CallbackPython`; no runtime validator/facade function changes.

- [x] Identify the 50 no-default positional-only-used protocol declarations from the AST and replace their field references with precise Callable types; delete unused declarations and imports.
- [x] Run Ruff and `uv run mypy --strict src tools scripts/keyvault_offline_digest.py hatch_build.py`; expect unchanged call checking and zero errors.
- [x] Run all `tests/test_dbcrypt_acceptance_*.py` and CLI `--help`; expect all seam/copy/sequence/manifest tests pass.
- [x] Commit `refactor(tools): remove redundant callback protocol classes`.

### Task 4: Final integration and delivery

**Files:** Existing performance report, docs/dev/TODO.md and plan/spec execution records only as evidence requires.

- [x] Independently review the additional component diffs and coverage-owner ledger; fix substantive findings with targeted failing/passing evidence.
- [ ] Run one full default suite using `-n 2 --dist=loadfile --max-worker-restart=0`, combined coverage, JUnit, durations and unchanged integration exclusion. Require zero failures and coverage >=80%.
- [ ] Run repository Ruff/format, strict mypy, import-linter, shellcheck and docs links; record counts/deltas and unrun device gates.
- [ ] Push component history, create one ready PR targeting dev, verify all mandatory CI/acceptance and exact current head/base evidence, then merge with merge method preserving commits.
