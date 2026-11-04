# Focused test and acceptance-tool reduction — 2026-11-04

Approved by the user on 2026-11-04. Implementation and measured limits are
recorded in the [validation report](../reports/2026-11-04-maintenance-performance.md).

## Intent

The user expanded the maintenance integration request to include substantially
fewer redundant test executions, refactoring, and removal of unnecessary code
in the same dev-targeted PR. This supersedes the earlier requirement to preserve
every collected case only where equivalent or stronger coverage is demonstrated.
Product behavior, unique fault/security cases, historical redaction oracles,
CI worker identities, live gates, timeouts and the 80% full-suite floor remain.

## Approaches

1. **Recommended: transfer duplicate assertions to stronger existing scenarios,
   separate exhaustive pure mappings from generic component lifecycles, and
   remove redundant callback declarations with equally precise types.** This
   reduces actual repeated executions and source boilerplate while retaining
   independently defined expectations. It requires explicit old/new coverage
   accounting and targeted fault injection.
2. Keep every scenario and only extract helpers. This reduces source lines but
   leaves duplicate execution/setup costs and does not meet the user's request
   to reduce the tests themselves.
3. Sample security corpora or delete broad platform/fault matrices. Rejected:
   a lower count alone does not justify losing distinct protection boundaries.

## Desktop tests

Baseline: `tests/test_desktop_page.py` and `test_desktop_windows_page.py`
collectively pass 343 cases in 14.28s on macOS arm64, Python 3.11.15.

- Delete the duplicate Windows ES-module syntax test, retaining the identical
  shared-source check in the portable module; remove its unused subprocess import.
- Remove one plain Linux layout row already strengthened by the misleading-text
  Linux row with identical routing metadata.
- Transfer the extra late Telegram cancellation assertions into the existing
  secret scenario, then remove the second invocation.
- Transfer repeated-idle and changed-count assertions from the two older import
  happy-path cases to their stronger existing stale-response race scenarios.
- Keep expired/busy vault-commit representatives for the only two lifecycle
  branches. Retain exhaustive closed-code label coverage.
- Replace seven full DirectToolsCard failure scenarios with one representative
  lifecycle scenario plus exhaustive pure error-wording checks.
- Replace fifteen mail setup failure scenarios with three lifecycle representatives
  (IMAP hint, mail-specific wording, shared wording); check all fifteen phrases
  independently through the real pure mapping boundary.
- Reuse a pure tree-text helper and avoid repeated preparation/full Node launches
  where one scenario already continues through the later stage. Keep effects,
  secret handling and request recording specific to each harness.

Expected reduction: about 25 collected cases plus redundant Node invocations and
roughly 100–180 test source lines. Retain all race, restart, malformed-response,
secret lifecycle, Windows repair and capability-outcome matrices.

## Activity test execution

- Test all 30 secret values through one admitted field kind rather than a 30×3
  Cartesian product. Keep representative secret refusal for the other two
  admitted kinds; existing ordinary-input tests cover field/operation admission.
  This retains every secret example and distinct field branch: 90 → 32 cases.
- Where an existing literal expected-output corpus already exercises one of the
  historical span inputs, run the independent historical-span assertion in that
  same case. Keep the complete immutable `BASE_SPANS` oracle. Remove only the
  duplicate standalone executions; keep all uncovered historical inputs selected.
  Audit found 33 overlapping historical inputs, not 33 removable expectations.
- No activity runtime/query/storage change is included.

## Acceptance-tool boilerplate

`tools/_dbcrypt_acceptance_common.py` contains 51 positional callback protocols.
Inline precise `Callable[[...], Return]` types in the frozen dependency records
where all consumers call positionally. Keep protocols with keyword-only,
variadic or optional/default arguments (including `_python`) so strict typing
retains those contracts. Remove now-unused private protocol declarations only.
Keep facade exports, current-call dependency capture, physical-copy isolation and
all acceptance behavior unchanged. Expected removal is roughly 150–250 lines.
No other production dead-code deletion is justified by the current audit.

## Verification

- Save focused baseline collection/outcomes, then explain every removed node by
  its retained owner. Do not claim this is the previous all-node-equivalent speed
  comparison; that evidence remains tied to its original revision.
- Run complete desktop/activity/acceptance modules and strict mypy. Check that
  retained tests detect secret-filter bypass, historical span loss, busy-flow
  loss, late cancellation, bad error wording and missed refresh/field clearing.
- Review the additional diff independently, fix substantive issues, then run one
  final integrated full suite with combined coverage and repository checks.
- Record actual counts, line reductions, warnings/skips and remaining device
  gates. Publish and merge only after acceptance for current PR head and base.
