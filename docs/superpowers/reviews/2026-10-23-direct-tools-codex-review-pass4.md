# Codex fourth-pass review: direct tool calls option (PR #265, 2026-10-23)

Response: every finding is fixed in `7709fc3f0`. The SPEC section "Direct tool calls (2026-10-23)" describes the result.

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox.
Commit reviewed: `c32ff2b89` (PR #265, branch `feat/direct-tools-option`; only `81b0f6d5b..c32ff2b89`, the fixes of the third pass); absolute links flattened to `path:line` text.

VERDICT: REVISE

Validation used source inspection and in-memory probes. File-writing test suites were not run in the read-only sandbox.

## Findings (condensed)

1. **P2: shared mappings inside YAML pairs bypass detection.** `src/mordred_hermes/wizard/_direct_tools_yaml.py:157`. ruamel constructs `!!pairs` entries as tuples, which the shared-container walk skipped, so `other: !!pairs [- option: &s {enabled: auto}]` with `tools: {tool_search: *s}` read as `deferral`; Hermes's setter then changed `other` too, and `off` removed the unrelated value. Fix: traverse tuples and every other container the safe loader produces, keep the cycle protection, test both directions, and correct the third-pass record's blanket claim until covered.
   - Response (`7709fc3f0`): the walk now descends into mappings, lists, tuples and sets, counting object ids with the same first-visit rule. Tests: the `!!pairs` and `!!omap` shapes are refused for `on` in the shared-shape table, and a two-way test refuses `!!pairs` for `on` (`auto`) and `off` (`'off'`) with no hermes call and the file unchanged. The third-pass record now points here.

2. **P3: reader-answer validation does not enforce its documented contract.** `src/mordred_hermes/wizard/direct_tools.py:152`. An `existing` of `[]` or `{}` raised `TypeError` in the membership test and escaped `read_mode`; and the parent took the last non-empty stdout line, so a refusal line followed by a success line counted as success, although SPEC promises exactly one conforming JSON line. Fix: check field types before membership tests, reject several non-empty lines, and test both.
   - Response (`7709fc3f0`): `_valid` checks that `source` and `existing` are strings before the membership tests; `_spawn_reader` accepts exactly one non-empty stdout line and treats anything else as no answer (`config_unreadable`, never cached). Tests: unhashable fields, two answer lines, and a refusal line followed by a success line are all `config_unreadable`.

3. **P3: SPEC describes status reads as never waiting.** `docs/dev/SPEC.md:5464` and `:5424`. A cache miss waits synchronously for the reader child (up to 20 s) and a failed answer is never cached, so an unchanged file the child cannot answer waits on every poll. Fix: say that the read takes no lock, that a cache hit spawns nothing, and that a miss or a repeated failure may wait for the child's timeout.
   - Response (`7709fc3f0`): both SPEC sentences, the `read_mode` docstring and the Desktop seam docstring now say exactly that. The fifth pass refined it: a conforming refusal is cached as well, and only a run with no conforming answer is retried; see [the fifth-pass record](2026-10-23-direct-tools-codex-review-pass5.md).
