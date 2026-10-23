# Codex second-pass review: direct tool calls option (PR #265, 2026-10-23)

Response: the design changed instead of patching the writer. Mordred no longer edits config.yaml; it runs Hermes's own `hermes config set|unset tools.tool_search.enabled` and checks with `hermes config get` (SPEC "Direct tool calls (2026-10-23)").

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox.
Commit reviewed: `33bbda0fc` (PR #265, branch `feat/direct-tools-option`); absolute links flattened to `path:line` text.

Reviewed through `33bbda0fc`. All probes were read-only and in memory; no network or prohibited files accessed. File-writing suites were not run.

## First-pass items

| Item | Status | Evidence |
|---|---|---|
| YAML warning disclosure | **PARTIAL** | Canary safely refused on `read_mode`, POSIX writer and Windows writer. Rollback and concurrent warning contexts still leak—below. |
| Alias/merge isolation | **RESOLVED** | Nine shapes refused on both writers, including shared anchors, inherited/shadowed merges and non-mapping `tools`. Injected unrelated edits were refused before writing; five non-deferral values returned `config_has_setting`. |
| Hermes parsing parity | **PARTIAL** | **26/26** match Hermes’s actual, AST-extracted functions. Confirmed quoted `enabled: "n"` and legacy `"off"`/`0` are deferred. YAML directives expose another mismatch—below. |
| Comment relocation | **RESOLVED** | Combined mapping-head and following-key comments survive exactly. |
| Status-only checkbox | **RESOLVED** | Four component tests pass, including the pending refresh. All 20 Windows snapshots match. |
| Regression-test gaps | **PARTIAL** | Original reproductions now covered; rollback parsing, warning-context overlap and directive cases remain uncovered. |
| Race-test gap | **PARTIAL** | Changes to all five identity fields refuse before writing. The final check/write window remains; rollback introduces another race. |
| Round-trip promise | **PARTIAL** | Empty/comment fixtures pass; replaced deferrals are now documented. But absent `enabled` still does not guarantee identical bytes: `{}\n` becomes empty, and `tools: {tool_search: {}}` disappears. |

## New findings

- **HIGH — Windows rollback leaks source and can fail unsanitized.** src/mordred_hermes/wizard/direct_tools.py:217 reparses outside `_quiet`. A duplicate-anchor canary reached stderr; malformed YAML escaped as `ValueError` with a source-bearing `ParserError` chain and left the original unrestored.

- **HIGH — POSIX rollback can recreate resealed plaintext.** src/mordred_hermes/wizard/direct_tools.py:171 restores unconditionally. Simulated resealing after publication produced `config_write_failed` **with plaintext recreated**. A newer concurrent configuration can likewise be overwritten.

- **HIGH, conditional — The warning lock does not isolate process-wide state.** src/mordred_hermes/wizard/_direct_tools_yaml.py:75: an unrelated, overlapping `catch_warnings` context can restore the global warning sink during parsing. Reproduced **canary disclosure and an accepted parse**. Unrelated warnings can also be swallowed and cause false refusals.

- **MEDIUM — Pure-parser behavior differs from Hermes’s C-first loader.** src/mordred_hermes/wizard/_direct_tools_yaml.py:102: with `%YAML 1.2`, mapping `enabled: n` or legacy `tool_search: off` is direct in Hermes but reported deferred here; `off` incorrectly does nothing.

- **Windows restoration remains incomplete by design.** src/mordred_hermes/wizard/direct_tools.py:216: failed verification leaves a newly created file enabled. Confirmed; documented, but incompatible with “nothing was changed.” Ordinary existing-file restoration works; POSIX also restores mode and deletes newly created files.

- **Library-only value exposure:** src/mordred_hermes/wizard/_direct_tools_yaml.py:161 now returns a legacy scalar alias’s referenced canary through `raw`. CLI and HTTP responses omit `raw`.

## Verdict

**REVISE** before merging into `feat/desktop-mail-ceremonies`. Fix rollback disclosure and reseal handling, warning-context isolation, and loader parity; narrow the remaining round-trip and failure-atomicity promises.