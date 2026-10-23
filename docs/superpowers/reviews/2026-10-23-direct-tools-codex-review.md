# Codex review: direct tool calls option (PR #265, 2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox.
Commit reviewed: `085110bf4` (PR #265, branch `feat/direct-tools-option`); absolute links flattened to `path:line` text.

## Findings

- **HIGH — YAML warnings disclose config values.** src/mordred_hermes/wizard/direct_tools.py:123: duplicate anchors emit `ReusedAnchorWarning` containing complete source lines. Confirmed `read_mode` succeeds while unrelated canary values reach stderr. **Fix:** convert YAML warnings into sanitized `config_unreadable` refusals on every parsing path, including Windows.

- **HIGH — Aliases and merges break write isolation and correctness.** src/mordred_hermes/wizard/direct_tools.py:278: editing an aliased `tool_search` mapping also changes its unrelated anchor owner. Conversely, removing an inherited `enabled: "off"` leaves the merge intact, so serialized config remains direct despite reporting success. **Fix:** safely detach/materialize the target mapping, or refuse these shapes; verify the serialized effective mode.

- **MEDIUM — Parsing disagrees with Hermes.** src/mordred_hermes/wizard/direct_tools.py:87: the writer’s default YAML 1.2 parser differs from Hermes’s YAML 1.1 loader. Confirmed legacy `tool_search: off`, `no`, or `n`, and mapping `enabled: n`, report deferred while Hermes treats them as direct. Consequently, `off` can incorrectly do nothing. **Fix:** match Hermes’s YAML resolution before interpreting the setting.

- **MEDIUM — Comment relocation still loses comments.** src/mordred_hermes/wizard/direct_tools.py:258: when `enabled` is the first key, has a preceding mapping-head comment, and is followed by a comment for `listing`, removing it drops the listing comment. **Fix:** transfer comments onto the surviving node while preserving existing head-comment associations.

- **LOW — Checkbox state is temporarily independent of status.** src/mordred_hermes/desktop/assets/desktop/plugin.js:1213: `pending` overrides `status.tools.direct` using the POST response until refresh finishes. This contradicts the requested status-only state. **Fix:** derive `checked` solely from status; retain separate saving/restart state.

## Test gaps

- Add regressions for the reproduced warning leak, aliases/merges, YAML 1.1 cases, and combined head/following comments. Existing canary tests miss parser warnings.
- tests/test_direct_tools.py:446 covers disappearance **before reading**, not after reading/stat. Real resealing takes no policy-write lock; add those interleavings before claiming complete race protection.
- The fixture round-trip assertions are meaningful, but tests/test_direct_tools.py:437 uses only `startswith`. Comment-only/empty files gain `{}\n` after on/off; preexisting `enabled: auto` is not restored. Narrow SPEC’s unconditional byte-for-byte promise or implement it.

Validation was local and read-only: in-memory reproductions and 26 comparisons against Hermes’s actual parsing functions. All 20 Windows page snapshot scenarios matched. File-writing test suites were not run.

## Verdict

**REVISE** — fix config-value disclosure, unsafe YAML edits, parsing parity, and comment loss before shipping.