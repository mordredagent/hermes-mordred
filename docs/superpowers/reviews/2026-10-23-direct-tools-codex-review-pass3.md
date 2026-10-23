# Codex third-pass review: direct tool calls option (PR #265, 2026-10-23)

Response: every finding is fixed. Finding 2 is fixed in `8088e48e0`. Findings 1, 3, 4 and 5, plus the test for finding 2, are fixed in `ac037485b`. The fourth pass found that the `!!pairs` tuples escaped the shared-mapping walk of finding 3; that is closed in the commit named in [the fourth-pass record](2026-10-23-direct-tools-codex-review-pass4.md). The SPEC section "Direct tool calls (2026-10-23)" describes the result.

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox.
Commit reviewed: `81b0f6d5b` (PR #265, branch `feat/direct-tools-option`; only `ef73e65ec..81b0f6d5b`); absolute links flattened to `path:line` text.

VERDICT: REVISE

Validation used source inspection and in-memory probes. File-writing suites were not run, and no prohibited files were accessed.

## Findings (condensed)

1. **P1: YAML warnings can still be disclosed.** `src/mordred_hermes/wizard/_direct_tools_yaml.py:48`. The lock covers only Mordred's own warning contexts. While Mordred parses, another thread can exit an unrelated `catch_warnings` context, which restores the process-wide warning sink. In an in-memory reproduction the YAML canary reached stderr, and the document was accepted. Fix: parse in a subprocess that returns only sanitized results, and add a regression test that overlaps warning-context exits.
   - Response (`ac037485b`): the Hermes process no longer parses YAML.
     - It reads config.yaml itself and pipes the text to `python -I`, which runs `mordred_hermes.wizard._direct_tools_yaml` as `__main__`.
     - The child answers with exactly one JSON line. Its stderr is captured and dropped, and it has a 20 s timeout. Answers are cached by the sha256 of the text, keeping the last 8.
     - Test: another thread enters and exits `warnings.catch_warnings()` while a `ReusedAnchorWarning` document and a `MantissaNoDotYAML1_1Warning` document are read. Nothing reaches stdout, stderr or the log, and the answer is `config_unreadable`.

2. **P2: the child commands reseal the running Desktop's configuration.** `src/mordred_hermes/wizard/direct_tools.py:144`. The child inherits the config-decrypt hook, so `set` and `get` each remove the working copy when they exit. The next status read is then unreadable. Fix: disable the hook in the child, and test with the lifecycle behaviour represented.
   - Response (`8088e48e0`): the child `hermes` runs with `MORDRED_CONFIG_DECRYPT=0`.
   - Test (`ac037485b`): `FakeHermes.plan(managed=True)` deletes config.yaml at exit unless that variable is `0`. After `set_direct(home, True)` the file still exists, and `read_mode` answers `{"direct": True, "source": "config"}`.

3. **P2: delegation changes unrelated aliased settings.** `src/mordred_hermes/wizard/direct_tools.py:182`. Take `other: &shared {enabled: true}` and `tools: {tool_search: *shared}`. Hermes's setter changes both values, and the getter still verifies success. Fix: refuse shared containers before delegating, and add a real-CLI fixture.
   - Response (`ac037485b`): the child reports `existing: "shared"` when the `tools` mapping or the `tools.tool_search` mapping object is referenced from more than one place. Both `on` and `off` then refuse with the restored code `config_unsupported_shape`, before any `hermes` command runs.
   - Tests:
     - the alias shape is refused for `on` and `off`, and the fake `hermes` records no call;
     - a `tools` alias, a merge source and an alias inside a list are refused too;
     - the real-CLI test keeps `other.enabled` unchanged.

4. **P2: a relative home can verify the wrong configuration.** `src/mordred_hermes/wizard/direct_tools.py:145`. With `HERMES_HOME=profile`, the subprocess changes directory into `profile` but keeps the relative value. Fix: make the home absolute first, and add a regression test.
   - Response (`ac037485b`): `read_mode`, `set_direct` and `hermes_command` make the home absolute first.
   - Test: `set_direct(Path("profile"), True)` runs with `HERMES_HOME` recorded as the absolute path, and no `profile/profile` appears.

5. **P2: concurrent disable requests are not serialized.** `src/mordred_hermes/wizard/direct_tools.py:179`. Two POSTs can both read direct mode. The second then fails with `config_write_failed`. Fix: serialize the whole read/change/verify, read again once the lock is held, and add a concurrency regression test.
   - Response (`ac037485b`): a module-level lock covers the whole read, command and check, and the state is read again once the lock is held.
   - Test: two threads call `set_direct(home, False)` at once. Both succeed, and the fake `hermes` records exactly one `unset`.
