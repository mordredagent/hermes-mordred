# Codex fifth-pass review: direct tool calls option (PR #265, 2026-10-23)

Response: the finding is fixed in `1701a622d` (wording only; the code is unchanged).

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox.
Commit reviewed: `c0b722138` (PR #265, branch `feat/direct-tools-option`; only `c32ff2b89..c0b722138`, the fixes of the fourth pass); absolute links flattened to `path:line` text.

VERDICT: REVISE

Validation: source inspection, in-memory regression probes and Ruff checks. File-writing pytest suites were not run in the read-only sandbox.

## Findings (condensed)

1. **P3: the revised documentation overstates retries after failures.** `docs/dev/SPEC.md:5467` said a file whose last answer failed waits for the child again, but `_answer` caches a conforming `{"code": "config_unreadable"}` answer before raising: invalid YAML and YAML warnings returned unreadable twice while invoking the reader once. Fix: distinguish cached parse refusals from uncached process or protocol failures in SPEC, the `read_mode` docstring and the fourth-pass record; only runs yielding no conforming answer are retried on every poll.
   - Response (`1701a622d`): both SPEC sentences, the `read_mode` docstring and the fourth-pass record now say that a conforming answer, a refusal included, is cached, and that only a run with no conforming answer (no process, a non-zero exit, a timeout, or output other than one JSON line) is read again on the next poll.
