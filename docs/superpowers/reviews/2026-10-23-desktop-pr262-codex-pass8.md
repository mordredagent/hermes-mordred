# Codex eighth-pass review: live-check fixes (PR #262, 2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run against commit ea126b2f2. Verdict REVISE on two P2 items (wrapper verification past the hard deadline; same-second attempt suppression), both fixed afterwards on PR #262. Absolute links were flattened to `path:line` text.


## Findings

1. **P2 — Platform verification can exceed the hard deadline.** imap.py:1001 calls truststore synchronously, including its native certificate verification. Socket timeout and duplicate-descriptor shutdown cannot interrupt that verification. An offline probe using the cached wrapper remained blocked after 405 ms against a 50 ms deadline, despite watchdog shutdown. **Fix:** bound the complete wrap-and-verification operation, close late results, preserve verification, and update SPEC’s timeout/cancellation wording.

2. **P2 — Different attempts can share the suppression timestamp.** plugin.js:2205 identifies attempts solely by `at`, which is stored in integer seconds. Reproduced: after a local success, a different same-second failure renders **Done without an alert**; advancing its timestamp restores the alert. **Fix:** use a unique attempt identity for suppression and add coverage for same-second failures.

Six targeted page checks passed, including the Windows snapshot. Diagnostic privacy and TLS cleanup probes passed; `mail_tool.py` is unchanged versus `10b4c6a9e`. No files changed or network used.

## Verdict

**REVISE**