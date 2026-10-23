# Codex tenth-pass review: Desktop mail and ceremony pages (PR #262, 2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run against commits through a8eba0b12. Two ninth-pass items RESOLVED, one PARTIAL (refusal of a saturated cap happened after the raw connection was opened); fixed afterwards by admitting before any route, DNS or TCP work. Absolute links were flattened to `path:line` text.


Reviewed through `a8eba0b12ab2009745141395bb2fbe29765f8ea2`, including the `_Slot` commit added during review. In-memory probes only; no writes, network, or excluded reads.

## Ninth-pass items

| Item | Status | Evidence |
|---|---|---|
| P2 late-socket publication race | **RESOLVED** | Both publish→abandon and abandon→publish closed exactly once; 100 concurrent schedules passed. |
| Unbounded abandoned handshake workers | **PARTIAL** | Four-worker bound holds; exceptions and pre-start failures release slots; counter stays nonnegative. Delayed workers cannot start after forfeiture. However, refusal occurs **after opening the raw connection**. |
| P3 CLI sink escapes invocation | **RESOLVED** | Sink cleared on success, failure, invalid arguments, and interruption. Text→JSON sequence emitted no JSON connection diagnostics. |

Local Python 3.13 `imaplib` source exercised over an in-memory transport confirmed: post-LOGIN CAPABILITY `BAD` → `imap_protocol`; rejected LOGIN → `imap_auth_failed` with `authentication_failed` hint; no duplicate CAPABILITY.

## New findings

- **P2 — Saturated-cap rejection still opens a connection.** `imap.py:1021` checks admission after `_raw_socket(link)` at line 1008. With four occupied slots, the fifth probe called the raw-socket factory before returning `imap_unreachable` and its diagnostic. Consequently, rejection can still incur DNS/proxy/TCP work and connection delays. Admit before opening the raw socket, preserving slot release on establishment failures.

No other regressions found in the reviewed commits.

## Verdict

**REVISE** — the requested refusal-before-socket condition remains unmet. The other ninth-pass fixes and Python 3.13 mapping checks pass.