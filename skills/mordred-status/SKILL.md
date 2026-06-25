---
name: mordred-status
description: "Read-only inspection of the Mordred privacy layer (status, policy, network path, plugins). Observe only — never mutate or read secrets."
version: 1.0.0
metadata:
  hermes:
    tags: [mordred, privacy, status, policy, network, keyvault, encryption]
    related_skills: []
  mordred:
    network_requirements: local-only
    requires_keyvault: false
---

# Mordred status (read-only)

Inspect the local Mordred privacy layer when the user asks things like
"mordredの状態は？" / "what's my mordred status" / "今のpolicyは？" /
"どのnetwork経路？" / "mordredのプラグイン一覧".

## CRITICAL — read-only boundary

Mordred's job is to **constrain and audit** this agent. You may **observe** its
state but you must **never change it or read its secrets** from a conversation.

**ALLOWED** (metadata only — no secrets):

| Intent | Command |
|--------|---------|
| Overall state | `MORDRED status` |
| Machine-readable state | `MORDRED status --json` |
| Active policy | `MORDRED policy show` |
| Explain a skill's install decision | `MORDRED policy explain <skill-id>` |
| Network path + liveness | `MORDRED network status` |
| Discovered Mordred plugins | `MORDRED plugins list` |

where `MORDRED` =
`/Users/kazuko/dev/work/intmax/Mordred-Hermes/mordred-hermes/.venv/bin/hermes-mordred`

Run these via the code-execution / shell tool and report the output.

**FORBIDDEN** — never run from this skill. If the user wants any of these, print
the exact command and tell them to run it themselves in their shell:

- Any mutation: `configure`, `upgrade`, `keyvault init|recover|enable-se|enable-tpm`,
  `encryption enable|disable|purge`, `network init|use`, `vault *`, `install`.
- Any secret read-out: `audit decrypt`, `vault cat`.
- Even read-only `audit tail|grep` — it can surface install decisions into the
  transcript. Do not run it; hand the command to the user instead.

## Why

These rules preserve the "domain separation" principle in
`mordred-docs/dev/HARNESS_PRIVACY.md`: a recording agent may watch Mordred's
on/off state, but secrets (recovery passphrase, `.env` contents, decrypted audit)
and control actions must stay on the operator's shell, outside the transcript.

## If the CLI is missing

If `MORDRED` is not found, tell the user the Mordred venv is not present at the
path above and stop — do not try to install or build anything.
