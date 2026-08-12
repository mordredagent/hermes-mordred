# Developer documentation

Start with [`setup.md`](./setup.md) for the editable environment and safe local
validation. This directory separates documents by the kind of decision they
own; a historical record is not a current implementation instruction.

## Current sources of truth

| Document | Owns |
|---|---|
| [`SPEC.md`](./SPEC.md) | Supported behavior, threat model, and product boundaries |
| [`PLAN.md`](./PLAN.md) | Current implementation shape and maintenance approach |
| [`TODO.md`](./TODO.md) | Open work only |
| [`CI.md`](./CI.md) | CI, branching, release, and changelog policy |
| [`PATHS.md`](./PATHS.md) | Mordred-owned filesystem paths and ownership |
| [`POLICY.md`](./POLICY.md) | Policy schema and audit reason codes |
| [`UPSTREAM.md`](./UPSTREAM.md) | Relationship with Hermes and the zero-PR commitment |
| [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) | Hook fields consumed by Mordred and drift validation |
| [`SLACK_E2E.md`](./SLACK_E2E.md) | Gateway `ENC:v3` wire and mandatory-E2E behavior |

When prose and code disagree, the typed implementation, tests, and machine
contracts named by the relevant document take precedence. Fix the prose in the
same change.

## Operational and design references

| Document | Purpose |
|---|---|
| [`setup.md`](./setup.md) | Development setup, the two venvs, and isolated validation |
| [`KEYVAULT_BACKENDS.md`](./KEYVAULT_BACKENDS.md) | Key-backend selection and platform guarantees |
| [`SECRETS_ENV_ENCRYPTION.md`](./SECRETS_ENV_ENCRYPTION.md) | At-rest vault architecture |
| [`HARNESS_PRIVACY.md`](./HARNESS_PRIVACY.md) | Harness and workspace threat analysis |
| [`ROADMAP.md`](./ROADMAP.md) | Work intentionally deferred beyond the current release |

## Historical decision records

[`MIGRATION.md`](./MIGRATION.md) records why the project moved from OpenClaw to
Hermes and adopted a standalone plugin-only repository. Its decisions remain
in force, but its old alternatives are not implementation instructions.

[`hermes/DESIGN.md`](./hermes/DESIGN.md) and
[`hermes/STRUCTURE.md`](./hermes/STRUCTURE.md) are point-in-time upstream Hermes
snapshots. Their links are pinned to the recorded upstream commit; verify live
Hermes source before changing compatibility code.

## Maintenance rules

- Keep all documentation in English.
- Do not rename existing headings; other documents and code comments cite them.
- Use repo-relative links between local documents. README links intended to
  render on PyPI may use absolute GitHub `main` URLs.
- Keep current behavior in the source-of-truth document and change history in
  PR descriptions. This repository has no `CHANGELOG.md`.
- Update package versions only with `python tools/bump_version.py <version>`.
- Run the documentation link test and the standard repository checks after
  editing these files.
